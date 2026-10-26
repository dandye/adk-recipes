# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""End-to-end FastAPI and A2A server integration tests for SecOps agents."""

import json
import logging
import os
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from typing import Any

import pytest
import requests
from requests.exceptions import RequestException

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_URL = "http://127.0.0.1:8000"
STREAM_URL = BASE_URL + "/run_sse"
AGENT_CARD_URL = BASE_URL + "/a2a/app/.well-known/agent-card.json"

HEADERS = {"Content-Type": "application/json"}


def log_output(pipe: Any, log_func: Any) -> None:
    """Forwards lines from a subprocess pipe to a logging function.

    Args:
        pipe: Text stream (`stdout` or `stderr`) attached to the subprocess.
        log_func: Logging callable (such as `logger.info` or `logger.error`).
    """
    for line in iter(pipe.readline, ""):
        log_func(line.strip())


def start_server() -> subprocess.Popen[str]:
    """Starts the FastAPI server subprocess and logs its output streams.

    Returns:
        Running `subprocess.Popen` handle for the Uvicorn server.
    """
    command = [
        sys.executable,
        "-m",
        "uvicorn",
        "app.fast_api_app:app",
        "--host",
        "0.0.0.0",
        "--port",
        "8000",
    ]
    env = os.environ.copy()
    env["INTEGRATION_TEST"] = "TRUE"
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env=env,
    )

    # Start threads to log stdout and stderr in real-time
    threading.Thread(
        target=log_output, args=(process.stdout, logger.info), daemon=True
    ).start()
    threading.Thread(
        target=log_output, args=(process.stderr, logger.error), daemon=True
    ).start()

    return process


def wait_for_server(timeout: int = 90, interval: int = 1) -> bool:
    """Polls `/docs` until the FastAPI server responds with HTTP 200.

    Args:
        timeout: Maximum wait time in seconds before giving up.
        interval: Sleep interval in seconds between polling attempts.

    Returns:
        `True` if the server became ready within `timeout`, otherwise `False`.
    """
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = requests.get("http://127.0.0.1:8000/docs", timeout=10)
            if response.status_code == 200:
                logger.info("Server is ready")
                return True
        except RequestException:
            pass
        time.sleep(interval)
    logger.error(f"Server did not become ready within {timeout} seconds")
    return False


@pytest.fixture(scope="session")
def server_fixture(request: Any) -> Iterator[subprocess.Popen[str]]:
    """Session-scoped pytest fixture managing the FastAPI server process.

    Args:
        request: Pytest fixture request object used to register teardown.

    Yields:
        Running `subprocess.Popen` handle for the Uvicorn server.
    """
    logger.info("Starting server process")
    server_process = start_server()
    if not wait_for_server():
        pytest.fail("Server failed to start")
    logger.info("Server process started")

    def stop_server() -> None:
        """Terminates and waits for the background Uvicorn server process."""
        logger.info("Stopping server process")
        server_process.terminate()
        server_process.wait()
        logger.info("Server process stopped")

    request.addfinalizer(stop_server)
    yield server_process


def test_chat_stream(server_fixture: subprocess.Popen[str]) -> None:
    """Tests streaming chat events over `/run_sse`.

    Args:
        server_fixture: Running Uvicorn server fixture.
    """
    logger.info("Starting chat stream test")
    # Create session first
    user_id = "test_user_123"
    session_data = {
        "state": {"preferred_language": "English", "visit_count": 1}
    }

    session_url = f"{BASE_URL}/apps/app/users/{user_id}/sessions"
    session_response = requests.post(
        session_url,
        headers=HEADERS,
        json=session_data,
        timeout=60,
    )
    assert session_response.status_code == 200
    logger.info(f"Session creation response: {session_response.json()}")
    session_id = session_response.json()["id"]

    # Then send chat message
    data = {
        "app_name": "app",
        "user_id": user_id,
        "session_id": session_id,
        "new_message": {
            "role": "user",
            "parts": [{"text": "Hi!"}],
        },
        "streaming": True,
    }
    response = requests.post(
        STREAM_URL, headers=HEADERS, json=data, stream=True, timeout=60
    )
    assert response.status_code == 200

    # Parse SSE events from response
    events = []
    for line in response.iter_lines():
        if line:
            # SSE format is "data: {json}"
            line_str = line.decode("utf-8")
            if line_str.startswith("data: "):
                event_json = line_str[6:]  # Remove "data: " prefix
                event = json.loads(event_json)
                events.append(event)

    assert events, "No events received from stream"
    # Check for valid content in the response
    has_text_content = False
    for event in events:
        content = event.get("content")
        if (
            content is not None
            and content.get("parts")
            and any(part.get("text") for part in content["parts"])
        ):
            has_text_content = True
            break

    assert has_text_content, "Expected at least one event with text content"


def test_chat_stream_error_handling(
    server_fixture: subprocess.Popen[str],
) -> None:
    """Tests that malformed `/run_sse` payloads return HTTP 422.

    Args:
        server_fixture: Running Uvicorn server fixture.
    """
    logger.info("Starting chat stream error handling test")
    data = {
        "input": {
            "messages": [{"type": "invalid_type", "content": "Cause an error"}]
        }
    }
    response = requests.post(
        STREAM_URL, headers=HEADERS, json=data, stream=True, timeout=10
    )

    assert response.status_code == 422, (
        f"Expected status code 422, got {response.status_code}"
    )
    logger.info("Error handling test completed successfully")


def test_a2a_agent_card(server_fixture: subprocess.Popen[str]) -> None:
    """Tests the A2A `.well-known/agent-card.json` discovery endpoint.

    Args:
        server_fixture: Running Uvicorn server fixture.
    """
    response = requests.get(AGENT_CARD_URL, headers=HEADERS, timeout=10)
    assert response.status_code == 200
    assert response.json().get("name") in {"secops_supervisor", "secops_agent"}
