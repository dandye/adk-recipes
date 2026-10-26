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

"""Attach A2A (Agent2Agent) endpoints to the FastAPI app.

`attach_a2a_routes` registers the dynamic agent-card endpoint and the JSON-RPC
endpoint so the same app serves A2A alongside the `adk_api` routes, reachable by
A2A clients and Gemini Enterprise A2A registration.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import (
    add_a2a_routes_to_fastapi,
    create_agent_card_routes,
    create_jsonrpc_routes,
)
from a2a.server.routes.common import DefaultServerCallContextBuilder
from a2a.server.tasks import TaskStore
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentExtension,
    AgentInterface,
)
from a2a.utils.constants import AGENT_CARD_WELL_KNOWN_PATH
from google.adk.a2a.executor.a2a_agent_executor import A2aAgentExecutor
from google.adk.a2a.utils.agent_card_builder import AgentCardBuilder


class _A2AServerCallContextBuilder(DefaultServerCallContextBuilder):
    """Context builder that ensures `A2A-Version` defaults when missing.

    Proxy infrastructure (such as Google Cloud API Gateways) can strip custom
    HTTP headers like `A2A-Version`. This builder infers the A2A version from
    the JSON-RPC method name when the header is absent.
    """

    def build(self, request: Any) -> Any:
        """Builds the A2A server call context with normalized version headers.

        Args:
            request: Incoming Starlette/FastAPI HTTP request.

        Returns:
            Constructed `ServerCallContext` with `A2A-Version` populated in
            `context.state["headers"]`.
        """
        context = super().build(request)
        headers = context.state.setdefault("headers", {})
        existing_version = (
            headers.get("A2A-Version")
            or headers.get("a2a-version")
            or headers.get("x-a2a-version")
            or headers.get("X-A2A-Version")
        )
        if existing_version:
            headers["A2A-Version"] = existing_version
            return context

        # 0.3 uses method names that include a '/' like "message/send"
        # 1.0 uses PascalCase like "SendMessage"
        json_body = getattr(request, "_json", {}) or {}
        method = (
            json_body.get("method") if isinstance(json_body, dict) else None
        )

        if method and "/" in str(method):
            headers["A2A-Version"] = "0.3"
        else:
            headers["A2A-Version"] = "1.0"

        return context


if TYPE_CHECKING:
    from fastapi import FastAPI
    from google.adk.agents import BaseAgent
    from google.adk.runners import Runner

# URI advertised on the agent card describing the executor extension shipped
# by ADK. Kept as a module-level constant so callers can override or extend
# the capabilities list when needed.
_ADK_AGENT_EXECUTOR_EXTENSION_URI = (
    "https://google.github.io/adk-docs/a2a/a2a-extension/"
)


async def _add_v0_3_compat_interface(card: AgentCard) -> AgentCard:
    """Advertises a v0.3 JSON-RPC interface on the served A2A `AgentCard`.

    Ensures the served card remains consumable by v0.3 A2A clients, notably
    Gemini Enterprise registration, whose validator requires the v0.3 card
    shape.

    Args:
        card: Base `AgentCard` constructed by `AgentCardBuilder`.

    Returns:
        Mutated `AgentCard` with an additional v0.3 `AgentInterface` entry.
    """
    if card.supported_interfaces:
        card.supported_interfaces.append(
            AgentInterface(
                protocol_binding="JSONRPC",
                protocol_version="0.3",
                url=card.supported_interfaces[0].url,
            )
        )
    return card


def _default_capabilities() -> AgentCapabilities:
    """Builds the default A2A `AgentCapabilities` advertised by the server.

    Returns:
        `AgentCapabilities` with streaming enabled and the ADK executor
        extension registered.
    """
    return AgentCapabilities(
        streaming=True,
        extensions=[
            AgentExtension(
                uri=_ADK_AGENT_EXECUTOR_EXTENSION_URI,
                description=(
                    "Ability to use the new agent executor implementation"
                ),
            ),
        ],
    )


async def attach_a2a_routes(
    app: FastAPI,
    *,
    agent: BaseAgent,
    runner: Runner,
    task_store: TaskStore,
    rpc_path: str,
    capabilities: AgentCapabilities | None = None,
    agent_version: str | None = None,
    app_url: str | None = None,
) -> None:
    """Registers A2A JSON-RPC and agent-card routes under `rpc_path`.

    Builds a dynamic agent card from `agent` and mounts the routes on `app`.
    The `runner` should share the session, artifact, and memory services with
    the standard ADK path. Call once per app (typically inside a FastAPI
    `lifespan` context manager).

    Args:
        app: FastAPI application on which to mount the A2A routes.
        agent: Root ADK `BaseAgent` exposed over A2A.
        runner: Shared ADK `Runner` instance executing agent turns.
        task_store: A2A `TaskStore` tracking in-flight and completed tasks.
        rpc_path: URL path prefix for the A2A JSON-RPC endpoint (for example,
            `/a2a/app`).
        capabilities: Optional `AgentCapabilities` override.
        agent_version: Optional version string override (defaults to
            `AGENT_VERSION` env var or `"0.1.0"`).
        app_url: Optional externally reachable base URL override (defaults to
            `APP_URL` env var or `"http://0.0.0.0:8000"`).
    """
    resolved_app_url = app_url or os.getenv("APP_URL", "http://0.0.0.0:8000")
    resolved_agent_version = agent_version or os.getenv(
        "AGENT_VERSION", "0.1.0"
    )
    resolved_capabilities = capabilities or _default_capabilities()

    agent_card = await AgentCardBuilder(
        agent=agent,
        capabilities=resolved_capabilities,
        rpc_url=f"{resolved_app_url}{rpc_path}",
        agent_version=resolved_agent_version,
    ).build()

    request_handler = DefaultRequestHandler(
        agent_executor=A2aAgentExecutor(runner=runner),
        task_store=task_store,
        agent_card=agent_card,
    )

    add_a2a_routes_to_fastapi(
        app,
        agent_card_routes=create_agent_card_routes(
            agent_card,
            card_modifier=_add_v0_3_compat_interface,
            card_url=f"{rpc_path}{AGENT_CARD_WELL_KNOWN_PATH}",
        ),
        jsonrpc_routes=create_jsonrpc_routes(
            request_handler,
            rpc_url=rpc_path,
            context_builder=_A2AServerCallContextBuilder(),
            enable_v0_3_compat=True,
        ),
    )
