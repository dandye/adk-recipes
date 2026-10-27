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

"""Package entrypoint for the Google SecOps canonical ADK recipe.

Loads environment variables from a local `.env` or `config.env` file if
present, strips unsubstituted template placeholders (`<TODO...>`,
`<YOUR_...>`, `your-gcp-project-id`), defaults `GOOGLE_GENAI_USE_VERTEXAI` to
`True`, and exports `agent`, `app`, and `root_agent` for ADK CLI discovery
(`adk web`, `adk run`, `adk api_server`).
"""

import os
from pathlib import Path

from dotenv import load_dotenv

# Load variables from .env, config.env, and .env.example if present. When
# deployed via `make deploy-agent-engine`, `make sync-config` copies
# `config.env` into `app/config.env` so it ships inside the Agent Engine bundle.
_PACKAGE_DIR = Path(__file__).resolve().parent
_RECIPE_DIR = _PACKAGE_DIR.parent
for _candidate_env in (
    _PACKAGE_DIR / "config.env",
    _RECIPE_DIR / "config.env",
    _RECIPE_DIR / ".env",
    _RECIPE_DIR / ".env.example",
):
    if _candidate_env.is_file():
        load_dotenv(_candidate_env)
load_dotenv()

# Strip <TODO...>, <YOUR_...>, or your-gcp-project-id placeholders so code
# checks can treat unset and unedited template values identically.
for _env_key, _env_value in list(os.environ.items()):
    if _env_value.startswith(("<TODO", "<YOUR_")) or (
        _env_value == "your-gcp-project-id"
    ):
        del os.environ[_env_key]

# Vertex AI Agent Engine reserves GOOGLE_CLOUD_PROJECT and
# GOOGLE_CLOUD_LOCATION in deployment_spec.env, so deployment scripts pass
# GCP_PROJECT_ID and GEMINI_MODEL_LOCATION and we restore them here.
if "GCP_PROJECT_ID" in os.environ and "GOOGLE_CLOUD_PROJECT" not in os.environ:
    os.environ["GOOGLE_CLOUD_PROJECT"] = os.environ["GCP_PROJECT_ID"]
if "GEMINI_MODEL_LOCATION" in os.environ:
    os.environ["GOOGLE_CLOUD_LOCATION"] = os.environ["GEMINI_MODEL_LOCATION"]

from app import agent  # noqa: E402 -- must come after load_dotenv()
from app.agent import app, root_agent  # noqa: E402

__all__ = ["agent", "app", "root_agent"]
