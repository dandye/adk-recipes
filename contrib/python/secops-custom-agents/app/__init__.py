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

Loads environment variables from a local `.env` file if present, strips
unsubstituted template placeholders (`<TODO...>` / `<YOUR_...>`), defaults
`GOOGLE_GENAI_USE_VERTEXAI` to `True`, and exports `agent`, `app`, and
`root_agent` for ADK CLI discovery (`adk web`, `adk run`, `adk api_server`).
"""

import os

from dotenv import load_dotenv

# Load variables from .env if present. In production the environment is
# already populated by the platform (Cloud Run, GKE, etc.), so a missing
# .env is expected and not an error.
load_dotenv()

# Strip <TODO...> or <YOUR_...> placeholders so code checks can treat unset
# and unedited .env.example values identically.
for _k, _v in list(os.environ.items()):
    if _v.startswith(("<TODO", "<YOUR_")):
        del os.environ[_k]

os.environ.setdefault("GOOGLE_GENAI_USE_VERTEXAI", "True")

from . import agent  # noqa: E402 -- must come after load_dotenv()
from .agent import app, root_agent  # noqa: E402

__all__ = ["agent", "app", "root_agent"]
