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

"""Live MCP toolset builders for Google SecOps OneMCP and Google Threat Intelligence (GTI)."""

import asyncio
import os
import shlex
import weakref
from collections.abc import Callable, Sequence
from typing import Any

import google.auth
import google.auth.transport.requests
from google.adk.tools.mcp_tool import (
    McpToolset,
    StdioConnectionParams,
    StreamableHTTPConnectionParams,
)
from mcp import StdioServerParameters

CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
RECIPE_USER_AGENT = "adk-recipes/1.0 (recipe:secops-custom-agents)"

# Filtering these 7 high-bloat feed-management tools reduces SecOps OneMCP
# eager inputSchema payload by 68.94% (246,347 B -> 76,507 B).
EXCLUDED_FEED_MANAGEMENT_TOOLS: frozenset[str] = frozenset(
    {
        "create_feed",
        "update_feed",
        "run_parser",
        "list_feeds",
        "get_feed",
        "disable_feed",
        "enable_feed",
    }
)

_LAST_LOOP_REF: weakref.ReferenceType[asyncio.AbstractEventLoop] | None = None


def _is_missing_or_placeholder(value: str | None) -> bool:
    """Returns True if an environment variable value is empty or a TODO placeholder."""
    if value is None:
        return True
    stripped = value.strip()
    return not stripped or stripped.startswith("<TODO:")


def validate_secops_onemcp_config(
    env: dict[str, str] | None = None,
) -> dict[str, str]:
    """Validates required Google SecOps OneMCP tenant environment variables."""
    project_id = (
        env.get("CHRONICLE_PROJECT_ID") or env.get("GOOGLE_CLOUD_PROJECT")
        if env is not None
        else (
            os.getenv("CHRONICLE_PROJECT_ID")
            or os.getenv("GOOGLE_CLOUD_PROJECT")
        )
    )
    customer_id = (
        env.get("CHRONICLE_CUSTOMER_ID")
        if env is not None
        else os.getenv("CHRONICLE_CUSTOMER_ID")
    )
    region = (
        env.get("CHRONICLE_REGION", "us")
        if env is not None
        else os.getenv("CHRONICLE_REGION", "us")
    )

    missing: list[str] = []
    if _is_missing_or_placeholder(project_id):
        missing.append("CHRONICLE_PROJECT_ID")
    if _is_missing_or_placeholder(customer_id):
        missing.append("CHRONICLE_CUSTOMER_ID")
    if _is_missing_or_placeholder(region):
        missing.append("CHRONICLE_REGION")

    if missing:
        raise RuntimeError(
            "Missing required Google SecOps OneMCP configuration: "
            f"{', '.join(missing)}. Set these variables in your environment or .env file."
        )

    return {
        "project_id": str(project_id).strip(),
        "customer_id": str(customer_id).strip(),
        "region": str(region).strip(),
    }


def validate_gti_mcp_config(
    env: dict[str, str] | None = None,
) -> str:
    """Validates required Google Threat Intelligence (GTI) MCP API key configuration."""
    api_key = (
        env.get("VT_APIKEY") or env.get("GTI_API_KEY")
        if env is not None
        else (os.getenv("VT_APIKEY") or os.getenv("GTI_API_KEY"))
    )
    if _is_missing_or_placeholder(api_key):
        raise RuntimeError(
            "Missing required GTI MCP credential: set VT_APIKEY (or GTI_API_KEY) "
            "in your environment or .env file."
        )
    return str(api_key).strip()


def resolve_secops_onemcp_url(
    env: dict[str, str] | None = None,
) -> str:
    """Resolves the regional Google SecOps OneMCP endpoint URL."""
    explicit_url = (
        env.get("SECOPS_ONEMCP_URL")
        if env is not None
        else os.getenv("SECOPS_ONEMCP_URL")
    )
    if explicit_url and not _is_missing_or_placeholder(explicit_url):
        return explicit_url.strip()
    raw_region = (
        env.get("CHRONICLE_REGION", "us")
        if env is not None
        else os.getenv("CHRONICLE_REGION", "us")
    )
    region = (raw_region or "us").strip()
    if _is_missing_or_placeholder(region):
        region = "us"
    return f"https://chronicle.{region}.rep.googleapis.com/mcp"


def should_include_secops_tool(
    tool: Any,
    allowed_prefixes: Sequence[str] | None = None,
) -> bool:
    """Filters out high-bloat feed tools and optionally scopes tools by persona role."""
    tool_name = tool if isinstance(tool, str) else getattr(tool, "name", "")
    normalized = (
        str(tool_name).removeprefix("secops_").removeprefix("secops-mcp_")
    )
    if normalized in EXCLUDED_FEED_MANAGEMENT_TOOLS:
        return False
    if allowed_prefixes:
        return any(normalized.startswith(prefix) for prefix in allowed_prefixes)
    return True


def make_secops_tool_filter(
    allowed_prefixes: Sequence[str] | None = None,
) -> Callable[[Any, Any], bool]:
    """Creates an ADK ToolPredicate for SecOps OneMCP with feed-bloat removal."""
    prefixes = tuple(allowed_prefixes) if allowed_prefixes else None

    def _predicate(tool: Any, readonly_context: Any = None) -> bool:
        del readonly_context
        return should_include_secops_tool(tool, allowed_prefixes=prefixes)

    return _predicate


def make_gti_tool_filter(
    allowed_prefixes: Sequence[str] | None = None,
) -> Callable[[Any, Any], bool]:
    """Creates an ADK ToolPredicate for GTI MCP scoped to a specialist persona."""
    prefixes = tuple(allowed_prefixes) if allowed_prefixes else None

    def _predicate(tool: Any, readonly_context: Any = None) -> bool:
        del readonly_context
        if not prefixes:
            return True
        tool_name = tool if isinstance(tool, str) else getattr(tool, "name", "")
        normalized = (
            str(tool_name).removeprefix("gti_").removeprefix("gti-mcp_")
        )
        return any(normalized.startswith(prefix) for prefix in prefixes)

    return _predicate


def build_secops_onemcp_header_provider(
    env: dict[str, str] | None = None,
    oauth_auth_id: str | None = None,
) -> Callable[[Any], dict[str, str]]:
    """Builds a dynamic header_provider that injects OAuth/ADC Bearer tokens for OneMCP."""

    def _header_provider(readonly_context: Any = None) -> dict[str, str]:
        cfg = validate_secops_onemcp_config(env=env)
        headers: dict[str, str] = {
            "x-goog-user-project": cfg["project_id"],
            "User-Agent": RECIPE_USER_AGENT,
        }

        state = getattr(readonly_context, "state", None)
        if isinstance(state, dict):
            if oauth_auth_id:
                token = state.get(f"temp:{oauth_auth_id}")
                if isinstance(token, str) and token.strip():
                    headers["Authorization"] = f"Bearer {token.strip()}"
                    return headers
            for key, val in state.items():
                if (
                    str(key).startswith("temp:")
                    and isinstance(val, str)
                    and val.strip()
                ):
                    headers["Authorization"] = f"Bearer {val.strip()}"
                    return headers

        credentials, _ = google.auth.default(scopes=[CLOUD_PLATFORM_SCOPE])
        if not credentials.valid:
            request = google.auth.transport.requests.Request()
            credentials.refresh(request)
        if not credentials.token:
            raise RuntimeError(
                "Failed to mint Google Cloud access token for SecOps OneMCP."
            )
        headers["Authorization"] = f"Bearer {credentials.token}"
        return headers

    return _header_provider


def build_gti_stdio_env(
    base_env: dict[str, str] | None = None,
    require_credentials: bool = False,
) -> dict[str, str]:
    """Builds a clean child environment for the GTI MCP stdio server.

    Unsets UV_PROJECT and UV_PROJECT_ENVIRONMENT so child uv/uvx commands resolve
    their own environment, and forwards VT_APIKEY explicitly because
    mcp.client.stdio strips non-default environment variables.
    """
    source = dict(base_env if base_env is not None else os.environ)
    if require_credentials:
        validate_gti_mcp_config(env=source)

    source.pop("UV_PROJECT", None)
    source.pop("UV_PROJECT_ENVIRONMENT", None)

    env: dict[str, str] = {}
    for key in ("PATH", "HOME", "USER", "LANG", "VT_APIKEY", "GTI_API_KEY"):
        val = source.get(key)
        if val:
            env[key] = val

    if "VT_APIKEY" not in env and "GTI_API_KEY" in env:
        env["VT_APIKEY"] = env["GTI_API_KEY"]

    return env


class LazyValidatedMcpToolset(McpToolset):
    """McpToolset subclass that validates live credentials before session creation."""

    def __init__(
        self,
        *args: Any,
        config_validator: Callable[[], Any] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._config_validator = config_validator

    async def get_tools(self, readonly_context: Any = None) -> list[Any]:
        """Validates credentials before connecting, or short-circuits in smoke tests."""
        if self._config_validator is not None:
            try:
                self._config_validator()
            except RuntimeError:
                if os.getenv("INTEGRATION_TEST"):
                    return []
                raise
        return await super().get_tools(readonly_context=readonly_context)


def build_secops_onemcp_toolset(
    allowed_prefixes: Sequence[str] | None = None,
    env: dict[str, str] | None = None,
    require_credentials: bool = False,
) -> McpToolset:
    """Creates a live McpToolset connected to Google SecOps OneMCP over Streamable HTTP."""
    if require_credentials:
        validate_secops_onemcp_config(env=env)

    url = resolve_secops_onemcp_url(env=env)
    return LazyValidatedMcpToolset(
        connection_params=StreamableHTTPConnectionParams(url=url),
        tool_filter=make_secops_tool_filter(allowed_prefixes=allowed_prefixes),
        tool_name_prefix="secops_",
        header_provider=build_secops_onemcp_header_provider(env=env),
        config_validator=lambda: validate_secops_onemcp_config(env=env),
    )


def build_gti_mcp_toolset(
    allowed_prefixes: Sequence[str] | None = None,
    env: dict[str, str] | None = None,
    require_credentials: bool = False,
) -> McpToolset:
    """Creates a live McpToolset for Google Threat Intelligence (GTI) MCP."""
    if require_credentials:
        validate_gti_mcp_config(env=env)

    gti_http_url = (
        env.get("GTI_MCP_URL") if env is not None else os.getenv("GTI_MCP_URL")
    )
    if gti_http_url and not _is_missing_or_placeholder(gti_http_url):
        raw_key = (
            env.get("VT_APIKEY") or env.get("GTI_API_KEY")
            if env is not None
            else (os.getenv("VT_APIKEY") or os.getenv("GTI_API_KEY"))
        )
        api_key = (raw_key or "").strip()
        headers = {"x-apikey": api_key} if api_key else {}
        return LazyValidatedMcpToolset(
            connection_params=StreamableHTTPConnectionParams(
                url=gti_http_url.strip(),
                headers=headers,
            ),
            tool_filter=make_gti_tool_filter(allowed_prefixes=allowed_prefixes),
            tool_name_prefix="gti_",
            config_validator=lambda: validate_gti_mcp_config(env=env),
        )

    raw_cmd = (
        env.get("GTI_MCP_COMMAND", "uvx")
        if env is not None
        else os.getenv("GTI_MCP_COMMAND", "uvx")
    )
    raw_args = (
        env.get("GTI_MCP_ARGS", "gti-mcp")
        if env is not None
        else os.getenv("GTI_MCP_ARGS", "gti-mcp")
    )
    command = (raw_cmd or "uvx").strip()
    args = (
        shlex.split(raw_args) if raw_args and raw_args.strip() else ["gti-mcp"]
    )
    stdio_env = build_gti_stdio_env(
        base_env=env,
        require_credentials=require_credentials,
    )

    return LazyValidatedMcpToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command=command,
                args=args,
                env=stdio_env,
            ),
            timeout=60.0,
        ),
        tool_filter=make_gti_tool_filter(allowed_prefixes=allowed_prefixes),
        tool_name_prefix="gti_",
        config_validator=lambda: validate_gti_mcp_config(env=env),
    )


def _reset_closed_event_loop_clients(callback_context: Any) -> None:
    """Resets cached Gemini._api_client when AdkApp switches asyncio event loops."""
    global _LAST_LOOP_REF
    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        return

    prev_loop = _LAST_LOOP_REF() if _LAST_LOOP_REF is not None else None
    loop_changed = prev_loop is not current_loop or (
        prev_loop is not None and prev_loop.is_closed()
    )
    _LAST_LOOP_REF = weakref.ref(current_loop)
    if not loop_changed or callback_context is None:
        return

    inv_ctx = getattr(callback_context, "_invocation_context", None)
    agent = getattr(inv_ctx, "agent", None)
    model = getattr(agent, "canonical_model", None) or getattr(
        agent, "model", None
    )
    if model is not None and hasattr(model, "_api_client"):
        try:
            delattr(model, "_api_client")
        except AttributeError:
            model._api_client = None


def strip_response_json_schema_callback(
    callback_context: Any,
    llm_request: Any,
) -> None:
    """Strips 3.73 MB response_json_schema bloat from SecOps OneMCP tool declarations."""
    _reset_closed_event_loop_clients(callback_context)
    cfg = getattr(llm_request, "config", None)
    if cfg is None:
        return
    tools = getattr(cfg, "tools", None) or []
    for tool in tools:
        decls = getattr(tool, "function_declarations", None) or []
        for fd in decls:
            if hasattr(fd, "response_json_schema"):
                fd.response_json_schema = None
            if hasattr(fd, "response"):
                fd.response = None
