# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""MCP toolset builders for Google SecOps OneMCP and Threat Intelligence.

Provides production-hardened `McpToolset` factories and callbacks:
  1. **Google SecOps OneMCP**
     (`https://chronicle.<region>.rep.googleapis.com/mcp`):
     - Dynamic `header_provider` supporting Gemini Enterprise OAuth state
       tokens (`temp:<AUTH_ID>`) and Google Application Default Credentials.
     - Feed-management tool filter (`EXCLUDED_FEED_MANAGEMENT_TOOLS`) that
       reduces eager `inputSchema` payload by 68.94% (246,347 B -> 76,507 B).
     - `strip_response_json_schema_callback` to strip 3.73 MB of
       `response_json_schema` bloat before each LLM call.
  2. **Google Threat Intelligence (GTI) MCP** (`gti-mcp`):
     - Supports both local stdio execution (`uvx gti-mcp`) with sanitized
       child environment variables and remote Streamable HTTP (`GTI_MCP_URL`).
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import os
import shlex
import weakref
from collections.abc import Callable, Mapping, Sequence
from typing import Any

import google.auth
import google.auth.transport.requests
from google.adk.tools.mcp_tool import (
    McpToolset,
    StdioConnectionParams,
    StreamableHTTPConnectionParams,
)
from mcp import StdioServerParameters

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Configuration Validation & URL Resolution
# ---------------------------------------------------------------------------
def _is_missing_or_placeholder(value: str | None) -> bool:
    """Check whether an environment value is unset or a template placeholder.

    Args:
        value: Raw environment variable string or `None`.

    Returns:
        `True` if `value` is `None`, empty/whitespace, equals
        `"your-gcp-project-id"`, or starts with a `<TODO` or `<YOUR_`
        placeholder prefix; `False` otherwise.
    """
    if value is None:
        return True
    stripped = value.strip()
    if stripped in {"", "your-gcp-project-id"}:
        return True
    return stripped.startswith(("<TODO", "<YOUR_"))


def validate_secops_onemcp_config(
    env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Validate required Google SecOps OneMCP tenant environment variables.

    Args:
        env: Optional environment mapping override for testing. Defaults to
            reading from `os.environ` via `os.getenv`.

    Returns:
        A dictionary containing validated `"project_id"`, `"customer_id"`,
        and `"region"` strings.

    Raises:
        RuntimeError: If `CHRONICLE_PROJECT_ID` (or `GOOGLE_CLOUD_PROJECT`),
            `CHRONICLE_CUSTOMER_ID`, or `CHRONICLE_REGION` is missing or
            still set to a template placeholder.
    """
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
        env.get("CHRONICLE_REGION")
        if env is not None
        else os.getenv("CHRONICLE_REGION")
    )

    missing: list[str] = []
    if _is_missing_or_placeholder(project_id):
        missing.append("CHRONICLE_PROJECT_ID")
    if _is_missing_or_placeholder(customer_id):
        missing.append("CHRONICLE_CUSTOMER_ID")
    if _is_missing_or_placeholder(region):
        missing.append("CHRONICLE_REGION")

    if missing:
        missing_str = ", ".join(missing)
        raise RuntimeError(
            f"Missing required Google SecOps OneMCP configuration: "
            f"{missing_str}. Set these variables in your environment or .env."
        )

    return {
        "project_id": str(project_id).strip(),
        "customer_id": str(customer_id).strip(),
        "region": str(region).strip(),
    }


def validate_gti_mcp_config(
    env: Mapping[str, str] | None = None,
) -> str:
    """Validate required Google Threat Intelligence (GTI) MCP API key settings.

    Args:
        env: Optional environment mapping override for testing. Defaults to
            reading from `os.environ` via `os.getenv`.

    Returns:
        The validated GTI / VirusTotal API key string.

    Raises:
        RuntimeError: If neither `VT_APIKEY` nor `GTI_API_KEY` is set to a
            non-placeholder value.
    """
    api_key = (
        env.get("VT_APIKEY") or env.get("GTI_API_KEY")
        if env is not None
        else (os.getenv("VT_APIKEY") or os.getenv("GTI_API_KEY"))
    )
    if _is_missing_or_placeholder(api_key):
        raise RuntimeError(
            "Missing required GTI MCP credential: set VT_APIKEY (or"
            " GTI_API_KEY) in your environment or .env file."
        )
    return str(api_key).strip()


def resolve_secops_onemcp_url(
    env: Mapping[str, str] | None = None,
) -> str:
    """Resolve the regional Google SecOps OneMCP Streamable HTTP endpoint URL.

    Args:
        env: Optional environment mapping override for testing.

    Returns:
        The explicit `SECOPS_ONEMCP_URL` if configured, or the regional
        `https://chronicle.<region>.rep.googleapis.com/mcp` URL.
    """
    explicit_url = (
        env.get("SECOPS_ONEMCP_URL")
        if env is not None
        else os.getenv("SECOPS_ONEMCP_URL")
    )
    if explicit_url and not _is_missing_or_placeholder(explicit_url):
        return explicit_url.strip()
    raw_region = (
        env.get("CHRONICLE_REGION")
        if env is not None
        else os.getenv("CHRONICLE_REGION")
    )
    region = (raw_region or "").strip()
    if _is_missing_or_placeholder(region):
        region = "us"
    return f"https://chronicle.{region}.rep.googleapis.com/mcp"


# ---------------------------------------------------------------------------
# Role-Scoped Tool Filters
# ---------------------------------------------------------------------------
def should_include_secops_tool(
    tool: Any,
    allowed_prefixes: Sequence[str] | None = None,
) -> bool:
    """Filter out high-bloat feed tools and scope tools by specialist persona.

    Args:
        tool: Tool name string or an ADK `BaseTool` object with a `.name`
            attribute.
        allowed_prefixes: Optional sequence of allowed tool name prefixes for
            a specialist persona. When `None`, all non-excluded SecOps tools
            are allowed.

    Returns:
        `True` if the tool should be exposed to the agent; `False` if it is
        in `EXCLUDED_FEED_MANAGEMENT_TOOLS` or outside `allowed_prefixes`.
    """
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
    """Create an ADK `ToolPredicate` for SecOps OneMCP with feed-bloat removal.

    Args:
        allowed_prefixes: Optional sequence of tool name prefixes permitted for
            a specialist persona.

    Returns:
        A predicate callable `(tool, readonly_context) -> bool` suitable for
        `McpToolset(tool_filter=...)`.
    """
    prefixes = tuple(allowed_prefixes) if allowed_prefixes else None

    def _predicate(tool: Any, readonly_context: Any = None) -> bool:
        """Evaluate whether a SecOps OneMCP tool is allowed for the agent.

        Args:
            tool: The candidate MCP tool or tool name.
            readonly_context: Optional ADK invocation readonly context.

        Returns:
            `True` if the tool passes feed-bloat and persona prefix filters.
        """
        del readonly_context
        return should_include_secops_tool(tool, allowed_prefixes=prefixes)

    return _predicate


def make_gti_tool_filter(
    allowed_prefixes: Sequence[str] | None = None,
) -> Callable[[Any, Any], bool]:
    """Create an ADK `ToolPredicate` for GTI MCP scoped to a persona role.

    Args:
        allowed_prefixes: Optional sequence of GTI tool name prefixes permitted
            for a specialist persona. When `None`, all GTI tools are allowed.

    Returns:
        A predicate callable `(tool, readonly_context) -> bool` suitable for
        `McpToolset(tool_filter=...)`.
    """
    prefixes = tuple(allowed_prefixes) if allowed_prefixes else None

    def _predicate(tool: Any, readonly_context: Any = None) -> bool:
        """Evaluate whether a GTI MCP tool matches the persona's prefixes.

        Args:
            tool: The candidate MCP tool or tool name.
            readonly_context: Optional ADK invocation readonly context.

        Returns:
            `True` if the tool matches `allowed_prefixes` or no prefix
            restriction is configured.
        """
        del readonly_context
        if not prefixes:
            return True
        tool_name = tool if isinstance(tool, str) else getattr(tool, "name", "")
        normalized = (
            str(tool_name).removeprefix("gti_").removeprefix("gti-mcp_")
        )
        return any(normalized.startswith(prefix) for prefix in prefixes)

    return _predicate


# ---------------------------------------------------------------------------
# Authentication & Environment Builders
# ---------------------------------------------------------------------------
def build_secops_onemcp_header_provider(
    env: Mapping[str, str] | None = None,
    oauth_auth_id: str | None = None,
) -> Callable[[Any], dict[str, str]]:
    """Build a dynamic `header_provider` injecting OAuth/ADC tokens for OneMCP.

    Supports two authentication paths:
      1. **Gemini Enterprise OAuth passthrough**: Checks
         `readonly_context.state` for `temp:<oauth_auth_id>` (or any `temp:*`
         access token).
      2. **Google Application Default Credentials (ADC)**: Mints/refreshes a
         short-lived OAuth 2.0 Bearer token with `cloud-platform` scope.

    Args:
        env: Optional environment mapping override for testing.
        oauth_auth_id: Optional Gemini Enterprise OAuth authorization ID key.

    Returns:
        A callable `(readonly_context) -> dict[str, str]` returning HTTP
        headers with `Authorization`, `x-goog-user-project`, and `User-Agent`.
    """

    def _header_provider(readonly_context: Any = None) -> dict[str, str]:
        """Resolve per-request HTTP headers for Google SecOps OneMCP.

        Args:
            readonly_context: Optional ADK `ReadonlyContext` carrying session
                state.

        Returns:
            A dictionary of HTTP headers for the Streamable HTTP MCP request.

        Raises:
            RuntimeError: If tenant configuration is missing or Google Cloud
                credentials fail to mint an access token.
        """
        validated_config = validate_secops_onemcp_config(env=env)
        headers: dict[str, str] = {
            "x-goog-user-project": validated_config["project_id"],
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
    base_env: Mapping[str, str] | None = None,
    require_credentials: bool = False,
) -> dict[str, str]:
    """Build a sanitized child environment for the GTI MCP stdio server.

    Unsets `UV_PROJECT` and `UV_PROJECT_ENVIRONMENT` so child `uvx`
    commands resolve their own isolated package environment, and explicitly
    forwards `VT_APIKEY` because `mcp.client.stdio` strips non-default
    environment variables.

    Args:
        base_env: Optional source environment mapping. Defaults to
            `os.environ`.
        require_credentials: When `True`, validates `VT_APIKEY` /
            `GTI_API_KEY` immediately and raises `RuntimeError` if unset.

    Returns:
        A dictionary of environment variables safe to pass to
        `StdioServerParameters(env=...)`.

    Raises:
        RuntimeError: If `require_credentials=True` and `VT_APIKEY` is
            missing.
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


# ---------------------------------------------------------------------------
# McpToolset Builders
# ---------------------------------------------------------------------------
def _disable_mcp_tool_output_schema(tool: Any) -> None:
    """Clear MCP tool outputSchema to prevent bloat and SDK 2.x errors.

    Google SecOps OneMCP attaches full UDM output schemas (3.73 MB across 62
    tools) and returns streaming text chunks without `structuredContent` on
    tools such as `list_security_alerts`. Clearing `outputSchema` /
    `output_schema` on the wrapped MCP tool and registering `None` in
    `session._tool_output_schemas` prevents both `response_json_schema`
    prompt bloat in ADK 2.x and `RuntimeError` in MCP SDK 2.x
    `validate_tool_result`.

    Args:
        tool: An ADK `McpTool` instance returned by `McpToolset.get_tools()`.
    """
    raw_tool = getattr(tool, "_mcp_tool", None)
    if raw_tool is None:
        return
    for attr in ("outputSchema", "output_schema"):
        if hasattr(raw_tool, attr):
            with contextlib.suppress(AttributeError, TypeError):
                setattr(raw_tool, attr, None)
    raw_name = getattr(raw_tool, "name", None)
    orig_create_session = getattr(tool, "_create_session", None)
    if (
        raw_name
        and callable(orig_create_session)
        and not getattr(tool, "_output_schema_disabled", False)
    ):

        async def _patched_create_session(*args: Any, **kwargs: Any) -> Any:
            """Retrieve an MCP session with output-schema check disabled."""
            session = await orig_create_session(*args, **kwargs)
            schemas = getattr(session, "_tool_output_schemas", None)
            if isinstance(schemas, dict):
                schemas[raw_name] = None
            return session

        tool._create_session = _patched_create_session
        tool._output_schema_disabled = True


class LazyValidatedMcpToolset(McpToolset):
    """McpToolset subclass that validates credentials before connecting.

    Validates required environment variables immediately before connecting so
    missing credentials surface a clear `RuntimeError` instead of a 60-second
    subprocess or socket timeout. When `INTEGRATION_TEST` is set in CI
    container smoke tests and live credentials are absent, `get_tools`
    returns an empty list so FastAPI and A2A agent-card discovery boot cleanly.
    """

    def __init__(
        self,
        *args: Any,
        config_validator: Callable[[], Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the toolset with an optional pre-connection validator.

        Args:
            *args: Positional arguments forwarded to `McpToolset.__init__`.
            config_validator: Optional callable that validates required
                environment variables and raises `RuntimeError` when missing.
            **kwargs: Keyword arguments forwarded to `McpToolset.__init__`.
        """
        super().__init__(*args, **kwargs)
        self._config_validator = config_validator

    async def get_tools(self, readonly_context: Any = None) -> list[Any]:
        """Validate credentials before connecting, or skip in smoke tests.

        Args:
            readonly_context: Optional ADK `ReadonlyContext` passed during
                tool resolution.

        Returns:
            A list of discovered MCP tools (or `[]` in unconfigured
            `INTEGRATION_TEST` smoke runs).

        Raises:
            RuntimeError: If required credentials are missing and
                `INTEGRATION_TEST` is not set.
        """
        if self._config_validator is not None:
            try:
                self._config_validator()
            except RuntimeError:
                if os.getenv("INTEGRATION_TEST"):
                    return []
                raise
        tools = await super().get_tools(readonly_context=readonly_context)
        for tool in tools:
            _disable_mcp_tool_output_schema(tool)
        return tools


def build_secops_onemcp_toolset(
    allowed_prefixes: Sequence[str] | None = None,
    env: Mapping[str, str] | None = None,
    require_credentials: bool = False,
) -> McpToolset:
    """Create a live `McpToolset` connected to Google SecOps OneMCP over HTTP.

    Args:
        allowed_prefixes: Optional sequence of tool name prefixes permitted for
            a specialist persona.
        env: Optional environment mapping override for testing.
        require_credentials: When `True`, validates tenant configuration at
            construction time rather than deferring to session startup.

    Returns:
        A configured `LazyValidatedMcpToolset` with `secops_` prefixing.

    Raises:
        RuntimeError: If `require_credentials=True` and required Chronicle
            tenant variables are missing.
    """
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
    env: Mapping[str, str] | None = None,
    require_credentials: bool = False,
) -> McpToolset:
    """Create a live `McpToolset` for Google Threat Intelligence (GTI) MCP.

    Uses `StreamableHTTPConnectionParams` when `GTI_MCP_URL` is set, or
    spawns `uvx gti-mcp` over stdio via `StdioConnectionParams` by default.

    Args:
        allowed_prefixes: Optional sequence of GTI tool name prefixes permitted
            for a specialist persona.
        env: Optional environment mapping override for testing.
        require_credentials: When `True`, validates `VT_APIKEY` at
            construction time rather than deferring to session startup.

    Returns:
        A configured `LazyValidatedMcpToolset` with `gti_` prefixing.

    Raises:
        RuntimeError: If `require_credentials=True` and `VT_APIKEY` is not
            configured.
    """
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
        env.get("GTI_MCP_COMMAND")
        if env is not None
        else os.getenv("GTI_MCP_COMMAND")
    )
    raw_args = (
        env.get("GTI_MCP_ARGS")
        if env is not None
        else os.getenv("GTI_MCP_ARGS")
    )
    command = (raw_cmd or "").strip() or "uvx"
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


# ---------------------------------------------------------------------------
# Model Callbacks (Event-Loop Guard & Schema Bloat Stripping)
# ---------------------------------------------------------------------------
def _reset_closed_event_loop_clients(callback_context: Any) -> None:
    """Reset cached `Gemini._api_client` when `AdkApp` switches event loops.

    Args:
        callback_context: The ADK `CallbackContext` for the current model
            invocation.
    """
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
) -> Any:
    """Strip 3.73 MB `response_json_schema` bloat from OneMCP declarations.

    Google SecOps OneMCP attaches full UDM output schemas to every tool's
    `response_json_schema` (totaling 3.73 MB across 62 tools), which exceeds
    Vertex AI's 1,048,576-token request limit if forwarded. Clearing
    `response_json_schema` and `response` in `before_model_callback`
    preserves full `parameters_json_schema` input validation while keeping
    each LLM request compact.

    Args:
        callback_context: The ADK `CallbackContext` for the current turn.
        llm_request: The outgoing `LlmRequest` whose tool declarations are
            sanitized in place.

    Returns:
        Always returns `None` so ADK proceeds with the sanitized `llm_request`.
    """
    _reset_closed_event_loop_clients(callback_context)
    if hasattr(llm_request, "append_instructions"):
        now_utc = datetime.datetime.now(datetime.UTC).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        llm_request.append_instructions(
            [
                f"Current UTC timestamp: {now_utc}. Use this timestamp when "
                "computing relative time windows for Chronicle OneMCP queries."
            ]
        )
    request_config = getattr(llm_request, "config", None)
    if request_config is None:
        return None
    tools = getattr(request_config, "tools", None) or []
    for tool in tools:
        decls = getattr(tool, "function_declarations", None) or []
        for func_decl in decls:
            if hasattr(func_decl, "response_json_schema"):
                func_decl.response_json_schema = None
            if hasattr(func_decl, "response"):
                func_decl.response = None
    return None
