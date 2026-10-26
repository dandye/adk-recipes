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

"""Unit tests for the Google SecOps canonical ADK recipe."""

from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

import pytest
from google.adk.tools.mcp_tool import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import (
    StdioConnectionParams,
    StreamableHTTPConnectionParams,
)
from google.adk.tools.skill_toolset import SkillToolset

from app.agent import (
    build_frontier_unified_agent,
    build_persona_hierarchy_agent,
    create_agent,
)
from app.mcp_tools import (
    EXCLUDED_FEED_MANAGEMENT_TOOLS,
    build_gti_mcp_toolset,
    build_secops_onemcp_header_provider,
    build_secops_onemcp_toolset,
    make_gti_tool_filter,
    make_secops_tool_filter,
    should_include_secops_tool,
    strip_response_json_schema_callback,
    validate_gti_mcp_config,
    validate_secops_onemcp_config,
)
from app.personas import (
    CANONICAL_PERSONAS,
    build_tenant_context_banner,
    get_persona,
    list_personas,
)
from app.skills_loader import (
    build_secops_skill_toolset,
    load_secops_skills,
    make_static_instruction_provider,
)


def test_list_personas_returns_five_specialists() -> None:
    """Verifies all five specialist personas load with non-empty instructions."""
    personas = list_personas()
    assert len(personas) == 5
    keys = [p.persona_id for p in personas]
    assert keys == [
        "cti_researcher",
        "detection_engineer",
        "incident_responder",
        "threat_hunter",
        "triage_analyst",
    ]
    for persona in personas:
        instruction = persona.load_instruction()
        assert len(instruction) > 100
        assert len(persona.skill_names) >= 1
        assert len(persona.secops_tool_prefixes) >= 1
        assert len(persona.gti_tool_prefixes) >= 1


def test_get_persona_unknown_raises_key_error() -> None:
    """Verifies requesting an unknown persona raises `KeyError`."""
    with pytest.raises(KeyError, match="Unknown persona"):
        get_persona("nonexistent_persona")


def test_load_secops_skills_discovers_all_six_runbooks() -> None:
    """Verifies all six canonical `SKILL.md` runbooks load cleanly via ADK."""
    skills = load_secops_skills()
    names = [skill.name for skill in skills]
    assert names == [
        "triage-alerts",
        "suspicious-login-triage",
        "malware-triage",
        "gti-collection-threat-hunt",
        "detection-rule-validation-tuning",
        "ioc-containment",
    ]


def test_build_secops_skill_toolset_scopes_by_persona() -> None:
    """Verifies `SkillToolset` can be scoped to a subset of skill names."""
    triage_spec = CANONICAL_PERSONAS["triage_analyst"]
    toolset = build_secops_skill_toolset(skill_names=triage_spec.skill_names)
    assert isinstance(toolset, SkillToolset)


def test_build_secops_skill_toolset_rejects_missing_skill() -> None:
    """Verifies requesting a nonexistent skill name raises `FileNotFoundError`."""
    with pytest.raises(
        FileNotFoundError, match="Expected SecOps skill directory"
    ):
        build_secops_skill_toolset(skill_names=("does-not-exist",))


def test_secops_tool_filter_excludes_feed_management_tools() -> None:
    """Verifies feed management tools are always excluded from SecOps OneMCP."""
    for tool_name in EXCLUDED_FEED_MANAGEMENT_TOOLS:
        assert not should_include_secops_tool(tool_name)

    assert should_include_secops_tool("search_security_events")
    assert should_include_secops_tool(
        "search_security_events",
        allowed_prefixes=("search_security_events", "lookup_entity"),
    )
    assert not should_include_secops_tool(
        "create_curated_rule_set_deployment",
        allowed_prefixes=("search_security_events", "lookup_entity"),
    )

    predicate = make_secops_tool_filter(("search_security_events",))
    fake_tool = SimpleNamespace(name="search_security_events")
    blocked_tool = SimpleNamespace(name="create_feed")
    other_tool = SimpleNamespace(name="list_cases")
    assert predicate(fake_tool, None) is True
    assert predicate(blocked_tool, None) is False
    assert predicate(other_tool, None) is False


def test_gti_tool_filter_scopes_prefixes() -> None:
    """Verifies GTI tool filter allows matching prefixes when configured."""
    unrestricted = make_gti_tool_filter(None)
    assert unrestricted(SimpleNamespace(name="get_file_report"), None) is True

    scoped = make_gti_tool_filter(("get_file_report", "search_threats"))
    assert scoped(SimpleNamespace(name="get_file_report"), None) is True
    assert scoped(SimpleNamespace(name="search_iocs"), None) is False


def test_validate_secops_onemcp_config_missing_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verifies missing Chronicle tenant variables raise `RuntimeError`.

    Args:
        monkeypatch: Pytest fixture used to clear environment variables.
    """
    monkeypatch.delenv("CHRONICLE_PROJECT_ID", raising=False)
    monkeypatch.delenv("CHRONICLE_CUSTOMER_ID", raising=False)
    with pytest.raises(RuntimeError, match="CHRONICLE_PROJECT_ID"):
        validate_secops_onemcp_config()


def test_secops_header_provider_uses_oauth_state_or_adc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verifies OneMCP header provider supports OAuth state and Google ADC.

    Args:
        monkeypatch: Pytest fixture used to set Chronicle environment variables.
    """
    monkeypatch.setenv("CHRONICLE_PROJECT_ID", "demo-secops-project")
    monkeypatch.setenv(
        "CHRONICLE_CUSTOMER_ID", "00000000-0000-0000-0000-000000000000"
    )
    monkeypatch.setenv("CHRONICLE_REGION", "us")

    provider = build_secops_onemcp_header_provider(oauth_auth_id="secops_oauth")
    ctx_with_oauth = SimpleNamespace(
        state={"temp:secops_oauth": "oauth-access-token-123"}
    )
    headers = provider(ctx_with_oauth)
    assert headers["Authorization"] == "Bearer oauth-access-token-123"
    assert headers["x-goog-user-project"] == "demo-secops-project"

    fake_creds = mock.MagicMock()
    fake_creds.valid = True
    fake_creds.token = "adc-access-token-456"
    with mock.patch(
        "app.mcp_tools.google.auth.default",
        return_value=(fake_creds, "demo-secops-project"),
    ):
        headers_adc = provider(SimpleNamespace(state={}))
    assert headers_adc["Authorization"] == "Bearer adc-access-token-456"
    assert headers_adc["x-goog-user-project"] == "demo-secops-project"


def test_validate_gti_mcp_config_and_transports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verifies GTI MCP toolset supports both stdio and remote HTTP modes.

    Args:
        monkeypatch: Pytest fixture used to configure `VT_APIKEY` and
            `GTI_MCP_URL`.
    """
    monkeypatch.delenv("VT_APIKEY", raising=False)
    monkeypatch.delenv("GTI_MCP_URL", raising=False)
    with pytest.raises(RuntimeError, match="VT_APIKEY"):
        validate_gti_mcp_config()

    monkeypatch.setenv("VT_APIKEY", "test-vt-api-key")
    stdio_toolset = build_gti_mcp_toolset(require_credentials=True)
    assert isinstance(stdio_toolset, McpToolset)
    assert isinstance(stdio_toolset._connection_params, StdioConnectionParams)

    monkeypatch.setenv("GTI_MCP_URL", "https://gti-mcp.example.com/mcp")
    http_toolset = build_gti_mcp_toolset(require_credentials=True)
    assert isinstance(http_toolset, McpToolset)
    assert isinstance(
        http_toolset._connection_params, StreamableHTTPConnectionParams
    )


def test_build_secops_onemcp_toolset_validates_when_requested(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verifies `build_secops_onemcp_toolset` validates credentials on demand.

    Args:
        monkeypatch: Pytest fixture used to set regional Chronicle variables.
    """
    monkeypatch.setenv("CHRONICLE_PROJECT_ID", "demo-secops-project")
    monkeypatch.setenv(
        "CHRONICLE_CUSTOMER_ID", "00000000-0000-0000-0000-000000000000"
    )
    monkeypatch.setenv("CHRONICLE_REGION", "eu")
    toolset = build_secops_onemcp_toolset(require_credentials=True)
    assert isinstance(toolset, McpToolset)
    assert (
        toolset._connection_params.url
        == "https://chronicle.eu.rep.googleapis.com/mcp"
    )


def test_strip_response_json_schema_callback_clears_output_schemas() -> None:
    """Verifies `before_model_callback` strips oversized MCP output schemas."""
    fn_decl = SimpleNamespace(
        name="secops_search_security_events",
        response_json_schema={"type": "object"},
        response={"type": "object"},
    )
    tool = SimpleNamespace(function_declarations=[fn_decl])
    llm_request = SimpleNamespace(config=SimpleNamespace(tools=[tool]))

    result = strip_response_json_schema_callback(None, llm_request)
    assert result is None
    assert fn_decl.response_json_schema is None
    assert fn_decl.response is None


def test_create_agent_persona_hierarchy_and_unified_modes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verifies adaptive topology builds supervisor or unified frontier agent.

    Args:
        monkeypatch: Pytest fixture used to populate Chronicle tenant context.
    """
    monkeypatch.setenv("CHRONICLE_PROJECT_ID", "demo-secops-project")
    monkeypatch.setenv(
        "CHRONICLE_CUSTOMER_ID", "00000000-0000-0000-0000-000000000000"
    )
    monkeypatch.setenv("CHRONICLE_REGION", "us")

    supervisor = create_agent(use_personas=True)
    assert supervisor.name == "secops_supervisor"
    assert len(supervisor.sub_agents) == 5
    sub_names = [sub.name for sub in supervisor.sub_agents]
    assert sub_names == [
        "secops_cti_researcher",
        "secops_detection_engineer",
        "secops_incident_responder",
        "secops_threat_hunter",
        "secops_triage_specialist",
    ]
    for sub in supervisor.sub_agents:
        assert len(sub.tools) == 3
        assert any(isinstance(t, SkillToolset) for t in sub.tools)
        mcp_count = sum(1 for t in sub.tools if isinstance(t, McpToolset))
        assert mcp_count == 2

    unified = create_agent(use_personas=False)
    assert unified.name == "secops_agent"
    assert len(unified.sub_agents) == 0
    assert len(unified.tools) == 3

    banner = build_tenant_context_banner()
    assert "demo-secops-project" in banner
    assert "00000000-0000-0000-0000-000000000000" in banner

    provider = make_static_instruction_provider("Test instruction")
    assert provider(None) == "Test instruction"
    assert build_persona_hierarchy_agent().name == "secops_supervisor"
    assert build_frontier_unified_agent().name == "secops_agent"


def test_fastapi_and_a2a_agent_card_boot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verifies FastAPI server and A2A agent card boot cleanly in smoke test mode.

    Args:
        monkeypatch: Pytest fixture used to enable `INTEGRATION_TEST` mode.
    """
    from fastapi.testclient import TestClient

    from app.fast_api_app import app

    monkeypatch.setenv("INTEGRATION_TEST", "1")
    monkeypatch.delenv("CHRONICLE_PROJECT_ID", raising=False)
    monkeypatch.delenv("CHRONICLE_CUSTOMER_ID", raising=False)
    monkeypatch.delenv("VT_APIKEY", raising=False)

    with TestClient(app) as client:
        apps_resp = client.get("/list-apps")
        assert apps_resp.status_code == 200
        assert "app" in apps_resp.json()

        card_resp = client.get("/a2a/app/.well-known/agent-card.json")
        assert card_resp.status_code == 200
        assert card_resp.json()["name"] == "secops_supervisor"
