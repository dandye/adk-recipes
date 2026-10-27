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

"""Google SecOps Autonomous Security Operations ADK Agent.

Combines four core capabilities into an adaptive ADK architecture:
  1. **Google SecOps OneMCP**
     (`https://chronicle.<region>.rep.googleapis.com/mcp`) for SIEM UDM search,
     entity lookup, YARA-L 2.0 (`YL2`) detection rule verification, and SOAR
     case operations.
  2. **Google Threat Intelligence (GTI) MCP** (`gti-mcp`) for file, domain,
     IP, URL, and threat collection enrichment.
  3. **ADK Skills** (`SkillToolset` + `load_skill_from_dir`) for progressive
     disclosure of 6 operational SOC runbooks.
  4. **Adaptive Specialist Personas** (`SECOPS_USE_PERSONAS=true` by default):
     - `secops_supervisor` orchestrating 5 role-scoped sub-agents
       (`secops_triage_specialist`, `secops_threat_hunter`,
       `secops_cti_researcher`, `secops_detection_engineer`, and
       `secops_incident_responder`), or
     - `secops_agent` (`SECOPS_USE_PERSONAS=false`) running as a single
       unified frontier agent.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

from google.adk.agents import Agent
from google.adk.apps import App
from google.adk.models import Gemini
from google.genai import types

from app import mcp_tools, personas, prompt, skills_loader


# ---------------------------------------------------------------------------
# Model & Topology Resolution Helpers
# ---------------------------------------------------------------------------
def _resolve_use_personas(
    use_personas: bool | None = None,
    env: Mapping[str, str] | None = None,
) -> bool:
    """Resolve whether to build the 5-persona hierarchy or unified agent.

    Args:
        use_personas: Explicit boolean override. When `None`, reads
            `SECOPS_USE_PERSONAS` from `env` or `os.environ` (defaulting
            to `True`).
        env: Optional environment mapping override for testing.

    Returns:
        `True` if the 5-persona supervisor hierarchy should be built;
        `False` for the single unified frontier agent.
    """
    if use_personas is not None:
        return use_personas
    raw_val = (
        env.get("SECOPS_USE_PERSONAS", "true")
        if env is not None
        else os.getenv("SECOPS_USE_PERSONAS", "true")
    )
    raw = (raw_val or "true").strip().lower()
    return raw not in {"false", "0", "no", "off", "frontier"}


def _build_gemini_model(
    model_name: str | None = None,
    env: Mapping[str, str] | None = None,
) -> Gemini:
    """Build the `Gemini` model instance with HTTP retry options.

    Args:
        model_name: Optional explicit model identifier override. When `None`,
            reads `MODEL_NAME` from `env` or `os.environ`.
        env: Optional environment mapping override for testing.

    Returns:
        A configured `google.adk.models.Gemini` instance with 3 HTTP retry
        attempts.
    """
    raw_model = (
        model_name
        if model_name is not None
        else (
            env.get("MODEL_NAME")
            if env is not None
            else os.getenv("MODEL_NAME")
        )
    )
    resolved_model = raw_model.strip() if raw_model else None
    if resolved_model:
        return Gemini(
            model=resolved_model,
            retry_options=types.HttpRetryOptions(attempts=3),
        )
    return Gemini(
        retry_options=types.HttpRetryOptions(attempts=3),
    )


# ---------------------------------------------------------------------------
# Specialist & Root Agent Builders
# ---------------------------------------------------------------------------
def build_specialist_sub_agent(
    spec: personas.PersonaSpec,
    model_name: str | None = None,
    env: Mapping[str, str] | None = None,
    require_credentials: bool = False,
) -> Agent:
    """Build a single role-scoped SecOps specialist sub-agent.

    Args:
        spec: The `PersonaSpec` defining the specialist's profile, allowed
            skills, and allowed SecOps/GTI tool prefixes.
        model_name: Optional Gemini model name override.
        env: Optional environment mapping override for testing.
        require_credentials: When `True`, validates SecOps OneMCP and GTI
            credentials immediately at agent construction time.

    Returns:
        A configured ADK `Agent` scoped to the specialist persona.
    """
    skill_toolset = skills_loader.build_secops_skill_toolset(
        skill_names=spec.skill_names,
    )
    secops_toolset = mcp_tools.build_secops_onemcp_toolset(
        allowed_prefixes=spec.secops_tool_prefixes,
        env=env,
        require_credentials=require_credentials,
    )
    gti_toolset = mcp_tools.build_gti_mcp_toolset(
        allowed_prefixes=spec.gti_tool_prefixes,
        env=env,
        require_credentials=require_credentials,
    )
    return Agent(
        name=spec.agent_name,
        model=_build_gemini_model(model_name=model_name, env=env),
        description=spec.description,
        instruction=skills_loader.make_static_instruction_provider(
            spec.load_instruction(env=env)
        ),
        tools=[skill_toolset, secops_toolset, gti_toolset],
        before_model_callback=mcp_tools.strip_response_json_schema_callback,
    )


def build_persona_hierarchy_agent(
    model_name: str | None = None,
    env: Mapping[str, str] | None = None,
    require_credentials: bool = False,
) -> Agent:
    """Build the hierarchical SecOps supervisor with 5 specialist personas.

    Args:
        model_name: Optional Gemini model name override.
        env: Optional environment mapping override for testing.
        require_credentials: When `True`, validates SecOps OneMCP and GTI
            credentials immediately at agent construction time.

    Returns:
        The `secops_supervisor` root `Agent` with 5 role-scoped `sub_agents`.
    """
    sub_agents = [
        build_specialist_sub_agent(
            spec=spec,
            model_name=model_name,
            env=env,
            require_credentials=require_credentials,
        )
        for spec in personas.list_personas()
    ]
    supervisor_skill_toolset = skills_loader.build_secops_skill_toolset()
    supervisor_secops_toolset = mcp_tools.build_secops_onemcp_toolset(
        env=env,
        require_credentials=require_credentials,
    )
    supervisor_gti_toolset = mcp_tools.build_gti_mcp_toolset(
        env=env,
        require_credentials=require_credentials,
    )
    supervisor_instruction = (
        prompt.COMPACT_SUPERVISOR_INSTRUCTION
        + prompt.build_tenant_context_banner(env=env)
    )
    return Agent(
        name="secops_supervisor",
        model=_build_gemini_model(model_name=model_name, env=env),
        description=(
            "Hierarchical Google SecOps Supervisor coordinating 5 role-scoped"
            " specialist personas (Triage, Threat Hunter, CTI Researcher,"
            " Detection Engineer, and Incident Responder) with SkillToolset,"
            " SecOps OneMCP, and GTI MCP."
        ),
        instruction=skills_loader.make_static_instruction_provider(
            supervisor_instruction
        ),
        tools=[
            supervisor_skill_toolset,
            supervisor_secops_toolset,
            supervisor_gti_toolset,
        ],
        sub_agents=sub_agents,
        before_model_callback=mcp_tools.strip_response_json_schema_callback,
    )


def build_frontier_unified_agent(
    model_name: str | None = None,
    env: Mapping[str, str] | None = None,
    require_credentials: bool = False,
) -> Agent:
    """Build the single unified Frontier SecOps agent with all tools/skills.

    Args:
        model_name: Optional Gemini model name override.
        env: Optional environment mapping override for testing.
        require_credentials: When `True`, validates SecOps OneMCP and GTI
            credentials immediately at agent construction time.

    Returns:
        The unified `secops_agent` ADK `Agent` instance.
    """
    skill_toolset = skills_loader.build_secops_skill_toolset()
    secops_toolset = mcp_tools.build_secops_onemcp_toolset(
        env=env,
        require_credentials=require_credentials,
    )
    gti_toolset = mcp_tools.build_gti_mcp_toolset(
        env=env,
        require_credentials=require_credentials,
    )
    unified_instruction = (
        prompt.FRONTIER_UNIFIED_INSTRUCTION
        + prompt.build_tenant_context_banner(env=env)
    )
    return Agent(
        name="secops_agent",
        model=_build_gemini_model(model_name=model_name, env=env),
        description=(
            "Unified Google SecOps Autonomous Agent for alert triage, threat"
            " hunting, CTI analysis, YARA-L 2.0 detection engineering, and SOAR"
            " incident response."
        ),
        instruction=skills_loader.make_static_instruction_provider(
            unified_instruction
        ),
        tools=[skill_toolset, secops_toolset, gti_toolset],
        before_model_callback=mcp_tools.strip_response_json_schema_callback,
    )


def create_agent(
    use_personas: bool | None = None,
    model_name: str | None = None,
    env: Mapping[str, str] | None = None,
    require_credentials: bool = False,
) -> Agent:
    """Create a fresh, isolated instance of the Google SecOps ADK agent.

    Args:
        use_personas: Optional boolean override selecting the 5-persona
            supervisor hierarchy (`True`) or unified frontier agent
            (`False`). When `None`, reads `SECOPS_USE_PERSONAS` from the
            environment (defaulting to `True`).
        model_name: Optional Gemini model name override.
        env: Optional environment mapping override for testing.
        require_credentials: When `True`, validates SecOps OneMCP and GTI
            credentials immediately at agent construction time.

    Returns:
        The configured root `Agent` instance.
    """
    if _resolve_use_personas(use_personas=use_personas, env=env):
        return build_persona_hierarchy_agent(
            model_name=model_name,
            env=env,
            require_credentials=require_credentials,
        )
    return build_frontier_unified_agent(
        model_name=model_name,
        env=env,
        require_credentials=require_credentials,
    )


# ---------------------------------------------------------------------------
# ADK Entry Points
# ---------------------------------------------------------------------------
root_agent = create_agent()

app = App(
    root_agent=root_agent,
    name="app",
)
