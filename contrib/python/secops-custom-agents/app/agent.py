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

"""Canonical Google SecOps ADK recipe with OneMCP, Skills, Personas, and GTI MCP."""

import os

from google.adk.agents import Agent
from google.adk.apps import App
from google.adk.models import Gemini
from google.genai import types

from app import mcp_tools, personas, skills_loader


def _resolve_use_personas(
    use_personas: bool | None = None,
    env: dict[str, str] | None = None,
) -> bool:
    """Resolves whether to build the 5-persona hierarchy or unified frontier agent."""
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
    env: dict[str, str] | None = None,
) -> Gemini:
    """Builds the Gemini model instance with retry options."""
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


def build_specialist_sub_agent(
    spec: personas.PersonaSpec,
    model_name: str | None = None,
    env: dict[str, str] | None = None,
    require_credentials: bool = False,
) -> Agent:
    """Builds a single role-scoped SecOps specialist sub-agent."""
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
    env: dict[str, str] | None = None,
    require_credentials: bool = False,
) -> Agent:
    """Builds the hierarchical SecOps supervisor agent with 5 specialist personas."""
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
        personas.COMPACT_SUPERVISOR_INSTRUCTION
        + personas.build_tenant_context_banner(env=env)
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
    env: dict[str, str] | None = None,
    require_credentials: bool = False,
) -> Agent:
    """Builds the single unified Frontier SecOps agent with full SkillToolset and MCP tools."""
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
        personas.FRONTIER_UNIFIED_INSTRUCTION
        + personas.build_tenant_context_banner(env=env)
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
    env: dict[str, str] | None = None,
    require_credentials: bool = False,
) -> Agent:
    """Creates the adaptive Google SecOps ADK agent (persona hierarchy or unified frontier)."""
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


root_agent = create_agent()

app = App(
    root_agent=root_agent,
    name="app",
)
