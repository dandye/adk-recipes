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

"""Role-scoped SecOps specialist personas and tool/skill slice definitions.

Defines the 5 canonical Security Operations Center (SOC) specialist personas:
  1. ``triage_analyst`` (``secops_triage_specialist``) — Alert and case triage
  2. ``threat_hunter`` (``secops_threat_hunter``) — 72h to 168h UDM hunts
  3. ``cti_researcher`` (``secops_cti_researcher``) — GTI actor/IOC enrichment
  4. ``detection_engineer`` (``secops_detection_engineer``) — YARA-L 2.0 rules
  5. ``incident_responder`` (``secops_incident_responder``) — SOAR containment

Each ``PersonaSpec`` binds a Markdown profile under ``app/profiles/`` with a
scoped subset of ``SkillToolset`` runbooks and ``McpToolset`` tool prefixes.
"""

from __future__ import annotations

import dataclasses
import pathlib

from app.prompt import (
    COMPACT_SUPERVISOR_INSTRUCTION,
    FRONTIER_UNIFIED_INSTRUCTION,
    build_tenant_context_banner,
)

__all__ = [
    "CANONICAL_PERSONAS",
    "COMPACT_SUPERVISOR_INSTRUCTION",
    "FRONTIER_UNIFIED_INSTRUCTION",
    "PROFILES_DIR",
    "PersonaSpec",
    "build_tenant_context_banner",
    "get_persona",
    "list_personas",
]

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROFILES_DIR = pathlib.Path(__file__).resolve().parent / "profiles"


# ---------------------------------------------------------------------------
# Specialist Persona Specification
# ---------------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class PersonaSpec:
    """Role-scoped specialist persona configuration.

    Attributes:
        persona_id: Short identifier key (e.g. ``"triage_analyst"``).
        agent_name: ADK agent identifier registered on ``Agent(name=...)``.
        display_name: Human-readable title for the specialist role.
        description: Concise summary exposed to the parent supervisor for
            routing and sub-agent delegation.
        profile_filename: Markdown file name inside ``app/profiles/``.
        skill_names: Tuple of ``SKILL.md`` directory names scoped to this role.
        secops_tool_prefixes: Allowed Google SecOps OneMCP tool name prefixes.
        gti_tool_prefixes: Allowed Google Threat Intelligence MCP tool prefixes.
    """

    persona_id: str
    agent_name: str
    display_name: str
    description: str
    profile_filename: str
    skill_names: tuple[str, ...]
    secops_tool_prefixes: tuple[str, ...]
    gti_tool_prefixes: tuple[str, ...]

    def load_instruction(self, env: dict[str, str] | None = None) -> str:
        """Load the Markdown persona profile and append active tenant context.

        Args:
            env: Optional environment dictionary override for tenant variables.

        Returns:
            The complete system instruction string combining the Markdown
            persona profile and the Google SecOps tenant parameter block.

        Raises:
            FileNotFoundError: If ``profile_filename`` does not exist under
                ``PROFILES_DIR``.
        """
        path = PROFILES_DIR / self.profile_filename
        base = path.read_text(encoding="utf-8").strip()
        return base + build_tenant_context_banner(env=env)


# ---------------------------------------------------------------------------
# Canonical SOC Specialist Roster
# ---------------------------------------------------------------------------
CANONICAL_PERSONAS: dict[str, PersonaSpec] = {
    "triage_analyst": PersonaSpec(
        persona_id="triage_analyst",
        agent_name="secops_triage_specialist",
        display_name="SOC Triage & Investigation Specialist",
        description=(
            "Triages SOAR cases and SIEM alerts, reconstructs 168h entity"
            " timelines, and distinguishes benign enterprise baselines from"
            " true compromises."
        ),
        profile_filename="triage_analyst.md",
        skill_names=(
            "triage-alerts",
            "suspicious-login-triage",
            "malware-triage",
        ),
        secops_tool_prefixes=(
            "get_case",
            "list_cases",
            "list_case",
            "list_security_alerts",
            "get_security_alert",
            "udm_search",
            "search_security_events",
            "lookup_entity",
            "get_ioc_matches",
        ),
        gti_tool_prefixes=(
            "get_file_report",
            "get_file_behavior_summary",
            "get_domain_report",
            "get_ip_address_report",
            "get_url_report",
        ),
    ),
    "threat_hunter": PersonaSpec(
        persona_id="threat_hunter",
        agent_name="secops_threat_hunter",
        display_name="Proactive Threat Hunter Specialist",
        description=(
            "Executes hypothesis-driven and campaign-driven threat hunts"
            " across 72h to 168h UDM horizons, DNS beacons, and LOTL activity."
        ),
        profile_filename="threat_hunter.md",
        skill_names=(
            "gti-collection-threat-hunt",
            "malware-triage",
        ),
        secops_tool_prefixes=(
            "udm_search",
            "search_security_events",
            "lookup_entity",
            "get_ioc_matches",
            "list_security_alerts",
            "list_cases",
        ),
        gti_tool_prefixes=(
            "get_collection_report",
            "get_entities_related_to_a_collection",
            "get_entities_related_to_a_domain",
            "get_domain_report",
            "get_file_report",
            "get_ip_address_report",
            "search_threats",
        ),
    ),
    "cti_researcher": PersonaSpec(
        persona_id="cti_researcher",
        agent_name="secops_cti_researcher",
        display_name="Cyber Threat Intelligence Researcher",
        description=(
            "Profiles GTI threat actor collections, campaigns, malware"
            " families, and multi-hop relational indicator graphs."
        ),
        profile_filename="cti_researcher.md",
        skill_names=(
            "gti-collection-threat-hunt",
            "ioc-containment",
        ),
        secops_tool_prefixes=(
            "get_ioc_matches",
            "lookup_entity",
            "udm_search",
        ),
        gti_tool_prefixes=(
            "get_collection",
            "get_entities_related_to",
            "get_file",
            "get_domain_report",
            "get_ip_address_report",
            "get_url_report",
            "search_",
        ),
    ),
    "detection_engineer": PersonaSpec(
        persona_id="detection_engineer",
        agent_name="secops_detection_engineer",
        display_name="Detection-as-Code Engineer (YARA-L 2.0)",
        description=(
            "Authors, validates, tunes, and retrohunts Google SecOps SIEM"
            " YARA-L 2.0 detection rules."
        ),
        profile_filename="detection_engineer.md",
        skill_names=("detection-rule-validation-tuning",),
        secops_tool_prefixes=(
            "list_rules",
            "get_rule",
            "list_security_rules",
            "get_detection_rule",
            "verify_rule_text",
            "validate_yaral2_rule",
            "generate_threat_detection_opportunity",
            "generate_synthetic_events",
            "evaluate_rule_coverage_long_running",
            "get_operation",
            "generate_rules",
            "udm_search",
            "search_security_events",
            "lookup_entity",
        ),
        gti_tool_prefixes=(
            "get_collection_report",
            "get_file_report",
            "get_domain_report",
        ),
    ),
    "incident_responder": PersonaSpec(
        persona_id="incident_responder",
        agent_name="secops_incident_responder",
        display_name="Incident Responder & SOAR Containment Coordinator",
        description=(
            "Executes verified containment after mandatory GTI signer checks,"
            " updates SOAR cases, and authors final incident reports."
        ),
        profile_filename="incident_responder.md",
        skill_names=(
            "ioc-containment",
            "triage-alerts",
        ),
        secops_tool_prefixes=(
            "get_case",
            "list_cases",
            "update_case",
            "change_case",
            "close_case",
            "add_case",
            "create_case_comment",
            "post_case_comment",
            "execute_manual_action",
            "attach_playbook",
            "lookup_entity",
            "udm_search",
        ),
        gti_tool_prefixes=(
            "get_file_report",
            "get_domain_report",
            "get_ip_address_report",
            "get_entities_related_to_a_domain",
        ),
    ),
}


def list_personas() -> list[PersonaSpec]:
    """Return all 5 canonical SecOps specialist personas in deterministic order.

    Returns:
        A list of ``PersonaSpec`` instances sorted by ``persona_id``.
    """
    return [CANONICAL_PERSONAS[key] for key in sorted(CANONICAL_PERSONAS)]


def get_persona(persona_id: str) -> PersonaSpec:
    """Look up a ``PersonaSpec`` by its identifier.

    Args:
        persona_id: Case-insensitive persona identifier (for example,
            ``"triage_analyst"`` or ``"detection_engineer"``).

    Returns:
        The matching ``PersonaSpec`` instance.

    Raises:
        KeyError: If ``persona_id`` is not in ``CANONICAL_PERSONAS``.
    """
    normalized = persona_id.strip().lower()
    if normalized not in CANONICAL_PERSONAS:
        raise KeyError(
            f"Unknown persona '{persona_id}'. Available: {sorted(CANONICAL_PERSONAS)}"
        )
    return CANONICAL_PERSONAS[normalized]
