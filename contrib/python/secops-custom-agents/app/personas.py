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

"""Role-scoped SecOps specialist personas and unified frontier instructions."""

import dataclasses
import os
import pathlib

PROFILES_DIR = pathlib.Path(__file__).resolve().parent / "profiles"

FRONTIER_UNIFIED_INSTRUCTION = """You are the unified Google SecOps Autonomous Security Operations Agent (`secops_agent`).

## Core Epistemic & Procedural Rules
1. **Progressive Skill Disclosure**: Before executing Google SecOps OneMCP (`secops_*`) or Google Threat Intelligence (`gti_*`) tools, call `load_skill` for the relevant operational runbook in the skills catalog.
2. **Pre-Containment Evidence Gate**: Never recommend or invoke host isolation, IOC blocking, or account disablement before checking case/alert details (`secops_get_case`, `secops_list_security_alerts`) and SIEM UDM telemetry (`secops_lookup_entity`, `secops_udm_search`).
3. **Multi-Horizon Threat Hunting (`72h` -> `168h`)**: Start UDM hunts at `72` hours and automatically widen to `168` hours (`7d`) whenever `72h` returns zero hits.
4. **Signed OS LOLBin & RFC-5737 Protection**: Always inspect `cert_status` via `gti_get_file_report` before blocking file hashes. Never block signed OS LOLBins (`rundll32.exe`, `wscript.exe`, `powershell.exe` with `VALID_CERTIFICATE`), RFC-1918 private IPs, or RFC-5737 test IPs (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
5. **Benign Enterprise Baseline Override**: When activity matches an authorized jump box, backup service account (`svc-backup`), CI/CD runner, or approved `CHG-...` maintenance window, classify as `BENIGN` and withhold containment.
6. **4-Way Verdict & Verbatim Entity Recall**: State one top-level verdict (`MALICIOUS`, `SUSPICIOUS`, `INCONCLUSIVE`, or `BENIGN`) without negated phrases, and quote every observed hostname, user, IP, domain, URL, DNS query, and SHA256 hash verbatim.
"""

COMPACT_SUPERVISOR_INSTRUCTION = """You are the SOC Supervisor Agent (`secops_supervisor`) coordinating 5 role-scoped specialist sub-agents:
- `secops_triage_specialist`: Alert and case triage, entity timelines, and duplicate/cluster analysis.
- `secops_threat_hunter`: Proactive `72h`->`168h` UDM threat hunts, DNS tunneling, and living-off-the-land (LOTL) sweeps.
- `secops_cti_researcher`: Google Threat Intelligence (GTI) collection, actor, and multi-hop IOC enrichment.
- `secops_detection_engineer`: YARA-L 2.0 (`YL2`) rule authoring, compiler validation, and retrohunts.
- `secops_incident_responder`: Pre-containment signer verification, IOC/host containment, and final incident reporting.

Route or delegate tasks to the appropriate specialist sub-agent using `transfer_to_agent`, or coordinate multi-stage investigations across specialists. Always enforce `load_skill` before executing `secops_*` or `gti_*` MCP tools, and synthesize a single 4-way verdict (`MALICIOUS`, `SUSPICIOUS`, `INCONCLUSIVE`, or `BENIGN`) quoting all observed entities and IOCs verbatim.
"""


def build_tenant_context_banner(
    env: dict[str, str] | None = None,
) -> str:
    """Builds a tenant parameter hint block so OneMCP calls include projectId/customerId/region."""
    project_id = (
        env.get("CHRONICLE_PROJECT_ID") or env.get("GOOGLE_CLOUD_PROJECT")
        if env is not None
        else (
            os.getenv("CHRONICLE_PROJECT_ID")
            or os.getenv("GOOGLE_CLOUD_PROJECT")
        )
    ) or "<CHRONICLE_PROJECT_ID>"
    customer_id = (
        env.get("CHRONICLE_CUSTOMER_ID")
        if env is not None
        else os.getenv("CHRONICLE_CUSTOMER_ID")
    ) or "<CHRONICLE_CUSTOMER_ID>"
    region = (
        env.get("CHRONICLE_REGION", "us")
        if env is not None
        else os.getenv("CHRONICLE_REGION", "us")
    ) or "us"
    return (
        "\n\n## Active Google SecOps Tenant Parameters\n"
        f"- `projectId`: `{project_id}`\n"
        f"- `customerId`: `{customer_id}`\n"
        f"- `region`: `{region}`\n"
        "Pass these parameters explicitly when invoking Google SecOps OneMCP (`secops_*`) tools."
    )


@dataclasses.dataclass(frozen=True)
class PersonaSpec:
    """Role-scoped specialist persona configuration."""

    persona_id: str
    agent_name: str
    display_name: str
    description: str
    profile_filename: str
    skill_names: tuple[str, ...]
    secops_tool_prefixes: tuple[str, ...]
    gti_tool_prefixes: tuple[str, ...]

    def load_instruction(self, env: dict[str, str] | None = None) -> str:
        """Loads the Markdown persona profile and appends tenant context."""
        path = PROFILES_DIR / self.profile_filename
        base = path.read_text(encoding="utf-8").strip()
        return base + build_tenant_context_banner(env=env)


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
    """Returns all 5 canonical SecOps specialist personas in deterministic order."""
    return [CANONICAL_PERSONAS[key] for key in sorted(CANONICAL_PERSONAS)]


def get_persona(persona_id: str) -> PersonaSpec:
    """Looks up a PersonaSpec by ID."""
    normalized = persona_id.strip().lower()
    if normalized not in CANONICAL_PERSONAS:
        raise KeyError(
            f"Unknown persona '{persona_id}'. Available: {sorted(CANONICAL_PERSONAS)}"
        )
    return CANONICAL_PERSONAS[normalized]
