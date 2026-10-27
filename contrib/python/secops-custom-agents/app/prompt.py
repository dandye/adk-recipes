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

"""System instructions and tenant context prompt builders for the SecOps agent.

Centralizes the top-level prompts for both agent topologies:
  1. `COMPACT_SUPERVISOR_INSTRUCTION`: Orchestrator prompt for
     `secops_supervisor` when `SECOPS_USE_PERSONAS=true`.
  2. `FRONTIER_UNIFIED_INSTRUCTION`: Single-agent prompt for
     `secops_agent` when `SECOPS_USE_PERSONAS=false`.
  3. `build_tenant_context_banner`: Appends the active Google SecOps
     `projectId`, `customerId`, and `region` parameters so OneMCP tool
     calls always carry the required tenant identifiers.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

# ---------------------------------------------------------------------------
# Unified Frontier Agent Instruction (SECOPS_USE_PERSONAS=false)
# ---------------------------------------------------------------------------
FRONTIER_UNIFIED_INSTRUCTION = (
    "You are the unified Google SecOps Autonomous Security Operations Agent"
    " (`secops_agent`).\n\n"
    "## Core Epistemic & Procedural Rules\n"
    "1. **Progressive Skill Disclosure**: Before executing Google SecOps"
    " OneMCP (`secops_*`) or Google Threat Intelligence (`gti_*`) tools, call"
    " `load_skill` for the relevant operational runbook in the skills"
    " catalog.\n"
    "2. **Pre-Containment Evidence Gate**: Never recommend or invoke host"
    " isolation, IOC blocking, or account disablement before checking"
    " case/alert details (`secops_get_case`, `secops_list_security_alerts`)"
    " and SIEM UDM telemetry (`secops_lookup_entity`, `secops_udm_search`).\n"
    "3. **Multi-Horizon Threat Hunting (`72h` -> `168h`)**: Start UDM hunts"
    " at `72` hours and automatically widen to `168` hours (`7d`) whenever"
    " `72h` returns zero hits.\n"
    "4. **Signed OS LOLBin & RFC-5737 Protection**: Always inspect"
    " `cert_status` via `gti_get_file_report` before blocking file hashes."
    " Never block signed OS LOLBins (`rundll32.exe`, `wscript.exe`,"
    " `powershell.exe` with `VALID_CERTIFICATE`), RFC-1918 private IPs, or"
    " RFC-5737 test IPs (`192.0.2.0/24`, `198.51.100.0/24`,"
    " `203.0.113.0/24`).\n"
    "5. **Benign Enterprise Baseline Override**: When activity matches an"
    " authorized jump box, backup service account (`svc-backup`), CI/CD"
    " runner, or approved `CHG-...` maintenance window, classify as `BENIGN`"
    " and withhold containment.\n"
    "6. **4-Way Verdict & Verbatim Entity Recall**: State one top-level"
    " verdict (`MALICIOUS`, `SUSPICIOUS`, `INCONCLUSIVE`, or `BENIGN`)"
    " without negated phrases, and quote every observed hostname, user, IP,"
    " domain, URL, DNS query, and SHA256 hash verbatim.\n"
)

# ---------------------------------------------------------------------------
# Hierarchical Supervisor Instruction (SECOPS_USE_PERSONAS=true)
# ---------------------------------------------------------------------------
COMPACT_SUPERVISOR_INSTRUCTION = (
    "You are the SOC Supervisor Agent (`secops_supervisor`) coordinating 5"
    " role-scoped specialist sub-agents:\n"
    "- `secops_triage_specialist`: Alert and case triage, entity timelines,"
    " and duplicate/cluster analysis.\n"
    "- `secops_threat_hunter`: Proactive `72h`->`168h` UDM threat hunts, DNS"
    " tunneling, and living-off-the-land (LOTL) sweeps.\n"
    "- `secops_cti_researcher`: Google Threat Intelligence (GTI) collection,"
    " actor, and multi-hop relational IOC enrichment.\n"
    "- `secops_detection_engineer`: Google SecOps SIEM YARA-L 2.0 (`YL2`)"
    " rule authoring, compiler validation, and retrohunts.\n"
    "- `secops_incident_responder`: Pre-containment signer verification,"
    " IOC/host containment, and final incident reporting.\n\n"
    "Route or delegate tasks to the appropriate specialist sub-agent using"
    " `transfer_to_agent`, or coordinate multi-stage investigations across"
    " specialists. Always enforce `load_skill` before executing `secops_*` or"
    " `gti_*` MCP tools, and synthesize a single 4-way verdict (`MALICIOUS`,"
    " `SUSPICIOUS`, `INCONCLUSIVE`, or `BENIGN`) quoting all observed"
    " entities and IOCs verbatim.\n"
)


# ---------------------------------------------------------------------------
# Tenant Context Banner Builder
# ---------------------------------------------------------------------------
def build_tenant_context_banner(
    env: Mapping[str, str] | None = None,
) -> str:
    """Build a tenant parameter hint block for Google SecOps OneMCP tool calls.

    Reads `CHRONICLE_PROJECT_ID` (falling back to `GOOGLE_CLOUD_PROJECT`),
    `CHRONICLE_CUSTOMER_ID`, and `CHRONICLE_REGION` so the model includes
    `projectId`, `customerId`, and `region` in every `secops_*` call.

    Args:
        env: Optional environment mapping override for testing. Defaults to
            reading from `os.environ` via `os.getenv`.

    Returns:
        A formatted Markdown section listing the active Google SecOps tenant
        parameters.
    """
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
        "Pass these parameters explicitly when invoking Google SecOps OneMCP"
        " (`secops_*`) tools."
    )
