---
name: gti-collection-threat-hunt
description: Use when sweeping enterprise telemetry for indicators and execution chains from a GTI collection or threat hypothesis.
category: hunting
version: 1.0.0
metadata:
  adk_additional_tools:
  - gti_get_collection_report
  - gti_get_entities_related_to_a_collection
  - gti_get_entities_related_to_a_domain
  - gti_get_domain_report
  - gti_get_file_report
  - gti_get_ip_address_report
  - secops_udm_search
  - secops_search_security_events
  - secops_lookup_entity
  - secops_list_security_alerts
  - secops_list_cases
---

# Proactive GTI Collection & Campaign Threat Hunt

## Objective
Sweep enterprise telemetry for indicators and execution chains linked to a Google Threat Intelligence (GTI) collection or threat hypothesis to identify Patient Zero, scope, and detection gaps.

## Scope
Covers fleet-wide CTI collection sweeps (GTI reports, C2 domains, and MITRE ATT&CK execution chains) across GTI MCP and Google SecOps OneMCP.

## Inputs
* `<collection_id>`: Target GTI collection, report ID, or seed C2 domain.
* `<time_frame_hours>`: SIEM lookback in hours (default `72`; widen to `168` on zero hits).

## Tools
* GTI MCP (`gti_`): `get_collection_report`, `get_entities_related_to_a_collection`, `get_entities_related_to_a_domain`, `get_domain_report`, `get_file_report`, `get_ip_address_report`
* SecOps OneMCP (`secops_`): `udm_search`, `search_security_events`, `lookup_entity`, `list_security_alerts`, `list_cases`

## Workflow Steps

### Stage A: CTI Collection & Multi-Horizon SIEM Sweep (`72h` to `168h`)
1. Call `gti_get_collection_report` and `gti_get_entities_related_to_a_collection` on `<collection_id>` to extract domains, hashes, IPs, and TTPs (or `gti_get_domain_report` and `gti_get_entities_related_to_a_domain` for a seed domain).
2. Run a `72`-hour SIEM sweep via `secops_udm_search` or `secops_search_security_events` for extracted indicators.
3. If `72` hours returns zero matches, widen the lookback window to `168` hours (`7` days) and re-run the SIEM search across DNS, network, `PROCESS_LAUNCH`, and `PROCESS_MODULE_LOAD`.

### Stage B: Second-Hop Domain Pivot, LOLBin Filtering, & Case Correlation
4. For matched C2 domains, call `gti_get_entities_related_to_a_domain` (`relationship_name="communicating_files"`) for second-hop payload hashes and search `PROCESS_MODULE_LOAD` over `168` hours.
5. Call `gti_get_file_report` on matched hashes to separate malicious payloads from signed OS LOLBins (`rundll32.exe`, `wscript.exe` with `VALID_CERTIFICATE`) or benign web files.
6. On `<matched_hostname>`, call `secops_lookup_entity` and `secops_list_cases` to verify lineage, `CHG-...` records, and unalerted cases.

### Stage C: Hunt Verdict, Containment, & Detection-Gap Handoff
7. Apply a verdict:
    * **MALICIOUS:** Campaign C2 or payload execution confirmed on `<matched_hostname>`. Recommend host isolation and blocking verified C2 domains, IPs, and unsigned payload hashes (never block signed OS LOLBins), and document Patient Zero and detection gaps.
    * **SUSPICIOUS:** Unconfirmed LOLBin/TTP outlier or critical-asset activity where isolation is prohibited. Document YARA-L 2.0 (`YL2`) detection criteria; never isolate or close.
    * **INCONCLUSIVE:** Tool outage (`HTTP 503`). Record `INCONCLUSIVE`.
    * **BENIGN:** Zero malicious hits across `72h` and `168h`, or authorized `CHG-...` maintenance. Close investigation as `BENIGN`.
