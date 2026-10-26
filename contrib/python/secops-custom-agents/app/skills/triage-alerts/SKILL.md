---
name: triage-alerts
description: Use when evaluating and categorizing incoming security alerts and SOAR cases to determine severity, entity scope, and initial response actions.
category: triage
version: 1.1.0
metadata:
  adk_additional_tools:
  - secops_udm_search
  - secops_search_security_events
  - secops_lookup_entity
  - secops_list_security_alerts
  - secops_list_cases
  - secops_get_case
  - secops_list_rules
  - gti_get_file_report
  - gti_get_domain_report
  - gti_get_ip_address_report
---

# Alert Triage

## Objective
Assess Google SecOps cases and SIEM alerts, enrich all involved entities across SecOps OneMCP and GTI MCP, and decide whether to escalate or close as benign.

## Scope
Covers initial alert review, full entity inventory across all alerts, 168-hour SIEM UDM sweeps, rule inspection, and 4-way triage disposition.

## Inputs
* `<case_id>`: Google SecOps case or alert identifier.
* `<asset_identifier>`: Primary hostname, IP, or user principal in the alert.

## Tools
* SecOps OneMCP (`secops_`): `get_case`, `list_cases`, `list_security_alerts`, `udm_search`, `search_security_events`, `lookup_entity`, `list_rules`
* GTI MCP (`gti_`): `get_file_report`, `get_domain_report`, `get_ip_address_report`

## Workflow Steps

### Stage A: Case & Alert Entity Inventory
1. Call `secops_get_case` and `secops_list_security_alerts` (passing configured `projectId`, `customerId`, `region`) on `<case_id>` to extract every rule name, severity, hostname, user, IP, domain, URL (`target.url`), DNS query (`network.dns.questions.name`), and SHA256 hash.
2. Call `secops_lookup_entity` on `<asset_identifier>` to check asset role, criticality, and `CHG-...` maintenance windows.

### Stage B: Alert-Specific SIEM Sweep
3. Call `secops_udm_search` or `secops_search_security_events` over a 168-hour lookback for all extracted hostnames, users, IPs, domains, and hashes to check for corroborating activity.
4. Decode Base64 command-line flags (`-enc`, `-EncodedCommand`) before classifying dual-use tools (`powershell.exe`, `wmic.exe`, `rundll32.exe`).

### Stage C: Threat Intelligence & Rule Check
5. Call `gti_get_ip_address_report`, `gti_get_domain_report`, or `gti_get_file_report` on every external IP, domain, and hash.

### Stage D: Disposition & Mandatory Entity Listing
6. Classify and list every distinct hostname, user (in all observed formats verbatim), external IP, domain, full URL, DNS query, and SHA256 hash verbatim:
    * **MALICIOUS:** Corroborated compromise across SIEM and GTI. Escalate priority to `HIGH`/`CRITICAL` and document all entities.
    * **SUSPICIOUS:** Unverified anomaly without corroboration. Escalate to Tier 2; do not isolate hosts or disable accounts.
    * **INCONCLUSIVE:** Telemetry or API outage (`HTTP 503`). Record gap; execute zero destructive actions.
    * **BENIGN:** Verified IT/backup administration or clean baseline noise with zero malicious GTI hits. Document every observed entity verbatim and close with `NOT_MALICIOUS`.
