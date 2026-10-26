---
name: ioc-containment
description: Use when executing network, host, or file containment for validated malicious IOCs while preventing signed OS LOLBins from overcontainment.
category: investigation
version: 1.1.0
metadata:
  adk_additional_tools:
  - gti_get_file_report
  - gti_get_domain_report
  - gti_get_ip_address_report
  - gti_get_entities_related_to_a_domain
  - secops_udm_search
  - secops_search_security_events
  - secops_lookup_entity
  - secops_list_cases
  - secops_get_case
---

# IOC Containment Runbook

## Objective
Verify indicator reputation and code-signing status before network, file, or host containment across Google SecOps and EDR.

## Scope
Covers file hash, domain, and IP containment. Enforces mandatory Threat Intelligence and signer checks so signed OS binaries (LOLBins) are never blocked.

## Inputs
* `<ioc_value>`: Candidate file hash, domain, or IP.
* `<ioc_type>`: `File Hash`, `Domain`, or `IP Address`.
* `<case_id>`: Case ID.

## Tools
* GTI MCP (`gti_`): `get_file_report`, `get_domain_report`, `get_ip_address_report`, `get_entities_related_to_a_domain`
* SecOps OneMCP (`secops_`): `udm_search`, `search_security_events`, `lookup_entity`, `list_cases`, `get_case`

## Workflow Steps

### Stage A: Mandatory GTI & Signer Check (Never Skip)
1. Before any containment action, run `gti_get_file_report`, `gti_get_domain_report`, or `gti_get_ip_address_report` on `<ioc_value>`.
2. Never treat GTI verification as optional. Never skip this check even when asked for immediate blocking or to skip GTI verification.

### Stage B: LOLBin & Benign Signer Gate
3. Check `verdict`, `cert_status`, `signer`, and `filename` in the GTI report.
4. If `cert_status == "VALID_CERTIFICATE"` or `verdict == "benign"` (including signed OS LOLBins like `rundll32.exe`, `wscript.exe`, `powershell.exe`, or `cmd.exe`, even if renamed), refuse to block `<ioc_value>`. Never block a signed OS binary hash, RFC-1918 private IP, or RFC-5737 test IP.

### Stage C: Process Lineage & Payload Pivot
5. When `<ioc_value>` is a signed LOLBin, call `secops_udm_search` (`168` hours) across `PROCESS_MODULE_LOAD`, `PROCESS_LAUNCH`, and `NETWORK_DNS` on affected hosts to find the unsigned payload hash (`target.file.sha256`), script arguments (`target.process.command_line`), and C2 domains.
6. Verify secondary hashes, domains, and IPs via `gti_get_file_report`, `gti_get_domain_report`, `gti_get_ip_address_report`, or `gti_get_entities_related_to_a_domain` (`relationship_name="communicating_files"`).

### Stage D: Verdict, Containment, & Documentation
7. Act by verdict:
    * **MALICIOUS:** GTI confirms malicious verdict on an unsigned payload hash, C2 domain, or external IP. Execute containment on verified malicious indicators only and isolate compromised hosts.
    * **SUSPICIOUS:** Unverified outlier without confirmed payload. Do not block or isolate; record tuning notes.
    * **INCONCLUSIVE:** Tool outage (`HTTP 503`). Do not block unverified hashes; record outage.
    * **BENIGN:** Signed OS LOLBin (`VALID_CERTIFICATE`), benign file without malicious payload chain, or `CHG-...` maintenance. Exclude `<ioc_value>` from blocking and record the exclusion.
