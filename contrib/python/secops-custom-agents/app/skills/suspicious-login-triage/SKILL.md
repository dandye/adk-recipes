---
name: suspicious-login-triage
description: Use when triaging anomalous or suspicious user authentication events, impossible travel, MFA anomalies, and credential abuse.
category: triage
version: 1.1.0
metadata:
  adk_additional_tools:
  - secops_lookup_entity
  - secops_udm_search
  - secops_search_security_events
  - secops_get_case
  - secops_list_security_alerts
  - gti_get_ip_address_report
---

# Suspicious Login Alert Triage Runbook

## Objective
Triage suspicious authentication alerts across IdP, SaaS, cloud, and Windows logs to distinguish credential compromise from benign travel or VPN usage.

## Scope
Covers reactive triage of `USER_LOGIN` and authentication alerts (`OKTA`, `DUO_AUTH`, `AZURE_AD`, `OFFICE_365`, `WORKSPACE_ACTIVITY`, `GCP_CLOUDAUDIT`, `WINEVTLOG`).

## Inputs
- `<case_id>`: Case identifier containing the login alert(s).
- `<user_or_ip>`: Primary username, email, NetBIOS account, or source IP.

## Tools
- **SecOps OneMCP (`secops_`)**: `get_case`, `list_security_alerts`, `lookup_entity`, `udm_search`, `search_security_events`
- **GTI MCP (`gti_`)**: `get_ip_address_report`

## Workflow Steps
- **Stage A (Case & Entity Extraction)**:
  1. Call `secops_get_case` and `secops_list_security_alerts` for `<case_id>`.
  2. Call `secops_lookup_entity` on each user and host to check privileges and login baselines.
  3. Record every user principal in all observed formats verbatim, including `DOMAIN\<user>` NetBIOS names alongside `<user>@<domain>` emails and short usernames.
- **Stage B (Source IP Scope & Reputation)**:
  1. Check if each login source IP is internal RFC-1918, corporate VPN egress, residential proxy, or external hosting.
  2. Call `gti_get_ip_address_report` on every external source IP to check reputation and threat associations.
- **Stage C (Authentication Timeline & Post-Login Pivots)**:
  1. Call `secops_udm_search` or `secops_search_security_events` over `168` hours for `<user_or_ip>` across IdP, cloud, and endpoint logs.
  2. Check for password spray bursts, MFA push bombing, helpdesk MFA resets, rogue admin creation, RMM execution, or cloud token assumption after login.
- **Stage D (Disposition & Action Matrix)**:
  - **MALICIOUS**: Malicious source IP or unauthorized MFA reset, lateral jump, rogue admin creation, or data access confirmed. Recommend session revocation and block confirmed malicious external IPs.
  - **SUSPICIOUS**: Unrecognized external IP without malicious GTI reputation or post-login abuse. Escalate for verification; do not lock accounts or close.
  - **INCONCLUSIVE**: Missing IdP telemetry or API timeout prevents verification. Document gaps; do not contain or close.
  - **BENIGN**: Login matches corporate VPN, known travel, or routine service-account baseline. Document closure note listing every observed host, user format, and IP.
