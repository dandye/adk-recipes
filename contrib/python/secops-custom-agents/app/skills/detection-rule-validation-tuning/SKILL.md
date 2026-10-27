---
name: detection-rule-validation-tuning
description: Use when authoring, validating, or tuning Google SecOps YARA-L 2.0 detection rules, reducing false positives, and evaluating rule coverage.
category: detection
version: 1.1.0
metadata:
  adk_additional_tools:
  - secops_list_rules
  - secops_get_rule
  - secops_verify_rule_text
  - secops_validate_yaral2_rule
  - secops_generate_threat_detection_opportunity
  - secops_generate_synthetic_events
  - secops_evaluate_rule_coverage_long_running
  - secops_udm_search
  - secops_search_security_events
  - secops_lookup_entity
---

# Detection Rule Validation & Tuning Runbook

## Objective
Validate Google SecOps YARA-L 2.0 (`YL2`) detection rule syntax, check retrohunt fidelity against attack and baseline UDM events, and propose tuned rules.

## Scope
Covers single-event and multi-event YARA-L 2.0 rule retrieval, compiler validation, synthetic coverage evaluation, and false-positive exclusion tuning.

## Inputs
- `<rule_id_or_query>`: Rule identifier (`ru_...`), usecase name, or candidate YARA-L 2.0 rule text.
- `<case_id>`: Optional SOAR case identifier tracking the review.

## Tools
- **SecOps OneMCP Rules (`secops_`)**: `list_rules`, `get_rule`, `verify_rule_text`, `validate_yaral2_rule`, `generate_threat_detection_opportunity`, `generate_synthetic_events`, `evaluate_rule_coverage_long_running`
- **SecOps OneMCP Telemetry (`secops_`)**: `udm_search`, `search_security_events`, `lookup_entity`

## Workflow Steps
- **Stage A (Rule Retrieval & Intent)**:
  1. Call `secops_list_rules` and `secops_get_rule` to retrieve existing YARA-L 2.0 rule text and `meta:` fields.
  2. Identify targeted UDM event types (`metadata.event_type`), event variables, `match:` window, `outcome:` risk score, and MITRE ATT&CK technique.
- **Stage B (Compiler & Syntax Validation)**:
  1. Call `secops_verify_rule_text` or `secops_validate_yaral2_rule` on the candidate YARA-L 2.0 rule text.
  2. Verify compilation succeeds and check required `meta:`, `events:`, and `condition:` sections, explicit UDM field paths (never `.ip` or `.hash` search aliases), and parenthesized `or` groups instead of inline `in (...)` tuples.
- **Stage C (Retrohunt & Noise Sampling)**:
  1. Call `secops_udm_search` over `168` hours matching the rule predicates to inspect attack events and benign baseline noise.
  2. Call `secops_lookup_entity` on noisy hosts or principals to check if routine admin traffic (`svc-backup`, `CHG-...`) causes false positives.
  3. If tuning is needed, draft an updated YARA-L 2.0 rule and re-validate until compilation succeeds.
- **Stage D (Disposition & Action Matrix)**:
  - **MALICIOUS**: Rule fires on confirmed attack telemetry and compiles cleanly. Document matched hosts, users, IPs, domains, hashes, and validated YARA-L 2.0 rule text.
  - **SUSPICIOUS**: Rule compiles cleanly but matches dual-use admin behavior needing narrower predicates. Provide tuned candidate rule; do not auto-deploy.
  - **INCONCLUSIVE**: Rule fails compilation or log source is absent. Document compiler errors; do not deploy.
  - **BENIGN**: Rule alerts only on authorized baseline activity. Propose explicit exclusions and verify syntax before documenting.
