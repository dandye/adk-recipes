# Google SecOps Custom Agents (OneMCP + Skills + Personas + GTI MCP)

This recipe provides a canonical Google Agent Development Kit (ADK) architecture for autonomous Security Operations Center (SOC) workflows. It integrates four core pillars:

1. **Google SecOps OneMCP (`secops_*`)**: Connects to the remote Google Security Operations Model Context Protocol endpoint (`https://chronicle.<region>.rep.googleapis.com/mcp`) over Streamable HTTP using Google Application Default Credentials (ADC) or Agent Engine OAuth pass-through. It filters out the 7 high-bloat feed-management tools (`create_feed`, `update_feed`, `run_parser`, `list_feeds`, `get_feed`, `disable_feed`, `enable_feed`), cutting eager `inputSchema` payload size by 68.94%, and strips `response_json_schema` via `before_model_callback`.
2. **Google Threat Intelligence MCP (`gti_*`)**: Connects to the GTI MCP server (`uvx gti-mcp` over stdio or remote Streamable HTTP via `GTI_MCP_URL`) for campaign collection profiling, multi-hop indicator pivoting, and code-signing verification (`VALID_CERTIFICATE`) to prevent signed OS LOLBin overcontainment.
3. **Progressive Skill Disclosure (`SkillToolset`)**: Bundles 6 curated SecOps operational `SKILL.md` runbooks (`triage-alerts`, `suspicious-login-triage`, `malware-triage`, `gti-collection-threat-hunt`, `detection-rule-validation-tuning`, and `ioc-containment`) loaded on demand with `google.adk.skills.load_skill_from_dir`.
4. **Adaptive Specialist Personas (`SECOPS_USE_PERSONAS`)**:
   - **Persona Hierarchy (`SECOPS_USE_PERSONAS=true`, default)**: Root `secops_supervisor` coordinates 5 role-scoped specialist sub-agents (`secops_triage_specialist`, `secops_threat_hunter`, `secops_cti_researcher`, `secops_detection_engineer`, and `secops_incident_responder`), each with its own Markdown persona instruction overlay (`app/profiles/*.md`), scoped `SkillToolset`, and role-filtered SecOps OneMCP and GTI MCP toolsets.
   - **Unified Frontier Agent (`SECOPS_USE_PERSONAS=false`)**: Single `secops_agent` equipped with the full 6-skill `SkillToolset` and live SecOps OneMCP and GTI MCP toolsets.

## Agent Details

| Feature | Description |
| --- | --- |
| **Interaction Type** | Conversational & Autonomous SOC Triage |
| **Complexity** | Advanced |
| **Agent Type** | Adaptive Multi-Agent Hierarchy (`secops_supervisor` + 5 specialists) or Unified Single Agent (`secops_agent`) |
| **Components** | `SkillToolset`, `McpToolset` (Google SecOps OneMCP over Streamable HTTP, Google Threat Intelligence MCP over stdio/HTTP), A2A Server |
| **Vertical** | Security Operations (SIEM / SOAR / Threat Intelligence / Detection Engineering) |

## Architecture

```mermaid
flowchart TD
    User["SOC Analyst / SOAR Trigger"] --> Supervisor["secops_supervisor (or Unified secops_agent)"]
    Supervisor --> Triage["secops_triage_specialist"]
    Supervisor --> Hunter["secops_threat_hunter"]
    Supervisor --> CTI["secops_cti_researcher"]
    Supervisor --> Detection["secops_detection_engineer"]
    Supervisor --> Responder["secops_incident_responder"]

    Triage --> Skills["ADK SkillToolset (app/skills/*/SKILL.md)"]
    Hunter --> Skills
    CTI --> Skills
    Detection --> Skills
    Responder --> Skills

    Triage --> OneMCP["Google SecOps OneMCP (Streamable HTTP)"]
    Hunter --> OneMCP
    Detection --> OneMCP
    Responder --> OneMCP

    Triage --> GTIMCP["Google Threat Intelligence MCP (stdio / HTTP)"]
    Hunter --> GTIMCP
    CTI --> GTIMCP
    Responder --> GTIMCP
```

## Project Structure

```text
secops-custom-agents/
├── app/
│   ├── __init__.py           # Package entrypoint: loads .env/config.env and exports agent, app, root_agent
│   ├── agent.py              # Adaptive agent builder (persona hierarchy vs. unified frontier agent)
│   ├── deploy.py             # Vertex AI Agent Engine deployment helper (python -m app.deploy)
│   ├── fast_api_app.py       # FastAPI server with ADK web, A2A, and Agent Engine routes
│   ├── mcp_tools.py          # SecOps OneMCP + GTI MCP toolsets, tool filters, and schema callbacks
│   ├── personas.py           # Specialist persona registry and Markdown overlay loader
│   ├── prompt.py             # Supervisor, unified frontier, and tenant context banner prompts
│   ├── skills_loader.py      # ADK SkillToolset loader for operational SKILL.md runbooks
│   ├── app_utils/            # Shared A2A, Agent Engine, and session/artifact service adapters
│   ├── profiles/             # Role-specific Markdown persona instructions (5 SOC specialists)
│   └── skills/               # 6 progressive-disclosure SecOps SKILL.md runbooks
├── tests/
│   ├── test_runnability.py   # Recipe import and symbol smoke test
│   ├── unit/                 # Offline unit tests for personas, skills, MCP filters, and A2A boot
│   └── integration/          # Live streaming and end-to-end FastAPI/A2A integration tests
├── .env.example              # Environment variable template
├── agents-cli-manifest.yaml  # ADK deployment CLI manifest
├── config.env.example        # Agent Starter Pack / Agent Garden config template
├── Dockerfile                # Cloud Run / container deployment image
├── Makefile                  # Install, sync-config, setup-infra, playground, and deploy targets
├── manifest.yaml             # ADK recipe catalog manifest
├── pyproject.toml            # Dependencies, Agent Starter Pack settings, and Pytest configuration
└── README.md
```

## Setup

1. Navigate to the recipe directory and install dependencies using `uv`:

```bash
RECIPE_DIR="contrib/python/secops-custom-agents"
cd "$RECIPE_DIR"
uv sync
```

2. Copy `.env.example` to `.env` and populate your Google Cloud project, Google SecOps tenant (`CHRONICLE_PROJECT_ID`, `CHRONICLE_CUSTOMER_ID`, `CHRONICLE_REGION`), and Google Threat Intelligence API key (`VT_APIKEY`):

```bash
cp .env.example .env
```

3. Authenticate with Google Cloud Application Default Credentials so the SecOps OneMCP `header_provider` can mint Bearer tokens with `https://www.googleapis.com/auth/cloud-platform` scope:

```bash
gcloud auth login --update-adc
```

## Run

Run the interactive ADK CLI or web playground from the recipe root:

```bash
# Run the interactive CLI session (defaults to SECOPS_USE_PERSONAS=true)
uv run adk run app

# Or launch the ADK web UI
uv run adk web

# Or switch to the unified single-agent frontier topology
SECOPS_USE_PERSONAS=false uv run adk run app
```

## Try It

| # | Query | What It Demonstrates |
| --- | --- | --- |
| 1 | `"List the open alerts in our SecOps tenant from the last 24 hours and triage the highest-severity login alert."` | Routes to `secops_triage_specialist`, loads `triage-alerts` and `suspicious-login-triage` via `SkillToolset`, and queries `secops_list_security_alerts` + `secops_search_security_events`. |
| 2 | `"Profile GTI collection report--25-10035907 and hunt for matching network and process activity across our SIEM over the last 7 days."` | Coordinates `secops_cti_researcher` (`gti_get_collection_report`, `gti_get_entities_related_to_a_collection`) with `secops_threat_hunter` (`gti-collection-threat-hunt` skill + UDM hunting). |
| 3 | `"Validate a YARA-L 2.0 rule detecting suspicious rundll32.exe execution and check its historical alert volume."` | Routes to `secops_detection_engineer`, loads `detection-rule-validation-tuning`, verifies syntax via `secops_verify_rule_text` / `secops_validate_yaral2_rule`, and backtests via `secops_evaluate_rule_coverage_long_running`. |
| 4 | `"Evaluate whether SHA-256 hash <hash> observed on workstation-04 should be contained or excluded as a signed OS LOLBin."` | Routes to `secops_incident_responder`, loads `ioc-containment`, checks `gti_get_file_report` for `VALID_CERTIFICATE`, and produces a 4-way Disposition and Containment Matrix. |

## Deploy with Agent Starter Pack (Vertex AI Agent Garden)

To scaffold and deploy this recipe using the Vertex AI Agent Garden `deploy_agent_starter_pack` workflow:

```bash
AGENT_NAME="secops-agents-${RANDOM}"
RECIPE_URL="https://github.com/google/adk-recipes/tree/main/contrib/python/secops-custom-agents"

uvx agent-starter-pack==0.41.0 create "$AGENT_NAME" \
  -d agent_engine \
  -ag \
  -a "$RECIPE_URL"

cd "$AGENT_NAME"
make sync-config

# Populate CHRONICLE_CUSTOMER_ID and GTI_API_KEY in config.env before deploying:
make install && make setup-infra && make deploy-agent-engine

# Optional: register the deployed Agent Engine resource in Gemini Enterprise:
make register-gemini-enterprise
```

## End-to-End Argolis Verification Screencast

See [`secops_custom_agents_argolis_screencast_walkthrough.md`](secops_custom_agents_argolis_screencast_walkthrough.md) for the complete 3-scene 1080p verification walkthrough (`uvx agent-starter-pack create`, Vertex AI Agent Engine deployment, remote `ReasoningEngine` streaming query, and `adk web` traces/hierarchy inspection).

![Google SecOps Custom Agents Argolis Verification Screencast](assets/secops_custom_agents_argolis_screencast.gif)

## Run Unit Tests

Unit tests validate agent hierarchy construction, unified frontier mode, progressive `SkillToolset` loading, OneMCP feed-tool filtering, `response_json_schema` stripping, and credential validation without requiring a `.env` file or live network calls:

```bash
uv run pytest
```
