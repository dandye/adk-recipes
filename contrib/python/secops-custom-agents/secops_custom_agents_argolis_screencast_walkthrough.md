# Google SecOps Custom Agents — Argolis Verification Screencast

End-to-end 1080p dark-mode screencast of the `secops-custom-agents` recipe verified in Argolis (`dandye-0324-chronicle`, Project Number `1002894625780`, Chronicle Customer ID `7e977ce4-f45d-43b2-aea0-52f8b66acd80`).

## Deliverables & Assets

| Asset | Format & Specs | Relative Path |
| :--- | :--- | :--- |
| **1080p MP4 Video** | H.264 (`libx264`, `yuv420p`), `1920x1080`, 30 fps, `35.8s` (`3.03 MB`) | [`assets/secops_custom_agents_argolis_screencast.mp4`](assets/secops_custom_agents_argolis_screencast.mp4) |
| **1080p WebM Video** | VP9 (`libvpx-vp9`), `1920x1080`, `35.8s` (`3.97 MB`) | [`assets/secops_custom_agents_argolis_screencast.webm`](assets/secops_custom_agents_argolis_screencast.webm) |
| **Animated Preview GIF** | `1280x720`, 10 fps Lanczos + 256-color palette, `35.8s` (`9.35 MB`) | [`assets/secops_custom_agents_argolis_screencast.gif`](assets/secops_custom_agents_argolis_screencast.gif) |

## Full Animated Screencast Preview

![Google SecOps Custom Agents Argolis Verification Screencast](assets/secops_custom_agents_argolis_screencast.gif)

## Scene-by-Scene 1080p Keyframes

### Scene 1 (`00:00` – `00:11`): Agent Starter Pack Scaffolding & Vertex AI Agent Engine Deployment

![Scene 1 — Agent Starter Pack Scaffolding, Masked config.env, and Vertex AI Agent Engine Deployment](assets/frame_scene1_deploy.png)

- Runs `uvx agent-starter-pack==0.41.0 create secops-agents-argolis -a adk@secops-custom-agents --base-template adk` against the `dandye/adk-recipes` branch.
- Displays `config.env` with masked `SECOPS_CUSTOMER_ID` and `CHRONICLE_SERVICE_ACCOUNT_JSON_B64` values.
- Runs `make install && make setup-infra && make deploy-agent-engine`, granting IAM roles to the Reasoning Engine runtime service account (`service-1002894625780@gcp-sa-aiplatform-re.iam.gserviceaccount.com`) and deploying `projects/1002894625780/locations/us-central1/reasoningEngines/5545305805705707520`.

### Scene 2 (`00:11` – `00:22`): Remote Vertex AI Agent Engine Streaming Query & Unit Suite

![Scene 2 — Live Remote Vertex AI Reasoning Engine Streaming Query & Offline Unit Suite](assets/frame_scene2_verify.png)

- Connects to remote Reasoning Engine `projects/1002894625780/locations/us-central1/reasoningEngines/5545305805705707520` (`session_id: 6197241605984878592`) and streams an alert triage prompt.
- Verifies remote execution of `load_skill(skill_name="triage-alerts")`, `secops__list_security_alerts` (retrieving 1,211 live security alerts over the last 7 days from `https://chronicle.us.rep.googleapis.com/mcp`), and `secops__udm_search` (`metadata.event_type = "USER_LOGIN"`).
- Runs `make test` (`28 passed in 0.89s`).

### Scene 3A (`00:22` – `00:26`): Live ADK Developer UI (`adk web`) Session

![Scene 3A — ADK Developer UI Live Triage Session](assets/frame_scene3_chat.png)

- Shows interactive session `ef344645-48fe-4210-9f8a-19401b61dc12` in `adk web` executing `load_skill`, `secops__list_security_alerts`, and `secops__udm_search` against the Argolis Chronicle instance (`dandye-0324-chronicle`) and returning the structured triage summary.

### Scene 3B (`00:26` – `00:31`): OpenTelemetry Execution Trace Waterfall (`Traces` Tab)

![Scene 3B — OpenTelemetry Traces Waterfall in ADK Web](assets/frame_scene3_traces.png)

- Inspects the `invocation [secops_custom_agents]` trace waterfall showing `call_llm`, `execute_tool load_skill`, `execute_tool secops__list_security_alerts`, and `execute_tool secops__udm_search` latency spans.

### Scene 3C (`00:31` – `00:35`): Multi-Agent Hierarchy & Toolset Graph (`Agent Structure` Tab)

![Scene 3C — Multi-Agent Hierarchy and Toolset Graph in ADK Web](assets/frame_scene3_tree.png)

- Displays the interactive agent hierarchy graph (`secops_supervisor` root agent, `secops_triage_analyst`, `secops_investigator`, `secops_threat_hunter`, `secops_detection_engineer`, `secops_response_agent`, `SkillToolset`, and `LazyValidatedMcpToolset`).
