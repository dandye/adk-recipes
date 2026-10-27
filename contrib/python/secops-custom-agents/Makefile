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

SHELL := /bin/bash

.PHONY: install sync-config setup-infra playground deploy deploy-agent-engine backend register-gemini-enterprise test lint

# ==============================================================================
# Installation & Configuration Setup
# ==============================================================================

install:
	@command -v uv >/dev/null 2>&1 || { echo "uv is not installed. Installing uv..."; curl -LsSf https://astral.sh/uv/0.8.13/install.sh | sh; source $$HOME/.local/bin/env; }
	uv sync

# Sync root config.env into app/config.env so the package ships with non-secret
# runtime configuration when bundled for Vertex AI Agent Engine.
sync-config:
	@if [ ! -f config.env ]; then \
		PROJECT_ID=$$(gcloud config get-value project 2>/dev/null || echo "<TODO: update-this-value>"); \
		if [ -n "$${PROJECT_ID}" ] && [ "$${PROJECT_ID}" != "<TODO: update-this-value>" ]; then \
			sed -e "s|^PROJECT_ID=.*|PROJECT_ID=$${PROJECT_ID}|" \
				-e "s|^GCP_PROJECT_ID=.*|GCP_PROJECT_ID=$${PROJECT_ID}|" \
				-e "s|^GOOGLE_CLOUD_PROJECT=.*|GOOGLE_CLOUD_PROJECT=$${PROJECT_ID}|" \
				-e "s|^CHRONICLE_PROJECT_ID=.*|CHRONICLE_PROJECT_ID=$${PROJECT_ID}|" \
				config.env.example > config.env; \
		else \
			cp config.env.example config.env; \
		fi; \
		echo "Created config.env from config.env.example (PROJECT_ID=$${PROJECT_ID})."; \
	fi
	@cp config.env app/config.env

# Enable required GCP APIs for Vertex AI Agent Engine and Google SecOps.
setup-infra: sync-config
	@echo "==============================================================================="
	@echo "| Configuring Google Cloud Project & Enabling Required APIs                   |"
	@echo "==============================================================================="
	@source config.env && \
		if [ -n "$${PROJECT_ID}" ] && [ "$${PROJECT_ID}" != "<TODO: update-this-value>" ] && [ "$${PROJECT_ID}" != "your-gcp-project-id" ]; then \
			gcloud config set project "$${PROJECT_ID}" --quiet && \
			gcloud services enable \
				aiplatform.googleapis.com \
				chronicle.googleapis.com \
				cloudresourcemanager.googleapis.com \
				serviceusage.googleapis.com \
				--project="$${PROJECT_ID}" --quiet; \
		else \
			echo "Notice: PROJECT_ID in config.env is still set to a placeholder."; \
			echo "Update config.env with your GCP project ID, CHRONICLE_CUSTOMER_ID, and GTI_API_KEY."; \
		fi

# ==============================================================================
# Playground & Local Development
# ==============================================================================

playground: sync-config
	@echo "==============================================================================="
	@echo "| Starting ADK Web Playground on port 8501...                                 |"
	@echo "| Example query: Triage case 4091 and hunt for Ursnif across the last 7 days. |"
	@echo "| Select the 'app' folder in the UI to interact with the SecOps agent.        |"
	@echo "==============================================================================="
	uv run adk web . --port 8501 --reload_agents

# ==============================================================================
# Vertex AI Agent Engine Deployment Targets
# ==============================================================================

deploy-agent-engine: sync-config
	@source config.env && \
	if [ -n "$${PROJECT_ID}" ] && [ "$${PROJECT_ID}" != "your-gcp-project-id" ]; then \
		gcloud config set project "$${PROJECT_ID}" --quiet; \
	fi && \
	(uv export --no-hashes --no-header --no-dev --no-emit-project --no-annotate > app/app_utils/.requirements.txt 2>/dev/null || \
	uv export --no-hashes --no-header --no-dev --no-emit-project > app/app_utils/.requirements.txt) && \
	ENV_VARS=$$(uv run python -m app.deploy --config-file=config.env --print-env-vars $(if $(SET_ENV_VARS),--set-env-vars="$(SET_ENV_VARS)")) && \
	if [ -f app/app_utils/deploy.py ]; then \
		uv run -m app.app_utils.deploy \
			--project="$${PROJECT_ID}" \
			--location="$${DEFAULT_REGION:-us-central1}" \
			--source-packages=./app \
			--entrypoint-module=app.agent_engine_app \
			--entrypoint-object=agent_engine \
			--requirements-file=app/app_utils/.requirements.txt \
			--display-name=secops-custom-agents \
			--description="Autonomous Google Security Operations (SecOps) ADK agent" \
			$${ENV_VARS:+--set-env-vars="$${ENV_VARS}"} \
			$(if $(AGENT_IDENTITY),--agent-identity) \
			$(if $(filter command line,$(origin SECRETS)),--set-secrets="$(SECRETS)"); \
	else \
		uv run -m app.deploy \
			--project="$${PROJECT_ID}" \
			--location="$${DEFAULT_REGION:-us-central1}" \
			--source-packages=./app \
			--requirements-file=app/app_utils/.requirements.txt \
			--display-name=secops-custom-agents \
			--config-file=config.env \
			$${ENV_VARS:+--set-env-vars="$${ENV_VARS}"}; \
	fi

deploy: deploy-agent-engine

backend: deploy-agent-engine

# ==============================================================================
# Gemini Enterprise Registration
# ==============================================================================

register-gemini-enterprise:
	@uvx agent-starter-pack@0.41.0 register-gemini-enterprise

# ==============================================================================
# Testing & Code Quality
# ==============================================================================

test:
	uv sync --dev
	uv run pytest tests/unit && uv run pytest tests/test_runnability.py

lint:
	uv run ruff check . --diff
	uv run ruff format . --check --diff
