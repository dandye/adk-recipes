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

"""Vertex AI Agent Engine deployment script for Google SecOps custom agents.

Supports the Agent Garden `deploy_agent_starter_pack` workflow where users
populate `config.env` from `config.env.example` and run:
  `make install && make setup-infra && make deploy-agent-engine`
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import google.auth
import vertexai
from dotenv import dotenv_values
from vertexai import agent_engines

from app.agent import root_agent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_DISPLAY_NAME = "secops-custom-agents"
DEFAULT_DESCRIPTION = (
    "Autonomous Google Security Operations (SecOps) ADK agent with SecOps"
    " OneMCP, GTI MCP, SkillToolset runbooks, and 5 specialist personas."
)
DEFAULT_LOCATION = "us-central1"
PLACEHOLDER_PREFIXES = ("<TODO", "<YOUR_")
PLACEHOLDER_EXACT_VALUES = frozenset({"your-gcp-project-id", ""})

RUNTIME_ENV_KEYS: tuple[str, ...] = (
    "GCP_PROJECT_ID",
    "GEMINI_MODEL_LOCATION",
    "GOOGLE_GENAI_USE_VERTEXAI",
    "MODEL_NAME",
    "SECOPS_USE_PERSONAS",
    "CHRONICLE_PROJECT_ID",
    "CHRONICLE_CUSTOMER_ID",
    "CHRONICLE_REGION",
    "SECOPS_ONEMCP_URL",
    "GTI_API_KEY",
    "VT_APIKEY",
    "GTI_MCP_COMMAND",
    "GTI_MCP_ARGS",
    "GTI_MCP_URL",
)

DEFAULT_REQUIREMENTS: tuple[str, ...] = (
    "a2a-sdk[http-server]>=1.0,<2",
    "aiohttp>=3.13.4",
    "gcsfs>=2024.11.0",
    "google-adk[gcp,mcp,otel-gcp]>=2.6.0,<3.0.0",
    "google-cloud-aiplatform[agent-engines]>=1.156.0,<2.0.0",
    "opentelemetry-resourcedetector-gcp<=1.12.0a0",
    "python-dotenv>=1.0.0,<2.0.0",
)


# ---------------------------------------------------------------------------
# Environment & CLI Parsing Helpers
# ---------------------------------------------------------------------------
def is_placeholder_value(value: str | None) -> bool:
    """Return True if an environment variable value is an unedited placeholder.

    Args:
        value: Raw string value from `config.env`, `.env`, or `os.environ`.

    Returns:
        `True` if `value` is `None`, empty, starts with `<TODO` / `<YOUR_`,
        or equals `your-gcp-project-id`.
    """
    if value is None:
        return True
    cleaned = value.strip()
    if cleaned in PLACEHOLDER_EXACT_VALUES:
        return True
    return cleaned.startswith(PLACEHOLDER_PREFIXES)


def parse_key_value_pairs(kv_string: str | None) -> dict[str, str]:
    """Parse comma-separated `KEY=VALUE` pairs into a dictionary.

    Args:
        kv_string: Optional comma-separated `KEY=VALUE` string from CLI flags.

    Returns:
        Dictionary of parsed key-value pairs with placeholders removed.
    """
    result: dict[str, str] = {}
    if not kv_string:
        return result
    for pair in kv_string.split(","):
        stripped_pair = pair.strip()
        if not stripped_pair:
            continue
        if "=" not in stripped_pair:
            logger.warning("Skipping malformed key-value pair: %s", pair)
            continue
        key, value = stripped_pair.split("=", 1)
        clean_key = key.strip()
        clean_val = value.strip()
        if clean_key and not is_placeholder_value(clean_val):
            result[clean_key] = clean_val
    return result


def load_env_file(path: str | Path) -> dict[str, str]:
    """Load non-placeholder key-value pairs from a dotenv file.

    Args:
        path: Path to `config.env` or `.env`.

    Returns:
        Dictionary of non-placeholder key-value strings from `path`.
    """
    env_path = Path(path)
    if not env_path.is_file():
        return {}
    raw_values = dotenv_values(env_path)
    cleaned: dict[str, str] = {}
    for key, val in raw_values.items():
        if key and val is not None and not is_placeholder_value(val):
            cleaned[key] = val.strip()
    return cleaned


def build_env_vars_from_mapping(
    source: Mapping[str, str],
    extra_env_vars: str | None = None,
) -> dict[str, str]:
    """Extract SecOps runtime environment variables from a mapping.

    Args:
        source: Source environment mapping (such as merged `config.env` and
            `os.environ`).
        extra_env_vars: Optional comma-separated `KEY=VALUE` overrides.

    Returns:
        Dictionary of non-placeholder runtime environment variables to pass
        to Vertex AI Agent Engine.
    """
    env_vars: dict[str, str] = {}
    for key in RUNTIME_ENV_KEYS:
        val = source.get(key)
        if val is not None and not is_placeholder_value(val):
            env_vars[key] = val.strip()

    project_id = (
        source.get("PROJECT_ID")
        or source.get("GCP_PROJECT_ID")
        or source.get("GOOGLE_CLOUD_PROJECT")
    )
    if project_id and not is_placeholder_value(project_id):
        env_vars.setdefault("GCP_PROJECT_ID", project_id.strip())
        env_vars.setdefault("CHRONICLE_PROJECT_ID", project_id.strip())

    model_loc = source.get("GEMINI_MODEL_LOCATION") or source.get(
        "GOOGLE_CLOUD_LOCATION"
    )
    if model_loc and not is_placeholder_value(model_loc):
        env_vars.setdefault("GEMINI_MODEL_LOCATION", model_loc.strip())

    env_vars.setdefault("GOOGLE_GENAI_USE_VERTEXAI", "True")
    env_vars.update(parse_key_value_pairs(extra_env_vars))
    # Never forward reserved Vertex AI Agent Engine keys in deployment_spec.env
    env_vars.pop("GOOGLE_CLOUD_PROJECT", None)
    env_vars.pop("GOOGLE_CLOUD_LOCATION", None)
    return env_vars


def format_env_vars_arg(env_vars: Mapping[str, str]) -> str:
    """Format a dictionary of environment variables as a `K=V,K2=V2` string.

    Args:
        env_vars: Mapping of environment variable names to values.

    Returns:
        Deterministic comma-separated `KEY=VALUE` string suitable for
        `--set-env-vars`.
    """
    return ",".join(f"{key}={value}" for key, value in sorted(env_vars.items()))


def load_requirements(requirements_file: str | Path | None) -> list[str]:
    """Load package requirement specifiers from file or return defaults.

    Args:
        requirements_file: Optional path to a `requirements.txt` file.

    Returns:
        List of requirement specifier strings.
    """
    if requirements_file:
        req_path = Path(requirements_file)
        if req_path.is_file():
            lines = [
                line.strip()
                for line in req_path.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            if lines:
                return lines
    return list(DEFAULT_REQUIREMENTS)


def write_deployment_metadata(
    resource_name: str,
    metadata_file: str | Path = "deployment_metadata.json",
) -> None:
    """Write Agent Starter Pack `deployment_metadata.json` for registration.

    Args:
        resource_name: Full Vertex AI ReasoningEngine resource name.
        metadata_file: Output JSON file path (default
            `deployment_metadata.json`).
    """
    metadata = {
        "remote_agent_engine_id": resource_name,
        "deployment_target": "agent_engine",
        "is_a2a": False,
        "deployment_timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
    }
    Path(metadata_file).write_text(
        json.dumps(metadata, indent=2) + "\n",
        encoding="utf-8",
    )
    logger.info("Agent Engine metadata written to %s", metadata_file)


# ---------------------------------------------------------------------------
# Deployment Execution
# ---------------------------------------------------------------------------
def deploy_to_agent_engine(
    project: str | None = None,
    location: str = DEFAULT_LOCATION,
    staging_bucket: str | None = None,
    display_name: str = DEFAULT_DISPLAY_NAME,
    description: str = DEFAULT_DESCRIPTION,
    source_packages: Sequence[str] = ("./app",),
    requirements_file: str | None = None,
    set_env_vars: str | None = None,
    config_file: str = "config.env",
) -> Any:
    """Create or update the Google SecOps agent on Vertex AI Agent Engine.

    Args:
        project: GCP project ID. Defaults to `PROJECT_ID` /
            `GOOGLE_CLOUD_PROJECT` or Application Default Credentials.
        location: GCP region for Vertex AI Agent Engine (default `us-central1`).
        staging_bucket: Optional GCS staging bucket URI (`gs://...`).
        display_name: Display name for the deployed Agent Engine resource.
        description: Description for the deployed Agent Engine resource.
        source_packages: Sequence of local package directories to bundle.
        requirements_file: Optional path to exported `requirements.txt`.
        set_env_vars: Optional comma-separated `KEY=VALUE` overrides.
        config_file: Path to `config.env` (default `config.env`).

    Returns:
        The created or updated `AgentEngine` resource handle.

    Raises:
        ValueError: If no GCP project ID can be resolved.
    """
    merged_env: dict[str, str] = {}
    merged_env.update(load_env_file(".env"))
    merged_env.update(load_env_file(config_file))
    for key, val in os.environ.items():
        if not is_placeholder_value(val):
            merged_env[key] = val

    resolved_project = project or (
        merged_env.get("PROJECT_ID") or merged_env.get("GOOGLE_CLOUD_PROJECT")
    )
    if not resolved_project or is_placeholder_value(resolved_project):
        _, default_project = google.auth.default()
        resolved_project = default_project
    if not resolved_project:
        raise ValueError(
            "GCP project ID is required. Set PROJECT_ID in config.env or pass"
            " --project."
        )

    resolved_location = (
        location or merged_env.get("DEFAULT_REGION") or DEFAULT_LOCATION
    )
    resolved_bucket = staging_bucket or merged_env.get("STAGING_BUCKET")
    if resolved_bucket and not resolved_bucket.startswith("gs://"):
        resolved_bucket = f"gs://{resolved_bucket}"

    env_vars = build_env_vars_from_mapping(
        merged_env,
        extra_env_vars=set_env_vars,
    )
    requirements = load_requirements(requirements_file)

    logger.info(
        "Initializing Vertex AI (project=%s, location=%s)",
        resolved_project,
        resolved_location,
    )
    vertexai.init(
        project=resolved_project,
        location=resolved_location,
        staging_bucket=resolved_bucket,
    )

    adk_app = agent_engines.AdkApp(
        agent=root_agent,
        enable_tracing=True,
    )

    existing_resource_name: str | None = None
    for existing in agent_engines.list():
        if getattr(existing, "display_name", None) == display_name:
            existing_resource_name = existing.resource_name
            break

    common_kwargs: dict[str, Any] = {
        "agent_engine": adk_app,
        "requirements": requirements,
        "extra_packages": list(source_packages),
        "env_vars": env_vars,
        "display_name": display_name,
        "description": description,
    }

    if existing_resource_name:
        logger.info(
            "Updating existing Agent Engine resource: %s",
            existing_resource_name,
        )
        remote_agent = agent_engines.update(
            resource_name=existing_resource_name,
            **common_kwargs,
        )
    else:
        logger.info("Creating new Agent Engine resource: %s", display_name)
        remote_agent = agent_engines.create(**common_kwargs)

    resource_name = getattr(remote_agent, "resource_name", "")
    if resource_name:
        write_deployment_metadata(resource_name)
    logger.info("Deployment complete: %s", resource_name)
    return remote_agent


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser for `app.deploy`.

    Returns:
        Configured `argparse.ArgumentParser` instance.
    """
    parser = argparse.ArgumentParser(
        description="Deploy the Google SecOps ADK agent to Vertex AI."
    )
    parser.add_argument(
        "--project",
        default=None,
        help="GCP project ID (defaults to PROJECT_ID in config.env or ADC).",
    )
    parser.add_argument(
        "--location",
        default=DEFAULT_LOCATION,
        help="GCP region for Vertex AI Agent Engine (default: us-central1).",
    )
    parser.add_argument(
        "--staging-bucket",
        default=None,
        help="Optional GCS staging bucket name or gs:// URI.",
    )
    parser.add_argument(
        "--display-name",
        default=DEFAULT_DISPLAY_NAME,
        help="Display name for the Agent Engine resource.",
    )
    parser.add_argument(
        "--description",
        default=DEFAULT_DESCRIPTION,
        help="Description for the Agent Engine resource.",
    )
    parser.add_argument(
        "--source-packages",
        action="append",
        default=None,
        help="Source package directories to bundle (default: ./app).",
    )
    parser.add_argument(
        "--requirements-file",
        default="app/app_utils/.requirements.txt",
        help="Path to exported requirements.txt file.",
    )
    parser.add_argument(
        "--set-env-vars",
        default=None,
        help="Comma-separated KEY=VALUE runtime environment variables.",
    )
    parser.add_argument(
        "--config-file",
        default="config.env",
        help="Path to config.env file (default: config.env).",
    )
    parser.add_argument(
        "--print-env-vars",
        action="store_true",
        help="Print comma-separated runtime KEY=VALUE pairs and exit.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for `python -m app.deploy`.

    Args:
        argv: Optional sequence of CLI arguments.

    Returns:
        Process exit code (`0` on success).
    """
    logging.basicConfig(level=logging.INFO)
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.print_env_vars:
        merged_env: dict[str, str] = {}
        merged_env.update(load_env_file(".env"))
        merged_env.update(load_env_file(args.config_file))
        env_vars = build_env_vars_from_mapping(
            merged_env,
            extra_env_vars=args.set_env_vars,
        )
        print(format_env_vars_arg(env_vars))
        return 0

    source_pkgs = tuple(args.source_packages or ["./app"])
    deploy_to_agent_engine(
        project=args.project,
        location=args.location,
        staging_bucket=args.staging_bucket,
        display_name=args.display_name,
        description=args.description,
        source_packages=source_pkgs,
        requirements_file=args.requirements_file,
        set_env_vars=args.set_env_vars,
        config_file=args.config_file,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
