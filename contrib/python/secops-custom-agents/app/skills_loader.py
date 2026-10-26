# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Loader for bundled SecOps operational skills using ADK SkillToolset."""

import pathlib
from collections.abc import Callable, Sequence
from typing import Any

from google.adk.skills import load_skill_from_dir, models
from google.adk.tools.skill_toolset import SkillToolset

DEFAULT_SKILLS_DIR = pathlib.Path(__file__).resolve().parent / "skills"

CANONICAL_SKILL_NAMES: tuple[str, ...] = (
    "triage-alerts",
    "suspicious-login-triage",
    "malware-triage",
    "gti-collection-threat-hunt",
    "detection-rule-validation-tuning",
    "ioc-containment",
)


def make_static_instruction_provider(
    instruction_text: str,
) -> Callable[[Any], str]:
    """Wraps static instruction text in a callable to bypass ADK state interpolation."""

    def _provider(readonly_context: Any) -> str:
        del readonly_context
        return instruction_text

    return _provider


def load_secops_skills(
    skills_dir: pathlib.Path = DEFAULT_SKILLS_DIR,
    skill_names: Sequence[str] | None = None,
) -> list[models.Skill]:
    """Loads SecOps SKILL.md definitions from disk in deterministic order."""
    names_to_load = (
        tuple(skill_names) if skill_names is not None else CANONICAL_SKILL_NAMES
    )
    loaded_skills: list[models.Skill] = []
    for name in names_to_load:
        skill_path = skills_dir / name
        if not (skill_path / "SKILL.md").is_file():
            raise FileNotFoundError(
                f"Expected SecOps skill directory with SKILL.md at {skill_path}"
            )
        loaded_skills.append(load_skill_from_dir(skill_path))
    return loaded_skills


def build_secops_skill_toolset(
    skills_dir: pathlib.Path = DEFAULT_SKILLS_DIR,
    skill_names: Sequence[str] | None = None,
    additional_tools: Sequence[Any] | None = None,
) -> SkillToolset:
    """Builds an ADK SkillToolset for progressive SecOps runbook disclosure."""
    skills = load_secops_skills(skills_dir=skills_dir, skill_names=skill_names)
    return SkillToolset(
        skills=skills,
        additional_tools=list(additional_tools or []),
    )
