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

"""Loader for bundled SecOps operational skills using ADK SkillToolset.

Implements the Agent Skills progressive disclosure pattern:
  - **Level 1 (Catalog)**: Only ``name`` and ``description`` from YAML
    frontmatter are injected into the initial prompt context.
  - **Level 2 (Instructions)**: Full ``SKILL.md`` body is loaded on demand
    when the agent invokes ``load_skill``.
  - **Level 3 (Resources)**: Additional references or templates are loaded via
    ``load_skill_resource`` when needed.

Also provides ``make_static_instruction_provider`` to wrap system instructions
in an ``InstructionProvider`` callable so ADK's ``{var}`` state template
interpolation does not raise ``KeyError`` on YARA-L 2.0 braces (for example,
``events: { $e.metadata.event_type = "USER_LOGIN" }``).
"""

from __future__ import annotations

import pathlib
from collections.abc import Callable, Sequence
from typing import Any

from google.adk.skills import load_skill_from_dir, models
from google.adk.tools.skill_toolset import SkillToolset

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_SKILLS_DIR = pathlib.Path(__file__).resolve().parent / "skills"

CANONICAL_SKILL_NAMES: tuple[str, ...] = (
    "triage-alerts",
    "suspicious-login-triage",
    "malware-triage",
    "gti-collection-threat-hunt",
    "detection-rule-validation-tuning",
    "ioc-containment",
)


# ---------------------------------------------------------------------------
# Instruction & SkillToolset Builders
# ---------------------------------------------------------------------------
def make_static_instruction_provider(
    instruction_text: str,
) -> Callable[[Any], str]:
    """Wrap static instruction text in a callable to bypass ADK state interpolation.

    ADK's default string instruction processor attempts ``{key}`` state
    variable substitution, which collides with curly braces inside YARA-L 2.0
    (``YL2``) detection rules and JSON examples. Returning the instruction from
    a callable bypasses template substitution completely.

    Args:
        instruction_text: The system instruction string to return verbatim.

    Returns:
        A callable accepting an ADK ``ReadonlyContext`` and returning
        ``instruction_text``.
    """

    def _provider(readonly_context: Any) -> str:
        """Return the static instruction string without state interpolation.

        Args:
            readonly_context: The ADK invocation readonly context (unused).

        Returns:
            The static system instruction text.
        """
        del readonly_context
        return instruction_text

    return _provider


def load_secops_skills(
    skills_dir: pathlib.Path = DEFAULT_SKILLS_DIR,
    skill_names: Sequence[str] | None = None,
) -> list[models.Skill]:
    """Load SecOps ``SKILL.md`` definitions from disk in deterministic order.

    Args:
        skills_dir: Base directory containing individual skill subdirectories.
            Defaults to ``app/skills/``.
        skill_names: Optional sequence of skill folder names to load. When
            ``None``, loads all 6 ``CANONICAL_SKILL_NAMES``.

    Returns:
        A list of parsed ``google.adk.skills.models.Skill`` objects.

    Raises:
        FileNotFoundError: If any requested skill directory or its ``SKILL.md``
            file does not exist on disk.
    """
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
    """Build an ADK ``SkillToolset`` for progressive SecOps runbook disclosure.

    Args:
        skills_dir: Base directory containing individual skill subdirectories.
        skill_names: Optional subset of skill names to expose to a specialist
            persona. When ``None``, exposes all 6 canonical SecOps skills.
        additional_tools: Optional extra ADK tools or ``McpToolset`` instances
            that can be dynamically activated by ``adk_additional_tools``.

    Returns:
        A configured ``SkillToolset`` registering ``list_skills``,
        ``load_skill``, and ``load_skill_resource``.

    Raises:
        FileNotFoundError: If any requested skill directory is missing.
    """
    skills = load_secops_skills(skills_dir=skills_dir, skill_names=skill_names)
    return SkillToolset(
        skills=skills,
        additional_tools=list(additional_tools or []),
    )
