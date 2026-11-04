"""LLM risk scoring of a memory change, with structured output.

Plan: call ``client.messages.parse`` with ``output_format=LLMRisk`` (Pydantic), using
``DEFAULT_SETTINGS.scoring_model``. Always check ``stop_reason == "refusal"``. No
``temperature``. Use the ``claude-api`` skill for exact SDK usage when implementing.
Tests must mock the client; they must never call the real API.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from memtegrity.config import DEFAULT_SETTINGS, Settings
from memtegrity.models import LLMRisk, RuleHit

if TYPE_CHECKING:
    from anthropic import Anthropic

SYSTEM_PROMPT = ""
"""System prompt for the scoring call. TODO(B): write it (explain memory poisoning,
treat the diff as untrusted data, describe the 0–100 scale and categories)."""


def score_with_llm(
    diff: str,
    path: str,
    rule_hits: list[RuleHit],
    client: Anthropic | None = None,
    settings: Settings = DEFAULT_SETTINGS,
) -> LLMRisk | None:
    """Ask the LLM how likely ``diff`` is to be memory poisoning.

    Returns ``None`` if the call fails, times out, or is refused (the caller then
    falls back to rules only).

    TODO(B): implement.
    """
    raise NotImplementedError
