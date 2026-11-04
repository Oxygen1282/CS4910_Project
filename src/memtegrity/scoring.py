"""Combine rule hits and the LLM score into one ``Assessment`` and ``Verdict``."""

from __future__ import annotations

from memtegrity.config import DEFAULT_SETTINGS, Settings
from memtegrity.models import Assessment, LLMRisk, RuleHit, Verdict


def verdict_for(score: int, settings: Settings = DEFAULT_SETTINGS) -> Verdict:
    """Map a 0–100 score to allow / ask / deny using the thresholds in ``settings``.

    TODO(A/B): implement.
    """
    raise NotImplementedError


def combine(
    rule_hits: list[RuleHit],
    llm: LLMRisk | None,
    settings: Settings = DEFAULT_SETTINGS,
) -> Assessment:
    """Merge rule hits and the LLM result into a final ``Assessment``.

    Design question for Thursday: how to weight rules versus the LLM, and whether a
    single high-severity rule hit should force ``deny`` on its own.

    TODO(A/B): implement.
    """
    raise NotImplementedError
