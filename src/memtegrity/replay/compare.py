"""Turn recorded tool calls into behaviors and compare clean vs. suspicious trials."""

from __future__ import annotations

from memtegrity.config import DEFAULT_SETTINGS, Settings
from memtegrity.models import BehaviorDiff, Trial


def extract_behaviors(trial: Trial) -> list[str]:
    """Normalize a trial's tool calls into behavior labels, e.g. ``"webfetch:<domain>"``,
    ``"bash:curl"``, ``"read:~/.ssh"``. Refusal is its own label.

    TODO(B): implement.
    """
    raise NotImplementedError


def compare(
    clean: list[Trial], suspicious: list[Trial], settings: Settings = DEFAULT_SETTINGS
) -> list[BehaviorDiff]:
    """Count each behavior per condition and flag it if it appears in at least
    ``flag_min_suspicious`` suspicious trials and at most ``flag_max_clean`` clean trials.

    TODO(B): implement.
    """
    raise NotImplementedError
