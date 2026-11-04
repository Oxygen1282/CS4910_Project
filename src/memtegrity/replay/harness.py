"""Simulated Claude Code harness: Claude API + memory loaded like Claude Code + fake tools.

Uses ``DEFAULT_SETTINGS.replay_model``. Runs ``trials_per_condition`` trials per condition,
since sampling parameters can't be fixed. Tests must mock the client.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from memtegrity.config import DEFAULT_SETTINGS, Settings
from memtegrity.models import ReplayResult, Trial, TrialCondition

if TYPE_CHECKING:
    from anthropic import Anthropic


def build_system_prompt(memory: dict[str, str], settings: Settings = DEFAULT_SETTINGS) -> str:
    """Build a system prompt that loads ``memory`` (path → content) the way Claude Code does,
    including the 200-line / 25 KB cap on ``MEMORY.md``.

    TODO(B): implement.
    """
    raise NotImplementedError


def run_trial(
    memory: dict[str, str],
    prompt: str,
    condition: TrialCondition,
    client: Anthropic,
    settings: Settings = DEFAULT_SETTINGS,
) -> Trial:
    """Run one agent loop (up to ``replay_max_turns``) with fake tools and record it.

    Must check ``stop_reason == "refusal"`` and set ``Trial.refused``.

    TODO(B): implement.
    """
    raise NotImplementedError


def generate_test_prompts(diff: str, client: Anthropic, n: int = 3) -> list[str]:
    """Ask the LLM for ordinary user prompts that would trigger the behavior in ``diff``
    (e.g. a deploy request for a deploy-related instruction).

    TODO(B): implement, and measure against the hand-written prompts in ``datasets/``.
    """
    raise NotImplementedError


def run_replay(
    clean_memory: dict[str, str],
    suspicious_memory: dict[str, str],
    prompts: list[str],
    client: Anthropic,
    settings: Settings = DEFAULT_SETTINGS,
) -> ReplayResult:
    """Run clean and suspicious trials for every prompt and compare them.

    Planned to run in the background via an async hook with ``asyncRewake``.

    TODO(B): implement.
    """
    raise NotImplementedError
