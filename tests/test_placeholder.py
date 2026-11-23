"""Smoke tests: the package imports and the skeleton is wired up."""

import pytest

import memtegrity
from memtegrity.hooks import HANDLERS
from memtegrity.models import HookEvent


def test_version() -> None:
    assert memtegrity.__version__ == "0.1.0"


def test_every_hook_event_has_a_handler() -> None:
    assert set(HANDLERS) == set(HookEvent)


def test_remaining_stubs_are_not_implemented_yet() -> None:
    # The AI judge is the next block's work (docs/BLOCK4.md).
    from memtegrity import llm_risk

    with pytest.raises(NotImplementedError):
        llm_risk.score_with_llm("", "CLAUDE.md", [])
