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
    # Replay (Block 5) and the HTML report (Block 6) are the next blocks' work
    # (docs/BLOCK4.md). Replace this when they land.
    from memtegrity.replay import harness

    with pytest.raises(NotImplementedError):
        harness.build_system_prompt({})
