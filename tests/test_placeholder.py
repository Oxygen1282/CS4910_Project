"""Smoke tests: the package imports and the skeleton is wired up."""

import pytest

import memtegrity
from memtegrity import integrity
from memtegrity.hooks import HANDLERS
from memtegrity.models import HookEvent


def test_version() -> None:
    assert memtegrity.__version__ == "0.1.0"


def test_every_hook_event_has_a_handler() -> None:
    assert set(HANDLERS) == set(HookEvent)


def test_stubs_are_not_implemented_yet() -> None:
    # Replace this with real tests as each TODO is implemented.
    with pytest.raises(NotImplementedError):
        integrity.hash_text("hello")
