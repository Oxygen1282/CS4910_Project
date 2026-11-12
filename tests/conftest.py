"""Shared test helpers that keep the suite working on macOS, Linux and Windows."""

from __future__ import annotations

import os
from pathlib import Path

import pytest


def set_home(monkeypatch: pytest.MonkeyPatch, home: Path) -> Path:
    """Point the home directory at ``home`` on every OS.

    POSIX reads ``HOME``; Windows Python reads ``USERPROFILE`` (then ``HOMEDRIVE`` +
    ``HOMEPATH``), so setting only ``HOME`` would leave the real home in place there.
    ``CLAUDE_CONFIG_DIR`` is cleared so a developer's own setting can't leak into tests.
    """
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("HOMEDRIVE", raising=False)
    monkeypatch.delenv("HOMEPATH", raising=False)
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    return home


def symlink_or_skip(link: Path, target: Path, *, target_is_directory: bool = False) -> None:
    """Create a symlink, or skip the test where the OS doesn't allow it (Windows without
    Developer Mode or admin rights). The behavior under test still runs on CI's Linux,
    macOS and Windows runners, which allow symlinks."""
    try:
        os.symlink(target, link, target_is_directory=target_is_directory)
    except OSError as exc:
        pytest.skip(f"symlinks not permitted here: {exc}")
