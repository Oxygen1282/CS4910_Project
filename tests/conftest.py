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


@pytest.fixture(autouse=True)
def _isolated_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Every test gets its own Memtegrity data folder (database, markers), so no test can
    read or write a developer's real one, and the session's project can't leak in."""
    data = tmp_path / "plugin-data"
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(data))
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    # Never the real API: the judge is off unless a test turns it on with a fake client,
    # and the plugin root (where a developer's .env with a real key lives) is empty.
    monkeypatch.setenv("MEMTEGRITY_JUDGE", "off")
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path / "plugin-root"))
    return data


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An empty fake home folder."""
    h = tmp_path / "home"
    h.mkdir()
    return set_home(monkeypatch, h)


@pytest.fixture
def project(tmp_path: Path, home: Path) -> Path:
    """A small project with a CLAUDE.md that imports docs/setup.md."""
    p = tmp_path / "proj"
    (p / "docs").mkdir(parents=True)
    (p / "CLAUDE.md").write_bytes(b"# Notes\n- Use pnpm.\n- Setup: see @docs/setup.md\n")
    (p / "docs" / "setup.md").write_bytes(b"Run pnpm install.\n")
    return p


def symlink_or_skip(link: Path, target: Path, *, target_is_directory: bool = False) -> None:
    """Create a symlink, or skip the test where the OS doesn't allow it (Windows without
    Developer Mode or admin rights). The behavior under test still runs on CI's Linux,
    macOS and Windows runners, which allow symlinks."""
    try:
        os.symlink(target, link, target_is_directory=target_is_directory)
    except OSError as exc:
        pytest.skip(f"symlinks not permitted here: {exc}")
