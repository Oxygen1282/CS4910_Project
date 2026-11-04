"""Decide which files count as Claude Code memory, and where Memtegrity keeps its state."""

from __future__ import annotations

from pathlib import Path

from memtegrity.config import DEFAULT_SETTINGS, Settings


def is_memory_path(path: Path, project_dir: Path, settings: Settings = DEFAULT_SETTINGS) -> bool:
    """Return True if ``path`` is a memory file Memtegrity protects.

    Will resolve ``~`` and symlinks, then match against ``settings.project_memory_globs``
    (relative to ``project_dir``) and ``settings.user_memory_globs``, plus a custom
    ``autoMemoryDirectory`` if one is configured.

    TODO(A): implement.
    """
    raise NotImplementedError


def list_memory_files(project_dir: Path, settings: Settings = DEFAULT_SETTINGS) -> list[Path]:
    """Return absolute paths of every existing memory file for this project.

    Used by SessionStart to hash the baseline and to build ``watchPaths`` for FileChanged.

    TODO(A): implement.
    """
    raise NotImplementedError


def data_dir(settings: Settings = DEFAULT_SETTINGS) -> Path:
    """Return the persistent data directory (``$CLAUDE_PLUGIN_DATA``), creating it if needed.

    TODO(A): implement, with a sensible fallback for running the CLI outside Claude Code.
    """
    raise NotImplementedError
