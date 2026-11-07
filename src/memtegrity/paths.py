"""Decide which files count as Claude Code memory, and where Memtegrity keeps its state.

Security rule: **canonicalize before you authorize.** A check on the path string Claude
passed us is easy to dodge (``docs/../CLAUDE.md``, a symlink named ``notes.md``, or
``claude.md`` on macOS's case-insensitive disk), so every decision here is made on the
fully resolved, case-folded path, and hard links are caught by comparing inodes.
"""

from __future__ import annotations

import json
import os
import unicodedata
from pathlib import Path

from memtegrity.config import DEFAULT_SETTINGS, Settings


def resolve_path(path: str | os.PathLike[str], base: Path | None = None) -> Path:
    """Return the canonical absolute path: ``~`` expanded, relative paths joined to
    ``base`` (default: the current directory), symlinks and ``..`` resolved.

    Works for files that don't exist yet (their existing parent folders are resolved).
    """
    p = Path(os.path.expanduser(os.fspath(path)))
    if not p.is_absolute():
        p = (base or Path.cwd()) / p
    return Path(os.path.realpath(p))


def _key(p: Path) -> tuple[str, ...]:
    """Path parts normalized for comparison: Unicode NFC (macOS stores NFD) and case-folded
    (APFS is case-insensitive by default, so ``claude.md`` *is* ``CLAUDE.md``)."""
    return tuple(unicodedata.normalize("NFC", part).casefold() for part in p.parts)


def _starts_with(parts: tuple[str, ...], prefix: tuple[str, ...]) -> bool:
    return len(parts) > len(prefix) and parts[: len(prefix)] == prefix


def auto_memory_dirs(project_dir: Path | None, settings: Settings = DEFAULT_SETTINGS) -> list[Path]:
    """Custom auto-memory folders set with ``autoMemoryDirectory`` in Claude Code settings.

    Malformed or unreadable settings files are skipped (they can't make a non-memory file
    count as memory in a way that weakens protection; at worst we miss a custom folder).
    """
    found: list[Path] = []
    for rel in settings.settings_files:
        if not rel.startswith("~") and project_dir is None:
            continue  # project settings need a project
        settings_path = resolve_path(rel, project_dir)
        try:
            data = json.loads(settings_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        value = data.get("autoMemoryDirectory") if isinstance(data, dict) else None
        if isinstance(value, str) and value.strip():
            found.append(resolve_path(value, project_dir))
    return found


def _same_inode_as_pinned(real: Path, project_dir: Path | None, settings: Settings) -> bool:
    """True if ``real`` is a hard link to one of the well-known memory files."""
    try:
        st = real.stat()
    except OSError:
        return False
    if st.st_nlink < 2:  # only hard-linked files can alias another name
        return False
    for rel in settings.pinned_memory_files:
        if not rel.startswith("~") and project_dir is None:
            continue
        candidate = resolve_path(rel, project_dir)
        try:
            cst = candidate.stat()
        except OSError:
            continue
        if (cst.st_dev, cst.st_ino) == (st.st_dev, st.st_ino):
            return True
    return False


def is_memory_path(
    path: str | os.PathLike[str],
    project_dir: Path | None = None,
    settings: Settings = DEFAULT_SETTINGS,
) -> bool:
    """Return True if ``path`` is a file whose content loads into future Claude sessions.

    Counts as memory:

    * ``CLAUDE.md``, ``CLAUDE.local.md``, ``AGENTS.md`` anywhere (any letter case)
    * ``.md`` files under any ``.claude/{rules,agents,commands,skills}/``
    * every file in auto memory (``~/.claude/projects/<project>/memory/``) or a custom
      ``autoMemoryDirectory``
    * a hard link to any of the well-known memory files

    Known gap (TODO(A, Block 2)): a file pulled in by an ``@import`` inside memory also loads
    every session, so an attacker could poison ``docs/x.md`` and rely on an existing
    ``@docs/x.md``. Treat import targets of memory files as memory once ``list_memory_files``
    exists.

    ``project_dir`` is the session's project folder (the hook input's ``cwd``); relative
    paths are resolved against it.
    """
    real = resolve_path(path, project_dir)
    parts = _key(real)
    if not parts:
        return False

    if parts[-1] in settings.memory_filenames:
        return True

    if parts[-1].endswith(".md"):
        for i, part in enumerate(parts[:-2]):
            if part == ".claude" and parts[i + 1] in settings.instruction_dirs:
                return True

    auto_root = _key(resolve_path(settings.auto_memory_root))
    in_auto_root = _starts_with(parts, auto_root) and len(parts) > len(auto_root) + 2
    if in_auto_root and parts[len(auto_root) + 1] == "memory":
        return True

    for custom in auto_memory_dirs(project_dir, settings):
        if _starts_with(parts, _key(custom)):
            return True

    return _same_inode_as_pinned(real, project_dir, settings)


def list_memory_files(project_dir: Path, settings: Settings = DEFAULT_SETTINGS) -> list[Path]:
    """Return absolute paths of every existing memory file for this project.

    Used by SessionStart to hash the baseline and to build ``watchPaths`` for FileChanged.

    TODO(A, Block 2): implement.
    """
    raise NotImplementedError


def data_dir(settings: Settings = DEFAULT_SETTINGS) -> Path:
    """Return the persistent data directory (``$CLAUDE_PLUGIN_DATA``), creating it if needed.

    TODO(A, Block 2): implement, with a sensible fallback for running the CLI outside Claude Code.
    """
    raise NotImplementedError
