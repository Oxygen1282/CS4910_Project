"""Canonical paths, and "is this a protected file?" (and which kind).

Security rule: **canonicalize before you authorize.** A check on the path string the agent
passed us is easy to dodge (``docs/../CLAUDE.md``, a symlink named ``notes.md``, or
``claude.md`` on macOS's case-insensitive disk), so every decision here is made on the
fully resolved, case-folded path, and hard links are caught by comparing inodes. On
Windows, Win32 name aliases (``CLAUDE.md.``, ``CLAUDE.md::$DATA``) are removed first.

Which files are protected is declared per agent in ``memtegrity.agents``.
"""

from __future__ import annotations

import ntpath
import os
import re
import unicodedata
from pathlib import Path

from memtegrity.surfaces import Surface, home_parts, matches, under

_WIN_STREAM_RX = re.compile(r"::\$data$|:(?:\$i30)?:\$index_allocation$", re.IGNORECASE)
_WIN_SEP_RX = re.compile(r"([\\/]+)")


def win32_alias_free(path: str) -> str:
    """Undo Windows name aliasing that ``realpath`` can't see for files that don't exist yet.

    Win32 opens all of these as the same file, so ``CLAUDE.md`` could be written under
    another name:

    * trailing dots and spaces are dropped (``CLAUDE.md.``, ``CLAUDE.md ``)
    * ``::$DATA`` names a file's main data stream (``CLAUDE.md::$DATA``)
    * ``::$INDEX_ALLOCATION`` names a directory (``.claude::$INDEX_ALLOCATION``)

    Pure string function (uses Windows path rules on any OS, so it is testable anywhere).
    """
    drive, rest = ntpath.splitdrive(path)
    out = []
    for part in _WIN_SEP_RX.split(rest):
        if part and part[0] not in "\\/":
            previous = None
            while part != previous:  # suffixes can be stacked: "CLAUDE.md. ::$DATA ."
                previous = part
                part = _WIN_STREAM_RX.sub("", part)
                stripped = part.rstrip(". ")
                if stripped.strip("."):  # leave ".", ".." and other all-dot names alone
                    part = stripped
        out.append(part)
    return drive + "".join(out)


def resolve_path(path: str | os.PathLike[str], base: Path | None = None) -> Path:
    """Return the canonical absolute path: ``~`` expanded, relative paths joined to
    ``base`` (default: the current directory), symlinks and ``..`` resolved, and on
    Windows, name aliases removed (see ``win32_alias_free``).

    Works for files that don't exist yet (their existing parent folders are resolved).
    """
    raw = os.fspath(path)
    if os.name == "nt":
        raw = win32_alias_free(raw)
    p = Path(os.path.expanduser(raw))
    if not p.is_absolute():
        p = (base or Path.cwd()) / p
    return Path(os.path.realpath(p))


def key(p: Path) -> tuple[str, ...]:
    """Path parts normalized for comparison: Unicode NFC (macOS stores NFD) and case-folded
    (APFS is case-insensitive by default, so ``claude.md`` *is* ``CLAUDE.md``)."""
    return tuple(unicodedata.normalize("NFC", part).casefold() for part in p.parts)


def _same_inode_as_pinned(real: Path, project_dir: Path | None) -> Surface | None:
    """If ``real`` is a hard link to a well-known protected file, return that file's surface."""
    try:
        st = real.stat()
    except OSError:
        return None
    if st.st_nlink < 2:  # only hard-linked files can alias another name
        return None
    from memtegrity.agents import PROFILES

    for profile in PROFILES:
        for rel in profile.pinned:
            if not rel.startswith("~") and project_dir is None:
                continue
            candidate = resolve_path(rel, project_dir)
            try:
                cst = candidate.stat()
            except OSError:
                continue
            if (cst.st_dev, cst.st_ino) == (st.st_dev, st.st_ino):
                return classify(candidate, project_dir, _follow_links=False)
    return None


def classify(
    path: str | os.PathLike[str],
    project_dir: Path | None = None,
    *,
    _follow_links: bool = True,
) -> Surface | None:
    """Return the protected ``Surface`` this path is, or ``None`` if it isn't protected.

    ``project_dir`` is the session's project folder (the hook input's ``cwd``); relative
    paths are resolved against it.

    Known gap (TODO(A, Block 2)): a file pulled in by an ``@import`` inside an instruction
    file also loads every session, so an attacker could poison ``docs/x.md`` and rely on an
    existing ``@docs/x.md``. Treat import targets as protected once ``list_memory_files``
    exists.
    """
    from memtegrity.agents import PROFILES

    real = resolve_path(path, project_dir)
    parts = key(real)
    if not parts:
        return None
    home = home_parts()

    for profile in PROFILES:
        for surface in profile.surfaces:
            if matches(surface.pattern, parts, home):
                return surface
    for profile in PROFILES:
        for root in profile.roots(project_dir) if profile.roots else ():
            if under(key(resolve_path(root.directory)), root.tail, parts):
                return root.surface

    return _same_inode_as_pinned(real, project_dir) if _follow_links else None


def is_memory_path(path: str | os.PathLike[str], project_dir: Path | None = None) -> bool:
    """True if ``path`` is any protected file (instructions, memory or config)."""
    return classify(path, project_dir) is not None


def list_memory_files(project_dir: Path) -> list[Path]:
    """Return absolute paths of every existing protected file for this project.

    Used by SessionStart to hash the baseline and to build ``watchPaths`` for FileChanged.

    TODO(A, Block 2): implement.
    """
    raise NotImplementedError


def data_dir() -> Path:
    """Return the persistent data directory (``$CLAUDE_PLUGIN_DATA``), creating it if needed.

    TODO(A, Block 2): implement, with a sensible fallback for running the CLI outside Claude Code.
    """
    raise NotImplementedError
