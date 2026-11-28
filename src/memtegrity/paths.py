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
import time
import unicodedata
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from functools import lru_cache
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


def _lexical(path: str | os.PathLike[str], base: Path | None = None) -> Path:
    """The absolute path *as named*, without following symlinks. A ``CLAUDE.md`` that is a
    symlink to ``docs/team.md`` is still ``CLAUDE.md`` to the agent that loads it, so both
    names are checked (only ever adding protection: the resolved path is checked too)."""
    raw = os.fspath(path)
    if os.name == "nt":
        raw = win32_alias_free(raw)
    p = Path(os.path.expanduser(raw))
    if not p.is_absolute():
        p = (base or Path.cwd()) / p
    return Path(os.path.normpath(p))


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

    A file pulled in by an ``@import`` inside an instruction file loads every session too,
    so it is protected as an instruction file (each agent profile's ``imported`` check).
    """
    from memtegrity.agents import PROFILES

    real = resolve_path(path, project_dir)
    parts = key(real)
    if not parts:
        return None
    surface = _match(parts, project_dir) or _match(key(_lexical(path, project_dir)), project_dir)
    if surface is not None:
        return surface
    for profile in PROFILES:
        if profile.imported is not None:
            surface = profile.imported(project_dir, real)
            if surface is not None:
                return surface
    return _same_inode_as_pinned(real, project_dir) if _follow_links else None


RootKeys = list[tuple[tuple[str, ...], str, Surface]]


def _root_keys(project_dir: Path | None) -> RootKeys:
    """Runtime folders (``AgentProfile.roots``), resolved once. They come from settings
    files, so batch callers compute this once instead of re-reading settings per file."""
    from memtegrity.agents import PROFILES

    return [
        (key(resolve_path(root.directory)), root.tail, root.surface)
        for profile in PROFILES
        for root in (profile.roots(project_dir) if profile.roots else ())
    ]


def _match(
    parts: tuple[str, ...], project_dir: Path | None, root_keys: RootKeys | None = None
) -> Surface | None:
    """Registry lookup (file patterns, then runtime folders) for normalized path parts."""
    from memtegrity.agents import PROFILES

    home = home_parts()
    for profile in PROFILES:
        for surface in profile.surfaces:
            if matches(surface.pattern, parts, home):
                return surface
    for directory, tail, surface in root_keys if root_keys is not None else _root_keys(project_dir):
        if under(directory, tail, parts):
            return surface
    return None


def is_memory_path(path: str | os.PathLike[str], project_dir: Path | None = None) -> bool:
    """True if ``path`` is any protected file (instructions, memory or config)."""
    return classify(path, project_dir) is not None


# --------------------------------------------------------------------------- discovery

SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        "dist",
        "build",
        ".tox",
        ".mypy_cache",
        ".trash",  # deleted items (e.g. ~/.claude/skills/.trash): never loaded
    }
)
"""Vendored / generated / deleted-item folders that are never walked."""

MAX_FILE_BYTES = 1_000_000
"""Protected files larger than this are listed but not snapshotted or analyzed."""


def iter_candidates(targets: Iterable[Path], exclude: Iterable[str] = ()) -> Iterator[Path]:
    """Files under ``targets`` (files are yielded as-is), skipping ``SKIP_DIRS`` and anything
    whose path contains one of ``exclude`` (compared with ``/`` separators on every OS)."""
    excluded = tuple(e.replace("\\", "/") for e in exclude)
    for target in targets:
        if target.is_file():
            yield target
            continue
        for dirpath, dirnames, filenames in os.walk(target):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                path = Path(dirpath) / name
                if not excluded or not any(part in path.as_posix() for part in excluded):
                    yield path


@lru_cache(maxsize=1)
def _anchors() -> frozenset[str]:
    """First literal segment of every registered pattern (``claude.md``, ``.claude``,
    ``.cursor``, ...). A file whose path contains none of them can't match any pattern, so
    discovery skips the full match for it."""
    from memtegrity.agents import PROFILES

    out = set()
    for profile in PROFILES:
        for surface in profile.surfaces:
            first = surface.pattern.removeprefix("~/").strip("/").split("/")[0].casefold()
            if any(c in first for c in "*?["):
                return frozenset()  # a wildcard first segment: no cheap filter possible
            out.add(first)
    return frozenset(out)


def could_be_protected(path: Path) -> bool:
    """Cheap pre-check (no disk access): False only if no registered pattern can match.
    ``@import`` targets and runtime folders are not covered; callers add those separately."""
    anchors = _anchors()
    return not anchors or not anchors.isdisjoint(key(path))


@dataclass
class Discovery:
    """Result of ``discover``: protected files that exist, and whether the search finished."""

    files: dict[Path, Surface] = field(default_factory=dict)
    complete: bool = True
    """False if the file or time budget ran out (a huge folder): the list is partial."""


def discover(
    project_dir: Path, *, max_files: int = 50_000, deadline: float | None = None
) -> Discovery:
    """Find every existing protected file that loads into sessions in ``project_dir``:

    * the project tree (every agent's files; ``SKIP_DIRS`` skipped),
    * per-agent places outside it (``AgentProfile.session_paths``: parent-folder
      CLAUDE.md files, ``~/.claude`` instructions and settings, this project's auto memory),
    * files those instruction files ``@import`` (``AgentProfile.import_closure``).

    ``max_files`` caps files *looked at* in the project tree and ``deadline`` (a
    ``time.monotonic()`` value) caps time, so a session started in a huge folder (or ``~``)
    can't stall. If either runs out, ``complete`` is False.
    """
    from memtegrity.agents import PROFILES

    project = resolve_path(project_dir)
    found = Discovery()
    anchors = _anchors()
    root_keys = _root_keys(project)

    def add(path: Path, surface: Surface | None = None) -> None:
        """Record ``path`` if it is protected. Discovery only needs the registry lookup
        (patterns and runtime folders), not ``classify``'s per-file @import search: import
        targets arrive with their own ``surface`` from ``import_closure``."""
        real = resolve_path(path)
        if real in found.files or not real.is_file():
            return
        # Match the real file, or the name it was found under: a CLAUDE.md that is a
        # symlink to docs/team.md loads every session, so its target is protected too.
        surface = (
            _match(key(real), project, root_keys)
            or _match(key(_lexical(path)), project, root_keys)
            or surface
        )
        if surface is not None:
            found.files[real] = surface

    def walk(folder: Path, budgeted: bool) -> None:
        for seen, path in enumerate(iter_candidates([folder]), 1):
            if budgeted and (
                seen > max_files or (deadline is not None and time.monotonic() > deadline)
            ):
                found.complete = False
                return
            parts = key(path)
            # Cheap checks on the unresolved path first; resolve (a syscall) only matches.
            if (
                anchors
                and anchors.isdisjoint(parts)
                and not any(parts[: len(d)] == d for d, _, _ in root_keys)
            ):
                continue
            if _match(parts, project, root_keys) is not None:
                add(path)

    walk(project, budgeted=True)

    for profile in PROFILES:
        for extra in profile.session_paths(project) if profile.session_paths else ():
            if extra.is_dir():
                walk(extra, budgeted=False)
            elif extra.is_file():
                add(extra)

    for profile in PROFILES:
        if profile.import_closure is not None:
            for target, surface in profile.import_closure(list(found.files)).items():
                add(target, surface)
    return found


def list_memory_files(project_dir: Path) -> list[Path]:
    """Return absolute paths of every existing protected file for this project (see
    ``discover``). Used by SessionStart for the baseline and for ``watchPaths``."""
    return sorted(discover(project_dir).files)


DATA_DIR_ENV = "MEMTEGRITY_DATA_DIR"
"""Explicit data folder for the CLI (the skills pass the plugin's own folder this way)."""


def data_dir() -> Path:
    """Return the persistent data directory, creating it if needed. In order:

    1. ``$MEMTEGRITY_DATA_DIR``: set explicitly (``--data-dir``; the skills set it);
    2. ``$CLAUDE_PLUGIN_DATA``: set by Claude Code for the plugin's hooks;
    3. the plugin's folder under ``~/.claude/plugins/data/`` if one has a database, so the
       ``memtegrity`` command in a terminal sees the same history as the plugin (the most
       recently used one if there are several: an install and a ``--plugin-dir`` test);
    4. ``~/.cache/memtegrity``, the same folder ``hooks/hooks.json`` falls back to.
    """
    from memtegrity.config import DEFAULT_SETTINGS

    env = os.environ.get(DATA_DIR_ENV) or os.environ.get(DEFAULT_SETTINGS.data_dir_env)
    d = Path(os.path.expanduser(env)) if env else _plugin_data_dir() or _fallback_data_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d


def _fallback_data_dir() -> Path:
    return Path.home() / ".cache" / "memtegrity"


def _plugin_data_dir() -> Path | None:
    from memtegrity.config import DEFAULT_SETTINGS

    cfg = os.environ.get("CLAUDE_CONFIG_DIR")
    base = (Path(os.path.expanduser(cfg)) if cfg else Path.home() / ".claude") / "plugins" / "data"
    try:
        dbs = [
            d / DEFAULT_SETTINGS.db_filename
            for d in base.iterdir()
            if d.name.casefold().startswith("memtegrity")
        ]
    except OSError:
        return None
    dbs = [db for db in dbs if db.is_file()]
    if not dbs:
        return None
    return max(dbs, key=lambda db: db.stat().st_mtime).parent
