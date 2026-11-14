"""Protected surfaces: the files an AI agent loads as instructions, memory or config.

Agent-neutral core. *Which* files matter is data, declared per agent platform in
``memtegrity.agents``; this module only defines the shapes and the path matcher. Adding an
agent means adding a profile there, not changing code here.

Patterns are matched against the *end* of a canonical path (so they apply in a project, in a
parent folder, or in the home directory alike), case-insensitively:

* ``*`` matches within one path segment (``*.md``)
* ``**`` matches any number of segments, including none
* a leading ``~/`` anchors the pattern to the home directory instead
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from memtegrity.enums import SurfaceKind

SHARED = "*"
"""Agent tag for cross-agent standards such as AGENTS.md."""


@dataclass(frozen=True)
class Surface:
    """One kind of protected file."""

    agent: str
    """Platform that loads it: ``claude-code``, ``cursor``, ``copilot``, ... or ``*``."""
    kind: SurfaceKind
    """instructions / memory / config: decides how changes are judged."""
    name: str
    """Human label used in messages and reports."""
    pattern: str
    """Path pattern (see module docstring)."""


@dataclass(frozen=True)
class Root:
    """A protected folder whose location is only known at runtime (e.g. a configured
    custom memory directory)."""

    directory: Path
    surface: Surface
    tail: str = "**"
    """Pattern for paths below ``directory``."""


@dataclass(frozen=True)
class AgentProfile:
    """Everything Memtegrity knows about one agent platform's files."""

    agent: str
    surfaces: tuple[Surface, ...]
    roots: Callable[[Path | None], list[Root]] | None = None
    """Runtime-discovered folders (settings, env vars). Must be cheap and never raise."""
    pinned: tuple[str, ...] = field(default=())
    """Well-known files compared by inode, so a hard link to one is still recognized."""
    session_paths: Callable[[Path], list[Path]] | None = None
    """Files/folders *outside* the project tree whose protected files load into sessions
    for this project (parent-folder instructions, user-level files, per-project memory).
    Used by SessionStart discovery. Must be cheap and never raise."""
    imported: Callable[[Path | None, Path], Surface | None] | None = None
    """Is this (canonical) path pulled into sessions by an import in one of the agent's
    instruction files? Runs on every Write/Edit for unprotected files: must be cheap."""
    import_closure: Callable[[list[Path]], dict[Path, Surface]] | None = None
    """Every existing file the given protected files import, directly or transitively, with
    the surface to treat it as."""


@lru_cache(maxsize=256)
def _split(pattern: str) -> tuple[str, ...]:
    return tuple(part.casefold() for part in pattern.strip("/").split("/") if part)


_SEP = "\x00"
"""Joins path parts for regex matching; can't occur in a file name on any OS."""


def _segment_rx(seg: str) -> str:
    """One glob segment as a regex that stays within a single path part."""
    return "".join("[^\x00]*" if c == "*" else "[^\x00]" if c == "?" else re.escape(c) for c in seg)


@lru_cache(maxsize=256)
def _compile(pat: tuple[str, ...]) -> re.Pattern[str]:
    """Pattern segments (``**`` = any run of parts, including none) → one regex over the
    parts joined by ``_SEP``. One regex match per pattern instead of a recursive glob,
    which matters when discovery checks hundreds of files."""
    out, first, pending_any = "", True, False
    for seg in pat:
        if seg == "**":
            pending_any = True
            continue
        if not first:
            out += _SEP
        if pending_any:
            out += "(?:[^\x00]*\x00)*"
            pending_any = False
        out += _segment_rx(seg)
        first = False
    if pending_any:
        out += "(?:[^\x00]*(?:\x00[^\x00]*)*)?" if first else "(?:\x00[^\x00]*)*"
    return re.compile(out, re.DOTALL)


def _match(pat: tuple[str, ...], parts: tuple[str, ...]) -> bool:
    """Full match of pattern segments against path segments (``**`` = any run)."""
    if not parts:
        return all(seg == "**" for seg in pat)
    return _compile(pat).fullmatch(_SEP.join(parts)) is not None


def matches(pattern: str, parts: tuple[str, ...], home_parts: tuple[str, ...]) -> bool:
    """True if canonical, case-folded ``parts`` match ``pattern``."""
    if pattern.startswith("~/"):
        n = len(home_parts)
        return parts[:n] == home_parts and _match(_split(pattern[2:]), parts[n:])
    return _match(("**", *_split(pattern)), parts)


def under(directory_parts: tuple[str, ...], tail: str, parts: tuple[str, ...]) -> bool:
    """True if ``parts`` is inside ``directory_parts`` and the rest matches ``tail``."""
    n = len(directory_parts)
    return parts[:n] == directory_parts and len(parts) > n and _match(_split(tail), parts[n:])


def home_parts() -> tuple[str, ...]:
    """The home folder's normalized parts. Cached per value of ``~`` (tests change it)."""
    return _home_parts(os.path.expanduser("~"))


@lru_cache(maxsize=8)
def _home_parts(home: str) -> tuple[str, ...]:
    from memtegrity.paths import key, resolve_path  # local: avoid import cycle

    return key(resolve_path(home))
