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

import fnmatch
import os
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


@lru_cache(maxsize=256)
def _split(pattern: str) -> tuple[str, ...]:
    return tuple(part.casefold() for part in pattern.strip("/").split("/") if part)


def _match(pat: tuple[str, ...], parts: tuple[str, ...]) -> bool:
    """Full match of pattern segments against path segments (``**`` = any run)."""
    if not pat:
        return not parts
    head, rest = pat[0], pat[1:]
    if head == "**":
        return any(_match(rest, parts[i:]) for i in range(len(parts) + 1))
    return bool(parts) and fnmatch.fnmatchcase(parts[0], head) and _match(rest, parts[1:])


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
    from memtegrity.paths import key, resolve_path  # local: avoid import cycle

    return key(resolve_path(os.path.expanduser("~")))
