"""Hashing and diffing of memory-file content.

* Hashes are SHA-256 from Python's standard ``hashlib``: audited, constant, no homemade
  crypto. They are the fingerprints Block 2 stores and compares.
* ``added_lines`` isolates exactly what a change *adds*, because poison is usually one short
  line slipped into a long, legitimate file; scoring the whole file would dilute it.
* ``apply_edit`` predicts what an Edit tool call will produce *before* it runs, so the
  PreToolUse hook can judge the future file instead of reacting after the fact.
"""

from __future__ import annotations

import difflib
import hashlib
from pathlib import Path

_CHUNK = 1 << 16
_MAX_DIFF_LINES = 5_000
"""Above this, fall back to a set-based comparison (difflib is roughly quadratic)."""

AddedLine = tuple[int | None, str]
"""(1-based line number in the new content, or ``None`` if unknown; line text)."""


class EditSimulationError(ValueError):
    """The Edit can't be reproduced exactly (``old_string`` missing or not unique)."""


def hash_bytes(data: bytes) -> str:
    """Return the hex SHA-256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


def hash_text(text: str) -> str:
    """Return the hex SHA-256 of ``text`` encoded as UTF-8.

    ``surrogatepass`` keeps this from crashing on malformed input (a lone surrogate from
    JSON), since a crash in a security hook is itself a bypass.
    """
    return hash_bytes(text.encode("utf-8", "surrogatepass"))


def hash_file(path: Path) -> str:
    """Return the hex SHA-256 of the file at ``path``, read in chunks."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as fh:
        while chunk := fh.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def read_text(path: Path) -> str | None:
    """Return the file's text, or ``None`` if it doesn't exist (a new file).

    Undecodable bytes become U+FFFD instead of raising, so a binary or corrupted memory
    file can still be analyzed.
    """
    try:
        data = Path(path).read_bytes()
    except FileNotFoundError:
        return None
    return data.decode("utf-8", errors="replace")


def diff_text(before: str, after: str, path: str) -> str:
    """Return a unified diff from ``before`` to ``after``, labelled with ``path``."""
    lines = difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
    )
    return "".join(line if line.endswith("\n") else line + "\n" for line in lines)


def added_lines(before: str, after: str) -> list[AddedLine]:
    """Return every line in ``after`` that is new or changed relative to ``before``.

    A line that was *modified* (e.g. a hidden character slipped into an existing line)
    counts as added, because its new version is what the agent will read.
    """
    old = before.splitlines()
    new = after.splitlines()
    if len(old) + len(new) > _MAX_DIFF_LINES:
        existing = set(old)
        return [(i + 1, line) for i, line in enumerate(new) if line not in existing]

    matcher = difflib.SequenceMatcher(None, old, new, autojunk=False)
    out: list[AddedLine] = []
    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if tag in ("replace", "insert"):
            out.extend((j + 1, new[j]) for j in range(j1, j2))
    return out


def apply_edit(current: str, old_string: str, new_string: str, replace_all: bool = False) -> str:
    """Return the content an Edit tool call *would* produce, without touching the file.

    Mirrors Claude Code's Edit: replace the single occurrence of ``old_string``, or every
    occurrence when ``replace_all`` is true. An LF ``old_string`` also matches a CRLF file.

    Raises ``EditSimulationError`` if the result can't be predicted exactly. Callers must then
    score ``new_string`` on its own rather than allow the write: Claude Code may still apply
    an edit we failed to reproduce, and "we couldn't simulate it" must never mean "it's safe".
    """
    if old_string == "":
        raise EditSimulationError("empty old_string")
    count = current.count(old_string)
    if count == 0 and "\r\n" in current and "\n" in old_string and "\r" not in old_string:
        # Windows (CRLF) file, LF edit: Claude Code matches across line endings and keeps
        # the file's CRLF, so do the same.
        old_string = old_string.replace("\n", "\r\n")
        new_string = new_string.replace("\r\n", "\n").replace("\n", "\r\n")
        count = current.count(old_string)
    if count == 0:
        raise EditSimulationError("old_string not found")
    if count > 1 and not replace_all:
        raise EditSimulationError(f"old_string is not unique ({count} matches)")
    if replace_all:
        return current.replace(old_string, new_string)
    return current.replace(old_string, new_string, 1)
