"""Hashing and diffing of memory-file content (hashlib + difflib)."""

from __future__ import annotations

from pathlib import Path


def hash_text(text: str) -> str:
    """Return the hex SHA-256 of ``text`` encoded as UTF-8.

    TODO(A): implement.
    """
    raise NotImplementedError


def hash_file(path: Path) -> str:
    """Return the hex SHA-256 of the file at ``path``.

    TODO(A): implement.
    """
    raise NotImplementedError


def diff_text(before: str, after: str, path: str) -> str:
    """Return a unified diff from ``before`` to ``after``, labelled with ``path``.

    TODO(A): implement.
    """
    raise NotImplementedError


def apply_edit(current: str, old_string: str, new_string: str, replace_all: bool = False) -> str:
    """Return the content an Edit tool call *would* produce, without touching the file.

    Mirrors Claude Code's Edit semantics: replace one occurrence of ``old_string``
    (or all of them when ``replace_all`` is true). Used by PreToolUse to score the
    proposed content before the write happens.

    TODO(A): implement, including the "old_string not found / not unique" cases.
    """
    raise NotImplementedError
