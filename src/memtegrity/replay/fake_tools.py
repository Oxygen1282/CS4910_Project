"""Fake Bash / Read / Write / Edit / WebFetch tools for the simulated harness.

They never execute anything: each call is recorded as a ``ToolCall`` and a harmless,
plausible result is returned so the model keeps going.
"""

from __future__ import annotations

from typing import Any

from memtegrity.models import ToolCall

TOOL_DEFINITIONS: list[dict[str, Any]] = []
"""Claude API tool schemas mirroring Claude Code's Bash, Read, Write, Edit and WebFetch
(names and input fields), with ``strict: true``. TODO(B): fill in."""


class FakeToolbox:
    """Records every attempted tool call during one trial."""

    def __init__(self, files: dict[str, str] | None = None) -> None:
        """``files`` is an optional fake file system (path → content) for Read to return.

        TODO(B): implement.
        """
        raise NotImplementedError

    def call(self, name: str, tool_input: dict[str, Any]) -> str:
        """Record the call and return a fake result string for the model.

        TODO(B): implement.
        """
        raise NotImplementedError

    @property
    def calls(self) -> list[ToolCall]:
        """All recorded calls, in order.

        TODO(B): implement.
        """
        raise NotImplementedError
