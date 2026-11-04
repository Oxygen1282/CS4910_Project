"""One handler per Claude Code hook event.

Each handler receives the hook's JSON input (parsed from stdin) and returns the JSON
object to print on stdout. ``cli.py`` does the stdin/stdout part.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from memtegrity.models import HookEvent

HookInput = dict[str, Any]
HookOutput = dict[str, Any]


def handle_session_start(payload: HookInput) -> HookOutput:
    """Compare every memory file with its last approved snapshot.

    Will warn about changes made between sessions (``hookSpecificOutput.additionalContext``
    for Claude, ``systemMessage`` for the user) and return ``hookSpecificOutput.watchPaths``
    (absolute paths) so FileChanged watches the memory files.

    TODO(A): implement.
    """
    raise NotImplementedError


def handle_pre_tool_use(payload: HookInput) -> HookOutput:
    """Score a Write/Edit to a memory file *before* it happens.

    Builds the proposed content (Write: ``content``; Edit: ``apply_edit`` with
    ``old_string``/``new_string``/``replace_all``), diffs it, scores it, and returns
    ``hookSpecificOutput.permissionDecision`` (allow/ask/deny) with a
    ``permissionDecisionReason``. Non-memory paths return an empty object.

    TODO(A): implement.
    """
    raise NotImplementedError


def handle_file_changed(payload: HookInput) -> HookOutput:
    """Handle a memory file changed outside Write/Edit (Bash, editors, other processes).

    Cannot block. Will snapshot, score, auto-restore if the verdict is deny, and notify
    via ``systemMessage``. Ignores Memtegrity's own restore writes.

    TODO(A): implement.
    """
    raise NotImplementedError


def handle_config_change(payload: HookInput) -> HookOutput:
    """Tamper protection: return ``{"decision": "block"}`` for settings changes that
    would disable or remove Memtegrity's hooks.

    TODO(A): implement.
    """
    raise NotImplementedError


HANDLERS: dict[HookEvent, Callable[[HookInput], HookOutput]] = {
    HookEvent.SESSION_START: handle_session_start,
    HookEvent.PRE_TOOL_USE: handle_pre_tool_use,
    HookEvent.FILE_CHANGED: handle_file_changed,
    HookEvent.CONFIG_CHANGE: handle_config_change,
}
"""Which handler runs for which ``memtegrity hook <event>``."""
