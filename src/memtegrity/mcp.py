"""What an MCP tool call is about to do to files, read from its arguments.

Agent-neutral: MCP is a cross-agent protocol, and file servers name their arguments in
many ways (``path``, ``file_path``, ``destination``, lists of edits). This turns one call
into a list of ``PlannedWrite``s so the guard can judge writes to protected files before
they happen, exactly like a built-in Write/Edit.

Deliberately conservative in both directions:

* a tool whose name has no write verb (``read_file``, ``search_files``) is not judged, so
  ordinary reads never cause prompts; the file watcher and post-tool check still catch a
  "read" tool that writes anyway;
* a write-ish tool whose effect can't be worked out from its arguments is reported as
  ``unknown``, and the guard asks the user instead of guessing it's safe.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from memtegrity import integrity

_WRITE_VERBS = frozenset(
    {
        *("write", "create", "edit", "update", "append", "put", "save", "move", "rename"),
        *("copy", "delete", "remove", "patch", "replace", "insert", "modify", "overwrite"),
        *("upload", "apply", "set"),
    }
)
_WORD_RX = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")
_TARGET_KEYS = (
    "path",
    "file_path",
    "filepath",
    "filename",
    "file",
    "target",
    "target_path",
    "destination",
    "dest",
    "new_path",
    "to",
    "output_path",
    "uri",
)
_SOURCE_KEYS = ("source", "src", "from", "old_path", "source_path")
_CONTENT_KEYS = ("content", "contents", "text", "data", "body", "file_text")
_LIST_KEYS = ("paths", "files")
_OLD_KEYS = ("oldText", "old_text", "old_string", "old", "search")
_NEW_KEYS = ("newText", "new_text", "new_string", "new", "replace")


@dataclass
class PlannedWrite:
    path: str
    kind: str
    """``write`` (full content known), ``edit`` (``after`` computed), ``delete``, or
    ``unknown`` (a write we can't predict)."""
    after: str | None = None
    """The file's full content after the call, when it can be worked out."""


def action(tool_name: str) -> str:
    """The tool part of ``mcp__<server>__<tool>``."""
    return tool_name.rsplit("__", 1)[-1]


def is_write_tool(tool_name: str) -> bool:
    """``write_file``, ``editFile``, ``move-file`` … yes; ``read_file``, ``get_settings`` no."""
    words = [w.lower() for w in _WORD_RX.findall(action(tool_name))]
    return any(w in _WRITE_VERBS or w.removesuffix("s") in _WRITE_VERBS for w in words)


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def _clean(p: str) -> str:
    return p.removeprefix("file://")


def _first(d: dict, keys: tuple[str, ...]) -> Any:
    for k in keys:
        if k in d:
            return d[k]
    return None


def planned_writes(
    tool_name: str, tool_input: dict, base: Path | None = None
) -> list[PlannedWrite]:
    """Every file this MCP call may write (see module docstring)."""
    if not isinstance(tool_input, dict) or not is_write_tool(tool_name):
        return []
    verb = action(tool_name).lower()
    targets = _strings(_first(tool_input, _TARGET_KEYS))
    for k in _LIST_KEYS:
        targets += _strings(tool_input.get(k))
    targets = [_clean(t) for t in targets if t]
    if not targets:
        return []

    def read(p: str) -> str | None:
        q = Path(p).expanduser()
        if not q.is_absolute() and base is not None:
            q = base / q
        return integrity.read_text(q) if q.is_file() else None

    if any(v in verb for v in ("delete", "remove")):
        return [PlannedWrite(t, "delete", "") for t in targets]

    if any(v in verb for v in ("move", "rename", "copy")):
        sources = _strings(_first(tool_input, _SOURCE_KEYS))
        content = read(_clean(sources[0])) if sources else None
        dest = _strings(_first(tool_input, ("destination", "dest", "to", "target", "new_path")))
        dests = [_clean(d) for d in dest] or targets[-1:]
        return [
            PlannedWrite(d, "write" if content is not None else "unknown", content) for d in dests
        ]

    content = _first(tool_input, _CONTENT_KEYS)
    edits = tool_input.get("edits")
    out = []
    for t in targets:
        current = read(t)
        if isinstance(edits, list):
            after = _apply_edits(current or "", edits)
            out.append(PlannedWrite(t, "edit" if after is not None else "unknown", after))
        elif isinstance(content, str):
            after = (current or "") + content if "append" in verb else content
            out.append(PlannedWrite(t, "write", after))
        else:
            old, new = _first(tool_input, _OLD_KEYS), _first(tool_input, _NEW_KEYS)
            after = _apply_edits(current or "", [{"old": old, "new": new}])
            out.append(PlannedWrite(t, "edit" if after is not None else "unknown", after))
    return out


def _apply_edits(current: str, edits: list) -> str | None:
    text = current
    for e in edits:
        if not isinstance(e, dict):
            return None
        old, new = _first(e, _OLD_KEYS), _first(e, _NEW_KEYS)
        if not isinstance(old, str) or not isinstance(new, str):
            return None
        try:
            text = integrity.apply_edit(text, old, new, bool(e.get("replace_all", False)))
        except integrity.EditSimulationError:
            return None
    return text
