"""Small marker files in the data folder that let hooks coordinate without the database.

Hooks are separate processes that each start in about 0.1 s. Loading the database layer
(SQLModel) costs about a second, so the frequent hooks first check these tiny files and
open the database only when there is something to do. Agent-neutral; standard library
only.

* ``awaiting-approval/<sha>``: content the user is being asked about in a permission
  prompt (PreToolUse ``ask``). If that exact content is then written, the user approved it.
* ``own-writes/<sha>``: content Memtegrity itself just wrote (a restore). The file-watch
  event this write causes is ignored, so a restore can't trigger itself again.
* ``in-flight/<session>__<tool call>``: an agent tool call (Bash, MCP) is running. A file
  change seen while it runs was made by the agent, so the post-tool check handles it.
* ``alerts/<session>.jsonl``: warnings for the agent that a hook couldn't deliver (the
  file-watch hook can't talk to the agent). The next hook that can delivers them.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import time
from pathlib import Path

from memtegrity import paths

OWN_WRITE_TTL_SECONDS = 120.0
"""How long a restore's own write is recognized (file-watch events arrive within seconds)."""

IN_FLIGHT_TTL_SECONDS = 30 * 60.0
"""Tool-call markers older than this are stale (a crashed or killed command)."""

_SAFE_RX = re.compile(r"[^A-Za-z0-9_-]")


def _safe(name: str | None) -> str:
    return _SAFE_RX.sub("_", name or "unknown")[:100] or "unknown"


def _folder(name: str) -> Path:
    d = paths.data_dir() / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def _age(path: Path) -> float:
    try:
        return time.time() - path.stat().st_mtime
    except OSError:
        return float("inf")


# --------------------------------------------------------------------------- approval


def awaiting_approval(sha256: str) -> Path:
    """Marker for content shown to the user in a permission prompt."""
    return paths.data_dir() / "awaiting-approval" / sha256


def is_awaiting_approval(sha256: str) -> bool:
    return awaiting_approval(sha256).is_file()


# --------------------------------------------------------------------------- own writes


def note_own_write(path: Path, sha256: str) -> None:
    """Call right before Memtegrity writes ``path`` with content hashing to ``sha256``."""
    marker = _folder("own-writes") / sha256
    marker.write_text(str(path), encoding="utf-8")


def is_own_write(path: Path, sha256: str) -> bool:
    """True if this exact content was written to ``path`` by Memtegrity just now."""
    marker = paths.data_dir() / "own-writes" / sha256
    if _age(marker) > OWN_WRITE_TTL_SECONDS:
        return False
    try:
        return marker.read_text(encoding="utf-8") == str(path)
    except OSError:
        return False


# --------------------------------------------------------------------------- tool calls


def _in_flight(session_id: str | None, tool_use_id: str | None) -> Path:
    return _folder("in-flight") / f"{_safe(session_id)}__{_safe(tool_use_id)}"


def tool_started(
    session_id: str | None, tool_use_id: str | None, tool_name: str, detail: str = ""
) -> None:
    """Record that an agent tool call that may write files is running."""
    data = {"tool": tool_name, "detail": detail[:500], "started": time.time()}
    _in_flight(session_id, tool_use_id).write_text(json.dumps(data), encoding="utf-8")


def tool_finished(session_id: str | None, tool_use_id: str | None) -> dict | None:
    """Clear the marker and return what was recorded (``None`` if there was none)."""
    marker = _in_flight(session_id, tool_use_id)
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = None
    with contextlib.suppress(OSError):
        marker.unlink()
    return data


def tool_running(session_id: str | None) -> bool:
    """True if an agent tool call in this session is running right now."""
    folder = paths.data_dir() / "in-flight"
    if not folder.is_dir():
        return False
    prefix = f"{_safe(session_id)}__"
    running = False
    for marker in folder.iterdir():
        if _age(marker) > IN_FLIGHT_TTL_SECONDS:
            with contextlib.suppress(OSError):
                marker.unlink()
        elif marker.name.startswith(prefix):
            running = True
    return running


# --------------------------------------------------------------------------- alerts


def add_alert(session_id: str | None, text: str) -> None:
    """Queue a warning for the agent in this session."""
    with (_folder("alerts") / f"{_safe(session_id)}.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"text": text}) + "\n")


def pop_alerts(session_id: str | None) -> list[str]:
    """Return and clear the queued warnings for this session (cheap when there are none)."""
    path = paths.data_dir() / "alerts" / f"{_safe(session_id)}.jsonl"
    if not path.is_file():
        return []
    taken = path.with_name(f"{path.name}.{os.getpid()}")
    try:
        path.replace(taken)  # atomic: two hooks can't deliver the same alert twice
        lines = taken.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    finally:
        with contextlib.suppress(OSError):
            taken.unlink()
    out = []
    for line in lines:
        with contextlib.suppress(ValueError):
            text = json.loads(line).get("text")
            if isinstance(text, str) and text not in out:
                out.append(text)
    return out
