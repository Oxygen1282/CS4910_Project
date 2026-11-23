"""Per-session watch list: which protected files and folders to check after each agent
tool call, with their size and modification time.

Agent-neutral; standard library only, so the check after every shell command costs a few
``stat`` calls and no database. SessionStart writes the list; the post-tool check compares
it with the disk and opens the database only for files that actually changed. A changed
*folder* (its modification time moves when a file is created in it) is listed again, so a
newly created protected file (a new rules file, a new memory topic) is noticed too.
"""

from __future__ import annotations

import contextlib
import json
import os
from collections.abc import Iterable
from pathlib import Path

from memtegrity import markers, paths

Signature = list[int] | None


def _path(session_id: str | None) -> Path:
    return paths.data_dir() / "sessions" / f"{markers._safe(session_id)}.json"


def signature(p: Path) -> Signature:
    try:
        st = p.stat()
    except OSError:
        return None
    return [st.st_mtime_ns, st.st_size]


def save(
    session_id: str | None, project_dir: Path, files: Iterable[Path], folders: Iterable[Path]
) -> None:
    """Record the protected files (and folders new ones would appear in) for a session."""
    data = {
        "project": str(project_dir),
        "files": {str(f): signature(f) for f in files},
        "folders": {str(d): signature(d) for d in folders},
    }
    target = _path(session_id)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(f"{target.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    tmp.replace(target)  # atomic: a concurrent reader never sees half a file


def load(session_id: str | None) -> dict | None:
    try:
        data = json.loads(_path(session_id).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def changed_files(session_id: str | None, project_dir: Path | None) -> list[Path] | None:
    """Protected files that changed (or appeared, or disappeared) since the list was last
    updated. ``None`` if this session has no list (SessionStart didn't run)."""
    data = load(session_id)
    if data is None:
        return None
    files: dict[str, Signature] = data.get("files", {})
    out = [Path(f) for f, sig in files.items() if signature(Path(f)) != sig]
    for folder, sig in data.get("folders", {}).items():
        d = Path(folder)
        if signature(d) == sig:
            continue
        with contextlib.suppress(OSError):
            for entry in d.iterdir():
                real = paths.resolve_path(entry)
                if str(real) in files or real in out or not real.is_file():
                    continue
                if paths.classify(entry, project_dir) is not None:
                    out.append(real)
    return out


def refresh(session_id: str | None, changed: Iterable[Path]) -> None:
    """Record the current state of ``changed`` files (adding new ones) and of all folders."""
    data = load(session_id)
    if data is None:
        return
    files = data.setdefault("files", {})
    for f in changed:
        files[str(f)] = signature(Path(f))
    folders = data.setdefault("folders", {})
    for d in list(folders):
        folders[d] = signature(Path(d))
    save(
        session_id,
        Path(data.get("project", ".")),
        [Path(f) for f in files],
        [Path(d) for d in folders],
    )
