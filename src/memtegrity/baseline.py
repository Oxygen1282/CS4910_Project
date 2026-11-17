"""Baselines: what changed in protected files *between* sessions, and who approved what.

Agent-neutral core, used by the Claude Code SessionStart hook and by the CLI
(``memtegrity baseline`` / ``status``).

* **First run for a project (trust on first use):** every protected file is approved as the
  baseline, quietly. One exception: a file the rules judge high risk (``deny``) on its own is
  *not* trusted, because a repository can arrive already poisoned (the scanner's job).
* **Later runs:** each file is hashed and compared with its latest approved snapshot. A
  changed or new file is judged by ``engine.assess_change(surface, approved, current)``:

  - ``allow`` → accepted as the new baseline (normal edits, Claude's own memory notes);
  - ``ask`` / ``deny`` → stored as a *pending* snapshot and reported every session until the
    user approves it (``memtegrity baseline``). The approved version stays the reference.

* A protected file that was approved and has disappeared is recorded and accepted (the
  deletion of a safeguard is a Block 4 concern).

Every decision is a ``ChangeEvent`` in the hash-chained audit log. Re-running on the same
content records nothing new.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy.engine import Engine

from memtegrity import engine as analysis
from memtegrity import integrity, paths, store
from memtegrity.models import (
    Assessment,
    ChangeEvent,
    FileEventKind,
    HookEvent,
    Snapshot,
    SnapshotStatus,
    Verdict,
)
from memtegrity.surfaces import Surface

FIRST_RUN_NOTE = "first baseline (trust on first use)"


@dataclass
class Finding:
    """One protected file whose current content isn't the approved one."""

    path: Path
    surface: Surface
    file_event: FileEventKind
    assessment: Assessment
    event_id: int | None = None
    """The audit-log event (``None`` if this exact content was already recorded)."""
    first_check: bool = False
    """Found on the project's first check (never approved), not changed since one."""

    @property
    def how(self) -> str:
        """Why the file is listed, for messages."""
        if self.first_check:
            return "was found on Memtegrity's first check of this project"
        if self.file_event is FileEventKind.ADD:
            return "was added since the last session"
        if self.file_event is FileEventKind.UNLINK:
            return "was deleted since the last session"
        return "changed since it was last approved"


@dataclass
class CheckResult:
    first_run: bool
    files: list[Path] = field(default_factory=list)
    """Every protected file found (for ``watchPaths``)."""
    flagged: list[Finding] = field(default_factory=list)
    """Changes the user must look at (ask / deny), newest risk first."""
    accepted: list[Finding] = field(default_factory=list)
    """Low-risk changes accepted as the new baseline."""
    skipped: list[Path] = field(default_factory=list)
    """Protected files too large to analyze."""
    complete: bool = True
    """False if discovery ran out of its file/time budget (very large folder)."""


def project_key(project_dir: Path) -> str:
    return str(paths.resolve_path(project_dir))


def _read(path: Path) -> str | None:
    try:
        if path.stat().st_size > paths.MAX_FILE_BYTES:
            return None
    except OSError:
        return None
    return integrity.read_text(path)


def snapshot(
    path: str, content: str, status: SnapshotStatus, session_id: str | None, note: str | None
) -> Snapshot:
    return Snapshot(
        path=path,
        sha256=integrity.hash_text(content),
        content=content,
        size_bytes=len(content.encode("utf-8", "surrogatepass")),
        status=status,
        session_id=session_id,
        note=note,
    )


def event(
    path: str,
    surface: Surface,
    source: HookEvent,
    file_event: FileEventKind,
    before: Snapshot | None,
    after: Snapshot | None,
    assessment: Assessment | None,
    session_id: str | None,
    note: str | None = None,
    tool_name: str | None = None,
    diff_from: str | None = None,
    diff_to: str | None = None,
) -> ChangeEvent:
    """Build an audit-log record. The diff runs from ``before`` to ``after`` unless
    ``diff_from`` / ``diff_to`` say otherwise (e.g. the current file → a proposed write)."""
    before_text = diff_from if diff_from is not None else (before.content if before else "")
    after_text = diff_to if diff_to is not None else (after.content if after else "")
    return ChangeEvent(
        path=path,
        agent=surface.agent,
        surface_kind=surface.kind,
        source=source,
        file_event=file_event,
        tool_name=tool_name,
        session_id=session_id,
        before_sha256=before.sha256 if before else None,
        after_sha256=after.sha256 if after else None,
        before_snapshot_id=before.id if before else None,
        after_snapshot_id=after.id if after else None,
        diff=integrity.diff_text(before_text, after_text, path),
        verdict=assessment.verdict if assessment else None,
        score=assessment.score if assessment else None,
        assessment_json=assessment.model_dump_json() if assessment else None,
        note=note,
    )


def check(
    db: Engine,
    project_dir: Path,
    *,
    session_id: str | None = None,
    budget_seconds: float = 0.8,
    source: HookEvent = HookEvent.SESSION_START,
) -> CheckResult:
    """Compare every protected file with its approved baseline (see module docstring)."""
    deadline = time.monotonic() + budget_seconds
    found = paths.discover(project_dir, deadline=deadline)
    project = project_key(project_dir)
    result = CheckResult(
        first_run=not store.is_baselined(db, project),
        files=sorted(found.files),
        complete=found.complete,
    )

    approved_now = store.latest_approved_many(db, [str(p) for p in found.files])
    first_baseline: list[Snapshot] = []
    for path, surface in sorted(found.files.items()):
        p = str(path)
        content = _read(path)
        if content is None:
            result.skipped.append(path)
            continue
        sha = integrity.hash_text(content)
        approved = approved_now.get(p)
        if approved is not None and approved.sha256 == sha:
            continue

        before_text = approved.content if approved else ""
        assessment = analysis.assess_change(surface, before_text, content)
        kind = (
            FileEventKind.ADD if approved is None or not approved.content else FileEventKind.CHANGE
        )

        if result.first_run and approved is None:
            if assessment.verdict is not Verdict.DENY:  # trust on first use...
                first_baseline.append(
                    snapshot(p, content, SnapshotStatus.APPROVED, session_id, FIRST_RUN_NOTE)
                )
                continue  # ...quietly: no event per file, one summary line instead
        elif assessment.verdict is Verdict.ALLOW:
            snap = store.save_snapshot(
                db, snapshot(p, content, SnapshotStatus.APPROVED, session_id, "low-risk change")
            )
            ev = store.record_change(
                db,
                event(
                    p,
                    surface,
                    source,
                    kind,
                    approved,
                    snap,
                    assessment,
                    session_id,
                    note="accepted: low risk",
                ),
            )
            result.accepted.append(Finding(path, surface, kind, assessment, ev.id))
            continue

        # Flagged: keep the approved version as the reference; record once per content.
        finding = Finding(
            path, surface, kind, assessment, first_check=result.first_run and approved is None
        )
        if store.find_change(db, p, sha, source=source.value) is None:
            pending = store.find_snapshot(
                db, p, sha, SnapshotStatus.PENDING
            ) or store.save_snapshot(
                db, snapshot(p, content, SnapshotStatus.PENDING, session_id, "flagged")
            )
            ev = store.record_change(
                db, event(p, surface, source, kind, approved, pending, assessment, session_id)
            )
            finding.event_id = ev.id
        result.flagged.append(finding)

    store.save_snapshots(db, first_baseline)
    _record_deletions(db, project_dir, set(found.files), session_id, source, result)

    if result.first_run:
        store.mark_baselined(db, project, len(result.files))
    result.flagged.sort(key=lambda f: -f.assessment.score)
    return result


def _scope(project_dir: Path) -> list[tuple[str, ...]]:
    """Folders/files whose protected files belong to this project's sessions (so a file
    deleted in *another* project isn't reported here)."""
    from memtegrity.agents import PROFILES

    project = paths.resolve_path(project_dir)
    out = [paths.key(project)]
    for profile in PROFILES:
        for extra in profile.session_paths(project) if profile.session_paths else ():
            out.append(paths.key(paths.resolve_path(extra)))
    return out


def _in_scope(path: Path, scope: list[tuple[str, ...]]) -> bool:
    k = paths.key(path)
    return any(k[: len(s)] == s for s in scope)


def _record_deletions(
    db: Engine,
    project_dir: Path,
    present: set[Path],
    session_id: str | None,
    source: HookEvent,
    result: CheckResult,
) -> None:
    present_keys = {paths.key(p) for p in present}
    scope = _scope(project_dir)
    for p in store.approved_paths(db):
        path = Path(p)
        if paths.key(path) in present_keys or path.exists() or not _in_scope(path, scope):
            continue
        approved = store.latest_approved(db, p)
        if approved is None or (approved.content == "" and approved.note == "deleted"):
            continue
        surface = paths.classify(path, project_dir)
        if surface is None:
            continue
        gone = store.save_snapshot(
            db, snapshot(p, "", SnapshotStatus.APPROVED, session_id, "deleted")
        )
        assessment = analysis.assess_change(surface, approved.content, "")
        ev = store.record_change(
            db,
            event(
                p,
                surface,
                source,
                FileEventKind.UNLINK,
                approved,
                gone,
                assessment,
                session_id,
                note="file deleted",
            ),
        )
        result.accepted.append(Finding(path, surface, FileEventKind.UNLINK, assessment, ev.id))


def approve_all(db: Engine, project_dir: Path, note: str = "approved by the user") -> int:
    """Approve the current content of every protected file (``memtegrity baseline``).
    Returns how many files got a new approved snapshot."""
    found = paths.discover(project_dir)
    count = 0
    for path, surface in sorted(found.files.items()):
        content = _read(path)
        if content is None:
            continue
        p = str(path)
        approved = store.latest_approved(db, p)
        if approved is not None and approved.sha256 == integrity.hash_text(content):
            continue
        snap = store.save_snapshot(db, snapshot(p, content, SnapshotStatus.APPROVED, None, note))
        kind = FileEventKind.ADD if approved is None else FileEventKind.CHANGE
        store.record_change(
            db,
            event(
                p,
                surface,
                HookEvent.SESSION_START,
                kind,
                approved,
                snap,
                None,
                None,
                note=f"{note} (memtegrity baseline)",
            ),
        )
        count += 1
    store.mark_baselined(db, project_key(project_dir), len(found.files))
    return count


@dataclass
class FileState:
    """One row of ``memtegrity status``."""

    path: Path
    surface: Surface
    approved: bool
    """Has an approved snapshot."""
    changed: bool | None
    """Differs from it (``None``: not approved yet, or too large to read)."""
    pending: bool
    """A flagged version of the current content is waiting for approval."""


def states(db: Engine, project_dir: Path) -> tuple[list[FileState], bool]:
    """Every protected file and whether it matches its approved snapshot (read-only)."""
    found = paths.discover(project_dir)
    out = []
    for path, surface in sorted(found.files.items()):
        p = str(path)
        approved = store.latest_approved(db, p)
        content = _read(path)
        sha = integrity.hash_text(content) if content is not None else None
        changed = None if approved is None or sha is None else approved.sha256 != sha
        pending = (
            sha is not None and store.find_snapshot(db, p, sha, SnapshotStatus.PENDING) is not None
        )
        out.append(FileState(path, surface, approved is not None, changed, pending))
    return out, found.complete
