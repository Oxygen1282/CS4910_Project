"""Contain and recover: judge a protected file that changed on disk, and restore it.

Agent-neutral core, used by the Claude Code file-watch and post-tool hooks and by the CLI
(``memtegrity restore``). The change can come from anywhere: an agent's shell command, an
MCP tool, an editor, ``git pull``.

**Restore policy** (who gets an automatic restore). A prompt injection acts *through the
agent*, so a high-risk change the agent made is put back automatically. A change from
outside the agent (the user's editor, ``git``) is more likely the user's own work, and
overwriting it would fight their editor or their repository, so it is flagged, the agent is
told to treat it as untrusted, and one command restores it. ``auto_restore`` in
``config.py`` (or ``$MEMTEGRITY_AUTO_RESTORE``) selects:

* ``agent`` (default): restore automatically only what the agent wrote;
* ``always``: also restore outside changes;
* ``off``: never restore automatically (warn only).

Restoring is destructive, so it is careful:

* it only ever goes back to an **approved** snapshot, byte for byte (line endings kept);
* the version it overwrites is kept first as a ``QUARANTINED`` snapshot (evidence, and
  ``memtegrity review`` can bring it back);
* it never deletes a file: a file with no approved version is flagged, not removed;
* it writes in place, so symlinks, hard links and permissions stay as they were;
* its own write is marked (``markers.note_own_write``), so the file-watch event it causes
  is ignored instead of starting a loop;
* ``$MEMTEGRITY_RESTORE_ROOTS`` (folders separated by ``os.pathsep``) limits where it may
  write at all; live tests set it to a throwaway folder.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING

from sqlalchemy.engine import Engine

from memtegrity import baseline, integrity, markers, paths, store
from memtegrity import engine as analysis
from memtegrity.config import DEFAULT_SETTINGS
from memtegrity.models import (
    Assessment,
    FileEventKind,
    HookEvent,
    Snapshot,
    SnapshotStatus,
    Verdict,
)
from memtegrity.surfaces import Surface

if TYPE_CHECKING:
    from memtegrity.judge import Judge

RESTORE_ROOTS_ENV = "MEMTEGRITY_RESTORE_ROOTS"
AUTO_RESTORE_ENV = "MEMTEGRITY_AUTO_RESTORE"


class RestorePolicy(StrEnum):
    AGENT = "agent"
    ALWAYS = "always"
    OFF = "off"


def restore_policy() -> RestorePolicy:
    value = os.environ.get(AUTO_RESTORE_ENV) or DEFAULT_SETTINGS.auto_restore
    try:
        return RestorePolicy(value.strip().lower())
    except ValueError:
        return RestorePolicy.AGENT


def matches_repository(path: Path) -> bool:
    """True if the file's content is exactly what the repository has committed
    (``git show HEAD:<file>``). An agent's ``git pull`` or ``git checkout`` brings in the
    repository's content, not the agent's own words, so such a change is treated like an
    outside change: flagged, not overwritten. Comparing content (not the command line) means
    ``git pull && echo poison >> CLAUDE.md`` gets no pass."""
    import subprocess

    try:
        out = subprocess.run(
            ["git", "-C", str(path.parent), "show", f"HEAD:./{path.name}"],
            capture_output=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if out.returncode != 0:
        return False
    try:
        return out.stdout == path.read_bytes()
    except OSError:
        return False


class CannotRestore(Exception):
    """There is no approved version to go back to, or restoring here isn't allowed."""


@dataclass
class Outcome:
    """What happened to one changed protected file."""

    path: Path
    surface: Surface
    action: str
    """``unchanged``, ``awaiting-approval``, ``accepted``, ``flagged``, ``restored``,
    ``deleted`` or ``duplicate`` (already reported)."""
    assessment: Assessment | None = None
    event_id: int | None = None
    quarantined_id: int | None = None
    """Snapshot id of the suspicious version kept as evidence."""
    why_not_restored: str | None = None
    """Set when the change was high risk but not restored (policy, or nothing approved)."""

    @property
    def needs_attention(self) -> bool:
        return self.action in {"flagged", "restored"}


# --------------------------------------------------------------------------- restore


def restore_allowed(path: Path) -> bool:
    roots = [r for r in os.environ.get(RESTORE_ROOTS_ENV, "").split(os.pathsep) if r]
    if not roots:
        return True
    k = paths.key(paths.resolve_path(path))
    return any(k[: len(rk)] == rk for rk in (paths.key(paths.resolve_path(r)) for r in roots))


def write_exact(path: Path, content: str) -> None:
    """Write ``content`` back exactly (in place), marking it as Memtegrity's own write."""
    data = content.encode("utf-8", "surrogatepass")
    markers.note_own_write(path, integrity.hash_bytes(data))
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("r+b" if path.exists() else "wb") as fh:
        fh.write(data)
        fh.truncate()


def _quarantine(db: Engine, p: str, content: str, session_id: str | None, note: str) -> Snapshot:
    sha = integrity.hash_text(content)
    existing = store.find_snapshot(db, p, sha, SnapshotStatus.QUARANTINED)
    if existing is not None:
        return existing
    pending = store.find_snapshot(db, p, sha, SnapshotStatus.PENDING)
    if pending is not None and pending.id is not None:  # flagged earlier: same evidence
        store.set_status(db, pending.id, SnapshotStatus.QUARANTINED, note)
        pending.status = SnapshotStatus.QUARANTINED
        return pending
    return store.save_snapshot(
        db, baseline.snapshot(p, content, SnapshotStatus.QUARANTINED, session_id, note)
    )


def restore(
    db: Engine,
    path: Path,
    surface: Surface,
    *,
    source: HookEvent,
    session_id: str | None = None,
    assessment: Assessment | None = None,
    note: str = "restored to the last approved version",
    tool_name: str | None = None,
) -> Outcome:
    """Put ``path`` back to its latest approved snapshot, keeping the current version as
    quarantined evidence. Raises ``CannotRestore`` if there is nothing safe to go back to."""
    p = str(path)
    approved = store.latest_approved(db, p)
    if approved is None:
        raise CannotRestore("this file has no approved version")
    if approved.content == "" and approved.note == "deleted":
        raise CannotRestore("the approved state is 'deleted'; Memtegrity never deletes files")
    if not restore_allowed(path):
        raise CannotRestore(f"restores are limited to ${RESTORE_ROOTS_ENV}")

    current = integrity.read_text(path)
    if current is not None and integrity.hash_text(current) == approved.sha256:
        return Outcome(path, surface, "unchanged", assessment)

    evidence = (
        _quarantine(db, p, current, session_id, "quarantined: replaced by a restore")
        if current is not None
        else None
    )
    write_exact(path, approved.content)
    event = store.record_change(
        db,
        baseline.event(
            p,
            surface,
            source,
            FileEventKind.ADD if current is None else FileEventKind.CHANGE,
            evidence,
            approved,
            assessment,
            session_id,
            note=note,
            tool_name=tool_name,
        ),
    )
    return Outcome(
        path, surface, "restored", assessment, event.id, evidence.id if evidence else None
    )


# --------------------------------------------------------------------------- one changed file


def handle_change(
    db: Engine,
    path: Path,
    surface: Surface,
    *,
    source: HookEvent,
    by_agent: bool,
    session_id: str | None = None,
    tool_name: str | None = None,
    repo_sync: bool = False,
    judge: Judge | None = None,
) -> Outcome:
    """Judge a protected file that changed on disk and act on it (see module docstring).

    ``by_agent``: the change happened during one of the agent's tool calls.
    ``repo_sync``: the new content is the repository's (see ``matches_repository``); found
    automatically when not given.
    ``judge``: the AI judge to consult (``memtegrity.judge``), or ``None`` for rules only.
    """
    p = str(path)
    content = integrity.read_text(path) if path.is_file() else None
    approved = store.latest_approved(db, p)

    if content is None:
        return _handle_deletion(db, path, surface, approved, source, session_id, tool_name, judge)

    sha = integrity.hash_text(content)
    if approved is not None and approved.sha256 == sha:
        return Outcome(path, surface, "unchanged")
    if markers.is_awaiting_approval(sha):
        return Outcome(path, surface, "awaiting-approval")  # the post-write hook confirms it

    before = approved.content if approved else ""
    assessment = analysis.assess_change(surface, before, content, judge=judge)
    kind = FileEventKind.ADD if not before else FileEventKind.CHANGE

    if assessment.verdict is Verdict.ALLOW:
        snap = store.save_snapshot(
            db,
            baseline.snapshot(p, content, SnapshotStatus.APPROVED, session_id, "low-risk change"),
        )
        ev = store.record_change(
            db,
            baseline.event(
                p, surface, source, kind, approved, snap, assessment, session_id,
                note="accepted: low risk", tool_name=tool_name,
            ),
        )  # fmt: skip
        return Outcome(path, surface, "accepted", assessment, ev.id)

    policy = restore_policy()
    if by_agent and not repo_sync and assessment.verdict is Verdict.DENY:
        repo_sync = matches_repository(path)
    wants_restore = assessment.verdict is Verdict.DENY and (
        policy is RestorePolicy.ALWAYS
        or (policy is RestorePolicy.AGENT and by_agent and not repo_sync)
    )
    why_not = None
    if wants_restore:
        try:
            return restore(
                db,
                path,
                surface,
                source=source,
                session_id=session_id,
                assessment=assessment,
                note="restored: high-risk change made by the agent"
                if by_agent
                else "restored: high-risk change (auto_restore=always)",
                tool_name=tool_name,
            )
        except CannotRestore as exc:
            why_not = str(exc)
    elif assessment.verdict is Verdict.DENY:
        why_not = (
            "it came from the repository"
            if repo_sync
            else "it was made outside the agent"
            if not by_agent
            else "automatic restore is off"
        )

    # Flagged: the approved version stays the reference; record each content once.
    if store.find_change(db, p, sha, source=source.value) is not None:
        return Outcome(path, surface, "duplicate", assessment, why_not_restored=why_not)
    pending = store.find_snapshot(db, p, sha, SnapshotStatus.PENDING) or store.save_snapshot(
        db, baseline.snapshot(p, content, SnapshotStatus.PENDING, session_id, "flagged")
    )
    ev = store.record_change(
        db,
        baseline.event(
            p, surface, source, kind, approved, pending, assessment, session_id,
            note="flagged" + (f"; not restored: {why_not}" if why_not else ""),
            tool_name=tool_name,
        ),
    )  # fmt: skip
    return Outcome(path, surface, "flagged", assessment, ev.id, why_not_restored=why_not)


def _handle_deletion(
    db: Engine,
    path: Path,
    surface: Surface,
    approved: Snapshot | None,
    source: HookEvent,
    session_id: str | None,
    tool_name: str | None,
    judge: Judge | None = None,
) -> Outcome:
    """A protected file disappeared. Record it (once); flag it if what was removed looks
    like a safeguard. Memtegrity doesn't recreate deleted files on its own."""
    p = str(path)
    if approved is None or (approved.content == "" and approved.note == "deleted"):
        return Outcome(path, surface, "unchanged")
    assessment = analysis.assess_change(surface, approved.content, "", judge=judge)
    flagged = assessment.verdict is not Verdict.ALLOW
    last = store.list_changes(db, p, limit=1)
    if (
        flagged
        and last
        and last[0].file_event is FileEventKind.UNLINK
        and last[0].before_sha256 == approved.sha256
    ):
        return Outcome(path, surface, "duplicate", assessment)  # already reported
    # A harmless deletion becomes the new approved state. A suspicious one (safeguards
    # removed) keeps the old version approved, so ``memtegrity restore`` can bring it back.
    gone = (
        None
        if flagged
        else store.save_snapshot(
            db, baseline.snapshot(p, "", SnapshotStatus.APPROVED, session_id, "deleted")
        )
    )
    ev = store.record_change(
        db,
        baseline.event(
            p, surface, source, FileEventKind.UNLINK, approved, gone, assessment, session_id,
            note="file deleted" + ("; flagged: safeguards removed" if flagged else ""),
            tool_name=tool_name, diff_to="",
        ),
    )  # fmt: skip
    return Outcome(path, surface, "flagged" if flagged else "deleted", assessment, ev.id)
