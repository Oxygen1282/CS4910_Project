"""SQLite storage (SQLModel) for snapshots, change events and baselines, kept in
``$CLAUDE_PLUGIN_DATA`` (see ``paths.data_dir``).

The audit log is **hash-chained**: each ``ChangeEvent`` stores the previous event's hash and
its own ``record_hash = sha256(prev_hash + canonical JSON)``. Editing or deleting an earlier
row breaks the chain at that exact row, which ``verify_chain`` reports. Snapshots are checked
against their own SHA-256.

Limits (documented, not hidden): someone who can write the database can also recompute the
whole chain, and deleting the newest rows leaves no gap. Both need the chain head to be
anchored somewhere the attacker can't write (``chain_head`` is shown by ``memtegrity status``
for that purpose). The threat model here is a poisoned agent, which has no reason to know
the database exists, not malware on the host.

Every transaction is ``BEGIN IMMEDIATE``: two Claude Code sessions appending at once are
serialized by SQLite instead of forking the chain.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path

from sqlalchemy import event as sa_event
from sqlalchemy.engine import Engine
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, col, create_engine, select

from memtegrity.models import ChangeEvent, ProjectBaseline, Snapshot, SnapshotStatus

GENESIS = "0" * 64
"""``prev_hash`` of the first event."""

_UNHASHED = frozenset({"id", "record_hash", "replay_json", "restored"})
"""Fields outside the hash: the id is assigned by SQLite, the hash can't cover itself, and
``replay_json`` / ``restored`` are filled in after the event is recorded."""

_ENGINES: dict[str, Engine] = {}


# --------------------------------------------------------------------------- engine


def get_engine(db_path: Path | str) -> Engine:
    """Create (or open) the SQLite database at ``db_path`` and create tables if missing.

    ``":memory:"`` gives a private in-memory database (for tests). Engines are cached per
    path for the life of the process.
    """
    key = str(db_path)
    if key in _ENGINES:
        return _ENGINES[key]
    if key == ":memory:":
        engine = create_engine(
            "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
        )
    else:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(
            f"sqlite:///{Path(db_path).as_posix()}", connect_args={"timeout": 10}
        )
        _ENGINES[key] = engine

    @sa_event.listens_for(engine, "connect")
    def _on_connect(dbapi_conn, _record) -> None:  # noqa: ANN001
        dbapi_conn.isolation_level = None  # let us issue BEGIN ourselves (below)
        if key != ":memory:":
            dbapi_conn.execute("PRAGMA journal_mode=WAL")
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

    @sa_event.listens_for(engine, "begin")
    def _on_begin(conn) -> None:  # noqa: ANN001
        conn.exec_driver_sql("BEGIN IMMEDIATE")

    SQLModel.metadata.create_all(engine)
    return engine


def default_engine() -> Engine:
    """The database in the plugin's data folder."""
    from memtegrity.config import DEFAULT_SETTINGS
    from memtegrity.paths import data_dir

    return get_engine(data_dir() / DEFAULT_SETTINGS.db_filename)


# --------------------------------------------------------------------------- snapshots


def save_snapshot(engine: Engine, snapshot: Snapshot) -> Snapshot:
    """Insert ``snapshot`` and return it with its ``id`` set."""
    with Session(engine, expire_on_commit=False) as s:
        s.add(snapshot)
        s.commit()
        s.refresh(snapshot)
    return snapshot


def save_snapshots(engine: Engine, snapshots: list[Snapshot]) -> None:
    """Insert many snapshots in one transaction (one disk flush, e.g. the first baseline)."""
    if not snapshots:
        return
    with Session(engine, expire_on_commit=False) as s:
        s.add_all(snapshots)
        s.commit()


def get_snapshot(engine: Engine, snapshot_id: int) -> Snapshot | None:
    with Session(engine, expire_on_commit=False) as s:
        return s.get(Snapshot, snapshot_id)


def latest_snapshot(
    engine: Engine, path: str, status: SnapshotStatus | None = None
) -> Snapshot | None:
    """Newest snapshot for ``path`` (optionally only with ``status``)."""
    q = select(Snapshot).where(Snapshot.path == path)
    if status is not None:
        q = q.where(Snapshot.status == status)
    q = q.order_by(col(Snapshot.id).desc()).limit(1)  # insert order; clocks can tie or skew
    with Session(engine, expire_on_commit=False) as s:
        return s.exec(q).first()


def latest_approved(engine: Engine, path: str) -> Snapshot | None:
    """Return the newest APPROVED snapshot for ``path``, or ``None`` if there is none."""
    return latest_snapshot(engine, path, SnapshotStatus.APPROVED)


def latest_approved_many(engine: Engine, paths: list[str]) -> dict[str, Snapshot]:
    """``latest_approved`` for many paths in one query (SessionStart checks every file)."""
    if not paths:
        return {}
    from sqlalchemy import func

    newest = (
        select(func.max(Snapshot.id))
        .where(Snapshot.status == SnapshotStatus.APPROVED, col(Snapshot.path).in_(paths))
        .group_by(Snapshot.path)
    )
    with Session(engine, expire_on_commit=False) as s:
        rows = s.exec(select(Snapshot).where(col(Snapshot.id).in_(newest))).all()
    return {r.path: r for r in rows}


def find_snapshot(
    engine: Engine, path: str, sha256: str, status: SnapshotStatus, session_id: str | None = None
) -> Snapshot | None:
    """Newest snapshot of ``path`` with exactly this content and status (and session)."""
    q = select(Snapshot).where(
        Snapshot.path == path, Snapshot.sha256 == sha256, Snapshot.status == status
    )
    if session_id is not None:
        q = q.where(Snapshot.session_id == session_id)
    q = q.order_by(col(Snapshot.id).desc()).limit(1)
    with Session(engine, expire_on_commit=False) as s:
        return s.exec(q).first()


def set_status(
    engine: Engine, snapshot_id: int, status: SnapshotStatus, note: str | None = None
) -> None:
    """Change a snapshot's status (approve, or quarantine)."""
    with Session(engine) as s:
        snap = s.get(Snapshot, snapshot_id)
        if snap is None:
            raise KeyError(f"no snapshot {snapshot_id}")
        snap.status = status
        if note is not None:
            snap.note = note
        s.add(snap)
        s.commit()


def approved_paths(engine: Engine) -> list[str]:
    """Every path that has at least one approved snapshot."""
    q = select(Snapshot.path).where(Snapshot.status == SnapshotStatus.APPROVED).distinct()
    with Session(engine) as s:
        return list(s.exec(q).all())


# --------------------------------------------------------------------------- baselines


def is_baselined(engine: Engine, project: str) -> bool:
    with Session(engine) as s:
        q = select(ProjectBaseline).where(ProjectBaseline.project == project)
        return s.exec(q).first() is not None


def mark_baselined(engine: Engine, project: str, file_count: int) -> None:
    with Session(engine) as s:
        if s.exec(select(ProjectBaseline).where(ProjectBaseline.project == project)).first():
            return
        s.add(ProjectBaseline(project=project, file_count=file_count))
        s.commit()


# --------------------------------------------------------------------------- audit log


def _canonical(event: ChangeEvent) -> str:
    """Stable JSON of the hashed fields. Datetimes become naive UTC ISO strings, because
    SQLite returns them without a time zone."""
    data = event.model_dump(exclude=set(_UNHASHED))
    for k, v in data.items():
        if isinstance(v, datetime):
            if v.tzinfo is not None:
                v = v.astimezone(UTC).replace(tzinfo=None)
            data[k] = v.isoformat()
        elif isinstance(v, Enum):
            data[k] = v.value
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_hash(prev_hash: str, event: ChangeEvent) -> str:
    payload = (prev_hash + _canonical(event)).encode("utf-8", "surrogatepass")
    return hashlib.sha256(payload).hexdigest()


def record_change(engine: Engine, event: ChangeEvent) -> ChangeEvent:
    """Insert a change event (the audit-trail record), chained to the previous one, and
    return it with ``id``, ``prev_hash`` and ``record_hash`` set."""
    with Session(engine, expire_on_commit=False) as s:  # BEGIN IMMEDIATE: one writer
        last = s.exec(select(ChangeEvent).order_by(col(ChangeEvent.id).desc()).limit(1)).first()
        event.prev_hash = (last.record_hash if last else None) or GENESIS
        event.record_hash = compute_hash(event.prev_hash, event)
        s.add(event)
        s.commit()
        s.refresh(event)
    return event


def list_changes(engine: Engine, path: str | None = None, limit: int = 50) -> list[ChangeEvent]:
    """Return recent change events, newest first, optionally for one path."""
    q = select(ChangeEvent)
    if path is not None:
        q = q.where(ChangeEvent.path == path)
    q = q.order_by(col(ChangeEvent.id).desc()).limit(limit)
    with Session(engine, expire_on_commit=False) as s:
        return list(s.exec(q).all())


def find_change(
    engine: Engine, path: str, after_sha256: str, source: str | None = None
) -> ChangeEvent | None:
    """Newest event for ``path`` whose new content has this hash (dedupe repeated checks)."""
    q = select(ChangeEvent).where(
        ChangeEvent.path == path, ChangeEvent.after_sha256 == after_sha256
    )
    if source is not None:
        q = q.where(ChangeEvent.source == source)
    q = q.order_by(col(ChangeEvent.id).desc()).limit(1)
    with Session(engine, expire_on_commit=False) as s:
        return s.exec(q).first()


def chain_head(engine: Engine) -> str:
    """Hash of the newest event (``GENESIS`` if there are none). Writing it down somewhere
    else makes deletion of the newest rows detectable too."""
    with Session(engine) as s:
        last = s.exec(select(ChangeEvent).order_by(col(ChangeEvent.id).desc()).limit(1)).first()
    return (last.record_hash if last else None) or GENESIS


@dataclass(frozen=True)
class ChainIssue:
    """One integrity problem found by ``verify_chain``."""

    table: str
    """``changeevent`` or ``snapshot``."""
    row_id: int | None
    problem: str


def verify_chain(engine: Engine) -> list[ChainIssue]:
    """Check the audit log and stored snapshots. Empty list = intact.

    * an edited event fails its own hash → reported at that row
    * a deleted (or inserted) event breaks the link → reported at the row after it
    * an edited snapshot no longer matches its SHA-256 → reported at that snapshot
    """
    from memtegrity.integrity import hash_text

    issues: list[ChainIssue] = []
    with Session(engine) as s:
        expected_prev = GENESIS
        for ev in s.exec(select(ChangeEvent).order_by(col(ChangeEvent.id))):
            if ev.prev_hash != expected_prev:
                issues.append(
                    ChainIssue("changeevent", ev.id, "the record before it was deleted or changed")
                )
            if ev.record_hash != compute_hash(ev.prev_hash or "", ev):
                issues.append(ChainIssue("changeevent", ev.id, "this record was modified"))
            expected_prev = ev.record_hash or ""
        for snap in s.exec(select(Snapshot).order_by(col(Snapshot.id))):
            if hash_text(snap.content) != snap.sha256:
                issues.append(ChainIssue("snapshot", snap.id, "content doesn't match its SHA-256"))
    return issues
