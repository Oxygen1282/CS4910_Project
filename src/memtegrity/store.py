"""SQLite storage (SQLModel) for snapshots and change events, kept in ``$CLAUDE_PLUGIN_DATA``."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.engine import Engine

from memtegrity.models import ChangeEvent, Snapshot, SnapshotStatus


def get_engine(db_path: Path) -> Engine:
    """Create (or open) the SQLite database at ``db_path`` and create tables if missing.

    TODO(A): implement.
    """
    raise NotImplementedError


def save_snapshot(engine: Engine, snapshot: Snapshot) -> Snapshot:
    """Insert ``snapshot`` and return it with its ``id`` set.

    TODO(A): implement.
    """
    raise NotImplementedError


def latest_approved(engine: Engine, path: str) -> Snapshot | None:
    """Return the newest APPROVED snapshot for ``path``, or ``None`` if there is none.

    TODO(A): implement.
    """
    raise NotImplementedError


def set_status(
    engine: Engine, snapshot_id: int, status: SnapshotStatus, note: str | None = None
) -> None:
    """Change a snapshot's status (approve, or quarantine).

    TODO(A): implement.
    """
    raise NotImplementedError


def record_change(engine: Engine, event: ChangeEvent) -> ChangeEvent:
    """Insert a change event (the audit-trail record) and return it with its ``id`` set.

    TODO(A): implement.
    """
    raise NotImplementedError


def list_changes(engine: Engine, path: str | None = None, limit: int = 50) -> list[ChangeEvent]:
    """Return recent change events, newest first, optionally for one path.

    TODO(A): implement.
    """
    raise NotImplementedError
