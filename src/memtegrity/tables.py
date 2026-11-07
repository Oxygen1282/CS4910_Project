"""Database tables (SQLModel) for snapshots and change events, stored by ``store.py``.

Kept separate from ``models.py`` because importing SQLModel/SQLAlchemy takes ~1–2 s, and
the PreToolUse hook runs on every Write/Edit: it must not pay that cost when it doesn't
touch the database. Import these from ``memtegrity.models`` as usual; they load lazily.
"""

from datetime import datetime

from sqlmodel import Field, SQLModel

from memtegrity.enums import FileEventKind, HookEvent, SnapshotStatus, Verdict
from memtegrity.models import _utcnow


class Snapshot(SQLModel, table=True):
    """One stored version of one memory file."""

    id: int | None = Field(default=None, primary_key=True)
    """Database id (assigned on insert)."""
    path: str = Field(index=True)
    """Absolute path of the memory file."""
    sha256: str = Field(index=True)
    """Hex SHA-256 of ``content`` (UTF-8 bytes)."""
    content: str
    """Full file content at this version. Empty string if the file was deleted."""
    size_bytes: int
    """Size of ``content`` in bytes."""
    status: SnapshotStatus = SnapshotStatus.PENDING
    """Approved / pending / quarantined."""
    created_at: datetime = Field(default_factory=_utcnow)
    """When the snapshot was taken (UTC)."""
    session_id: str | None = None
    """Claude Code session that produced this version, if known."""
    note: str | None = None
    """Free-text note, e.g. why it was approved or quarantined."""


class ChangeEvent(SQLModel, table=True):
    """One detected (or attempted) change to a memory file, with its assessment.

    This is the audit-trail record and the unit the HTML report is built from.
    """

    id: int | None = Field(default=None, primary_key=True)
    """Database id (assigned on insert)."""
    path: str = Field(index=True)
    """Absolute path of the memory file."""
    source: HookEvent
    """Which hook detected it: PreToolUse (attempted write), FileChanged or SessionStart."""
    file_event: FileEventKind = FileEventKind.CHANGE
    """change / add / unlink."""
    tool_name: str | None = None
    """For PreToolUse: ``Write`` or ``Edit``. ``None`` otherwise."""
    session_id: str | None = None
    """Claude Code session id from the hook input."""
    before_sha256: str | None = None
    """Hash of the last approved version (``None`` if the file is new)."""
    after_sha256: str | None = None
    """Hash of the new or proposed content (``None`` if the file was deleted)."""
    before_snapshot_id: int | None = Field(default=None, foreign_key="snapshot.id")
    """Snapshot this change is compared against."""
    after_snapshot_id: int | None = Field(default=None, foreign_key="snapshot.id")
    """Snapshot that stores the new or proposed content."""
    diff: str = ""
    """Unified diff from before to after."""
    verdict: Verdict | None = None
    """Final decision (copied from the assessment for easy querying)."""
    score: int | None = None
    """Final 0–100 risk score (copied from the assessment)."""
    assessment_json: str | None = None
    """The full ``Assessment``, serialized with ``Assessment.model_dump_json()``."""
    replay_json: str | None = None
    """The ``ReplayResult``, serialized, once a background replay has finished."""
    restored: bool = False
    """True if Memtegrity restored the file to the last approved snapshot."""
    created_at: datetime = Field(default_factory=_utcnow)
    """When the change was detected (UTC)."""
