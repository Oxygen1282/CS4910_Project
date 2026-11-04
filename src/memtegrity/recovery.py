"""Restore and quarantine: the "contain → recover" half of incident response."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.engine import Engine

from memtegrity.models import ChangeEvent, Snapshot


def restore(engine: Engine, path: Path) -> Snapshot:
    """Overwrite ``path`` with its latest approved snapshot and return that snapshot.

    Must record the restore so FileChanged ignores the write it causes (see
    ``is_own_write``), avoiding a restore → FileChanged → restore loop.

    TODO(A): implement.
    """
    raise NotImplementedError


def quarantine(engine: Engine, event: ChangeEvent) -> ChangeEvent:
    """Mark the suspicious version as QUARANTINED, keep it in the DB as evidence,
    and restore the file.

    TODO(A): implement.
    """
    raise NotImplementedError


def is_own_write(path: Path, sha256: str) -> bool:
    """Return True if this content was just written by ``restore`` (loop guard).

    TODO(A): implement.
    """
    raise NotImplementedError
