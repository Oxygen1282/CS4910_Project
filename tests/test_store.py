"""store: snapshots, baselines, and the hash-chained audit log (in-memory SQLite)."""

from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.engine import Engine

from memtegrity import store
from memtegrity.integrity import hash_text
from memtegrity.models import ChangeEvent, HookEvent, Snapshot, SnapshotStatus, Verdict
from memtegrity.paths import data_dir


@pytest.fixture
def db() -> Engine:
    return store.get_engine(":memory:")


def snap(content: str, status: SnapshotStatus = SnapshotStatus.PENDING) -> Snapshot:
    return Snapshot(
        path="/p/CLAUDE.md",
        sha256=hash_text(content),
        content=content,
        size_bytes=len(content),
        status=status,
    )


def event(score: int) -> ChangeEvent:
    return ChangeEvent(
        path="/p/CLAUDE.md", source=HookEvent.SESSION_START, verdict=Verdict.ASK, score=score
    )


# --------------------------------------------------------------------------- snapshots


def test_save_approve_latest(db: Engine) -> None:
    assert store.latest_approved(db, "/p/CLAUDE.md") is None
    s = store.save_snapshot(db, snap("v1"))
    assert s.id is not None
    assert store.latest_approved(db, "/p/CLAUDE.md") is None  # pending isn't approved
    store.set_status(db, s.id, SnapshotStatus.APPROVED, "ok")
    got = store.latest_approved(db, "/p/CLAUDE.md")
    assert got is not None and got.id == s.id and got.content == "v1" and got.note == "ok"


def test_latest_approved_is_newest(db: Engine) -> None:
    store.save_snapshot(db, snap("v1", SnapshotStatus.APPROVED))
    store.save_snapshot(db, snap("v2", SnapshotStatus.APPROVED))
    store.save_snapshot(db, snap("v3"))  # pending: ignored
    assert store.latest_approved(db, "/p/CLAUDE.md").content == "v2"


def test_set_status_unknown_id(db: Engine) -> None:
    with pytest.raises(KeyError):
        store.set_status(db, 999, SnapshotStatus.APPROVED)


def test_baseline_marker(db: Engine) -> None:
    assert not store.is_baselined(db, "/p")
    store.mark_baselined(db, "/p", 3)
    store.mark_baselined(db, "/p", 5)  # idempotent
    assert store.is_baselined(db, "/p")


def test_file_database_and_data_dir(tmp_path: Path) -> None:
    db = store.get_engine(tmp_path / "sub" / "m.db")
    store.save_snapshot(db, snap("x"))
    assert (tmp_path / "sub" / "m.db").is_file()
    assert store.get_engine(tmp_path / "sub" / "m.db") is db  # cached per path
    assert data_dir().is_dir()  # the autouse fixture points it at a temp folder


# --------------------------------------------------------------------------- audit log


def test_chain_links_events(db: Engine) -> None:
    a = store.record_change(db, event(10))
    b = store.record_change(db, event(20))
    assert a.prev_hash == store.GENESIS
    assert b.prev_hash == a.record_hash
    assert store.chain_head(db) == b.record_hash
    assert store.verify_chain(db) == []
    assert [e.score for e in store.list_changes(db)] == [20, 10]  # newest first
    assert store.list_changes(db, path="/other") == []


def test_editing_an_old_row_is_reported_at_that_row(db: Engine) -> None:
    ids = [store.record_change(db, event(s)).id for s in (10, 20, 30)]
    with db.begin() as conn:
        conn.execute(text("UPDATE changeevent SET score = 0 WHERE id = :i"), {"i": ids[1]})
    issues = store.verify_chain(db)
    assert [(i.table, i.row_id) for i in issues] == [("changeevent", ids[1])]
    assert "modified" in issues[0].problem


def test_deleting_an_old_row_is_reported_at_the_next_row(db: Engine) -> None:
    ids = [store.record_change(db, event(s)).id for s in (10, 20, 30)]
    with db.begin() as conn:
        conn.execute(text("DELETE FROM changeevent WHERE id = :i"), {"i": ids[1]})
    issues = store.verify_chain(db)
    assert [(i.table, i.row_id) for i in issues] == [("changeevent", ids[2])]
    assert "deleted" in issues[0].problem


def test_edited_snapshot_is_reported(db: Engine) -> None:
    s = store.save_snapshot(db, snap("trusted", SnapshotStatus.APPROVED))
    with db.begin() as conn:
        conn.execute(text("UPDATE snapshot SET content = 'evil' WHERE id = :i"), {"i": s.id})
    assert [(i.table, i.row_id) for i in store.verify_chain(db)] == [("snapshot", s.id)]


def test_replay_and_restored_can_be_filled_in_later(db: Engine) -> None:
    e = store.record_change(db, event(10))
    with db.begin() as conn:
        conn.execute(
            text("UPDATE changeevent SET replay_json = '{}', restored = 1 WHERE id = :i"),
            {"i": e.id},
        )
    assert store.verify_chain(db) == []
