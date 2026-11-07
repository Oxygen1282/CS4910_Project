"""integrity: hashing, diffs, added lines, and Edit simulation."""

from pathlib import Path

import pytest

from memtegrity.integrity import (
    EditSimulationError,
    added_lines,
    apply_edit,
    diff_text,
    hash_file,
    hash_text,
    read_text,
)

SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_hash_text_known_vector() -> None:
    assert hash_text("abc") == SHA256_ABC  # NIST FIPS 180-2 test vector


def test_hash_file_matches_hash_text_across_chunks(tmp_path: Path) -> None:
    text = "line of memory\n" * 20_000  # > one 64 KiB chunk
    f = tmp_path / "CLAUDE.md"
    f.write_text(text)
    assert hash_file(f) == hash_text(text)


def test_hash_text_survives_lone_surrogate() -> None:
    assert len(hash_text("bad \ud800 input")) == 64


def test_read_text(tmp_path: Path) -> None:
    assert read_text(tmp_path / "missing.md") is None
    f = tmp_path / "bin.md"
    f.write_bytes(b"ok \xff\xfe")
    assert read_text(f).startswith("ok ")


def test_added_lines_insert_and_modify() -> None:
    before = "a\nb\nc\n"
    after = "a\nb2\nc\nd\n"
    assert added_lines(before, after) == [(2, "b2"), (4, "d")]


def test_added_lines_ignores_deletions() -> None:
    assert added_lines("a\nb\nc\n", "a\nc\n") == []


def test_added_lines_new_file() -> None:
    assert added_lines("", "x\ny\n") == [(1, "x"), (2, "y")]


def test_diff_text() -> None:
    d = diff_text("a\n", "a\nb\n", "CLAUDE.md")
    assert "+++ b/CLAUDE.md" in d and "+b\n" in d


def test_apply_edit_unique() -> None:
    assert apply_edit("x = 1\ny = 2\n", "y = 2", "y = 3") == "x = 1\ny = 3\n"


def test_apply_edit_replace_all() -> None:
    assert apply_edit("a a a", "a", "b", replace_all=True) == "b b b"


@pytest.mark.parametrize(
    ("current", "old"),
    [("abc", "zzz"), ("a a", "a"), ("abc", "")],
    ids=["not-found", "not-unique", "empty"],
)
def test_apply_edit_refuses_to_guess(current: str, old: str) -> None:
    with pytest.raises(EditSimulationError):
        apply_edit(current, old, "new")
