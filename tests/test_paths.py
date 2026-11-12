"""paths.is_memory_path: what counts as memory, and the evasion tricks it must see through."""

import json
import os
from pathlib import Path

import pytest
from conftest import set_home, symlink_or_skip

from memtegrity.paths import is_memory_path, resolve_path, win32_alias_free


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    h = tmp_path / "home"
    h.mkdir()
    set_home(monkeypatch, h)
    return h


@pytest.fixture
def proj(tmp_path: Path, home: Path) -> Path:
    p = tmp_path / "proj"
    (p / ".claude").mkdir(parents=True)
    (p / "CLAUDE.md").write_text("# notes\n")
    return p


@pytest.mark.parametrize(
    "rel",
    [
        "CLAUDE.md",
        "CLAUDE.local.md",
        "AGENTS.md",
        ".claude/CLAUDE.md",
        "packages/web/CLAUDE.md",  # nested CLAUDE.md files load on demand
        ".claude/rules/style.md",
        ".claude/rules/deep/nested.md",
        ".claude/agents/reviewer.md",
        ".claude/commands/deploy.md",
        ".claude/skills/release/SKILL.md",
        ".claude/skills/release/reference.md",
        ".claude/output-styles/terse.md",
        ".claude/agent-memory/reviewer/MEMORY.md",
        ".claude/agent-memory-local/reviewer/notes.md",
        ".claude/settings.json",  # config surface
        ".mcp.json",  # config surface
    ],
)
def test_memory_files(proj: Path, rel: str) -> None:
    assert is_memory_path(proj / rel, proj)


@pytest.mark.parametrize(
    "rel",
    [
        "README.md",
        "src/app.py",
        "docs/notes.md",
        ".claude/rules/style.txt",
        "rules/style.md",  # not under .claude/
        "CLAUDE.md.bak",
    ],
)
def test_non_memory_files(proj: Path, rel: str) -> None:
    assert not is_memory_path(proj / rel, proj)


def test_case_insensitive_name(proj: Path) -> None:
    # On macOS's default (case-insensitive) disk, claude.md IS CLAUDE.md.
    assert is_memory_path(proj / "claude.md", proj)
    assert is_memory_path(proj / "Agents.MD", proj)


def test_relative_and_traversal_paths(proj: Path) -> None:
    assert is_memory_path("CLAUDE.md", proj)
    assert is_memory_path("docs/../CLAUDE.md", proj)
    assert is_memory_path("src/./../.claude/rules/x.md", proj)


def test_symlink_to_memory_file(proj: Path) -> None:
    symlink_or_skip(proj / "notes.md", proj / "CLAUDE.md")
    assert is_memory_path(proj / "notes.md", proj)


def test_symlinked_directory(proj: Path) -> None:
    symlink_or_skip(proj / "cfg", proj / ".claude", target_is_directory=True)
    assert is_memory_path(proj / "cfg" / "rules" / "x.md", proj)


def test_hard_link_to_memory_file(proj: Path) -> None:
    os.link(proj / "CLAUDE.md", proj / "innocent.md")
    assert is_memory_path(proj / "innocent.md", proj)


def test_unrelated_hard_link_is_not_memory(proj: Path) -> None:
    (proj / "a.md").write_text("x")
    os.link(proj / "a.md", proj / "b.md")
    assert not is_memory_path(proj / "b.md", proj)


def test_user_memory(home: Path) -> None:
    assert is_memory_path(home / ".claude" / "CLAUDE.md")
    assert is_memory_path("~/.claude/rules/global.md")


def test_auto_memory(home: Path) -> None:
    mem = home / ".claude" / "projects" / "-Users-me-proj" / "memory"
    assert is_memory_path(mem / "MEMORY.md")
    assert is_memory_path(mem / "topic-notes.txt")  # every file there loads as memory
    assert not is_memory_path(mem.parent / "transcript.jsonl")


def test_custom_auto_memory_directory(proj: Path) -> None:
    (proj / ".claude" / "settings.json").write_text(
        json.dumps({"autoMemoryDirectory": "mem"}), encoding="utf-8"
    )
    assert is_memory_path(proj / "mem" / "notes.md", proj)
    assert not is_memory_path(proj / "other" / "notes.md", proj)


def test_malformed_settings_do_not_crash(proj: Path) -> None:
    (proj / ".claude" / "settings.json").write_text("{not json")
    assert not is_memory_path(proj / "src" / "x.md", proj)


def test_resolve_path_handles_missing_files(proj: Path) -> None:
    p = resolve_path("new/dir/CLAUDE.md", proj)
    assert p.is_absolute() and p.name == "CLAUDE.md"


@pytest.mark.parametrize(
    ("alias", "real"),
    [
        (r"C:\p\CLAUDE.md.", r"C:\p\CLAUDE.md"),
        (r"C:\p\CLAUDE.md . .", r"C:\p\CLAUDE.md"),
        (r"C:\p\CLAUDE.md::$DATA", r"C:\p\CLAUDE.md"),
        (r"C:\p\claude.md::$data", r"C:\p\claude.md"),
        (r"C:\p\CLAUDE.md. ::$DATA .", r"C:\p\CLAUDE.md"),  # stacked
        (r"C:\p\.claude::$INDEX_ALLOCATION\settings.json", r"C:\p\.claude\settings.json"),
        (r"C:\p\.claude:$I30:$INDEX_ALLOCATION/rules/x.md", r"C:\p\.claude/rules/x.md"),
        ("C:/p/.claude./rules/x.md", "C:/p/.claude/rules/x.md"),
        (r"..\CLAUDE.md", r"..\CLAUDE.md"),  # "." and ".." are left alone
        (r"C:\p\CLAUDE.md:notes", r"C:\p\CLAUDE.md:notes"),  # a separate stream, not loaded
    ],
)
def test_win32_aliases_are_removed(alias: str, real: str) -> None:
    # Pure string logic, so it is checked on every OS.
    assert win32_alias_free(alias) == real


@pytest.mark.skipif(os.name != "nt", reason="Win32 name aliases exist only on Windows")
def test_win32_aliases_classify_as_memory(proj: Path) -> None:
    (proj / "CLAUDE.md").unlink()  # not on disk, so realpath can't resolve the alias
    for alias in ("CLAUDE.md.", "CLAUDE.md ", "CLAUDE.md::$DATA"):
        assert is_memory_path(proj / alias, proj), alias
    assert is_memory_path(str(proj) + r"\.claude::$INDEX_ALLOCATION\settings.json", proj)
