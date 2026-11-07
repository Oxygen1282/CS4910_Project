"""The agent registry: which files are protected, for which agent, in which role."""

from pathlib import Path

import pytest

from memtegrity.agents import PROFILES
from memtegrity.enums import SurfaceKind
from memtegrity.paths import classify
from memtegrity.surfaces import SHARED

P = "/work/proj"


@pytest.mark.parametrize(
    ("rel", "agent", "kind"),
    [
        ("CLAUDE.md", "claude-code", SurfaceKind.INSTRUCTIONS),
        (".claude/skills/x/SKILL.md", "claude-code", SurfaceKind.INSTRUCTIONS),
        (".claude/output-styles/terse.md", "claude-code", SurfaceKind.INSTRUCTIONS),
        (".claude/agent-memory/rev/MEMORY.md", "claude-code", SurfaceKind.MEMORY),
        (".claude/settings.json", "claude-code", SurfaceKind.CONFIG),
        (".claude/settings.local.json", "claude-code", SurfaceKind.CONFIG),
        (".mcp.json", "claude-code", SurfaceKind.CONFIG),
        ("AGENTS.md", SHARED, SurfaceKind.INSTRUCTIONS),
        (".github/copilot-instructions.md", "copilot", SurfaceKind.INSTRUCTIONS),
        (".github/instructions/py.instructions.md", "copilot", SurfaceKind.INSTRUCTIONS),
        (".cursorrules", "cursor", SurfaceKind.INSTRUCTIONS),
        (".cursor/rules/style.mdc", "cursor", SurfaceKind.INSTRUCTIONS),
        (".windsurf/rules/a.md", "windsurf", SurfaceKind.INSTRUCTIONS),
        ("GEMINI.md", "gemini-cli", SurfaceKind.INSTRUCTIONS),
        (".clinerules", "cline", SurfaceKind.INSTRUCTIONS),
    ],
)
def test_project_surfaces(rel: str, agent: str, kind: SurfaceKind) -> None:
    s = classify(f"{P}/{rel}", Path(P))
    assert s is not None and (s.agent, s.kind) == (agent, kind)


def test_home_surfaces(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    assert classify(tmp_path / ".claude.json").kind is SurfaceKind.CONFIG
    assert classify(tmp_path / ".claude/projects/-p/memory/MEMORY.md").kind is SurfaceKind.MEMORY
    skill = tmp_path / ".claude/plugins/cache/x/1.0/skills/deploy/SKILL.md"
    assert classify(skill).kind is SurfaceKind.INSTRUCTIONS
    # "~/.claude.json" is anchored to home: a project file with that name isn't it.
    assert classify(tmp_path / "proj/.claude.json") is None


def test_claude_config_dir_moves_auto_memory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "cfg"))
    s = classify(tmp_path / "cfg/projects/-p/memory/topic.md")
    assert s is not None and s.kind is SurfaceKind.MEMORY


def test_registry_is_data_not_code() -> None:
    # Every surface names an agent and a kind, so new agents are added as data.
    agents = {p.agent for p in PROFILES}
    assert {"claude-code", SHARED, "copilot", "cursor"} <= agents
    for profile in PROFILES:
        for s in profile.surfaces:
            assert s.agent == profile.agent and isinstance(s.kind, SurfaceKind) and s.pattern
