"""The plugin, marketplace and hooks JSON files are valid and consistent."""

import json
from pathlib import Path

from memtegrity.models import HookEvent

ROOT = Path(__file__).resolve().parents[1]


def load(rel: str) -> dict:
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def test_marketplace_entry_matches_plugin() -> None:
    plugin = load(".claude-plugin/plugin.json")
    market = load(".claude-plugin/marketplace.json")
    assert [p["name"] for p in market["plugins"]] == [plugin["name"]]
    assert market["plugins"][0]["source"] == "./"


def test_plugin_version_matches_package() -> None:
    import memtegrity

    assert load(".claude-plugin/plugin.json")["version"] == memtegrity.__version__


def test_hooks_call_known_cli_events() -> None:
    hooks = load("hooks/hooks.json")["hooks"]
    assert set(hooks) == {
        "SessionStart",
        "PreToolUse",
        "PostToolUse",
        "FileChanged",
        "ConfigChange",
        "UserPromptSubmit",
        "PostToolUseFailure",
    }
    cli_names = {e.value for e in HookEvent}
    for groups in hooks.values():
        for group in groups:
            for h in group["hooks"]:
                assert '"${CLAUDE_PLUGIN_ROOT}"' in h["command"]
                assert h["command"].split()[-1] in cli_names


def test_first_run_cannot_time_out_the_guard() -> None:
    """The first hook builds the Python environment (over a minute on a slow Windows
    machine). A PreToolUse timeout lets the write through, so its limit must be generous,
    and SessionStart (which runs first and builds the environment) must have room too."""
    hooks = load("hooks/hooks.json")["hooks"]
    assert hooks["PreToolUse"][0]["hooks"][0]["timeout"] >= 300
    assert hooks["SessionStart"][0]["hooks"][0]["timeout"] >= 300
    assert hooks["PostToolUse"][0]["matcher"] == hooks["PreToolUse"][0]["matcher"]
