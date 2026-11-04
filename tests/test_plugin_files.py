"""The plugin, marketplace and hooks JSON files are valid and consistent."""

import json
from pathlib import Path

from memtegrity.models import HookEvent

ROOT = Path(__file__).resolve().parents[1]


def load(rel: str) -> dict:
    return json.loads((ROOT / rel).read_text())


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
    assert set(hooks) == {"SessionStart", "PreToolUse", "FileChanged", "ConfigChange"}
    cli_names = {e.value for e in HookEvent}
    for groups in hooks.values():
        for group in groups:
            for h in group["hooks"]:
                assert '"${CLAUDE_PLUGIN_ROOT}"' in h["command"]
                assert h["command"].split()[-1] in cli_names
