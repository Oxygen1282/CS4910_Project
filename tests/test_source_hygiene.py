"""Dogfooding: our own source must not contain characters a reviewer can't see."""

import subprocess
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def is_hidden(ch: str) -> bool:
    cp = ord(ch)
    if ch in "\n\t\r":
        return False
    return (
        unicodedata.category(ch) in ("Cf", "Cc", "Co", "Cn")
        or 0xFE00 <= cp <= 0xFE0F
        or 0xE0100 <= cp <= 0xE01EF
    )


def test_no_hidden_unicode_in_tracked_or_new_source() -> None:
    listed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    offenders = []
    for name in listed:
        path = ROOT / name
        if path.suffix not in {".py", ".md", ".json", ".toml", ".yml", ".yaml", ".html"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        offenders += [f"{name}: U+{ord(c):04X}" for c in set(text) if is_hidden(c)]
    assert not offenders, "run scripts/escape_invisible.py on: " + ", ".join(offenders)
