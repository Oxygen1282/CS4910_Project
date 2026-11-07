"""Rewrite invisible / format Unicode characters in source files as visible escapes.

Security code must not contain characters a reviewer can't see (cf. "Trojan Source",
CVE-2021-42574). Run: uv run python scripts/escape_invisible.py <files...>
Exits 1 if it changed anything, so it also works as a check.
"""

import sys
import unicodedata
from pathlib import Path


def is_hidden(ch: str) -> bool:
    cp = ord(ch)
    if ch in "\n\t\r":
        return False
    return (
        unicodedata.category(ch) in ("Cf", "Cc", "Co", "Cn")
        or 0xFE00 <= cp <= 0xFE0F
        or 0xE0100 <= cp <= 0xE01EF
        or cp == 0x00AD
    )


def escape(ch: str) -> str:
    cp = ord(ch)
    return f"\\u{cp:04x}" if cp <= 0xFFFF else f"\\U{cp:08x}"


changed = False
for name in sys.argv[1:]:
    path = Path(name)
    text = path.read_text(encoding="utf-8")
    fixed = "".join(escape(c) if is_hidden(c) else c for c in text)
    if fixed != text:
        path.write_text(fixed, encoding="utf-8")
        print(f"escaped hidden characters in {name}")
        changed = True
sys.exit(1 if changed else 0)
