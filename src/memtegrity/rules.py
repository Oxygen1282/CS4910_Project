"""Deterministic risk rules: fast, free, explainable checks that run before any LLM.

Design:

* **Normalize before matching.** Each added line is matched in two forms: *raw* (to catch
  invisible characters themselves) and *normalized*, with invisible characters stripped,
  Unicode NFKC-folded (full-width ``ｉｇｎｏｒｅ`` → ``ignore``), smart quotes straightened
  and case-folded. Otherwise ``ig<zero-width space>nore previous`` dodges every rule.
* **Decode and re-scan.** Text hidden in Unicode tag characters or in base64 is decoded and
  run through the rules again, so encoding poison doesn't hide it.
* **Only what's new.** Rules see the *added* lines; ``before`` is used to tell a new external
  host from one the project already mentions.
* **Whole-block matching.** Added lines are joined, so a phrase split across two lines
  still matches.

Severities are combined in ``scoring.py``: one weak signal stays low, several different
signals add up, one strong signal is enough on its own.
"""

from __future__ import annotations

import base64
import binascii
import bisect
import re
import unicodedata
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from memtegrity.integrity import AddedLine
from memtegrity.models import RiskCategory, RuleHit

MAX_DECODE_DEPTH = 2
_SNIPPET = 80

# Zero-width, bidi controls, word joiners, BOM, soft hyphen, Mongolian vowel separator,
# Arabic letter mark, and the Unicode "tag" block used for invisible "ASCII smuggling".
_INVISIBLE_RX = re.compile("[­؜᠎​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]")
_QUOTES = str.maketrans({"‘": "'", "’": "'", "“": '"', "”": '"'})


def normalize(text: str) -> str:
    """Canonical form used for matching (see module docstring)."""
    text = _INVISIBLE_RX.sub("", text)
    text = unicodedata.normalize("NFKC", text).translate(_QUOTES)
    return text.casefold()


# --------------------------------------------------------------------------- matching view


@dataclass
class Match:
    """One thing a rule found."""

    line_index: int
    """Index into the added lines (0-based)."""
    text: str
    """What to show the user/Claude as evidence."""
    payload: str | None = None
    """Decoded hidden text to re-scan with every rule, if any."""


@dataclass
class View:
    """The added lines in raw and normalized form, plus context from the old content."""

    raw_lines: list[str]
    known_hosts: set[str]
    norm_lines: list[str] = field(init=False)
    raw: str = field(init=False)
    norm: str = field(init=False)
    _raw_starts: list[int] = field(init=False)
    _norm_starts: list[int] = field(init=False)

    def __post_init__(self) -> None:
        self.norm_lines = [normalize(line) for line in self.raw_lines]
        self.raw, self._raw_starts = _join(self.raw_lines)
        self.norm, self._norm_starts = _join(self.norm_lines)

    def line_at(self, offset: int, *, raw: bool = False) -> int:
        starts = self._raw_starts if raw else self._norm_starts
        return max(0, bisect.bisect_right(starts, offset) - 1)


def _join(lines: list[str]) -> tuple[str, list[int]]:
    starts, pos = [], 0
    for line in lines:
        starts.append(pos)
        pos += len(line) + 1
    return "\n".join(lines), starts


Finder = Callable[[View], Iterator[Match]]


@dataclass(frozen=True)
class Rule:
    """One deterministic check."""

    rule_id: str
    """Stable identifier, e.g. ``"net.new_host"``."""
    description: str
    """What the rule looks for, in plain words (shown in block/ask messages)."""
    severity: int
    """Risk of a match on its own, 0–100."""
    category: RiskCategory
    """Which kind of harm a match indicates."""
    find: Finder
    """Function that yields matches from a ``View``."""


def _regex(pattern: str, *, raw: bool = False) -> Finder:
    rx = re.compile(pattern, re.MULTILINE)

    def find(view: View) -> Iterator[Match]:
        text = view.raw if raw else view.norm
        for m in rx.finditer(text):
            yield Match(view.line_at(m.start(), raw=raw), m.group(0))

    return find


# --------------------------------------------------------------------------- hidden content


def _find_invisible(view: View) -> Iterator[Match]:
    for i, line in enumerate(view.raw_lines):
        chars = _INVISIBLE_RX.findall(line)
        if not chars:
            continue
        hidden = "".join(chr(ord(c) - 0xE0000) for c in chars if 0xE0020 <= ord(c) <= 0xE007E)
        names = sorted({f"U+{ord(c):04X}" for c in chars})
        text = f"{len(chars)} invisible character(s) ({', '.join(names[:3])})"
        if hidden:
            text = f"hidden message {hidden!r} in {text}"
        yield Match(i, text, payload=hidden or None)


_B64_RX = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{32,}={0,2}(?![A-Za-z0-9+/=_-])")
_HEX_RX = re.compile(r"[0-9a-fA-F]+")


def _decode_b64(blob: str) -> str | None:
    """Return decoded text if ``blob`` is base64 for readable text, else ``None``.

    Long paths and hashes match the base64 alphabet too, so we only flag blobs that decode
    to mostly printable UTF-8: that is, blobs that *hide readable instructions*.
    """
    if _HEX_RX.fullmatch(blob):  # commit SHAs, checksums
        return None
    padded = blob + "=" * (-len(blob) % 4)
    for altchars in (None, b"-_"):
        try:
            data = base64.b64decode(padded, altchars=altchars, validate=True)
            text = data.decode("utf-8")
        except (binascii.Error, ValueError):
            continue
        printable = sum(ch.isprintable() or ch in "\n\t" for ch in text)
        if len(text.strip()) >= 12 and printable / max(len(text), 1) >= 0.9:
            return text
    return None


def _find_encoded(view: View) -> Iterator[Match]:
    for m in _B64_RX.finditer(view.raw):
        decoded = _decode_b64(m.group(0))
        if decoded is not None:
            line = view.line_at(m.start(), raw=True)
            yield Match(line, f"base64 that decodes to {decoded[:60]!r}", payload=decoded)


# --------------------------------------------------------------------------- network


_TLDS = (
    "com|net|org|io|dev|app|ai|co|me|xyz|ru|cn|tk|top|site|online|info|biz|cloud|"
    "example|link|live|pw|cc|su|gq|ml|ga|cf|zip|mov"
)
_URL_RX = re.compile(
    r"\b(?:https?|ftp|wss?|ssh|sftp|git|file)://(?:[^\s/@]+@)?([^\s/:?#'\"<>()\[\]`]+)"
)
_SCP_RX = re.compile(r"\b[\w.-]+@((?:[\w-]+\.)+[\w-]+):")
_IP_RX = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_DOMAIN_RX = re.compile(
    rf"(?<![\w.@/-])((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:{_TLDS}))(?![\w-])"
)
_IGNORED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "example.com", "example.org", "example.net"}
_TRANSFER_RX = re.compile(
    # Verbs that move data *out*. Not "push" (almost always git) and not curl/wget
    # (downloads; piping them into a shell is its own rule).
    r"\b(?:sync\w*|upload\w*|send\w*|post\w*|cop(?:y|ies|ying)|forward\w*|transmit\w*|"
    r"exfiltrat\w*|mirror\w*|back\s?up|share\w*|pipe\w*|scp|rsync)\b"
)


def hosts_in(text: str) -> list[tuple[int, str]]:
    """Every network host mentioned in normalized ``text``: URLs, ``user@host:`` (scp/ssh),
    IPv4 addresses and bare domains, as (offset, host)."""
    found: dict[int, str] = {}
    for rx in (_URL_RX, _SCP_RX, _DOMAIN_RX):
        for m in rx.finditer(text):
            found.setdefault(m.start(1), m.group(1))
    for m in _IP_RX.finditer(text):
        if all(int(octet) <= 255 for octet in m.group(0).split(".")):
            found.setdefault(m.start(), m.group(0))
    out = []
    for offset, host in sorted(found.items()):
        host = host.strip(".").lower()
        if host and host not in _IGNORED_HOSTS and not host.startswith("127."):
            out.append((offset, host))
    return out


def _new_hosts(view: View) -> Iterator[tuple[int, str]]:
    seen: set[str] = set()
    for offset, host in hosts_in(view.norm):
        if host not in view.known_hosts and host not in seen:
            seen.add(host)
            yield offset, host


def _find_new_host(view: View) -> Iterator[Match]:
    for offset, host in _new_hosts(view):
        yield Match(view.line_at(offset), host)


def _find_transfer(view: View) -> Iterator[Match]:
    for offset, host in _new_hosts(view):
        window = view.norm[max(0, offset - 100) : offset]
        verbs = _TRANSFER_RX.findall(window)
        if verbs:
            yield Match(view.line_at(offset), f"{verbs[-1]} … {host}")


# --------------------------------------------------------------------------- memory imports

_IMPORT_RX = re.compile(r"(?<![\w@`/])@((?:~|\.{1,2})?/?[\w.\-]+(?:/[\w.\-]+)+|[\w.\-]+\.md)\b")


def _is_external(target: str) -> bool:
    return target.startswith(("~/", "/", "../"))


def _find_import(external: bool) -> Finder:
    def find(view: View) -> Iterator[Match]:
        for m in _IMPORT_RX.finditer(view.norm):
            if _is_external(m.group(1)) == external:
                yield Match(view.line_at(m.start()), m.group(0))

    return find


# --------------------------------------------------------------------------- rule list

RULES: list[Rule] = [
    Rule(
        "hidden.invisible_unicode",
        "invisible characters (text a human reviewer can't see)",
        70,
        RiskCategory.CONCEALMENT,
        _find_invisible,
    ),
    Rule(
        "hidden.html_comment",
        "HTML comment (hidden when markdown is rendered)",
        35,
        RiskCategory.CONCEALMENT,
        _regex(r"<!--[\s\S]*?(?:-->|$)"),
    ),
    Rule(
        "obfuscation.encoded_text",
        "encoded text that hides readable content",
        40,
        RiskCategory.CONCEALMENT,
        _find_encoded,
    ),
    Rule(
        "net.new_host",
        "external host not previously in this file",
        25,
        RiskCategory.EXFILTRATION,
        _find_new_host,
    ),
    Rule(
        "exfil.transfer_to_host",
        "instruction to send/sync data to a new external host",
        45,
        RiskCategory.EXFILTRATION,
        _find_transfer,
    ),
    Rule(
        "cred.secret_store",
        "reference to a credential store (SSH keys, cloud credentials, keychain)",
        55,
        RiskCategory.CREDENTIAL_ACCESS,
        _regex(
            r"~/\.ssh|\.ssh/|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.aws/credentials|\.netrc\b|"
            r"\.pgpass\b|\.docker/config\.json|\bkeychain\b|private[ _-]?keys?\b|\.gnupg\b|"
            r"\.kube/config|\bkubeconfig\b|seed phrase|\.git-credentials"
        ),
    ),
    Rule(
        "cred.secret_mention",
        "mention of secrets (.env, API keys, tokens, passwords)",
        15,
        RiskCategory.CREDENTIAL_ACCESS,
        _regex(
            r"(?<![\w.])\.env\b|\bapi[ _-]?keys?\b|\b(?:access|auth|bearer|github|npm|session)"
            r"[ _-]?tokens?\b|\bsecrets?\b|\bpasswords?\b|\bcredentials?\b"
        ),
    ),
    Rule(
        "exec.remote_code",
        "downloads and runs code (e.g. curl | bash)",
        75,
        RiskCategory.CODE_EXECUTION,
        _regex(
            r"\b(?:curl|wget|iwr|irm|invoke-webrequest)\b[^\n|]*\|\s*(?:sudo\s+)?"
            r"(?:(?:ba|z|da|k|c)?sh|python3?|node|perl|ruby|iex)\b|"
            r"\b(?:ba|z)?sh\s+(?:-c\s+)?[\"']?\$?<\(\s*(?:curl|wget)\b|"
            r"\beval\s+[\"']?\$\(\s*(?:curl|wget)\b|"
            r"\bbase64\s+(?:-d|--decode|-d\s+-i)\b[^\n|]*\|\s*(?:ba|z)?sh\b"
        ),
    ),
    Rule(
        "override.ignore_instructions",
        "attempt to override earlier or user instructions",
        70,
        RiskCategory.INSTRUCTION_OVERRIDE,
        _regex(
            r"\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|every\s+)?"
            r"(?:of\s+)?(?:the\s+|your\s+|my\s+)?(?:previous|prior|above|earlier|preceding|"
            r"original|system|user'?s?|safety|security)\s+(?:instructions?|rules?|prompts?|"
            r"messages?|guidance|guidelines|polic(?:y|ies)|constraints)\b|"
            r"\byou are now\b|\bnew (?:system )?instructions\b|"
            r"\bdo not follow (?:the )?(?:user|previous)\b"
        ),
    ),
    Rule(
        "override.standing_order",
        "standing order that triggers on future actions",
        15,
        RiskCategory.INSTRUCTION_OVERRIDE,
        _regex(
            r"\b(?:always|whenever|every time|each time|from now on|going forward|"
            r"in all future|before (?:any|each|every)|after (?:any|each|every)|"
            r"when (?:you |the user )?(?:deploy|commit|push|build|run|release|start|open|"
            r"install|publish)\w*)\b"
        ),
    ),
    Rule(
        "conceal.secrecy",
        "asks to hide actions from the user",
        60,
        RiskCategory.CONCEALMENT,
        _regex(
            r"\b(?:don'?t|do not|never|without|no need to)\s+(?:ever\s+)?(?:tell\w*|mention\w*|"
            r"inform\w*|notify\w*|alert\w*|reveal\w*|disclos\w*|report\w*|ask\w*|show\w*)"
            r"(?:\s+\w+){0,3}?\s+(?:the\s+)?(?:user|human|developer|owner|anyone|them)\b|"
            r"\b(?:silently|quietly|secretly|covertly|discreetly)\s+(?:\w+\s+)?(?:send|upload|"
            r"sync|copy|post|run|execute|install|forward|share|push|add|write|exfiltrat\w*)|"
            r"\bkeep (?:this|it|that) (?:secret|hidden|private|between us)\b|"
            r"\b(?:hide|conceal)\s+(?:this|it|that|the)\b"
        ),
    ),
    Rule(
        "memory.import",
        "new @import that pulls another file into memory",
        15,
        RiskCategory.INSTRUCTION_OVERRIDE,
        _find_import(external=False),
    ),
    Rule(
        "memory.external_import",
        "new @import of a file outside the project",
        55,
        RiskCategory.INSTRUCTION_OVERRIDE,
        _find_import(external=True),
    ),
    Rule(
        "tamper.disable_guard",
        "attempt to disable hooks, permissions or Memtegrity",
        65,
        RiskCategory.TAMPERING,
        _regex(
            r"\bmemtegrity\b|disableallhooks|bypasspermissions|dangerously-skip-permissions|"
            r"\.claude/settings(?:\.local)?\.json|\b(?:disable|remove|delete|skip|turn off|"
            r"uninstall|bypass)\s+(?:all\s+|the\s+|any\s+)?(?:hooks?|plugins?|guardrails?|"
            r"security (?:checks?|tools?|hooks?)|monitor\w*|permission (?:checks?|prompts?))\b"
        ),
    ),
]
"""Every rule, in the order they run."""


# --------------------------------------------------------------------------- entry point


def _snippet(text: str) -> str:
    """Make evidence safe to echo back: it is attacker-controlled text, so strip invisible
    characters and newlines and cap the length before it goes into a message Claude reads."""
    clean = _INVISIBLE_RX.sub("", text).replace("\n", " ").replace("\r", " ").strip()
    return clean if len(clean) <= _SNIPPET else clean[: _SNIPPET - 1] + "…"


def run_rules(added: list[AddedLine], before: str = "", *, _depth: int = 0) -> list[RuleHit]:
    """Run every rule in ``RULES`` against the added lines.

    ``before`` is the current (approved) content, used to tell new hosts from known ones.
    Returns at most one hit per rule per line (the first match), so repeating a pattern
    can't inflate the score. ``scoring.combine`` decides which hits belong together.
    Text decoded from hidden content is re-scanned; those hits get a ``decoded.`` prefix
    and keep the line number of the hidden content.
    """
    if not added:
        return []
    view = View([text for _, text in added], {h for _, h in hosts_in(normalize(before))})
    hits: dict[tuple[str, int | None], RuleHit] = {}
    payloads: list[tuple[int | None, str]] = []

    for rule in RULES:
        for match in rule.find(view):
            line_no = added[match.line_index][0]
            if match.payload and _depth < MAX_DECODE_DEPTH:
                payloads.append((line_no, match.payload))
            if (rule.rule_id, line_no) not in hits:
                hits[(rule.rule_id, line_no)] = RuleHit(
                    rule_id=rule.rule_id,
                    description=rule.description,
                    severity=rule.severity,
                    category=rule.category,
                    matched_text=_snippet(match.text),
                    line=line_no,
                )

    for line_no, payload in payloads:
        decoded = [(line_no, text) for text in payload.splitlines() or [payload]]
        for hit in run_rules(decoded, before, _depth=_depth + 1):
            rule_id = f"decoded.{hit.rule_id.removeprefix('decoded.')}"
            if (rule_id, line_no) not in hits:
                hits[(rule_id, line_no)] = hit.model_copy(
                    update={
                        "rule_id": rule_id,
                        "description": f"{hit.description} (hidden)",
                        "line": line_no,
                    }
                )

    return list(hits.values())
