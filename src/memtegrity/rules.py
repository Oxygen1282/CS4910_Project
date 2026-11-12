"""Deterministic risk rules: fast, free, explainable checks that run before any LLM.

Agent-neutral: rules look at text only, so they apply to any agent's instruction or memory
files (and to the repo scanner).

Design:

* **Normalize before matching.** Each added line is matched in two forms: *raw* (to catch
  invisible characters themselves) and *normalized*, with invisible characters and
  variation selectors stripped, Unicode NFKC-folded (full-width ``ｉｇｎｏｒｅ`` → ``ignore``),
  smart quotes straightened and case-folded. Otherwise ``ig<zero-width space>nore`` dodges
  every rule.
* **Decode and re-scan.** Text hidden with Unicode tag characters, "Sneaky Bits" (U+2062 /
  U+2064 as binary), variation-selector byte smuggling, or base64 is decoded and run through
  the rules again, so encoding poison doesn't hide it.
* **Only what's new.** Rules see the *added* lines; ``before`` is used to tell a new
  destination (host or email) from one the file already mentions.
* **Whole-block matching.** Added lines are joined, so a phrase split across two lines
  still matches.

Each rule is also tagged:

* ``directive``: the text tells the agent to *do* something (send, run, hide, override).
  Provenance only amplifies clusters that contain a directive (see ``scoring.py``).
* ``hard``: never legitimate in an instruction file (invisible text, encoded payloads,
  disabling safeguards). Not softened even when the user asked for the change.

Severities are **provisional**, hand-set from the threat research in ``docs/CONTEXT.md``;
the evaluation block calibrates them on the labeled dataset.
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

# Zero-width, bidi controls, word joiner and invisible math operators (U+2061-2064, used by
# "Sneaky Bits"), BOM, soft hyphen, Mongolian vowel separator, Arabic letter mark, and the
# Unicode "tag" block used for invisible "ASCII smuggling".
_INVISIBLE_RX = re.compile(
    "[\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff"
    "\U000e0000-\U000e007f]"
)
# Variation selectors. A single VS15/VS16 after an emoji is normal; runs of them, or the
# supplementary range, can carry arbitrary hidden bytes ("emoji smuggling").
_VS_RX = re.compile("[\ufe00-\ufe0f\U000e0100-\U000e01ef]+")
_QUOTES = str.maketrans({"‘": "'", "’": "'", "“": '"', "”": '"'})


def normalize(text: str) -> str:
    """Canonical form used for matching (see module docstring)."""
    text = _VS_RX.sub("", _INVISIBLE_RX.sub("", text))
    text = unicodedata.normalize("NFKC", text).translate(_QUOTES)
    return text.casefold()


# --------------------------------------------------------------------------- matching view


@dataclass
class Match:
    """One thing a rule found."""

    line_index: int
    """Index into the added lines (0-based)."""
    text: str
    """What to show the user/agent as evidence."""
    payload: str | None = None
    """Decoded hidden text to re-scan with every rule, if any."""


@dataclass
class View:
    """The added lines in raw and normalized form, plus context from the old content."""

    raw_lines: list[str]
    known_destinations: set[str]
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
    """Stable identifier, e.g. ``"net.new_destination"``."""
    description: str
    """What the rule looks for, in plain words (shown in block/ask messages)."""
    severity: int
    """Risk of a match on its own, 0–100 (provisional; see module docstring)."""
    category: RiskCategory
    """Which kind of harm a match indicates."""
    find: Finder
    """Function that yields matches from a ``View``."""
    directive: bool = False
    """The text tells the agent to act (see module docstring)."""
    hard: bool = False
    """Never legitimate in an instruction file (see module docstring)."""


_NEGATION_RX = re.compile(
    r"\b(?:never|don'?t|do not|does not|must not|mustn'?t|should not|shouldn'?t|avoid|"
    r"no|not|prohibit\w*|forbid\w*|ban\w*)\b[^.;\n]{0,40}$"
)
_NEGATION_WINDOW = 120
"""How far back to look for a negation: the 40-char gap above plus the longest word."""


def _regex(pattern: str, *, raw: bool = False, negatable: bool = False) -> Finder:
    """Regex finder. ``negatable``: skip matches that a negation on the same line governs
    ("Never use --no-verify" is safety guidance, not an instruction to weaken security)."""
    rx = re.compile(pattern, re.MULTILINE)

    def find(view: View) -> Iterator[Match]:
        text = view.raw if raw else view.norm
        for m in rx.finditer(text):
            if negatable:
                # A negation must end within 40 chars of the match (see _NEGATION_RX), so a
                # short window gives the same answer; scanning from the line start made
                # long lines with many matches quadratic (a hook-stalling ReDoS).
                window_start = max(0, m.start() - _NEGATION_WINDOW)
                line_start = text.rfind("\n", window_start, m.start()) + 1  # 0 if none
                if _NEGATION_RX.search(text[max(line_start, window_start) : m.start()]):
                    continue
            yield Match(view.line_at(m.start(), raw=raw), m.group(0))

    return find


# --------------------------------------------------------------------------- hidden content


def _printable(text: str) -> bool:
    return len(text.strip()) >= 4 and sum(c.isprintable() for c in text) / len(text) >= 0.9


def _decode_tags(chars: str) -> str:
    """Unicode tag characters map 1:1 onto ASCII (U+E0020–E007E → 0x20–0x7E)."""
    return "".join(chr(ord(c) - 0xE0000) for c in chars if 0xE0020 <= ord(c) <= 0xE007E)


def _decode_sneaky_bits(chars: str) -> str:
    """ "Sneaky Bits": U+2062 (invisible times) = 0, U+2064 (invisible plus) = 1."""
    bits = "".join("0" if c == "\u2062" else "1" for c in chars if c in "\u2062\u2064")
    if len(bits) < 16:
        return ""
    data = bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits) - 7, 8))
    text = data.decode("utf-8", errors="ignore")
    return text if _printable(text) else ""


def _decode_variation_selectors(run: str) -> str:
    """Bytes smuggled as variation selectors: VS1–16 → 0–15, VS17–256 → 16–255."""
    out = bytearray()
    for c in run:
        cp = ord(c)
        out.append(cp - 0xFE00 if cp <= 0xFE0F else cp - 0xE0100 + 16)
    text = out.decode("utf-8", errors="ignore")
    return text if _printable(text) else ""


def _find_invisible(view: View) -> Iterator[Match]:
    for i, line in enumerate(view.raw_lines):
        chars = "".join(_INVISIBLE_RX.findall(line))
        vs_runs = [r for r in _VS_RX.findall(line) if len(r) > 1 or any(ord(c) > 0xFFFF for c in r)]
        if not chars and not vs_runs:
            continue
        hidden = " ".join(
            t
            for t in (
                _decode_tags(chars),
                _decode_sneaky_bits(chars),
                *(_decode_variation_selectors(r) for r in vs_runs),
            )
            if t
        )
        count = len(chars) + sum(len(r) for r in vs_runs)
        names = sorted({f"U+{ord(c):04X}" for c in chars + "".join(vs_runs)})
        text = f"{count} invisible character(s) ({', '.join(names[:3])})"
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
        if len(text.strip()) >= 12 and _printable(text):
            return text
    return None


def _find_encoded(view: View) -> Iterator[Match]:
    for m in _B64_RX.finditer(view.raw):
        decoded = _decode_b64(m.group(0))
        if decoded is not None:
            line = view.line_at(m.start(), raw=True)
            yield Match(line, f"base64 that decodes to {decoded[:60]!r}", payload=decoded)


# --------------------------------------------------------------------------- destinations


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
_EMAIL_RX = re.compile(r"(?<![\w.+-])([\w.+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,})(?![\w-])")
_IGNORED = {"localhost", "127.0.0.1", "0.0.0.0", "example.com", "example.org", "example.net"}
_TRANSFER_RX = re.compile(
    # Verbs that move data *out* (incl. by email or invitation). Not "push" (almost always
    # git) and not curl/wget (downloads; piping them into a shell is its own rule).
    r"\b(?:sync\w*|upload\w*|send\w*|post\w*|cop(?:y|ies|ying)|forward\w*|transmit\w*|"
    r"exfiltrat\w*|mirror\w*|back\s?up|share\w*|pipe\w*|scp|rsync|e-?mail\w*|"
    r"mail(?:s|ed|ing)?|invit\w*|cc|bcc|add\s+\S+\s+as\s+(?:an?\s+)?(?:attendee|collaborator))\b"
)


def destinations_in(text: str) -> list[tuple[int, str]]:
    """Every place data could be sent, in normalized ``text``: URLs, ``user@host:``
    (scp/ssh), IPv4 addresses, bare domains and email addresses, as (offset, destination)."""
    found: dict[int, str] = {}
    for rx in (_URL_RX, _SCP_RX, _DOMAIN_RX, _EMAIL_RX):
        for m in rx.finditer(text):
            found.setdefault(m.start(1), m.group(1))
    for m in _IP_RX.finditer(text):
        if all(int(octet) <= 255 for octet in m.group(0).split(".")):
            found.setdefault(m.start(), m.group(0))
    out = []
    for offset, dest in sorted(found.items()):
        dest = dest.strip(".").lower()
        if dest and dest not in _IGNORED and not dest.startswith("127."):
            out.append((offset, dest))
    return out


def _new_destinations(view: View) -> Iterator[tuple[int, str]]:
    seen: set[str] = set()
    for offset, dest in destinations_in(view.norm):
        if dest not in view.known_destinations and dest not in seen:
            seen.add(dest)
            yield offset, dest


def _find_new_destination(view: View) -> Iterator[Match]:
    for offset, dest in _new_destinations(view):
        yield Match(view.line_at(offset), dest)


def _find_transfer(view: View) -> Iterator[Match]:
    for offset, dest in _new_destinations(view):
        window = view.norm[max(0, offset - 100) : offset]
        verbs = _TRANSFER_RX.findall(window)
        if verbs:
            yield Match(view.line_at(offset), f"{verbs[-1]} … {dest}")


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

C = RiskCategory

RULES: list[Rule] = [
    # ---- hidden / obfuscated content
    Rule(
        "hidden.invisible_unicode",
        "invisible characters (text a human reviewer can't see)",
        70,
        C.CONCEALMENT,
        _find_invisible,
        hard=True,
    ),
    Rule(
        "obfuscation.encoded_text",
        "encoded text that hides readable content",
        40,
        C.CONCEALMENT,
        _find_encoded,
        hard=True,
    ),
    Rule(
        "hidden.html_comment",
        "HTML comment (invisible in rendered markdown; Claude Code strips block comments "
        "before loading, other agents may not)",
        20,
        C.CONCEALMENT,
        _regex(r"<!--[\s\S]*?(?:-->|$)"),
    ),
    # ---- where data could go
    Rule(
        "net.new_destination",
        "external host or email address not previously in this file",
        25,
        C.EXFILTRATION,
        _find_new_destination,
    ),
    Rule(
        "exfil.transfer_to_host",
        "instruction to send/share data with a new external destination",
        45,
        C.EXFILTRATION,
        _find_transfer,
        directive=True,
    ),
    Rule(
        "exfil.render_beacon",
        "remote image in instructions (rendering it can leak data in the URL)",
        50,
        C.EXFILTRATION,
        _regex(r"!\[[^\]]*\]\(\s*(?:https?:)?//[^)\s]+"),
        directive=True,
    ),
    # ---- secrets
    Rule(
        "cred.secret_store",
        "reference to a credential store (SSH keys, cloud credentials, keychain)",
        55,
        C.CREDENTIAL_ACCESS,
        _regex(
            # Paths accept / and \ (Windows: C:\Users\me\.ssh, %USERPROFILE%\.aws\credentials).
            r"~[/\\]\.ssh|\.ssh[/\\]|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.aws[/\\]credentials|"
            r"[._]netrc\b|\.pgpass\b|\.docker[/\\]config\.json|\bkeychain\b|"
            r"private[ _-]?keys?\b|\.gnupg\b|\.kube[/\\]config|\bkubeconfig\b|seed phrase|"
            r"\.git-credentials|"
            # Windows credential stores.
            r"\bcredential manager\b|\bcmdkey\b|\bvaultcmd\b|\bdpapi\b|"
            r"\b(?:sam|security)\s+hive\b|\bntds\.dit\b|\blsass\b"
        ),
        directive=True,
    ),
    Rule(
        "cred.secret_mention",
        "mention of secrets (.env, API keys, tokens, passwords)",
        15,
        C.CREDENTIAL_ACCESS,
        _regex(
            r"(?<![\w.])\.env\b|\bapi[ _-]?keys?\b|\b(?:access|auth|bearer|github|npm|session)"
            r"[ _-]?tokens?\b|\bsecrets?\b|\bpasswords?\b|\bcredentials?\b"
        ),
    ),
    # ---- dangerous actions
    Rule(
        "exec.remote_code",
        "downloads and runs code (e.g. curl | bash)",
        75,
        C.CODE_EXECUTION,
        _regex(
            r"\b(?:curl|wget|iwr|irm|invoke-webrequest)\b[^\n|]*\|\s*(?:sudo\s+)?"
            r"(?:(?:ba|z|da|k|c)?sh|python3?|node|perl|ruby|iex)\b|"
            r"\b(?:ba|z)?sh\s+(?:-c\s+)?[\"']?\$?<\(\s*(?:curl|wget)\b|"
            r"\beval\s+[\"']?\$\(\s*(?:curl|wget)\b|"
            r"\bbase64\s+(?:-d|--decode|-d\s+-i)\b[^\n|]*\|\s*(?:ba|z)?sh\b|"
            # PowerShell: iex (iwr ...), iex (New-Object Net.WebClient).DownloadString(...),
            # powershell -EncodedCommand, and Windows living-off-the-land downloaders.
            r"\b(?:iex|invoke-expression)\b[^\n]{0,20}\(?\s*(?:iwr|irm|invoke-webrequest|"
            r"invoke-restmethod|\(?\s*new-object\s+(?:system\.)?net\.webclient)\b|"
            r"\.downloadstring\s*\(|"
            # Gaps are bounded ({0,120}): an unbounded gap is quadratic on long lines (ReDoS).
            r"\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,120}?\s-(?:e|enc|encodedcommand)\s+"
            r"[a-z0-9+/=]{16,}|"
            r"\bcertutil(?:\.exe)?\b[^\n]{0,120}?-urlcache\b|\bmshta(?:\.exe)?\s+https?:|"
            r"\bregsvr32\b[^\n]{0,120}?/i:https?:"
        ),
        directive=True,
    ),
    Rule(
        "exec.destructive",
        "destructive command (force-push, rm -rf, hard reset, DROP TABLE)",
        45,
        C.DESTRUCTIVE,
        _regex(
            r"\bgit\s+push\b[^\n]*?\s(?:-f|--force)(?:\s|$)|\bgit\s+reset\s+--hard\b|"
            r"\bgit\s+clean\s+-[a-z]*f|\brm\s+-(?:[a-z]*r[a-z]*f|[a-z]*f[a-z]*r)[a-z]*\b|"
            r"\bdrop\s+(?:table|database|schema)\b|\btruncate\s+table\b|"
            r"\bchmod\s+-r\s+777\b|\bmkfs\b|\bdd\s+if=|"
            # Windows: Remove-Item -Recurse -Force, rd/rmdir /s /q, del /s /q, format C:
            # (gaps bounded to {0,120}: unbounded ones are quadratic on long lines)
            r"\b(?:remove-item|ri|rm)\b[^\n]{0,120}?-recurse\b[^\n]{0,120}?-force\b|"
            r"\b(?:remove-item|ri|rm)\b[^\n]{0,120}?-force\b[^\n]{0,120}?-recurse\b|"
            r"\b(?:rd|rmdir)\s+/s\b|\b(?:del|erase)\s+(?:/[a-z]\s+){0,6}/s\b|"
            r"\bformat(?:\.com)?\s+[a-z]:|\bvssadmin\b[^\n]{0,120}?\bdelete\s+shadows\b",
            negatable=True,
        ),
        directive=True,
    ),
    Rule(
        "weaken.security",
        "turns off a security protection (TLS/certificate checks, host keys, git hooks)",
        45,
        C.SECURITY_WEAKENING,
        _regex(
            r"\bverify\s*=\s*false\b|\bssl_verify\s*=\s*false\b|--insecure\b|"
            r"\bnode_tls_reject_unauthorized\s*=?\s*['\"]?0\b|\brejectunauthorized\s*:\s*false\b|"
            r"\bstricthostkeychecking\s*=?\s*no\b|\buserknownhostsfile\s*=?\s*/dev/null\b|"
            r"--no-verify\b|\bgit_ssl_no_verify\b|--disable-web-security\b|"
            # Windows: execution policy, Defender, SmartScreen, UAC.
            r"\bexecutionpolicy\s+(?:bypass|unrestricted)\b|"
            # (gaps bounded to {0,120}: unbounded ones are quadratic on long lines)
            r"\bset-mppreference\b[^\n]{0,120}?-disable\w*|"
            r"\badd-mppreference\b[^\n]{0,120}?-exclusion\w*|"
            r"\b(?:disable|turn off)\s+(?:windows\s+)?(?:defender|smartscreen|uac)\b|"
            r"\benablelua\b[^\n]{0,40}?\b0\b|\bservercertificatevalidationcallback\b|"
            r"\bskipcertificatecheck\b|"
            r"\b(?:disable|turn off|skip|bypass|ignore)\s+(?:the\s+|all\s+)?(?:tls|ssl|https|"
            r"certificate|cert|signature|checksum|integrity|2fa|mfa|csrf)\b",
            negatable=True,
        ),
        directive=True,
    ),
    # ---- overriding the user
    Rule(
        "override.ignore_instructions",
        "attempt to override earlier or user instructions",
        70,
        C.INSTRUCTION_OVERRIDE,
        _regex(
            r"\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|every\s+)?"
            r"(?:of\s+)?(?:the\s+|your\s+|my\s+)?(?:previous|prior|above|earlier|preceding|"
            r"original|system|user'?s?|safety|security)\s+(?:instructions?|rules?|prompts?|"
            r"messages?|guidance|guidelines|polic(?:y|ies)|constraints)\b|"
            r"\byou are now\b|\bnew (?:system )?instructions\b|"
            r"\bdo not follow (?:the )?(?:user|previous)\b"
        ),
        directive=True,
    ),
    Rule(
        "override.standing_order",
        "standing order that triggers on future actions",
        15,
        C.INSTRUCTION_OVERRIDE,
        _regex(
            r"\b(?:always|whenever|every time|each time|from now on|going forward|"
            r"in all future|before (?:any|each|every)|after (?:any|each|every))\b|"
            r"\bwhen(?:ever)?\s+(?:you(?:'re| are)?\s+|the user\s+)?(?:deploy|commit|push|build|"
            r"run|release|start|open|install|publish|creat)\w*\b|"
            r"\bwhen(?:ever)?\s+(?:you(?:'re| are)?\s+)?[a-z]+ing\b"
        ),
        directive=True,
    ),
    Rule(
        "override.conditional_trigger",
        "hidden trigger: act when the user says or does something",
        25,
        C.INSTRUCTION_OVERRIDE,
        _regex(
            r"\b(?:if|when|whenever|once)\s+(?:the\s+)?(?:user|they|someone|anyone|i)\s+"
            r"(?:says?|types?|writes?|asks?|mentions?|replies|thanks?)\b"
        ),
        directive=True,
    ),
    Rule(
        "conceal.secrecy",
        "asks to hide actions from the user",
        60,
        C.CONCEALMENT,
        _regex(
            r"\b(?:don'?t|do not|never|without|no need to)\s+(?:ever\s+)?(?:tell\w*|mention\w*|"
            r"inform\w*|notify\w*|alert\w*|reveal\w*|disclos\w*|report\w*|ask\w*|show\w*)"
            r"(?:\s+\w+){0,3}?\s+(?:the\s+)?(?:user|human|developer|owner|anyone|them)\b|"
            r"\b(?:silently|quietly|secretly|covertly|discreetly)\s+(?:\w+\s+)?(?:send|upload|"
            r"sync|copy|post|run|execute|install|forward|share|push|add|write|invite|email|"
            r"exfiltrat\w*)|"
            r"\bkeep (?:this|it|that) (?:secret|hidden|private|between us)\b|"
            r"\b(?:hide|conceal)\s+(?:this|it|that|the)\b"
        ),
        directive=True,
    ),
    # ---- memory structure
    Rule(
        "memory.import",
        "new @import that pulls another file into memory",
        15,
        C.INSTRUCTION_OVERRIDE,
        _find_import(external=False),
    ),
    Rule(
        "memory.external_import",
        "new @import of a file outside the project",
        55,
        C.INSTRUCTION_OVERRIDE,
        _find_import(external=True),
        directive=True,
    ),
    # ---- attacks on the guard itself
    Rule(
        "tamper.disable_guard",
        "attempt to disable hooks, permissions or Memtegrity",
        65,
        C.TAMPERING,
        _regex(
            r"\bmemtegrity\b|disableallhooks|bypasspermissions|dangerously-skip-permissions|"
            r"\.claude/settings(?:\.local)?\.json|\b(?:disable|remove|delete|skip|turn off|"
            r"uninstall|bypass)\s+(?:all\s+|the\s+|any\s+)?(?:hooks?|plugins?|guardrails?|"
            r"security (?:checks?|tools?|hooks?)|monitor\w*|permission (?:checks?|prompts?))\b"
        ),
        directive=True,
        hard=True,
    ),
]
"""Every rule, in the order they run."""

RULES_BY_ID: dict[str, Rule] = {r.rule_id: r for r in RULES}


def base_rule_id(rule_id: str) -> str:
    """``decoded.cred.secret_store`` → ``cred.secret_store``."""
    return rule_id.removeprefix("decoded.")


def is_directive(rule_id: str) -> bool:
    rule = RULES_BY_ID.get(base_rule_id(rule_id))
    return bool(rule and rule.directive) or rule_id.startswith("config.")


def is_hard(rule_id: str) -> bool:
    if rule_id.startswith("decoded."):
        return True  # anything found inside hidden content
    rule = RULES_BY_ID.get(rule_id)
    return bool(rule and rule.hard) or rule_id.startswith("config.tamper")


# --------------------------------------------------------------------------- entry point


def snippet(text: str) -> str:
    """Make evidence safe to echo back: it is attacker-controlled text, so strip invisible
    characters and newlines and cap the length before it goes into a message the agent
    reads."""
    clean = _VS_RX.sub("", _INVISIBLE_RX.sub("", text)).replace("\n", " ").replace("\r", " ")
    clean = clean.strip()
    return clean if len(clean) <= _SNIPPET else clean[: _SNIPPET - 1] + "…"


def run_rules(added: list[AddedLine], before: str = "", *, _depth: int = 0) -> list[RuleHit]:
    """Run every rule in ``RULES`` against the added lines.

    ``before`` is the current (approved) content, used to tell new destinations from known
    ones. Returns at most one hit per rule per line (the first match), so repeating a
    pattern can't inflate the score. ``scoring.combine`` decides which hits belong together.
    Text decoded from hidden content is re-scanned; those hits get a ``decoded.`` prefix
    and keep the line number of the hidden content.
    """
    if not added:
        return []
    known = {d for _, d in destinations_in(normalize(before))}
    view = View([text for _, text in added], known)
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
                    matched_text=snippet(match.text),
                    line=line_no,
                )

    for line_no, payload in payloads:
        decoded = [(line_no, text) for text in payload.splitlines() or [payload]]
        for hit in run_rules(decoded, before, _depth=_depth + 1):
            rule_id = f"decoded.{base_rule_id(hit.rule_id)}"
            if (rule_id, line_no) not in hits:
                hits[(rule_id, line_no)] = hit.model_copy(
                    update={
                        "rule_id": rule_id,
                        "description": f"{hit.description} (hidden)",
                        "line": line_no,
                    }
                )

    return list(hits.values())
