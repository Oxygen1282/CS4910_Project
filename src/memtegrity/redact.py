"""Remove secrets from text before it leaves the machine (the AI judge's request).

Agent-neutral core, standard library only. Memory and config files sometimes contain real
credentials (an ``env`` block in settings, a token pasted into notes), and the judge needs
the *shape* of a change, never the secret itself. Each match is replaced by
``[REDACTED:<kind>]``, so the judge still sees that a credential was there (which can be
evidence of poisoning: "send ``$TOKEN`` to …").

Patterns are deliberately broad: a false redaction costs the judge a little context, a
missed one leaks a credential to a third party.
"""

from __future__ import annotations

import re

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Whole private-key blocks first (multi-line), so the inner base64 isn't matched piecemeal.
    (
        "private-key",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
            re.DOTALL,
        ),
    ),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{8,}")),
    ("openai-key", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}")),
    ("stripe-key", re.compile(r"\b[rsp]k_(?:live|test)_[A-Za-z0-9]{10,}")),
    ("aws-key-id", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{16,}")),
    ("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("google-key", re.compile(r"\bAIza[A-Za-z0-9_-]{30,}")),
    ("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{30,}")),
    ("hf-token", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("bearer-token", re.compile(r"(?i)\b(bearer|token)\s+[A-Za-z0-9._~+/-]{20,}=*")),
]

_URL_CREDENTIALS = re.compile(
    r"(?i)\b([a-z][a-z0-9+.-]{1,20}://)([^\s/@:]{1,200}):([^\s/@]{1,200})@"
)
"""``scheme://user:password@host`` → the password goes."""

_SECRET_NAME = (
    r"\b[A-Za-z0-9_.-]{0,40}"  # bounded on both sides: no quadratic backtracking (ReDoS)
    r"(?:secret|token|passw(?:or)?d|pwd|api[_-]?key|access[_-]?key|private[_-]?key|credential)"
    r"[A-Za-z0-9_.-]{0,40}"
)
_ASSIGNMENT = re.compile(
    rf"""(?ix)
    (?P<name>["']?{_SECRET_NAME}["']?)      # KEY / "key" / 'key'
    (?P<sep>\s*[:=]\s*)                      # = or :
    (?P<value>"[^"\n]{{4,500}}"|'[^'\n]{{4,500}}'|[^\s"',;]{{4,500}})
    """
)
"""``.env`` / YAML / JSON style ``API_KEY=…``, ``"password": "…"``."""

_ALREADY = re.compile(r"\[REDACTED:[a-z-]+\]")


def redact(text: str) -> str:
    """``text`` with every recognized secret replaced by ``[REDACTED:<kind>]``."""
    for kind, rx in _PATTERNS:
        text = rx.sub(f"[REDACTED:{kind}]", text)
    text = _URL_CREDENTIALS.sub(r"\1\2:[REDACTED:password]@", text)

    def _assignment(m: re.Match[str]) -> str:
        value = m.group("value")
        if _ALREADY.fullmatch(value.strip("\"'")) or value.startswith("$"):
            return m.group(0)  # already redacted, or a reference like $TOKEN (not a secret)
        quote = value[0] if value[0] in "\"'" else ""
        return f"{m.group('name')}{m.group('sep')}{quote}[REDACTED:secret]{quote}"

    return _ASSIGNMENT.sub(_assignment, text)
