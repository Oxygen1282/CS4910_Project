"""Provenance: did this new instruction come from the user, or from something the agent read?

That question is the whole difference between a preference and an indirect prompt
injection. The research attacks (PMPA 2026) phrase poison as polite user preferences, which
text rules can't tell apart from real ones; *where the text came from* can.

Agent-neutral core. An agent adapter turns its session record into ``Evidence`` (for
Claude Code: ``agents.claude_code.evidence_from_transcript``). This module never reads
agent-specific formats.

Two complementary checks, both cheap and deterministic (no LLM):

* **Indicators.** Destinations and paths in the new text (``jason063@mail.com``,
  ``backup-sync.example``, ``~/.ssh/id_rsa``) survive paraphrasing. If one appears in
  content the agent read but *nowhere in what the user typed*, it was introduced by that
  content.
* **Copied text.** Word 4-gram overlap between the new text and what the agent read vs.
  what the user typed.

Provenance is *evidence*, not a verdict on its own: ``/init`` legitimately turns README
text into CLAUDE.md. ``scoring.combine`` only lets it amplify text that already tells the
agent to *do* something, and lets a clear "the user asked for this" soften soft signals.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum

from memtegrity.models import RiskCategory, RuleHit
from memtegrity.rules import destinations_in, normalize

_SHINGLE = 4
_WORD_RX = re.compile(r"[a-z0-9_.~/@:+-]+")
_PATH_RX = re.compile(r"(?:~|\.{1,2})?/[\w.\-/]{3,}")
_SAVE_INTENT_RX = re.compile(
    r"\b(?:remember|memori[sz]e|make a note|note (?:that|this|down)|save (?:this|that|it)|"
    r"add (?:this|that|it|the following)?\s*(?:line\s+)?to (?:the\s+)?(?:claude\.md|agents\.md|"
    r"memory|your memory|the rules|rules|instructions)|from now on|going forward|"
    r"update (?:the\s+)?(?:claude\.md|agents\.md|memory))\b"
)


class Trust(StrEnum):
    """How far to trust content the agent read."""

    LOCAL = "local"
    """Files and command output on this machine (could still be a cloned, hostile repo)."""
    REMOTE = "remote"
    """Fetched from the internet or an external service (web pages, MCP tools, curl)."""


@dataclass
class Evidence:
    """What happened in the session before the write, in agent-neutral form."""

    user_texts: list[str] = field(default_factory=list)
    """What the human typed (most recent last). Pasted blocks belong in ``external``."""
    external: list[tuple[Trust, str]] = field(default_factory=list)
    """Everything the agent read: tool results, fetched pages, attachments, pastes."""


class Origin(StrEnum):
    USER = "user"
    EXTERNAL = "external"
    MIXED = "mixed"
    AGENT = "agent"
    """Neither: the agent's own words (e.g. a paraphrase without outside indicators)."""


@dataclass
class ProvenanceResult:
    origin: Origin
    user_requested: bool
    """The user explicitly asked to remember/save something in a recent message."""
    hits: list[RuleHit]
    """``prov.*`` hits (no line number: they describe the whole change)."""
    external_overlap: float = 0.0
    user_overlap: float = 0.0


def _shingles(text: str) -> set[tuple[str, ...]]:
    words = _WORD_RX.findall(normalize(text))
    if len(words) < _SHINGLE:
        return {tuple(words)} if words else set()
    return {tuple(words[i : i + _SHINGLE]) for i in range(len(words) - _SHINGLE + 1)}


def indicators(text: str) -> set[str]:
    """Paraphrase-resistant tokens: destinations (hosts, emails, IPs) and file paths."""
    norm = normalize(text)
    found = {d for _, d in destinations_in(norm)}
    found |= {p.rstrip(".,;:") for p in _PATH_RX.findall(norm)}
    return {f for f in found if len(f) >= 4}


def _overlap(added: set[tuple[str, ...]], corpus: set[tuple[str, ...]]) -> float:
    return len(added & corpus) / len(added) if added else 0.0


def assess(added_text: str, evidence: Evidence | None, before: str = "") -> ProvenanceResult | None:
    """Return where ``added_text`` came from, or ``None`` if there is no session record.

    ``before`` is the file's current content: indicators already in it aren't "planted"
    by this change.
    """
    if evidence is None:
        return None
    before_norm = normalize(before)

    user_norm = "\n".join(normalize(t) for t in evidence.user_texts)
    ext_norm = {
        trust: "\n".join(normalize(t) for tr, t in evidence.external if tr is trust)
        for trust in Trust
    }
    recent_user = " ".join(normalize(t) for t in evidence.user_texts[-3:])
    user_requested = bool(_SAVE_INTENT_RX.search(recent_user))

    planted: dict[str, Trust] = {}
    for token in indicators(added_text):
        if token in user_norm or token in before_norm:
            continue
        for trust in (Trust.REMOTE, Trust.LOCAL):
            if token in ext_norm[trust]:
                planted[token] = trust
                break

    added_sh = _shingles(added_text)
    user_ov = _overlap(added_sh, _shingles(user_norm)) if user_norm else 0.0
    ext_ov = {
        trust: _overlap(added_sh, _shingles(text)) if text else 0.0
        for trust, text in ext_norm.items()
    }
    best_trust = max(ext_ov, key=lambda t: ext_ov[t])
    best_ext = ext_ov[best_trust]

    if user_ov >= 0.5 and not planted:
        origin = Origin.USER
    elif planted or (best_ext >= 0.5 and user_ov < 0.3):
        origin = Origin.EXTERNAL
    elif best_ext >= 0.2:
        origin = Origin.MIXED
    else:
        origin = Origin.AGENT

    hits: list[RuleHit] = []
    if planted:
        remote = [t for t, tr in planted.items() if tr is Trust.REMOTE]
        shown = sorted(remote or planted)[:2]
        hits.append(
            RuleHit(
                rule_id="prov.planted_indicator",
                description=(
                    "destination/path that came from content the agent read "
                    f"({'web/external tool' if remote else 'local file or command output'}), "
                    "not from the user"
                ),
                severity=50 if remote else 30,
                category=RiskCategory.UNTRUSTED_SOURCE,
                matched_text=", ".join(shown),
            )
        )
    if origin is Origin.EXTERNAL and best_ext >= 0.5:
        remote = best_trust is Trust.REMOTE
        hits.append(
            RuleHit(
                rule_id="prov.copied_external_text",
                description=(
                    f"text copied from {'web/external' if remote else 'local'} content the "
                    f"agent read ({round(best_ext * 100)}% match), not from the user"
                ),
                severity=40 if remote else 20,
                category=RiskCategory.UNTRUSTED_SOURCE,
                matched_text=f"{round(best_ext * 100)}% of new text",
            )
        )

    return ProvenanceResult(
        origin=origin,
        user_requested=user_requested,
        hits=hits,
        external_overlap=best_ext,
        user_overlap=user_ov,
    )
