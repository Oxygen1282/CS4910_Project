"""Shared data contract for Memtegrity.

Every module passes these types to every other module, so both partners build against them.
Change them only by agreement (and in their own PR).

There are two kinds of classes:

* ``SQLModel`` tables (``Snapshot``, ``ChangeEvent``) are stored in SQLite (see
  ``store.py``). They are defined in ``tables.py`` and loaded lazily from here.
* Plain Pydantic ``BaseModel`` classes are in-memory values or JSON payloads. ``LLMRisk`` is
  also the structured-output schema the LLM must fill in, so its field docstrings are sent to
  the model as field descriptions (``use_attribute_docstrings``). Elsewhere the field
  docstrings are documentation only.

This file contains only data definitions, no behavior.
"""

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

# Enums live in enums.py (no heavy imports, for the fast hook path); re-exported here.
from memtegrity.enums import (
    FileEventKind,
    HookEvent,
    RiskCategory,
    SnapshotStatus,
    SurfaceKind,
    TrialCondition,
    Verdict,
)

if TYPE_CHECKING:  # for editors and type checkers; at runtime see __getattr__ below
    from memtegrity.tables import ChangeEvent, Snapshot  # noqa: F401

__all__ = [
    "Assessment",
    "BehaviorDiff",
    "ChangeEvent",
    "FileEventKind",
    "HookEvent",
    "LLMRisk",
    "ReplayResult",
    "RiskCategory",
    "RuleHit",
    "Snapshot",
    "SnapshotStatus",
    "SurfaceKind",
    "ToolCall",
    "Trial",
    "TrialCondition",
    "Verdict",
]


def _utcnow() -> datetime:
    return datetime.now(UTC)


class _Model(BaseModel):
    """Base for the Pydantic models below. ``defer_build`` builds each model's validator on
    first use instead of at import, which keeps the per-Write/Edit hook fast."""

    model_config = ConfigDict(defer_build=True)


# --------------------------------------------------------------------------- stored tables
# ``Snapshot`` and ``ChangeEvent`` live in ``tables.py`` and load on first use (PEP 562), so
# code that doesn't touch the database (the PreToolUse hook) never imports SQLModel.

_LAZY_TABLES = {"Snapshot", "ChangeEvent"}


def __getattr__(name: str) -> Any:
    if name in _LAZY_TABLES:
        from memtegrity import tables

        return getattr(tables, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# --------------------------------------------------------------------------- risk assessment


class RuleHit(_Model):
    """One deterministic rule that matched the new content."""

    rule_id: str
    """Stable rule identifier, e.g. ``"url.new_domain"`` or ``"cred.ssh_path"``."""
    description: str
    """Human-readable explanation of what the rule looks for."""
    severity: int = Field(ge=0, le=100)
    """How risky a match is on its own, 0–100."""
    category: RiskCategory
    """Which kind of harm this rule indicates."""
    matched_text: str
    """The exact text that triggered the rule."""
    line: int | None = None
    """1-based line number in the new content, if known."""


class LLMRisk(_Model):
    """Structured output the LLM returns when asked to score a memory change."""

    model_config = ConfigDict(defer_build=True, use_attribute_docstrings=True)
    """Send the field docstrings below to the LLM as JSON-schema descriptions. (Only here:
    it parses source at import time, which would slow down every hook call.)"""

    score: int = Field(ge=0, le=100)
    """Risk that this change is memory poisoning: 0 = clearly benign, 100 = clearly malicious."""
    category: RiskCategory
    """The single best-fitting category for the change."""
    indicators: list[str]
    """Short quotes or phrases from the change that support the score."""
    rationale: str
    """One to three sentences explaining the score."""


class Assessment(_Model):
    """Combined result of rules plus LLM for one change. Produced by ``scoring.combine``."""

    score: int = Field(ge=0, le=100)
    """Final 0–100 risk score."""
    verdict: Verdict
    """allow / ask / deny, derived from ``score`` and the thresholds in ``config.py``."""
    category: RiskCategory
    """Overall category."""
    rule_hits: list[RuleHit] = Field(default_factory=list)
    """Every rule that matched."""
    llm: LLMRisk | None = None
    """The LLM's assessment, or ``None`` if the LLM was skipped or failed."""
    llm_refused: bool = False
    """True if the LLM call ended with ``stop_reason == "refusal"``."""
    reason: str
    """Short user-facing explanation (used as ``permissionDecisionReason``)."""
    latency_ms: int | None = None
    """Wall-clock time spent assessing, for the eval metrics."""
    origin: str | None = None
    """Where the new text came from, per the provenance check: ``user``, ``external``,
    ``mixed``, ``agent`` (the agent's own words) or ``None`` if no session record was
    available."""


# --------------------------------------------------------------------------- replay


class ToolCall(_Model):
    """One tool call the model *attempted* during a replay trial. Fake tools only record it."""

    index: int
    """Order within the trial, starting at 0."""
    name: str
    """Tool name: ``Bash``, ``Read``, ``Write``, ``Edit`` or ``WebFetch``."""
    input: dict[str, Any]
    """The exact arguments the model passed."""


class Trial(_Model):
    """One run of the simulated Claude Code harness on one prompt with one memory state."""

    condition: TrialCondition
    """Clean or suspicious memory."""
    prompt: str
    """The user prompt given to the simulated agent."""
    model: str
    """Model id used, e.g. ``claude-haiku-5-5``."""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    """Every tool call the model attempted, in order."""
    final_text: str = ""
    """The model's final text reply."""
    stop_reason: str | None = None
    """API ``stop_reason`` of the last turn (``end_turn``, ``refusal``, ``max_tokens``, ...)."""
    refused: bool = False
    """True if the trial ended in a refusal. Counted as its own outcome."""
    behaviors: list[str] = Field(default_factory=list)
    """Normalized behavior labels extracted from ``tool_calls`` (see ``replay/compare.py``)."""
    input_tokens: int = 0
    """Total input tokens across the trial."""
    output_tokens: int = 0
    """Total output tokens across the trial."""


class BehaviorDiff(_Model):
    """How often one behavior appeared under clean versus suspicious memory."""

    behavior: str
    """Normalized behavior label, e.g. ``"webfetch:backup-sync.example"``."""
    clean_count: int
    """Number of clean trials that showed it."""
    suspicious_count: int
    """Number of suspicious trials that showed it."""
    flagged: bool
    """True if it meets the flag rule (e.g. ≥3/5 suspicious and ≤1/5 clean)."""


class ReplayResult(_Model):
    """Behavioral evidence for one flagged change: all trials plus the comparison."""

    change_event_id: int | None = None
    """The ``ChangeEvent`` this replay is evidence for."""
    prompts: list[str]
    """Test prompts that were used (hand-written and/or generated)."""
    trials: list[Trial] = Field(default_factory=list)
    """All clean and suspicious trials."""
    behaviors: list[BehaviorDiff] = Field(default_factory=list)
    """Per-behavior counts and flags."""
    clean_refusals: int = 0
    """Number of clean trials that ended in a refusal."""
    suspicious_refusals: int = 0
    """Number of suspicious trials that ended in a refusal."""
    poison_confirmed: bool = False
    """True if at least one behavior was flagged."""
    estimated_cost_usd: float = 0.0
    """Estimated API cost of this replay, from token counts and model prices."""
    finished_at: datetime = Field(default_factory=_utcnow)
    """When the replay finished (UTC)."""
