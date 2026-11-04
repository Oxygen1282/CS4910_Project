"""Shared data contract for Memtegrity.

Every module passes these types to every other module, so both partners build against them.
Change them only by agreement (and in their own PR).

There are two kinds of classes:

* ``SQLModel`` classes with ``table=True`` are stored in SQLite (see ``store.py``).
* Plain Pydantic ``BaseModel`` classes are in-memory values or JSON payloads. ``LLMRisk`` is
  also the structured-output schema the LLM must fill in, so its field docstrings are sent to
  the model as field descriptions (``use_attribute_docstrings``).

This file contains only data definitions, no behavior.
"""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict
from pydantic import Field as PydanticField
from sqlmodel import Field, SQLModel


def _utcnow() -> datetime:
    return datetime.now(UTC)


_DOCSTRING_CONFIG = ConfigDict(use_attribute_docstrings=True)


# --------------------------------------------------------------------------- enums


class Verdict(StrEnum):
    """What Memtegrity decides to do about a memory change.

    The values match Claude Code's PreToolUse ``permissionDecision`` strings.
    """

    ALLOW = "allow"
    """Low risk: let the write through silently."""
    ASK = "ask"
    """Medium risk: show Claude Code's permission prompt so the user decides."""
    DENY = "deny"
    """High risk: block the write (PreToolUse) or auto-restore it (FileChanged)."""


class SnapshotStatus(StrEnum):
    """Lifecycle state of a stored memory-file version."""

    APPROVED = "approved"
    """Trusted baseline. Restores go back to the latest approved snapshot."""
    PENDING = "pending"
    """Seen but not yet approved by the user (e.g. an 'ask' that is awaiting review)."""
    QUARANTINED = "quarantined"
    """Judged malicious: the file was restored and this version is kept only as evidence."""


class HookEvent(StrEnum):
    """Claude Code hook events Memtegrity handles. Values are the CLI names
    (``memtegrity hook <value>``)."""

    SESSION_START = "session-start"
    PRE_TOOL_USE = "pre-tool-use"
    FILE_CHANGED = "file-changed"
    CONFIG_CHANGE = "config-change"


class FileEventKind(StrEnum):
    """Kind of file-system change, as reported in the FileChanged hook's ``event`` field."""

    CHANGE = "change"
    ADD = "add"
    UNLINK = "unlink"


class RiskCategory(StrEnum):
    """What kind of harm a suspicious memory change is trying to cause."""

    BENIGN = "benign"
    """Normal project notes or preferences."""
    EXFILTRATION = "exfiltration"
    """Sends code, secrets or data to an outside host."""
    CREDENTIAL_ACCESS = "credential_access"
    """Reads keys, tokens, ``.env`` files, ``~/.ssh``, etc."""
    CODE_EXECUTION = "code_execution"
    """Runs downloaded or obfuscated code (e.g. ``curl ... | bash``)."""
    INSTRUCTION_OVERRIDE = "instruction_override"
    """Standing orders that override the user or safety ("always", "ignore previous")."""
    CONCEALMENT = "concealment"
    """Hides actions from the user ("don't tell the user", "don't mention")."""
    TAMPERING = "tampering"
    """Tries to disable Memtegrity, hooks, or other safeguards."""
    OTHER = "other"
    """Suspicious, but none of the above."""


class TrialCondition(StrEnum):
    """Which memory a replay trial was run with."""

    CLEAN = "clean"
    """The last approved memory."""
    SUSPICIOUS = "suspicious"
    """The memory including the flagged change."""


# --------------------------------------------------------------------------- stored tables


class Snapshot(SQLModel, table=True):
    """One stored version of one memory file."""

    id: int | None = Field(default=None, primary_key=True)
    """Database id (assigned on insert)."""
    path: str = Field(index=True)
    """Absolute path of the memory file."""
    sha256: str = Field(index=True)
    """Hex SHA-256 of ``content`` (UTF-8 bytes)."""
    content: str
    """Full file content at this version. Empty string if the file was deleted."""
    size_bytes: int
    """Size of ``content`` in bytes."""
    status: SnapshotStatus = SnapshotStatus.PENDING
    """Approved / pending / quarantined."""
    created_at: datetime = Field(default_factory=_utcnow)
    """When the snapshot was taken (UTC)."""
    session_id: str | None = None
    """Claude Code session that produced this version, if known."""
    note: str | None = None
    """Free-text note, e.g. why it was approved or quarantined."""


class ChangeEvent(SQLModel, table=True):
    """One detected (or attempted) change to a memory file, with its assessment.

    This is the audit-trail record and the unit the HTML report is built from.
    """

    id: int | None = Field(default=None, primary_key=True)
    """Database id (assigned on insert)."""
    path: str = Field(index=True)
    """Absolute path of the memory file."""
    source: HookEvent
    """Which hook detected it: PreToolUse (attempted write), FileChanged or SessionStart."""
    file_event: FileEventKind = FileEventKind.CHANGE
    """change / add / unlink."""
    tool_name: str | None = None
    """For PreToolUse: ``Write`` or ``Edit``. ``None`` otherwise."""
    session_id: str | None = None
    """Claude Code session id from the hook input."""
    before_sha256: str | None = None
    """Hash of the last approved version (``None`` if the file is new)."""
    after_sha256: str | None = None
    """Hash of the new or proposed content (``None`` if the file was deleted)."""
    before_snapshot_id: int | None = Field(default=None, foreign_key="snapshot.id")
    """Snapshot this change is compared against."""
    after_snapshot_id: int | None = Field(default=None, foreign_key="snapshot.id")
    """Snapshot that stores the new or proposed content."""
    diff: str = ""
    """Unified diff from before to after."""
    verdict: Verdict | None = None
    """Final decision (copied from the assessment for easy querying)."""
    score: int | None = None
    """Final 0–100 risk score (copied from the assessment)."""
    assessment_json: str | None = None
    """The full ``Assessment``, serialized with ``Assessment.model_dump_json()``."""
    replay_json: str | None = None
    """The ``ReplayResult``, serialized, once a background replay has finished."""
    restored: bool = False
    """True if Memtegrity restored the file to the last approved snapshot."""
    created_at: datetime = Field(default_factory=_utcnow)
    """When the change was detected (UTC)."""


# --------------------------------------------------------------------------- risk assessment


class RuleHit(BaseModel):
    """One deterministic rule that matched the new content."""

    model_config = _DOCSTRING_CONFIG

    rule_id: str
    """Stable rule identifier, e.g. ``"url.new_domain"`` or ``"cred.ssh_path"``."""
    description: str
    """Human-readable explanation of what the rule looks for."""
    severity: int = PydanticField(ge=0, le=100)
    """How risky a match is on its own, 0–100."""
    category: RiskCategory
    """Which kind of harm this rule indicates."""
    matched_text: str
    """The exact text that triggered the rule."""
    line: int | None = None
    """1-based line number in the new content, if known."""


class LLMRisk(BaseModel):
    """Structured output the LLM returns when asked to score a memory change."""

    model_config = _DOCSTRING_CONFIG

    score: int = PydanticField(ge=0, le=100)
    """Risk that this change is memory poisoning: 0 = clearly benign, 100 = clearly malicious."""
    category: RiskCategory
    """The single best-fitting category for the change."""
    indicators: list[str]
    """Short quotes or phrases from the change that support the score."""
    rationale: str
    """One to three sentences explaining the score."""


class Assessment(BaseModel):
    """Combined result of rules plus LLM for one change. Produced by ``scoring.combine``."""

    model_config = _DOCSTRING_CONFIG

    score: int = PydanticField(ge=0, le=100)
    """Final 0–100 risk score."""
    verdict: Verdict
    """allow / ask / deny, derived from ``score`` and the thresholds in ``config.py``."""
    category: RiskCategory
    """Overall category."""
    rule_hits: list[RuleHit] = PydanticField(default_factory=list)
    """Every rule that matched."""
    llm: LLMRisk | None = None
    """The LLM's assessment, or ``None`` if the LLM was skipped or failed."""
    llm_refused: bool = False
    """True if the LLM call ended with ``stop_reason == "refusal"``."""
    reason: str
    """Short user-facing explanation (used as ``permissionDecisionReason``)."""
    latency_ms: int | None = None
    """Wall-clock time spent assessing, for the eval metrics."""


# --------------------------------------------------------------------------- replay


class ToolCall(BaseModel):
    """One tool call the model *attempted* during a replay trial. Fake tools only record it."""

    model_config = _DOCSTRING_CONFIG

    index: int
    """Order within the trial, starting at 0."""
    name: str
    """Tool name: ``Bash``, ``Read``, ``Write``, ``Edit`` or ``WebFetch``."""
    input: dict[str, Any]
    """The exact arguments the model passed."""


class Trial(BaseModel):
    """One run of the simulated Claude Code harness on one prompt with one memory state."""

    model_config = _DOCSTRING_CONFIG

    condition: TrialCondition
    """Clean or suspicious memory."""
    prompt: str
    """The user prompt given to the simulated agent."""
    model: str
    """Model id used, e.g. ``claude-haiku-5-5``."""
    tool_calls: list[ToolCall] = PydanticField(default_factory=list)
    """Every tool call the model attempted, in order."""
    final_text: str = ""
    """The model's final text reply."""
    stop_reason: str | None = None
    """API ``stop_reason`` of the last turn (``end_turn``, ``refusal``, ``max_tokens``, ...)."""
    refused: bool = False
    """True if the trial ended in a refusal. Counted as its own outcome."""
    behaviors: list[str] = PydanticField(default_factory=list)
    """Normalized behavior labels extracted from ``tool_calls`` (see ``replay/compare.py``)."""
    input_tokens: int = 0
    """Total input tokens across the trial."""
    output_tokens: int = 0
    """Total output tokens across the trial."""


class BehaviorDiff(BaseModel):
    """How often one behavior appeared under clean versus suspicious memory."""

    model_config = _DOCSTRING_CONFIG

    behavior: str
    """Normalized behavior label, e.g. ``"webfetch:backup-sync.example"``."""
    clean_count: int
    """Number of clean trials that showed it."""
    suspicious_count: int
    """Number of suspicious trials that showed it."""
    flagged: bool
    """True if it meets the flag rule (e.g. ≥3/5 suspicious and ≤1/5 clean)."""


class ReplayResult(BaseModel):
    """Behavioral evidence for one flagged change: all trials plus the comparison."""

    model_config = _DOCSTRING_CONFIG

    change_event_id: int | None = None
    """The ``ChangeEvent`` this replay is evidence for."""
    prompts: list[str]
    """Test prompts that were used (hand-written and/or generated)."""
    trials: list[Trial] = PydanticField(default_factory=list)
    """All clean and suspicious trials."""
    behaviors: list[BehaviorDiff] = PydanticField(default_factory=list)
    """Per-behavior counts and flags."""
    clean_refusals: int = 0
    """Number of clean trials that ended in a refusal."""
    suspicious_refusals: int = 0
    """Number of suspicious trials that ended in a refusal."""
    poison_confirmed: bool = False
    """True if at least one behavior was flagged."""
    estimated_cost_usd: float = 0.0
    """Estimated API cost of this replay, from token counts and model prices."""
    finished_at: datetime = PydanticField(default_factory=_utcnow)
    """When the replay finished (UTC)."""
