"""Enumerations shared across Memtegrity (part of the data contract in ``models.py``).

Kept in their own module with no third-party imports, so the PreToolUse hook can decide
"is this a memory file?" without loading Pydantic. Import them from ``memtegrity.models``
as usual; they are re-exported there.
"""

from enum import StrEnum


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
