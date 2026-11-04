"""Default settings for Memtegrity.

These are plain constants with no logic. Values marked "confirm Thursday" are open decisions
in ``docs/PLANNING.md``.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class Settings(BaseModel):
    """All tunable settings. ``DEFAULT_SETTINGS`` below is what the hooks use."""

    model_config = ConfigDict(frozen=True, use_attribute_docstrings=True)

    # ------------------------------------------------------------------ what counts as memory
    project_memory_globs: tuple[str, ...] = (
        "CLAUDE.md",
        ".claude/CLAUDE.md",
        "CLAUDE.local.md",
        "AGENTS.md",
        ".claude/rules/**/*.md",
    )
    """Memory files relative to the project directory (confirm Thursday)."""

    user_memory_globs: tuple[str, ...] = (
        "~/.claude/CLAUDE.md",
        "~/.claude/rules/**/*.md",
        "~/.claude/projects/*/memory/**/*.md",
    )
    """Memory files in the user's home directory. The last one is auto memory (``MEMORY.md``
    index plus topic files). If ``autoMemoryDirectory`` is set, that folder counts too."""

    memory_index_max_lines: int = 200
    """Claude Code loads only the first 200 lines of ``MEMORY.md`` per session."""

    memory_index_max_bytes: int = 25_000
    """...and at most 25 KB of it."""

    # ------------------------------------------------------------------ models
    scoring_model: str = "claude-sonnet-5-5"
    """Model used for LLM risk scoring."""

    test_generation_model: str = "claude-sonnet-5-5"
    """Model used to generate replay test prompts."""

    replay_model: str = "claude-haiku-5-5"
    """Model used inside the simulated harness for replay trials (cheap, many calls)."""

    llm_timeout_seconds: float = 20.0
    """Max time to wait for the scoring call. PreToolUse blocks Claude while it waits."""

    # ------------------------------------------------------------------ verdict thresholds
    ask_threshold: int = 40
    """Score at or above this → ``ask`` (confirm Thursday)."""

    deny_threshold: int = 75
    """Score at or above this → ``deny`` / auto-restore (confirm Thursday)."""

    # ------------------------------------------------------------------ replay
    trials_per_condition: int = 5
    """Number of clean trials and number of suspicious trials per prompt."""

    flag_min_suspicious: int = 3
    """A behavior is flagged if it appears in at least this many suspicious trials..."""

    flag_max_clean: int = 1
    """...and in at most this many clean trials."""

    replay_max_turns: int = 8
    """Max agent turns per trial before stopping."""

    # ------------------------------------------------------------------ storage
    data_dir_env: str = "CLAUDE_PLUGIN_DATA"
    """Environment variable holding the persistent data dir (``~/.claude/plugins/data/<id>/``).
    Never store state in ``CLAUDE_PLUGIN_ROOT``, which changes on every version."""

    db_filename: str = "memtegrity.db"
    """SQLite file name inside the data dir."""

    reports_dirname: str = "reports"
    """Folder inside the data dir where HTML reports are written."""


DEFAULT_SETTINGS = Settings()
