"""Per-agent knowledge: which files each AI agent platform loads, and (for supported
agents) how to read its hook input and session records.

The core (rules, scoring, provenance, integrity) never imports from here except through
``PROFILES``. To support a new agent: add a module with an ``AgentProfile`` (its files),
and, to enforce in real time, an adapter for that agent's hook protocol (see
``memtegrity.hooks`` for Claude Code's).
"""

from memtegrity.agents import claude_code, others
from memtegrity.surfaces import AgentProfile

PROFILES: tuple[AgentProfile, ...] = (claude_code.PROFILE, others.SHARED_PROFILE, *others.PROFILES)
"""Every known agent profile. Order matters only for ties: first match wins."""

__all__ = ["PROFILES"]
