"""Deterministic risk rules: fast, free, explainable checks run before the LLM."""

from __future__ import annotations

from dataclasses import dataclass

from memtegrity.models import RiskCategory, RuleHit


@dataclass(frozen=True)
class Rule:
    """One deterministic check."""

    rule_id: str
    """Stable identifier, e.g. ``"url.new_domain"``."""
    description: str
    """What the rule looks for."""
    severity: int
    """Risk of a match on its own, 0–100."""
    category: RiskCategory
    """Which kind of harm a match indicates."""
    pattern: str
    """Regular expression run against *added* lines only."""


RULES: list[Rule] = []
"""The rule list. TODO(A): fill in. Planned rules:

* URLs, and especially domains not seen in the approved memory
* credential paths: ``~/.ssh``, ``.env``, ``id_rsa``, tokens, API keys
* standing-override phrasing: "always", "never", "ignore previous", "don't tell the user"
* base64 / long opaque blobs
* piping downloads into a shell: ``curl ... | bash``, ``wget ... | sh``
* attempts to disable hooks or Memtegrity itself
"""


def run_rules(diff: str, before: str = "") -> list[RuleHit]:
    """Run every rule in ``RULES`` against the lines added in ``diff``.

    ``before`` is the approved content, used by rules like "new domain" that need
    to know what was already there.

    TODO(A): implement.
    """
    raise NotImplementedError
