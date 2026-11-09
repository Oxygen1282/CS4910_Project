"""The decision engine: "is this change to a protected file dangerous?"

Agent-neutral core. Inputs are plain values (which surface, old text, new text, session
evidence); outputs are an ``Assessment``. Every agent adapter (today: Claude Code's hook in
``memtegrity.hooks``) and the repo scanner (``memtegrity scan``) call this one function, so
detection behaves identically everywhere.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from memtegrity import integrity, provenance, rules, scoring
from memtegrity.enums import SurfaceKind
from memtegrity.models import Assessment, RiskCategory, RuleHit
from memtegrity.provenance import Evidence
from memtegrity.surfaces import Surface

ConfigAnalyzer = Callable[[str, str], list[RuleHit]]


def _config_analyzer(agent: str) -> ConfigAnalyzer | None:
    """Structural analyzer for an agent's config format, if we have one."""
    if agent == "claude-code":
        from memtegrity.agents.claude_code import assess_config

        return assess_config
    return None


def assess_change(
    surface: Surface,
    before: str,
    after: str | None,
    *,
    inserted: str | None = None,
    evidence: Evidence | None = None,
) -> Assessment:
    """Judge a change to a protected file.

    ``after`` is the full new content. If it can't be predicted exactly (an edit we couldn't
    reproduce), pass ``after=None`` and the ``inserted`` text instead: it is judged on its
    own, because "couldn't predict it" must never mean "it's safe".
    """
    started = time.perf_counter()

    if after is not None:
        added = integrity.added_lines(before, after)
    else:
        added = [(None, line) for line in (inserted or "").splitlines()]
    added_text = "\n".join(text for _, text in added)

    analyzer = _config_analyzer(surface.agent) if surface.kind is SurfaceKind.CONFIG else None
    if analyzer is not None and after is not None:
        hits = analyzer(before, after)
    else:
        hits = rules.run_rules(added, before)
        if surface.kind is SurfaceKind.CONFIG:
            hits.append(
                RuleHit(
                    rule_id="config.unverified",
                    description="config change that couldn't be fully analyzed",
                    severity=45,
                    category=RiskCategory.OTHER,
                    matched_text=rules.snippet(added_text) or surface.name,
                )
            )

    prov = provenance.assess(added_text, evidence, before)
    assessment = scoring.combine(hits, provenance=prov)
    assessment.latency_ms = round((time.perf_counter() - started) * 1000)
    return assessment
