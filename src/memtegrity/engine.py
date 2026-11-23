"""The decision engine: "is this change to a protected file dangerous?"

Agent-neutral core. Inputs are plain values (which surface, old text, new text, session
evidence); outputs are an ``Assessment``. Every agent adapter (today: Claude Code's hook in
``memtegrity.hooks``) and the repo scanner (``memtegrity scan``) call this one function, so
detection behaves identically everywhere.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

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
    path: Path | None = None,
) -> Assessment:
    """Judge a change to a protected file.

    ``after`` is the full new content. If it can't be predicted exactly (an edit we couldn't
    reproduce), pass ``after=None`` and the ``inserted`` text instead: it is judged on its
    own, because "couldn't predict it" must never mean "it's safe".

    ``path`` (the file being changed) lets the engine follow newly added imports: an edit
    that adds ``@notes.md`` is judged together with what ``notes.md`` already contains, so
    poisoning a plain file first and importing it second doesn't slip through.
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

    if after is not None and analyzer is None:
        hits += rules.run_removal_rules(integrity.removed_lines(before, after), after)
    if path is not None and after is not None and surface.kind is not SurfaceKind.CONFIG:
        hits += _import_target_hits(surface, path, before, after)

    prov = provenance.assess(added_text, evidence, before)
    assessment = scoring.combine(hits, provenance=prov)
    assessment.latency_ms = round((time.perf_counter() - started) * 1000)
    return assessment


_IMPORT_TARGET_MAX_BYTES = 1_000_000


def _import_target_hits(surface: Surface, path: Path, before: str, after: str) -> list[RuleHit]:
    """One hit per newly imported file that is risky on its own (judged as a new file)."""
    from memtegrity.agents import PROFILES

    hits = []
    for profile in PROFILES:
        if profile.agent != surface.agent or profile.new_import_targets is None:
            continue
        for target in profile.new_import_targets(path, before, after):
            try:
                if target.stat().st_size > _IMPORT_TARGET_MAX_BYTES:
                    continue
            except OSError:
                continue
            text = integrity.read_text(target) or ""
            judged = assess_change(surface, "", text)  # no ``path``: one hop only
            if judged.score == 0:
                continue
            hits.append(
                RuleHit(
                    rule_id="memory.import_target",
                    description=f"new @import pulls in {target.name}, which looks risky",
                    severity=judged.score,
                    category=judged.category,
                    matched_text=rules.snippet(f"{target.name}: {judged.reason}"),
                )
            )
    return hits
