"""Repository scanner: check every agent's instruction, memory and config files at rest.

Real-time hooks catch poison as an agent writes it. The scanner covers the other way in:
poison that arrives *in the repository* (a cloned project, a pull request, a teammate's
commit). That is how the Rules File Backdoor (Pillar Security, 2025) and the repo-settings
hooks CVE (CVE-2025-59536) reach a victim. Runs anywhere: CLI, pre-commit, CI.

Agent-neutral: it covers every file in the ``memtegrity.agents`` registry, for all agents.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from memtegrity import engine, integrity, paths
from memtegrity.models import Assessment
from memtegrity.surfaces import Surface

SKIP_DIRS = paths.SKIP_DIRS
MAX_BYTES = paths.MAX_FILE_BYTES
iter_candidates = paths.iter_candidates


@dataclass
class Finding:
    path: Path
    surface: Surface
    assessment: Assessment


def scan(targets: Iterable[Path], exclude: Iterable[str] = ()) -> list[Finding]:
    """Assess every protected file under ``targets`` as if it were newly added, including
    files that the instruction files ``@import`` (when they are inside a scanned folder)."""
    from memtegrity.agents import PROFILES

    targets = [Path(t) for t in targets]
    project = targets[0].resolve() if len(targets) == 1 and targets[0].is_dir() else Path.cwd()
    explicit = {paths.resolve_path(t) for t in targets if t.is_file()}
    found: dict[Path, Surface] = {}
    for path in iter_candidates(targets, exclude):
        real = paths.resolve_path(path)
        if real not in explicit and not paths.could_be_protected(path):
            continue  # cheap name check first: classify() also follows @imports
        surface = paths.classify(path, project)
        if surface is not None:
            found.setdefault(path, surface)
    seen = {paths.key(paths.resolve_path(p)) for p in found}

    folders = [paths.key(paths.resolve_path(t)) for t in targets if t.is_dir()]
    excluded = tuple(e.replace("\\", "/") for e in exclude)
    for profile in PROFILES:
        if profile.import_closure is None:
            continue
        for target, imported in profile.import_closure(list(found)).items():
            k = paths.key(target)
            inside = any(k[: len(f)] == f for f in folders)
            if k in seen or not inside or any(e in target.as_posix() for e in excluded):
                continue
            seen.add(k)
            found[target] = paths.classify(target, project) or imported

    findings = []
    for path, surface in found.items():
        try:
            if path.stat().st_size > MAX_BYTES:
                continue
        except OSError:
            continue
        content = integrity.read_text(path) or ""
        findings.append(Finding(path, surface, engine.assess_change(surface, "", content)))
    return findings
