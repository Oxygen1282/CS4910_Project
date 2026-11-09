"""Repository scanner: check every agent's instruction, memory and config files at rest.

Real-time hooks catch poison as an agent writes it. The scanner covers the other way in:
poison that arrives *in the repository* (a cloned project, a pull request, a teammate's
commit). That is how the Rules File Backdoor (Pillar Security, 2025) and the repo-settings
hooks CVE (CVE-2025-59536) reach a victim. Runs anywhere: CLI, pre-commit, CI.

Agent-neutral: it covers every file in the ``memtegrity.agents`` registry, for all agents.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from memtegrity import engine, integrity, paths
from memtegrity.models import Assessment
from memtegrity.surfaces import Surface

SKIP_DIRS = frozenset(
    {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox", ".mypy_cache"}
)
MAX_BYTES = 1_000_000


@dataclass
class Finding:
    path: Path
    surface: Surface
    assessment: Assessment


def iter_candidates(targets: Iterable[Path], exclude: Iterable[str] = ()) -> Iterator[Path]:
    """Files under ``targets`` (files are yielded as-is), skipping vendored/build folders
    and anything whose path contains one of ``exclude``."""
    excluded = tuple(exclude)
    for target in targets:
        if target.is_file():
            yield target
            continue
        for dirpath, dirnames, filenames in os.walk(target):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                path = Path(dirpath) / name
                if not any(part in str(path) for part in excluded):
                    yield path


def scan(targets: Iterable[Path], exclude: Iterable[str] = ()) -> list[Finding]:
    """Assess every protected file under ``targets`` as if it were newly added."""
    targets = [Path(t) for t in targets]
    project = targets[0].resolve() if len(targets) == 1 and targets[0].is_dir() else Path.cwd()
    findings = []
    for path in iter_candidates(targets, exclude):
        surface = paths.classify(path, project)
        if surface is None:
            continue
        try:
            if path.stat().st_size > MAX_BYTES:
                continue
        except OSError:
            continue
        content = integrity.read_text(path) or ""
        findings.append(Finding(path, surface, engine.assess_change(surface, "", content)))
    return findings
