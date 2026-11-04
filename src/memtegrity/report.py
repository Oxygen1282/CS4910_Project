"""HTML incident report (Jinja2), built from stored change events and replay results."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.engine import Engine

TEMPLATE_NAME = "report.html"
"""Template file in ``memtegrity/templates/``."""


def render_report(engine: Engine, out_dir: Path, event_ids: list[int] | None = None) -> Path:
    """Render ``templates/report.html`` for the given change events (default: all
    flagged ones) and return the path of the written HTML file.

    TODO(A): implement.
    """
    raise NotImplementedError
