"""The internal ``memtegrity`` command-line interface (Typer).

Hooks call ``memtegrity hook <event>``. The other commands back the plugin's skills.
Every command is a stub for now.
"""

from __future__ import annotations

from pathlib import Path

import typer

from memtegrity.models import HookEvent

app = typer.Typer(help="Memtegrity: integrity monitoring for Claude Code memory (skeleton).")


@app.command()
def hook(event: HookEvent) -> None:
    """Run a hook handler: read JSON from stdin, print the JSON response on stdout.

    TODO(A): implement (look up ``hooks.HANDLERS[event]``; errors must never crash Claude Code).
    """
    raise NotImplementedError


@app.command()
def status() -> None:
    """Show watched memory files, their integrity state, and pending/quarantined changes.

    TODO(A): implement (Rich table).
    """
    raise NotImplementedError


@app.command()
def review(event_id: int | None = None) -> None:
    """Show a flagged change (diff, rule hits, LLM score, replay evidence) and approve or reject it.

    TODO(A): implement.
    """
    raise NotImplementedError


@app.command()
def restore(path: Path) -> None:
    """Restore a memory file to its last approved snapshot and quarantine the current version.

    TODO(A): implement.
    """
    raise NotImplementedError


@app.command()
def report(out: Path | None = None) -> None:
    """Write the HTML incident report and print its path.

    TODO(A): implement.
    """
    raise NotImplementedError


@app.command()
def replay(event_id: int) -> None:
    """Run behavioral replay for a flagged change (normally run in the background by a hook).

    TODO(B): implement.
    """
    raise NotImplementedError


@app.command()
def baseline() -> None:
    """Approve the current memory files as the trusted baseline (first-time setup).

    TODO(A): implement.
    """
    raise NotImplementedError


if __name__ == "__main__":
    app()
