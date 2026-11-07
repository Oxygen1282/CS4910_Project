"""The internal ``memtegrity`` command-line interface (Typer).

Hooks call ``memtegrity hook <event>``. The other commands back the plugin's skills and
are still stubs.
"""

from __future__ import annotations

from pathlib import Path

import typer

from memtegrity.models import HookEvent, Verdict

app = typer.Typer(help="Memtegrity: integrity monitoring for Claude Code memory.")


@app.command()
def hook(event: HookEvent) -> None:
    """Run a hook handler: read JSON from stdin, print the JSON response on stdout.

    (Hooks normally reach ``hooks.emit`` through the fast path in ``entry.py``.)
    """
    from memtegrity.hooks import emit

    emit(event)


@app.command()
def scan(
    targets: list[Path] = typer.Argument(  # noqa: B008 - Typer's declaration style
        None, help="Files or folders to scan (default: current folder)."
    ),
    fail_on: Verdict = typer.Option(  # noqa: B008
        Verdict.DENY, "--fail-on", help="Exit 1 if any file reaches this verdict."
    ),
    exclude: list[str] = typer.Option(  # noqa: B008
        [], "--exclude", help="Skip paths containing this text (repeatable)."
    ),
) -> None:
    """Scan every AI agent's instruction, memory and config files for poisoning.

    Covers Claude Code, AGENTS.md, Copilot, Cursor, Windsurf, Gemini CLI and Cline files.
    Use in CI or pre-commit to catch poison that arrives through the repository.
    """
    from rich.console import Console
    from rich.table import Table

    from memtegrity.scan import scan as run_scan

    findings = run_scan(targets or [Path(".")], exclude)
    order = {Verdict.ALLOW: 0, Verdict.ASK: 1, Verdict.DENY: 2}
    console = Console()
    table = Table(title=f"Memtegrity scan: {len(findings)} agent file(s)")
    for col in ("verdict", "risk", "file", "agent / kind", "why"):
        table.add_column(col, overflow="fold")
    style = {Verdict.ALLOW: "green", Verdict.ASK: "yellow", Verdict.DENY: "bold red"}
    for f in sorted(findings, key=lambda f: -f.assessment.score):
        a = f.assessment
        table.add_row(
            f"[{style[a.verdict]}]{a.verdict.value}[/]",
            str(a.score),
            str(f.path),
            f"{f.surface.agent} / {f.surface.kind.value}",
            a.reason if a.verdict is not Verdict.ALLOW else "",
        )
    console.print(table)
    failed = [f for f in findings if order[f.assessment.verdict] >= order[fail_on]]
    if failed:
        console.print(f"[bold red]{len(failed)} file(s) at or above '{fail_on.value}'.[/]")
        raise typer.Exit(1)


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
