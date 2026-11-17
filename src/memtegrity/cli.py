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


_PROJECT = typer.Option(  # noqa: B008
    None, "--project", "-p", help="Project folder (default: current folder)."
)


@app.command()
def status(project: Path | None = _PROJECT) -> None:
    """Show every protected file, whether it matches its approved version, and whether the
    audit log is intact."""
    from rich.console import Console
    from rich.table import Table

    from memtegrity import baseline, store

    project_dir = project or Path.cwd()
    db = store.default_engine()
    rows, complete = baseline.states(db, project_dir)
    console = Console()
    table = Table(title=f"Memtegrity: {len(rows)} protected file(s) for {project_dir}")
    for col in ("file", "agent / kind", "approved?", "changed?"):
        table.add_column(col, overflow="fold")
    for r in rows:
        if r.changed is None:
            changed = "[dim]-[/]"
        elif r.changed:
            changed = "[bold red]yes, flagged[/]" if r.pending else "[yellow]yes[/]"
        else:
            changed = "[green]no[/]"
        table.add_row(
            _short(r.path, project_dir),
            f"{r.surface.agent} / {r.surface.kind.value}",
            "[green]yes[/]" if r.approved else "[yellow]no[/]",
            changed,
        )
    console.print(table)
    if not complete:
        console.print("[yellow]Folder too large: the list may be incomplete.[/]")
    issues = store.verify_chain(db)
    if issues:
        console.print(f"[bold red]Audit log damaged ({len(issues)} problem(s)):[/]")
        for i in issues:
            console.print(f"  {i.table} #{i.row_id}: {i.problem}")
        raise typer.Exit(2)
    console.print(f"Audit log intact. Chain head: {store.chain_head(db)}")


def _short(path: Path, project_dir: Path) -> str:
    from memtegrity.paths import resolve_path

    for base, prefix in ((resolve_path(project_dir), ""), (resolve_path(Path.home()), "~")):
        try:
            rel = path.relative_to(base)
        except ValueError:
            continue
        return str(Path(prefix) / rel) if prefix else str(rel)
    return str(path)


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
def baseline(project: Path | None = _PROJECT) -> None:
    """Approve the current content of every protected file as the trusted baseline
    (first-time setup, or after you've checked a flagged change yourself)."""
    from rich.console import Console

    from memtegrity import baseline as core
    from memtegrity import store

    project_dir = project or Path.cwd()
    n = core.approve_all(store.default_engine(), project_dir)
    Console().print(f"Approved {n} changed file(s) as the new baseline for {project_dir}.")


if __name__ == "__main__":
    app()
