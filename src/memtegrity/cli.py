"""The internal ``memtegrity`` command-line interface (Typer).

Hooks call ``memtegrity hook <event>``. The other commands are for people (and back the
``/memtegrity:*`` skills): ``status``, ``review``, ``restore``, ``approve``, ``baseline`` and
``scan``. ``report`` and ``replay`` are still stubs (see ``docs/BLOCK4.md``).
"""

from __future__ import annotations

from pathlib import Path

import typer

from memtegrity.models import HookEvent, Verdict

app = typer.Typer(help="Memtegrity: integrity monitoring for Claude Code memory.")


@app.callback()
def _options(
    data_dir: Path | None = typer.Option(  # noqa: B008
        None, "--data-dir", help="Memtegrity's data folder (default: found automatically)."
    ),
) -> None:
    if data_dir is not None:
        import os

        from memtegrity.paths import DATA_DIR_ENV

        os.environ[DATA_DIR_ENV] = str(data_dir)


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
    """Short path for output, always with ``/`` so it can be pasted into a shell command
    (a ``\\`` separator is dropped by Git Bash on Windows)."""
    from memtegrity.paths import resolve_path

    for base, prefix in ((resolve_path(project_dir), ""), (resolve_path(Path.home()), "~")):
        try:
            rel = path.relative_to(base)
        except ValueError:
            continue
        return (Path(prefix) / rel).as_posix() if prefix else rel.as_posix()
    return path.as_posix()


@app.command()
def review(
    event_id: int | None = typer.Argument(None, help="An event number to show in full."),
    limit: int = typer.Option(20, "--limit", "-n", help="How many recent events to list."),
    show_all: bool = typer.Option(
        False, "--all", help="List every event, not only the ones that need attention."
    ),
) -> None:
    """List recent flagged, blocked and restored changes, or show one in full (what changed,
    why it was flagged, the diff, and how to approve or undo it)."""
    from rich.console import Console
    from rich.table import Table

    from memtegrity import store

    db = store.default_engine()
    console = Console()
    if event_id is None:
        events = [e for e in store.list_changes(db, limit=500) if show_all or _needs_attention(e)][
            :limit
        ]
        if not events:
            console.print("Nothing to review: no flagged, blocked or restored changes.")
            return
        table = Table(title="Memtegrity: changes to review (newest first)")
        for col in ("#", "when (UTC)", "file", "what happened", "risk"):
            table.add_column(col, overflow="fold")
        for e in events:
            table.add_row(
                str(e.id),
                e.created_at.strftime("%Y-%m-%d %H:%M"),
                _short(Path(e.path), Path.cwd()),
                _what(e),
                "" if e.score is None else f"{e.score}/100",
            )
        console.print(table)
        console.print("Details: [bold]memtegrity review <#>[/]")
        return

    event = _event_or_exit(db, event_id)
    _print_event(console, db, event)


def _needs_attention(e) -> bool:  # noqa: ANN001 - ChangeEvent, imported lazily
    from memtegrity.models import Verdict

    note = e.note or ""
    return (
        e.verdict in (Verdict.ASK, Verdict.DENY) or note.startswith("restored") or "flagged" in note
    ) and not note.startswith("accepted")


def _what(e) -> str:  # noqa: ANN001
    source = {
        "pre-tool-use": "Claude tried to write it",
        "post-tool-use": "Claude's command changed it",
        "file-changed": "changed outside Claude",
        "session-start": "changed between sessions",
        "config-change": "settings change",
    }.get(e.source.value, e.source.value)
    note = e.note or ""
    if note.startswith("restored"):
        return f"{source}; restored"
    if note == "blocked":
        return f"{source}; blocked"
    if note.startswith("approved"):
        return "approved"
    verdict = e.verdict.value if e.verdict else ""
    return f"{source}; {note or verdict}"


def _event_or_exit(db, event_id: int):  # noqa: ANN001, ANN202
    from sqlmodel import Session

    from memtegrity.models import ChangeEvent

    with Session(db) as s:
        event = s.get(ChangeEvent, event_id)
    if event is None:
        typer.echo(f"No event #{event_id}. Run `memtegrity review` to list them.", err=True)
        raise typer.Exit(1)
    return event


def _print_event(console, db, e) -> None:  # noqa: ANN001
    import json as _json

    from rich.syntax import Syntax

    from memtegrity import store
    from memtegrity.models import SnapshotStatus

    console.print(f"[bold]Event #{e.id}[/]  {e.created_at:%Y-%m-%d %H:%M:%S} UTC")
    console.print(
        f"File: {e.path}  ({e.agent} / {e.surface_kind.value if e.surface_kind else '?'})"
    )
    console.print(f"What happened: {_what(e)}" + (f" (tool: {e.tool_name})" if e.tool_name else ""))
    if e.score is not None:
        verdict = e.verdict.value if e.verdict else "-"
        console.print(f"Risk: {e.score}/100 → {verdict}")
    if e.assessment_json:
        a = _json.loads(e.assessment_json)
        console.print(f"Why: {a.get('reason', '')}")
        for h in a.get("rule_hits", [])[:8]:
            line = f" (line {h['line']})" if h.get("line") else ""
            console.print(f"  • {h['description']}: {h['matched_text']!r}{line} [{h['severity']}]")
        if a.get("origin"):
            console.print(f"Where the text came from: {a['origin']}")
    if e.diff:
        console.print(Syntax(e.diff, "diff", word_wrap=True))

    kept = [
        snap
        for sid in (e.after_snapshot_id, e.before_snapshot_id)
        if sid is not None
        and (snap := store.get_snapshot(db, sid)) is not None
        and snap.status is not SnapshotStatus.APPROVED
    ]
    console.print("\n[bold]What you can do[/]")
    if kept:
        console.print(
            f"  It's yours / it's fine:  memtegrity approve {e.id}"
            "   (makes the flagged version the approved one, and writes it back if needed)"
        )
    console.print(
        f"  Undo it:                 memtegrity restore {_short(Path(e.path), Path.cwd())}"
        "   (back to the last approved version)"
    )


@app.command()
def restore(
    path: Path = typer.Argument(..., help="The protected file to put back."),  # noqa: B008
) -> None:
    """Put a protected file back to its last approved version. The version it replaces is
    kept as evidence (see `memtegrity review`)."""
    from memtegrity import paths, recovery, store
    from memtegrity.models import HookEvent

    surface = paths.classify(path, Path.cwd())
    if surface is None:
        typer.echo(f"{path} isn't a file Memtegrity protects.", err=True)
        raise typer.Exit(1)
    real = paths.resolve_path(path)
    try:
        out = recovery.restore(
            store.default_engine(),
            real,
            surface,
            source=HookEvent.SESSION_START,
            note="restored by the user (memtegrity restore)",
        )
    except recovery.CannotRestore as exc:
        typer.echo(f"Can't restore {path}: {exc}.", err=True)
        raise typer.Exit(1) from exc
    if out.action == "unchanged":
        typer.echo(f"{path} already matches its approved version.")
    else:
        typer.echo(
            f"Restored {path} (event #{out.event_id}). The replaced version is kept: "
            f"`memtegrity review {out.event_id}`."
        )


@app.command()
def approve(
    target: str = typer.Argument(
        ...,
        help="A protected file (approve what it contains now) or an event number "
        "(approve the version that event flagged).",
    ),
) -> None:
    """Mark content as yours: it becomes the approved version that Memtegrity compares
    against. Run this yourself; when Claude tries to run it, you get a permission prompt."""
    from memtegrity import baseline as core
    from memtegrity import integrity, paths, recovery, store
    from memtegrity.models import FileEventKind, HookEvent, SnapshotStatus

    db = store.default_engine()
    if target.isdigit():
        event = _event_or_exit(db, int(target))
        snap = next(
            (
                s
                for sid in (event.after_snapshot_id, event.before_snapshot_id)
                if sid is not None
                and (s := store.get_snapshot(db, sid)) is not None
                and s.status is not SnapshotStatus.APPROVED
            ),
            None,
        )
        if snap is None:
            typer.echo(f"Event #{event.id} has no flagged version to approve.", err=True)
            raise typer.Exit(1)
        path, content = Path(event.path), snap.content
    else:
        path = paths.resolve_path(target)
        current = integrity.read_text(path)
        if current is None:
            typer.echo(f"{target} doesn't exist.", err=True)
            raise typer.Exit(1)
        content = current

    surface = paths.classify(path, Path.cwd())
    if surface is None:
        typer.echo(f"{path} isn't a file Memtegrity protects.", err=True)
        raise typer.Exit(1)
    p = str(path)
    previous = store.latest_approved(db, p)
    current = integrity.read_text(path)
    if current != content:  # bring the approved version back into the file
        if not recovery.restore_allowed(path):
            typer.echo(f"Not allowed to write {path} (${recovery.RESTORE_ROOTS_ENV}).", err=True)
            raise typer.Exit(1)
        recovery.write_exact(path, content)
    snap = store.save_snapshot(
        db, core.snapshot(p, content, SnapshotStatus.APPROVED, None, "approved by the user")
    )
    ev = store.record_change(
        db,
        core.event(
            p,
            surface,
            HookEvent.SESSION_START,
            FileEventKind.ADD if previous is None else FileEventKind.CHANGE,
            previous,
            snap,
            None,
            None,
            note="approved by the user (memtegrity approve)",
        ),
    )
    typer.echo(f"Approved {_short(path, Path.cwd())} (event #{ev.id}).")


@app.command()
def report(out: Path | None = None) -> None:
    """Write the HTML incident report and print its path.

    TODO(Block 6): implement.
    """
    raise NotImplementedError


@app.command()
def replay(event_id: int) -> None:
    """Run behavioral replay for a flagged change (normally run in the background by a hook).

    TODO(Block 5): implement.
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
