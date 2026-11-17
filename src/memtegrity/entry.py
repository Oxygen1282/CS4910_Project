"""Console entry point for ``memtegrity``.

Hooks run on every Write/Edit, so ``memtegrity hook <event>`` takes a fast path that skips
the CLI framework (Typer/Rich) and the database layer. Every other command goes to the
full Typer app in ``cli.py``.
"""

import contextlib
import sys


def main() -> None:
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == "hook":
        from memtegrity.enums import HookEvent

        try:
            event = HookEvent(args[1])
        except ValueError:
            pass  # unknown event: let Typer print a proper error
        else:
            from memtegrity.hooks import emit

            emit(event)
            return

    _no_encoding_crashes()
    from memtegrity.cli import app

    app()


def _no_encoding_crashes() -> None:
    """On Windows, piped output (pre-commit, CI) uses a legacy code page; printing a path or
    evidence snippet it can't encode would crash the scan. Replace such characters instead."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(OSError, ValueError):
                reconfigure(errors="replace")


if __name__ == "__main__":
    main()
