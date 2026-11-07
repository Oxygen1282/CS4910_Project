"""Console entry point for ``memtegrity``.

Hooks run on every Write/Edit, so ``memtegrity hook <event>`` takes a fast path that skips
the CLI framework (Typer/Rich) and the database layer. Every other command goes to the
full Typer app in ``cli.py``.
"""

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

    from memtegrity.cli import app

    app()


if __name__ == "__main__":
    main()
