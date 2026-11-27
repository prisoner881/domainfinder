"""The start-of-run banner."""

from __future__ import annotations

import sys

from . import BANNER, METHOD, NAME, TAGLINE, __version__


def render(console) -> None:
    """Framed, coloured banner on a terminal; the plain one-liner elsewhere
    (logs, pipes, CI), so log files don't fill up with box-drawing characters."""
    if not console.is_terminal:
        print(BANNER, file=console.file, flush=True)
        return
    from rich.panel import Panel
    from rich.text import Text

    body = Text()
    body.append(NAME, style="bold cyan")
    body.append(f"  v{__version__}\n", style="dim")
    body.append(TAGLINE + "\n")
    body.append(METHOD, style="dim")
    console.print(Panel(body, border_style="cyan", padding=(0, 2), expand=False))


def show() -> None:
    from rich.console import Console

    render(Console(stderr=True))


if __name__ == "__main__":  # pragma: no cover
    show()
    sys.exit(0)
