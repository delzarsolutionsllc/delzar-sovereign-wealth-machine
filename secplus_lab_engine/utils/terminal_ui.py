"""
Terminal rendering helpers.

Uses `rich` when installed for colour, tables and panels. If `rich` is missing
(or ``--plain`` is passed) it falls back to plain ASCII output so the engine
still runs on a bare Python install.
"""

from __future__ import annotations

import textwrap
from typing import Any, Iterable, Sequence

try:  # optional dependency
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box

    RICH_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without rich
    RICH_AVAILABLE = False

# Verdict / status words mapped to rich styles.
STATUS_STYLES = {
    "ALLOW": "bold green",
    "ALLOWED": "bold green",
    "APPROVE": "bold green",
    "PASS": "bold green",
    "OK": "bold green",
    "VALID": "bold green",
    "GRANTED": "bold green",
    "STEP_UP": "bold yellow",
    "REQUIRE_HUMAN_APPROVAL": "bold yellow",
    "APPROVE_WITH_CONDITIONS": "bold yellow",
    "WARN": "bold yellow",
    "MEDIUM": "yellow",
    "DENY": "bold red",
    "DENIED": "bold red",
    "BLOCK": "bold red",
    "BLOCKED": "bold red",
    "REJECT": "bold red",
    "FAIL": "bold red",
    "TAMPERED": "bold red",
    "MANIFEST_FORGED": "bold red",
    "QUARANTINED": "bold white on red",
    "HIGH": "bold red",
    "CRITICAL": "bold white on red",
    "LOW": "green",
}


class UI:
    """Small facade over rich / plain-text output."""

    def __init__(self, plain: bool = False, quiet: bool = False):
        self.quiet = quiet
        self.use_rich = RICH_AVAILABLE and not plain
        self.console = Console(highlight=False) if self.use_rich else None

    # ------------------------------------------------------------------ basics
    def print(self, text: str = "", style: str | None = None) -> None:
        if self.quiet:
            return
        if self.use_rich:
            self.console.print(text, style=style)
        else:
            print(_strip_markup(text))

    def header(self, title: str, subtitle: str = "") -> None:
        if self.quiet:
            return
        if self.use_rich:
            body = f"[bold]{title}[/bold]" + (f"\n[dim]{subtitle}[/dim]" if subtitle else "")
            self.console.print(Panel(body, border_style="cyan", box=box.DOUBLE))
        else:
            bar = "=" * 78
            print(f"\n{bar}\n{title}")
            if subtitle:
                print(subtitle)
            print(bar)

    def section(self, title: str) -> None:
        if self.quiet:
            return
        if self.use_rich:
            self.console.rule(f"[bold cyan]{title}")
        else:
            print(f"\n--- {title} " + "-" * max(0, 72 - len(title)))

    def status(self, label: str, verdict: str, detail: str = "") -> None:
        """Print ``label .... VERDICT  detail`` with colour-coded verdict."""
        if self.quiet:
            return
        if self.use_rich:
            style = STATUS_STYLES.get(verdict.upper(), "bold")
            self.console.print(f"  {label:<46} [{style}]{verdict}[/{style}]  [dim]{detail}[/dim]")
        else:
            print(f"  {label:<46} {verdict}  {detail}")

    def bullet(self, text: str, style: str | None = None) -> None:
        self.print(f"  • {text}", style=style)

    # ------------------------------------------------------------------ tables
    def table(self, title: str, columns: Sequence[str], rows: Iterable[Sequence[Any]]) -> None:
        if self.quiet:
            return
        rows = [[str(c) for c in r] for r in rows]
        if self.use_rich:
            t = Table(title=title, box=box.SIMPLE_HEAVY, header_style="bold magenta")
            for col in columns:
                t.add_column(col, overflow="fold")
            for r in rows:
                styled = [_style_cell(c) for c in r]
                t.add_row(*styled)
            self.console.print(t)
        else:
            # Plain mode: flatten multi-line cells, cap all but the last column.
            rows = [[c.replace("\n", ", ") for c in r] for r in rows]
            last = len(columns) - 1
            widths = [len(c) for c in columns]
            for r in rows:
                for i, c in enumerate(r[:last]):
                    widths[i] = min(max(widths[i], len(c)), 40)
            fmt = "  ".join("{:<%d}" % w for w in widths[:last]) + "  {}"
            print(f"\n{title}")
            print(fmt.format(*columns))
            print("  ".join("-" * w for w in widths))
            for r in rows:
                print(fmt.format(*[c[:40] for c in r[:last]], r[last]))

    # ------------------------------------------------------------------ panels
    def panel(self, title: str, body: str, style: str = "blue") -> None:
        if self.quiet:
            return
        if self.use_rich:
            self.console.print(Panel(body, title=title, border_style=style, expand=True))
        else:
            print(f"\n+-- {title} " + "-" * max(0, 70 - len(title)))
            for line in _strip_markup(body).splitlines():
                for wrapped in textwrap.wrap(line, 74) or [""]:
                    print(f"| {wrapped}")
            print("+" + "-" * 77)

    def insight(self, insight: dict) -> None:
        """
        Render the "Exam & Architectural Insight" panel.

        ``insight`` keys: objective, concepts (list), failure_modes (list),
        ai_governance (list), exam_tips (list).
        """
        parts = [f"[bold]Objective:[/bold] {insight.get('objective', '')}"]
        for key, label in (
            ("concepts", "Key Concepts"),
            ("failure_modes", "Manual Failure Modes"),
            ("ai_governance", "How to Govern an AI Agent Here"),
            ("exam_tips", "Exam Tips"),
        ):
            items = insight.get(key) or []
            if items:
                parts.append(f"\n[bold underline]{label}[/bold underline]")
                parts.extend(f"  • {i}" for i in items)
        self.panel("Exam & Architectural Insight", "\n".join(parts), style="green")

    # ------------------------------------------------------------------ input
    def ask(self, prompt: str) -> str:
        if self.use_rich:
            return self.console.input(f"[bold cyan]{prompt}[/bold cyan] ")
        return input(f"{prompt} ")


def _style_cell(cell: str) -> str:
    style = STATUS_STYLES.get(cell.upper())
    return f"[{style}]{cell}[/{style}]" if style else cell


def _strip_markup(text: str) -> str:
    """Remove simple rich markup tags like [bold] / [/bold] for plain output."""
    import re

    return re.sub(r"\[/?[a-z_ ]+(?: on [a-z]+)?\]", "", text)
