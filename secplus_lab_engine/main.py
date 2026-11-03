#!/usr/bin/env python3
"""
Security+ SY0-701 Python Lab Engine & AI Agent Governor
=======================================================

Offline, CLI-driven simulator for manual security operations.

Usage
-----
    python main.py                      # interactive menu
    python main.py list                 # list labs
    python main.py lab 3                # run one lab's example scenario
    python main.py lab 4 --file x.json  # run a lab against your own data
    python main.py all                  # run every lab back-to-back
    python main.py test                 # run the pytest suite
    python main.py --plain lab 1        # no colour (for logs / screen readers)
    python main.py --policies my.json lab 2   # use a custom policy file
"""

from __future__ import annotations

import argparse
import logging
import subprocess
import sys
from pathlib import Path

# Allow ``python main.py`` from any directory.
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from labs import LABS  # noqa: E402
from utils.loader import load_data, load_json, load_policies  # noqa: E402
from utils.terminal_ui import UI  # noqa: E402

log = logging.getLogger("secplus_lab_engine")

BANNER = "Security+ SY0-701 Lab Engine & AI Agent Governor"
SUBTITLE = "Offline, first-principles practice for manual security operations → governed automation"


def run_lab(ui: UI, number: int, policies: dict, data_file: str | None = None) -> dict:
    """Run one lab's example scenario and return its summary dict."""
    if number not in LABS:
        raise SystemExit(f"Unknown lab {number}. Choose from {sorted(LABS)}.")
    module, default_file = LABS[number]
    data = load_json(data_file) if data_file else load_data(default_file)
    ui.header(module.TITLE, module.OBJECTIVES)
    log.info("running lab %s with data=%s", number, data_file or default_file)
    summary = module.run_demo(ui, policies, data)
    ui.panel("Lab summary", "\n".join(f"{k}: {v}" for k, v in summary.items()), style="cyan")
    return summary


def list_labs(ui: UI) -> None:
    ui.table("Available labs", ["#", "Lab", "Objectives", "Default data"],
             [[n, m.TITLE, m.OBJECTIVES, f] for n, (m, f) in LABS.items()])


def run_tests(extra: list[str] | None = None) -> int:
    cmd = [sys.executable, "-m", "pytest", str(ROOT / "tests"), "-q", *(extra or [])]
    return subprocess.call(cmd, cwd=ROOT)


def interactive_menu(ui: UI, policies: dict) -> None:
    ui.header(BANNER, SUBTITLE)
    while True:
        list_labs(ui)
        ui.print("  [bold]1-5[/bold] run a lab   [bold]A[/bold] run all   [bold]T[/bold] run tests   [bold]Q[/bold] quit")
        try:
            choice = ui.ask(">").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ui.print("\nbye")
            return
        if choice in {"q", "quit", "exit"}:
            return
        if choice in {"a", "all"}:
            for n in LABS:
                run_lab(ui, n, policies)
        elif choice in {"t", "test", "tests"}:
            run_tests()
        elif choice.isdigit() and int(choice) in LABS:
            run_lab(ui, int(choice), policies)
        else:
            ui.print(f"Unrecognised option '{choice}'", style="yellow")
            continue
        try:
            ui.ask("Press Enter to return to the menu…")
        except (EOFError, KeyboardInterrupt):
            return


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secplus_lab_engine", description=BANNER)
    p.add_argument("--plain", action="store_true", help="disable colour / rich formatting")
    p.add_argument("--policies", metavar="FILE", help="path to an alternative policy JSON file")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging to stderr")
    sub = p.add_subparsers(dest="command")
    sub.add_parser("menu", help="interactive menu (default)")
    sub.add_parser("list", help="list labs")
    lab = sub.add_parser("lab", help="run a single lab")
    lab.add_argument("number", type=int, choices=sorted(LABS))
    lab.add_argument("--file", metavar="JSON", help="custom scenario data for this lab")
    sub.add_parser("all", help="run every lab")
    t = sub.add_parser("test", help="run the pytest suite")
    t.add_argument("pytest_args", nargs=argparse.REMAINDER)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    ui = UI(plain=args.plain)
    policies = load_policies(args.policies)

    if args.command in (None, "menu"):
        interactive_menu(ui, policies)
    elif args.command == "list":
        list_labs(ui)
    elif args.command == "lab":
        run_lab(ui, args.number, policies, args.file)
    elif args.command == "all":
        ui.header(BANNER, SUBTITLE)
        for n in LABS:
            run_lab(ui, n, policies)
    elif args.command == "test":
        return run_tests(args.pytest_args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
