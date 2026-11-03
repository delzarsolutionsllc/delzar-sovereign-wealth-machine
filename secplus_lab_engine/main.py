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
    python main.py challenge 4          # predict-the-outcome quiz for a lab (or "challenge all")
    python main.py lab 4 --challenge    # same thing
    python main.py progress             # scores per SY0-701 objective, weakest first
    python main.py challenge 9 --random --seed 42   # fresh generated scenario (labs with a generator)
    python main.py lab 12 --random      # run a lab on a generated scenario
    python main.py exam                 # timed 90-question practice exam weighted by SY0-701 domain
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
from utils.challenge import Progress, run_challenge  # noqa: E402
from utils.exam import build_exam, run_exam  # noqa: E402
from utils.scenario_generator import GENERATORS, generate  # noqa: E402
from utils.loader import load_data, load_json, load_policies  # noqa: E402
from utils.terminal_ui import UI  # noqa: E402

log = logging.getLogger("secplus_lab_engine")

BANNER = "Security+ SY0-701 Lab Engine & AI Agent Governor"
SUBTITLE = "Offline, first-principles practice for manual security operations → governed automation"


def lab_data(number: int, policies: dict, data_file: str | None = None, randomize: bool = False,
             seed: int | None = None) -> dict:
    """Scenario data for a lab: --file, a generated scenario (--random), or the bundled sample."""
    if number not in LABS:
        raise SystemExit(f"Unknown lab {number}. Choose from {sorted(LABS)}.")
    if data_file:
        return load_json(data_file)
    if randomize:
        if number not in GENERATORS:
            raise SystemExit(f"Lab {number} has no random generator (supported: {sorted(GENERATORS)}).")
        return generate(number, policies, seed)
    return load_data(LABS[number][1])


def run_lab(ui: UI, number: int, policies: dict, data_file: str | None = None,
            randomize: bool = False, seed: int | None = None) -> dict:
    """Run one lab's example scenario and return its summary dict."""
    data = lab_data(number, policies, data_file, randomize, seed)
    module, default_file = LABS[number]
    ui.header(module.TITLE, module.OBJECTIVES + (f" · generated scenario (seed {seed})" if randomize else ""))
    log.info("running lab %s with data=%s", number, data_file or default_file)
    summary = module.run_demo(ui, policies, data)
    ui.panel("Lab summary", "\n".join(f"{k}: {v}" for k, v in summary.items()), style="cyan")
    return summary


def challenge_lab(ui: UI, number: int, policies: dict, data_file: str | None = None,
                  progress_path: str | None = None, ask=None, seed: int | None = None, randomize: bool = False):
    """Run challenge mode for one lab and record the score."""
    data = lab_data(number, policies, data_file, randomize, seed)
    module = LABS[number][0]
    ui.header(f"CHALLENGE · {module.TITLE}", "Predict the engine's verdict, then see why. Answer with the option number."
              + (f" Generated scenario (seed {seed})." if randomize else ""))
    questions = module.build_challenges(policies, data)
    progress = Progress(progress_path) if progress_path is not None else Progress()
    return run_challenge(ui, number, questions, ask=ask, progress=progress, seed=seed)


def show_progress(ui: UI, progress_path: str | None = None) -> None:
    p = Progress(progress_path) if progress_path is not None else Progress()
    rows = p.rows()
    if not rows:
        ui.print("No challenge results yet. Try: python main.py challenge 1", style="yellow")
        return
    ui.table("Progress by SY0-701 objective (weakest first)", ["Objective", "Attempted", "Correct", "Score", "Status"], rows)
    recent = p.data.get("sessions", [])[-5:]
    if recent:
        ui.table("Recent sessions", ["When (UTC)", "Lab", "Score"], [[s["ts"], s["lab"], s["score"]] for s in recent])


def exam(ui: UI, policies: dict, count: int = 90, minutes: float = 90, seed: int | None = None,
         randomize: bool = True, ask=None, progress_path: str | None = None):
    questions, alloc, shortfall = build_exam(policies, count, seed, randomize)
    ui.header("PRACTICE EXAM · SY0-701", f"{len(questions)} questions · {minutes:g} minutes · per domain {alloc} · "
                                         "no feedback until the end")
    progress = Progress(progress_path) if progress_path is not None else Progress()
    return run_exam(ui, questions, minutes, ask=ask, progress=progress, shortfall=shortfall)


def list_labs(ui: UI) -> None:
    ui.table("Available labs", ["#", "Lab", "Objectives", "Default data", "Random"],
             [[n, m.TITLE, m.OBJECTIVES, f, "yes" if n in GENERATORS else "-"] for n, (m, f) in LABS.items()])


def run_tests(extra: list[str] | None = None) -> int:
    cmd = [sys.executable, "-m", "pytest", str(ROOT / "tests"), "-q", *(extra or [])]
    return subprocess.call(cmd, cwd=ROOT)


def interactive_menu(ui: UI, policies: dict) -> None:
    ui.header(BANNER, SUBTITLE)
    while True:
        list_labs(ui)
        ui.print(f"  [bold]1-{len(LABS)}[/bold] run a lab   [bold]C<n>[/bold] challenge (e.g. C3)   "
                 "[bold]R<n>[/bold] challenge on a random scenario   [bold]E[/bold] practice exam   [bold]P[/bold] progress   "
                 "[bold]A[/bold] run all   [bold]T[/bold] run tests   [bold]Q[/bold] quit")
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
        elif choice in {"p", "progress"}:
            show_progress(ui)
        elif choice.startswith("c") and choice[1:].strip().isdigit() and int(choice[1:]) in LABS:
            challenge_lab(ui, int(choice[1:]), policies)
        elif choice.startswith("r") and choice[1:].strip().isdigit() and int(choice[1:]) in GENERATORS:
            challenge_lab(ui, int(choice[1:]), policies, randomize=True)
        elif choice in {"e", "exam"}:
            exam(ui, policies)
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
    lab.add_argument("--challenge", action="store_true", help="quiz mode: predict outcomes before they are revealed")
    lab.add_argument("--random", action="store_true", help="use a freshly generated scenario (labs with a generator)")
    lab.add_argument("--seed", type=int, help="seed for --random / question order")
    ch = sub.add_parser("challenge", help="predict-the-outcome quiz for a lab")
    ch.add_argument("target", help="lab number, or 'all'")
    ch.add_argument("--file", metavar="JSON", help="custom scenario data (single lab only)")
    ch.add_argument("--seed", type=int, help="fix the question order (and the generated scenario with --random)")
    ch.add_argument("--random", action="store_true", help="generate a fresh scenario so answers can't be memorised")
    ex = sub.add_parser("exam", help="timed practice exam weighted by SY0-701 domain")
    ex.add_argument("--count", type=int, default=90, help="number of questions (default 90)")
    ex.add_argument("--minutes", type=float, default=90, help="time limit in minutes (default 90)")
    ex.add_argument("--seed", type=int, help="make the exam reproducible")
    ex.add_argument("--fixed", action="store_true", help="use bundled sample data only (no generated scenarios)")
    sub.add_parser("progress", help="show challenge scores per SY0-701 objective")
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
        if args.challenge:
            challenge_lab(ui, args.number, policies, args.file, seed=args.seed, randomize=args.random)
        else:
            run_lab(ui, args.number, policies, args.file, randomize=args.random, seed=args.seed)
    elif args.command == "challenge":
        if args.target == "all":
            for n in LABS:
                challenge_lab(ui, n, policies, seed=args.seed, randomize=args.random and n in GENERATORS)
        elif args.target.isdigit():
            challenge_lab(ui, int(args.target), policies, args.file, seed=args.seed, randomize=args.random)
        else:
            raise SystemExit("challenge target must be a lab number or 'all'")
    elif args.command == "progress":
        show_progress(ui)
    elif args.command == "exam":
        exam(ui, policies, args.count, args.minutes, args.seed, randomize=not args.fixed)
    elif args.command == "all":
        ui.header(BANNER, SUBTITLE)
        for n in LABS:
            run_lab(ui, n, policies)
    elif args.command == "test":
        return run_tests(args.pytest_args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
