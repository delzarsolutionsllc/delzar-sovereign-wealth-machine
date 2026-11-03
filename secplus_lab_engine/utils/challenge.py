"""
Challenge mode & progress tracking.

Watching a lab run teaches less than predicting its outcome first. In
challenge mode each lab turns its own scenarios into multiple-choice
questions. You answer, then the engine reveals its verdict and the
reasoning behind it. Scores are stored per SY0-701 objective in
``progress.json`` so ``python main.py progress`` can show your weak areas.

Questions are *computed* by the lab engines rather than hard-coded, so if
you change the policy file or the scenario data, the "correct" answers
change with them.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

DEFAULT_PROGRESS_PATH = Path(__file__).resolve().parent.parent / "progress.json"


@dataclass
class Question:
    """One multiple-choice question generated from a lab scenario."""

    prompt: str
    choices: list[str]
    answer: str
    explanation: str
    objective: str            # e.g. "4.6" — used to aggregate progress
    context: str = ""         # optional scenario detail shown above the prompt

    def __post_init__(self) -> None:
        if self.answer not in self.choices:
            raise ValueError(f"answer '{self.answer}' not among choices {self.choices}")
        if any(c.strip().isdigit() for c in self.choices):
            # A typed digit selects an option by NUMBER, so a choice like "2" would be ambiguous.
            raise ValueError(f"choices must not be bare numbers (use e.g. '2 disks'): {self.choices}")


@dataclass
class ChallengeResult:
    lab: int
    total: int
    correct: int
    missed: list[Question] = field(default_factory=list)

    @property
    def percent(self) -> float:
        return 100.0 * self.correct / self.total if self.total else 0.0


# --------------------------------------------------------------------------- #
# Progress store
# --------------------------------------------------------------------------- #
class Progress:
    """Tiny JSON-backed score store: {objective: {"attempted": n, "correct": n}}."""

    def __init__(self, path: str | Path | None = DEFAULT_PROGRESS_PATH):
        self.path = Path(path) if path else None
        self.data: dict = {"objectives": {}, "sessions": []}
        if self.path and self.path.exists():
            try:
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pass  # corrupt or unreadable file: start fresh rather than crash

    def record(self, objective: str, correct: bool) -> None:
        slot = self.data["objectives"].setdefault(objective, {"attempted": 0, "correct": 0})
        slot["attempted"] += 1
        slot["correct"] += int(correct)

    def record_session(self, result: ChallengeResult) -> None:
        self.data["sessions"].append({
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "lab": result.lab, "score": f"{result.correct}/{result.total}",
        })

    def save(self) -> None:
        if self.path:
            self.path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")

    def rows(self) -> list[list]:
        """Per-objective rows sorted weakest first."""
        out = []
        for obj, s in self.data["objectives"].items():
            pct = 100.0 * s["correct"] / s["attempted"] if s["attempted"] else 0.0
            out.append([obj, s["attempted"], s["correct"], f"{pct:.0f}%", _rating(pct, s["attempted"])])
        return sorted(out, key=lambda r: (float(r[3].rstrip("%")), r[0]))


def _rating(pct: float, attempted: int) -> str:
    if attempted < 3:
        return "LOW" if pct < 50 else "MEDIUM"  # not enough data yet
    if pct >= 85:
        return "PASS"
    if pct >= 65:
        return "WARN"
    return "FAIL"


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #
def run_challenge(
    ui,
    lab_number: int,
    questions: list[Question],
    ask: Callable[[str], str] | None = None,
    progress: Progress | None = None,
    shuffle: bool = True,
    seed: int | None = None,
) -> ChallengeResult:
    """
    Ask each question, reveal the answer, record the score.

    ``ask`` defaults to ``ui.ask``; tests pass a scripted function instead.
    Answers may be given as the option number (``2``) or the option text.
    """
    ask = ask or ui.ask
    qs = list(questions)
    if shuffle:
        random.Random(seed).shuffle(qs)
    result = ChallengeResult(lab_number, len(qs), 0)

    for i, q in enumerate(qs, 1):
        ui.section(f"Question {i}/{len(qs)}  ·  SY0-701 {q.objective}")
        if q.context:
            ui.print(q.context, style="dim")
        ui.print(f"[bold]{q.prompt}[/bold]")
        for n, c in enumerate(q.choices, 1):
            ui.print(f"  {n}) {c}")
        try:
            raw = ask("Your answer:").strip()
        except (EOFError, KeyboardInterrupt):
            ui.print("\n  Challenge stopped early. Scoring the questions answered so far.", style="yellow")
            result.total = i - 1
            break
        chosen = _resolve(raw, q.choices)
        ok = chosen == q.answer
        if ok:
            result.correct += 1
            ui.status("Your answer", "PASS", q.answer)
        else:
            result.missed.append(q)
            ui.status("Your answer", "FAIL", f"you said '{chosen or raw}', engine says '{q.answer}'")
        ui.print(f"  [dim]Why:[/dim] {q.explanation}")
        if progress:
            progress.record(q.objective, ok)

    ui.panel(
        "Challenge score",
        f"{result.correct}/{result.total} correct ({result.percent:.0f}%)"
        + ("\n\nReview these:\n" + "\n".join(f"  • {q.prompt} → {q.answer}" for q in result.missed)
           if result.missed else "\n\nPerfect run."),
        style="green" if result.percent >= 85 else "yellow" if result.percent >= 65 else "red",
    )
    if progress:
        progress.record_session(result)
        progress.save()
    return result


def _resolve(raw: str, choices: list[str]) -> str | None:
    if raw.isdigit() and 1 <= int(raw) <= len(choices):
        return choices[int(raw) - 1]
    for c in choices:
        if raw.lower() == c.lower():
            return c
    return None


def pick_distractors(answer: str, pool, k: int = 3, exclude=(), key: str = "") -> list[str]:
    """
    Choose ``k`` wrong options deterministically.

    ``exclude`` must list every option that would ALSO be correct for this
    question, so a distractor is never a second right answer. ``key`` varies
    the selection between questions while keeping it reproducible.
    """
    banned = {answer, *exclude}
    candidates = sorted({p for p in pool if p not in banned})
    if not candidates:
        return []
    start = sum(map(ord, key)) % len(candidates)
    return [candidates[(start + i) % len(candidates)] for i in range(min(k, len(candidates)))]


def choices_with(answer: str, pool, k: int = 3, exclude=(), key: str = "") -> list[str]:
    """Sorted answer + distractors, ready for ``Question.choices``."""
    return sorted([answer, *pick_distractors(answer, pool, k, exclude, key)])
