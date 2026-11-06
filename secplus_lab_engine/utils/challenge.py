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

def _progress_file() -> Path:
    """progress.json for Security+ (unchanged); progress-<course>.json for every other course."""
    from utils import course
    name = "progress.json" if course.code() == course.DEFAULT else f"progress-{course.code()}.json"
    return Path(__file__).resolve().parent.parent / name


DEFAULT_PROGRESS_PATH = _progress_file()


KINDS = ("single", "multi", "order", "match")


@dataclass
class Question:
    """
    One exam or challenge question.

    ``kind`` is "single" (one answer, the default and the only kind the labs make),
    "multi" (select TWO: ``answers`` holds the correct choices), "order" (``items``
    holds the steps in the CORRECT order; ``choices`` is the order shown) or
    "match" (``pairs`` holds (item, target) tuples; ``choices`` lists every target,
    distractors included). For non-single kinds ``answer`` is a readable string of
    the correct response, so code that prints ``q.answer`` keeps working; score
    with :func:`check`, never by comparing against ``answer``.
    """

    prompt: str
    choices: list[str]
    answer: str
    explanation: str
    objective: str            # e.g. "4.6" — used to aggregate progress
    context: str = ""         # optional scenario detail shown above the prompt
    qid: str = ""             # stable id for exam-bank questions (e.g. "D3-031"); empty for lab questions
    kind: str = "single"
    answers: tuple = ()       # multi: the correct choices
    items: tuple = ()         # order: the correct order
    pairs: tuple = ()         # match: ((item, target), ...)

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"unknown question kind '{self.kind}'")
        if any(c.strip().isdigit() for c in self.choices):
            # A typed digit selects an option by NUMBER, so a choice like "2" would be ambiguous.
            raise ValueError(f"choices must not be bare numbers (use e.g. '2 disks'): {self.choices}")
        self.answers, self.items = tuple(self.answers), tuple(self.items)
        self.pairs = tuple((str(i), str(m)) for i, m in self.pairs)
        if self.kind == "single":
            if self.answer not in self.choices:
                raise ValueError(f"answer '{self.answer}' not among choices {self.choices}")
        elif self.kind == "multi":
            if len(self.answers) < 2 or len(set(self.answers)) != len(self.answers) or not set(self.answers) <= set(self.choices):
                raise ValueError(f"multi: answers {self.answers} must be 2+ distinct choices")
        elif self.kind == "order":
            if len(self.items) < 2 or sorted(self.items) != sorted(self.choices):
                raise ValueError("order: choices must be the same steps as items (in any order)")
        elif self.kind == "match":
            items = [i for i, _ in self.pairs]
            if len(items) < 2 or len(set(items)) != len(items) or not {m for _, m in self.pairs} <= set(self.choices):
                raise ValueError("match: every pair target must be among choices and items must be distinct")

    @property
    def select(self) -> int:
        """How many options a multi question asks for (1 for every other kind)."""
        return len(self.answers) if self.kind == "multi" else 1

    def check(self, response) -> bool:
        return check(self, response)


def answer_text(kind: str, answer: str = "", answers=(), items=(), pairs=()) -> str:
    """Stable, readable form of the correct response (what ``Question.answer`` holds for non-single kinds)."""
    if kind == "multi":
        return "; ".join(answers)
    if kind == "order":
        return " → ".join(items)
    if kind == "match":
        return "; ".join(f"{i} = {m}" for i, m in pairs)
    return answer


def check(question: Question, response) -> bool:
    """
    Is ``response`` fully correct? No partial credit, like the real exam's
    all-or-nothing marking of a single item.

    single: the chosen choice text · multi: an iterable of chosen choices (exactly
    the right set) · order: a sequence of items (exactly the right order) ·
    match: a mapping item -> target (every item matched correctly).
    """
    q = question
    if response is None:
        return False
    if q.kind == "single":
        return response == q.answer
    if q.kind == "multi":
        if isinstance(response, str):
            return False
        chosen = list(response)
        return len(chosen) == len(set(chosen)) == len(q.answers) and set(chosen) == set(q.answers)
    if q.kind == "order":
        return not isinstance(response, str) and tuple(response) == q.items
    if q.kind == "match":
        return isinstance(response, dict) and len(response) == len(q.pairs) and all(response.get(i) == m for i, m in q.pairs)
    return False


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
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    self.data = loaded
            except (OSError, json.JSONDecodeError):
                pass  # corrupt or unreadable file: start fresh rather than crash
        # Older files have no spaced-repetition state: add the empty defaults.
        self.data.setdefault("objectives", {})
        self.data.setdefault("sessions", [])
        if not isinstance(self.data.get("srs"), dict):
            self.data["srs"] = {}
        if not isinstance(self.data.get("streak"), dict):
            self.data["streak"] = {"last_day": None, "count": 0}

    def record(self, objective: str, correct: bool, qid: str = "", today=None, review: bool = False) -> None:
        """
        Count one answer for ``objective``. With an exam-bank ``qid`` the answer also
        schedules spaced repetition (see utils/review.py): a miss always enters review;
        a right answer updates an existing card, or starts one when ``review`` is true
        (answered in a review session, which also counts toward the daily streak).
        """
        slot = self.data["objectives"].setdefault(objective, {"attempted": 0, "correct": 0})
        slot["attempted"] += 1
        slot["correct"] += int(correct)
        if qid or review:
            from utils import review as srs
            from datetime import date
            day = today if today is not None else date.today()
            if qid:
                srs.record_answer(self.data["srs"], qid, correct, day, enroll_correct=review)
            if review:
                self.data["streak"] = srs.touch_streak(self.data.get("streak"), day)

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
def _exam_code() -> str:
    from utils import course
    return course.active().get("exam_code") or "SY0-701"


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
    Answers may be given as the option number (``2``), letter (``B``) or the option text.
    """
    ask = ask or ui.ask
    qs = list(questions)
    if shuffle:
        random.Random(seed).shuffle(qs)
    result = ChallengeResult(lab_number, len(qs), 0)

    for i, q in enumerate(qs, 1):
        ui.section(f"Question {i}/{len(qs)}  ·  {_exam_code()} {q.objective}")
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
        if q.kind == "single":
            chosen = _resolve(raw, q.choices)
            ok = chosen == q.answer
        else:                                   # multi / order / match typed at a terminal
            chosen = raw
            ok = raw.strip() == q.answer or check(q, _parse_list(raw, q))
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


def option_index(token: str, choices: list[str]) -> int | None:
    """
    0-based option index for a typed number (``2``) or letter (``B``, case-insensitive).
    Letters are off for a question whose options include a one-letter text (such as "A"),
    so typing that text always means the text itself.
    """
    t = token.strip()
    if t.isdigit():
        return int(t) - 1 if 1 <= int(t) <= len(choices) else None
    if len(t) == 1 and t.isalpha() and not any(len(c.strip()) == 1 and c.strip().isalpha() for c in choices):
        k = ord(t.lower()) - ord("a")
        return k if 0 <= k < len(choices) else None
    return None


def _parse_list(raw: str, q: Question):
    """Options typed as numbers or letters separated by commas/spaces (``2,4`` or ``B D``), for multi and order."""
    picks = []
    for tok in raw.replace(",", " ").split():
        k = option_index(tok, q.choices)
        if k is None:
            return None
        picks.append(q.choices[k])
    return picks or None


def _resolve(raw: str, choices: list[str]) -> str | None:
    """Choice for an answer typed as its exact text, its number (``2``) or its letter (``B``)."""
    for c in choices:
        if raw.strip().lower() == c.lower():
            return c
    k = option_index(raw, choices)
    return choices[k] if k is not None else None


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
