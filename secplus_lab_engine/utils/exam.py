"""
Exam simulator.

Draws a timed, mixed-domain practice exam weighted by the official SY0-701
domain percentages. By default the questions come from the exam-style bank
(data/exam_bank: original scenario questions written like the real exam);
``--source labs`` uses the labs' hands-on challenge questions instead:

    1 General Security Concepts            12 %
    2 Threats, Vulnerabilities & Mitigations 22 %
    3 Security Architecture                18 %
    4 Security Operations                  28 %
    5 Security Program Management          20 %

Labs with a random generator contribute several freshly generated scenarios
(seeded), so two exams with different seeds differ. Like the real exam there
is no feedback per question: you get your score, a per-domain breakdown and a
review of misses at the end.

Scoring: percent correct, mapped to an APPROXIMATE 100–900 scale
(CompTIA's real scaled scoring is not public or linear; 750 is the pass mark).
Questions left unanswered when time runs out count as wrong.

Usage
-----
    python main.py exam                        # 90 questions, 90 minutes
    python main.py exam --count 30 --minutes 30 --seed 7
    python main.py exam --fixed                # sample data only, no random scenarios
    python main.py exam --domain 4             # domain test: 30 questions from Domain 4 only

Domain tests draw only from one domain, spread evenly across its objectives,
and report a score per objective. They are marked against a target of
``DOMAIN_TEST_TARGET`` percent; that is a study target, not a CompTIA figure
(CompTIA publishes no per-domain pass mark).
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Callable

DOMAIN_WEIGHTS = {"1": 0.12, "2": 0.22, "3": 0.18, "4": 0.28, "5": 0.20}
DOMAIN_NAMES = {"1": "General Security Concepts", "2": "Threats, Vulnerabilities & Mitigations",
                "3": "Security Architecture", "4": "Security Operations", "5": "Security Program Management"}
PASS_SCALED = 750
DOMAIN_TEST_TARGET = 80          # percent; a study target for domain tests, not an official number


@dataclass
class ExamResult:
    total: int
    correct: int
    answered: int
    timed_out: bool
    by_domain: dict = field(default_factory=dict)      # domain -> [correct, total]
    missed: list = field(default_factory=list)
    shortfall: dict = field(default_factory=dict)      # domain -> questions short of target
    domain: str | None = None                          # set for a single-domain test
    by_objective: dict = field(default_factory=dict)   # objective -> [correct, total]

    @property
    def percent(self) -> float:
        return 100.0 * self.correct / self.total if self.total else 0.0

    @property
    def scaled(self) -> int:
        return round(100 + 8 * self.percent)

    @property
    def passed(self) -> bool:
        if self.domain:
            return self.percent >= DOMAIN_TEST_TARGET
        return self.scaled >= PASS_SCALED


SOURCES = ("bank", "labs")


def bank_pool() -> dict:
    """Exam-style bank questions grouped by domain (empty lists if the bank is missing)."""
    from utils.exam_bank import as_questions
    pool: dict[str, list] = {d: [] for d in DOMAIN_WEIGHTS}
    for q in as_questions():
        pool[q.objective.split(".")[0]].append(q)
    return pool


def collect_questions(policies: dict, seed: int | None = None, randomize: bool = True, rounds: int = 3,
                      source: str = "bank") -> dict:
    """
    Questions grouped by domain.

    source="bank" (default): the exam-style question bank (data/exam_bank), which
    reads like the real exam. Falls back to the lab questions if the bank is empty.
    source="labs": the labs' challenge questions (de-duplicated), useful for
    practising the hands-on scenarios under exam conditions.
    """
    if source not in SOURCES:
        raise ValueError(f"unknown question source '{source}' (use {', '.join(SOURCES)})")
    if source == "bank":
        pool = bank_pool()
        if any(pool.values()):
            return pool
    from labs import LABS
    from utils.loader import load_data
    from utils.scenario_generator import GENERATORS, generate

    pool: dict[str, list] = {d: [] for d in DOMAIN_WEIGHTS}
    seen: set = set()
    base = seed if seed is not None else 0
    for n, (module, data_file) in LABS.items():
        datasets = [load_data(data_file)]
        if randomize and n in GENERATORS:
            datasets += [generate(n, policies, seed=base * 1000 + n * 10 + r) for r in range(rounds)]
        for data in datasets:
            for q in module.build_challenges(policies, data):
                key = (q.prompt, q.context, *q.choices)       # same prompt can come with different choices
                dom = q.objective.split(".")[0]
                if key in seen or dom not in pool:
                    continue
                seen.add(key)
                pool[dom].append(q)
    return pool


def allocate(count: int, available: dict) -> tuple[dict, dict]:
    """
    Split ``count`` across domains by official weight (largest-remainder),
    then move any shortfall (domain has too few questions) to other domains.
    """
    raw = {d: count * w for d, w in DOMAIN_WEIGHTS.items()}
    alloc = {d: int(v) for d, v in raw.items()}
    for d in sorted(raw, key=lambda d: raw[d] - alloc[d], reverse=True)[: count - sum(alloc.values())]:
        alloc[d] += 1
    shortfall = {d: alloc[d] - available.get(d, 0) for d in alloc if alloc[d] > available.get(d, 0)}
    for d in shortfall:
        alloc[d] = available.get(d, 0)
    spare = count - sum(alloc.values())
    while spare > 0:
        room = [d for d in sorted(DOMAIN_WEIGHTS, key=DOMAIN_WEIGHTS.get, reverse=True) if alloc[d] < available.get(d, 0)]
        if not room:
            break
        for d in room:
            if spare == 0:
                break
            alloc[d] += 1
            spare -= 1
    return alloc, shortfall


def _shuffled_choices(q, rng: random.Random):
    """Copy of a question with its options in a random order (the answer letter varies between exams)."""
    from dataclasses import replace
    choices = list(q.choices)
    rng.shuffle(choices)
    return replace(q, choices=choices)


def build_exam(policies: dict, count: int = 90, seed: int | None = None, randomize: bool = True,
               source: str = "bank"):
    rng = random.Random(seed)
    pool = collect_questions(policies, seed, randomize, source=source)
    alloc, shortfall = allocate(count, {d: len(q) for d, q in pool.items()})
    questions = []
    for d, n in alloc.items():
        questions += rng.sample(pool[d], n)
    rng.shuffle(questions)
    if source == "bank":
        questions = [_shuffled_choices(q, rng) for q in questions]
    return questions, alloc, shortfall


def build_domain_test(policies: dict, domain: str, count: int = 30, seed: int | None = None,
                      randomize: bool = True, source: str = "bank") -> tuple[list, dict]:
    """
    Questions from one domain only, spread evenly over its objectives (round-robin),
    so a 30-question Domain 3 test covers 3.1, 3.2, 3.3 and 3.4 rather than
    whichever objective has the most questions. Returns (questions, per-objective counts).
    """
    domain = str(domain)
    if domain not in DOMAIN_WEIGHTS:
        raise ValueError(f"unknown domain '{domain}' (use 1-5)")
    rng = random.Random(seed)
    pool = collect_questions(policies, seed, randomize, source=source)[domain]
    by_obj: dict[str, list] = {}
    for q in pool:
        by_obj.setdefault(q.objective, []).append(q)
    for qs in by_obj.values():
        rng.shuffle(qs)
    picked, order = [], sorted(by_obj, key=lambda o: tuple(map(int, o.split("."))))
    while len(picked) < count and any(by_obj[o] for o in order):
        for o in order:
            if by_obj[o] and len(picked) < count:
                picked.append(by_obj[o].pop())
    rng.shuffle(picked)
    if source == "bank":
        picked = [_shuffled_choices(q, rng) for q in picked]
    counts: dict[str, int] = {}
    for q in picked:
        counts[q.objective] = counts.get(q.objective, 0) + 1
    return picked, dict(sorted(counts.items(), key=lambda kv: tuple(map(int, kv[0].split(".")))))


def run_exam(ui, questions: list, minutes: float = 90, ask: Callable[[str], str] | None = None,
             clock: Callable[[], float] = time.monotonic, progress=None, shortfall: dict | None = None,
             domain: str | None = None) -> ExamResult:
    from utils.challenge import _resolve

    ask = ask or ui.ask
    deadline = clock() + minutes * 60
    res = ExamResult(len(questions), 0, 0, False, {d: [0, 0] for d in DOMAIN_WEIGHTS}, [], shortfall or {},
                     str(domain) if domain else None)
    for q in questions:
        res.by_domain[q.objective.split(".")[0]][1] += 1
        res.by_objective.setdefault(q.objective, [0, 0])[1] += 1
    for i, q in enumerate(questions, 1):
        left = deadline - clock()
        if left <= 0:
            res.timed_out = True
            res.missed += [(x, None) for x in questions[i - 1:]]
            break
        ui.section(f"Question {i}/{len(questions)}  ·  {int(left // 60)}:{int(left % 60):02d} left")
        if q.context:
            ui.print(q.context, style="dim")
        ui.print(f"[bold]{q.prompt}[/bold]")
        for n, c in enumerate(q.choices, 1):
            ui.print(f"  {n}) {c}")
        try:
            raw = ask("Answer:").strip()
        except (EOFError, KeyboardInterrupt):
            res.missed += [(x, None) for x in questions[i - 1:]]
            break
        res.answered += 1
        chosen = _resolve(raw, q.choices)
        ok = chosen == q.answer
        if ok:
            res.correct += 1
            res.by_domain[q.objective.split(".")[0]][0] += 1
            res.by_objective[q.objective][0] += 1
        else:
            res.missed.append((q, chosen or raw))
        if progress:
            progress.record(q.objective, ok)

    verdict = "PASS" if res.passed else "FAIL"
    if res.domain:
        rows = [[o, f"{c}/{t}", f"{(100 * c / t):.0f}%" if t else "-", "weak" if t and 100 * c / t < DOMAIN_TEST_TARGET else ""]
                for o, (c, t) in sorted(res.by_objective.items(), key=lambda kv: tuple(map(int, kv[0].split("."))))]
        ui.table(f"Domain {res.domain} {DOMAIN_NAMES[res.domain]}: score by objective",
                 ["Objective", "Correct", "Score", ""], rows)
        headline = (f"{res.correct}/{res.total} correct ({res.percent:.0f}%) · target {DOMAIN_TEST_TARGET}%: {verdict}\n"
                    f"Domain {res.domain} is {int(DOMAIN_WEIGHTS[res.domain] * 100)}% of the real exam. "
                    "The target is a study goal; CompTIA publishes no per-domain pass mark.")
        title = f"Domain {res.domain} test result"
    else:
        rows = [[d, DOMAIN_NAMES[d], f"{int(DOMAIN_WEIGHTS[d] * 100)}%", f"{c}/{t}", f"{(100 * c / t):.0f}%" if t else "-"]
                for d, (c, t) in res.by_domain.items()]
        ui.table("Score by domain", ["Domain", "Name", "Weight", "Correct", "Score"], rows)
        headline = (f"{res.correct}/{res.total} correct ({res.percent:.0f}%) → approx. scaled score {res.scaled} "
                    f"(pass {PASS_SCALED}): {verdict}")
        title = "Practice exam result"
    ui.panel(title, headline
             + ("\nTime ran out: unanswered questions count as wrong." if res.timed_out else "")
             + (f"\nNot enough questions for domain(s) {res.shortfall}; extra questions came from other domains."
                if res.shortfall else ""),
             style="green" if res.passed else "red")
    if res.missed:
        ui.section("Review (first 15 misses)")
        for q, given in res.missed[:15]:
            ui.bullet(f"[{q.objective}] {q.prompt} → {q.answer}" + (f" (you: {given})" if given else " (unanswered)"))
            ui.print(f"      {q.explanation}", style="dim")
    if progress:
        progress.data["sessions"].append({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "lab": f"domain {res.domain} test" if res.domain else "exam",
            "score": f"{res.correct}/{res.total} ({res.percent:.0f}%)" if res.domain
            else f"{res.correct}/{res.total} (scaled {res.scaled})"})
        progress.save()
    return res
