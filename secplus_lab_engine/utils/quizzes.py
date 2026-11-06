"""
Objective quizzes: several short quizzes for every SY0-701 objective ("subdomain", e.g. 2.4),
so each concept can be learned one at a time.

For each objective the exam-style bank (utils/exam_bank.py) gives:

* **Concept quizzes**: one per topic of the objective (e.g. 2.4 Malware, 2.4 Password attacks),
  every question tagged with that topic. Topics follow the official objective sub-bullets
  (data/exam_bank/topics/*.json).
* **Mixed sets**: Set 1, Set 2, ... of about ``SET_SIZE`` questions that together cover the
  whole objective once, each set spread across the topics.

Quizzes are untimed and teach as you go: answer, see the right answer and why at once.
Answers count toward the objective's score and feed the daily review (misses come back
tomorrow), and each quiz keeps your best and last score.

Quiz ids are stable for a given bank: ``2.4-set1``, ``2.4-t3`` (topic 3 of 2.4).

    python main.py quiz                 # every objective and its quizzes
    python main.py quiz 2.4             # the quizzes for one objective
    python main.py quiz 2.4 --set 2     # take Set 2
    python main.py quiz 2.4 --topic 3   # take the concept quiz for topic 3
"""

from __future__ import annotations

import random
import re
from functools import lru_cache

SET_SIZE = 10
MIN_LAST_SET = 5                      # a smaller remainder joins the previous set
QUIZ_ID = re.compile(r"^(\d{1,2}\.\d{1,2})-(set|t)(\d{1,2})$")
OTHER_TOPIC = "Other"


def _objective_names() -> dict:
    from tools.export_anki import OBJECTIVE_NAMES
    return OBJECTIVE_NAMES


def _sort_key(q: dict):
    m = re.match(r"^D(\d{1,2})-(\d+)$", q["id"])
    return (0, int(m.group(1)), int(m.group(2)), "") if m else (1, 0, 0, q["id"])


def _chunks(qs: list, size: int = SET_SIZE, min_last: int = MIN_LAST_SET) -> list[list]:
    """
    Deal ``qs`` (grouped topic by topic) round-robin into about len/size sets, like cards:
    sets differ in size by at most one, and every topic with at least as many questions as
    there are sets lands in every set.
    """
    if not qs:
        return []
    n = max(1, round(len(qs) / size))
    if len(qs) - (n - 1) * size < min_last and n > 1:
        n -= 1
    return [qs[k::n] for k in range(n)]


@lru_cache(maxsize=1)
def catalog() -> dict:
    """
    ``{objective: {"name", "domain", "topics": [{"name", "count"}], "count",
    "quizzes": [{"id", "kind": "set"|"topic", "title", "topic", "qids"}]}}`` for every objective.
    """
    from utils.exam_bank import VALID_OBJECTIVES, load_bank, load_topics
    topic_lists, _ = load_topics()
    names = _objective_names()
    bank = sorted(load_bank(), key=_sort_key)
    out: dict[str, dict] = {}
    for obj in sorted(VALID_OBJECTIVES, key=lambda o: tuple(map(int, o.split(".")))):
        qs = [q for q in bank if q["objective"] == obj]
        order = list(topic_lists.get(obj, []))
        for q in qs:                                   # a tag outside the list still gets a quiz
            t = q.get("topic") or OTHER_TOPIC
            if t not in order:
                order.append(t)
        by_topic = {t: [q for q in qs if (q.get("topic") or OTHER_TOPIC) == t] for t in order}
        quizzes = []                                   # study order: one concept at a time, then the mixed sets
        for k, t in enumerate(order, 1):
            if by_topic[t]:
                quizzes.append({"id": f"{obj}-t{k}", "kind": "topic", "title": t, "topic": t,
                                "qids": [q["id"] for q in by_topic[t]]})
        grouped = [q for t in order for q in by_topic[t]]      # topic by topic; dealing then spreads each topic over every set
        for k, part in enumerate(_chunks(grouped), 1):
            quizzes.append({"id": f"{obj}-set{k}", "kind": "set", "title": f"Set {k}", "topic": None,
                            "qids": [q["id"] for q in part]})
        out[obj] = {"name": names.get(obj, ""), "domain": obj.split(".")[0], "count": len(qs),
                    "topics": [{"name": t, "count": len(by_topic[t])} for t in order if by_topic[t]],
                    "quizzes": quizzes}
    return out


def find(quiz_id: str) -> dict:
    """An objective quiz (``2.4-set1``, ``2.4-t3``) or a glossary quiz (``g3-acr-1``)."""
    if str(quiz_id or "").startswith("g"):
        from utils import glossary
        return glossary.find(quiz_id)
    m = QUIZ_ID.match(str(quiz_id or ""))
    quiz = next((q for q in catalog().get(m.group(1), {}).get("quizzes", []) if q["id"] == quiz_id), None) if m else None
    if not quiz:
        raise ValueError(f"unknown quiz '{quiz_id}'")
    return quiz


def is_glossary(quiz_id: str) -> bool:
    return str(quiz_id or "").startswith("g")


def records(quiz_id: str) -> list[dict]:
    """The quiz's question records (exam bank or generated glossary questions), in catalogue order."""
    if is_glossary(quiz_id):
        from utils import glossary
        return glossary.as_records(quiz_id)
    from utils.exam_bank import load_bank
    by_id = {r["id"]: r for r in load_bank()}
    return [by_id[i] for i in find(quiz_id)["qids"]]


def questions(quiz_id: str, seed=None) -> list:
    """The quiz's questions as challenge ``Question`` objects: order and options shuffled by ``seed``."""
    from utils.exam import _shuffled_choices
    from utils.exam_bank import as_question
    rng = random.Random(seed)
    qs = [_shuffled_choices(as_question(r), rng) for r in records(quiz_id)]
    rng.shuffle(qs)
    return qs


def record(data: dict, quiz_id: str, correct: int, total: int, today: str) -> dict:
    """Store a quiz score in progress data: best, last, attempts and the day it was taken."""
    find(quiz_id)
    p = int(100 * correct / total + 0.5) if total else 0       # same rounding as the web app
    slot = data.setdefault("quizzes", {}).setdefault(quiz_id, {"best": 0, "last": 0, "attempts": 0, "last_day": None})
    slot.update(best=max(int(slot.get("best", 0)), p), last=p, attempts=int(slot.get("attempts", 0)) + 1, last_day=today)
    return slot
