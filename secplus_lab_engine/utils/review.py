"""
Spaced repetition and the adaptive daily review session.

Two jobs, both pure and deterministic (the caller passes ``today``; nothing
here reads the clock, the disk or the network):

1. **Schedule** each exam-bank question you have answered, keyed by its stable
   id (``"D3-031"``), so a question you miss comes back soon and a question you
   keep getting right comes back less and less often.
2. **Build today's session**: every review that is due, oldest first, then new
   questions you have never seen from your weakest objectives.

The scheduling rule in plain English
------------------------------------

Each question has a card: ``due`` (ISO date), ``interval_days``, ``ease``,
``reps`` (right answers in a row), ``lapses`` (times you got it wrong after
seeing it) and ``last_result``.

* **Wrong answer:** the streak of right answers resets to 0, ``lapses`` goes up
  by 1, the interval resets to 1 day so the question is **due tomorrow**, and
  ``ease`` drops by 0.20 (never below 1.30).
* **Right answer:** ``reps`` goes up by 1. The 1st right answer in a row waits
  1 day, the 2nd waits 3 days, the 3rd waits 7 days, and after that the wait is
  the previous wait times ``ease`` (rounded, at most 180 days). ``ease`` rises by
  0.05 (never above 2.80). A new card starts at ease 2.50.
* A question missed in a practice exam or domain test enters review the same
  way. A question answered *right* in an exam only updates a card that already
  exists (otherwise every exam would flood tomorrow with 90 reviews).

How the session is built
------------------------

1. Due reviews (``due <= today``), oldest due date first, ties by id.
2. Then new questions (no card yet) from the weakest objectives. Mastery is
   smoothed: ``(correct + 1) / (attempted + 2)``, so an objective you have never
   practised scores 50% and counts as weak, one at 40% (2 of 5) is weaker still,
   and one at 90% is strong. Objectives are ranked weakest first; questions are
   taken round-robin from the 4 weakest objectives that still have new
   questions (one from each in turn, so a session is never all one objective).
   When one runs out, the next weakest takes its place.
3. Within an objective the order is a seeded shuffle (``mulberry32``, the same
   generator as the web app) of the questions sorted by id. With no seed the
   seed is the date (``20261105``), so a day's session is stable.

Questions whose ``type`` is not single-answer are skipped for now. The web app
(``web/index.html``, ``buildReviewSession``) implements the same rules for the
hosted and desktop modes; keep the two in step.

Streak: consecutive calendar days with at least one review-session answer.
"""

from __future__ import annotations

import math
from datetime import date, timedelta

START_EASE = 2.5
MIN_EASE = 1.3
MAX_EASE = 2.8
EASE_UP = 0.05
EASE_DOWN = 0.2
FIRST_INTERVALS = (1, 3, 7)
MAX_INTERVAL = 180
WEAK_OBJECTIVES = 4          # how many weakest objectives a session interleaves
DEFAULT_SIZE = 15


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def as_date(today) -> date:
    """Accept a ``date`` or an ISO ``YYYY-MM-DD`` string; anything else is a ValueError."""
    if isinstance(today, date):
        return today if type(today) is date else date(today.year, today.month, today.day)
    if isinstance(today, str):
        try:
            return date.fromisoformat(today.strip()[:10])
        except ValueError:
            pass
    raise ValueError(f"today must be a date or YYYY-MM-DD, got {today!r}")


def _round_half_up(x: float) -> int:
    return int(math.floor(x + 0.5))


def _round2(x: float) -> float:
    return math.floor(x * 100 + 0.5) / 100


def mulberry32(seed: int):
    """Same 32-bit PRNG as the web app's ``mulberry32``: identical sequence for the same seed."""
    a = int(seed) & 0xFFFFFFFF

    def rnd() -> float:
        nonlocal a
        a = (a + 0x6D2B79F5) & 0xFFFFFFFF
        t = ((a ^ (a >> 15)) * (1 | a)) & 0xFFFFFFFF
        t = ((t + (((t ^ (t >> 7)) * (61 | t)) & 0xFFFFFFFF)) & 0xFFFFFFFF) ^ t
        return ((t ^ (t >> 14)) & 0xFFFFFFFF) / 4294967296
    return rnd


def shuffle(items: list, rnd) -> list:
    """Fisher-Yates from the end, exactly like the web app's ``shuffle``."""
    a = list(items)
    for i in range(len(a) - 1, 0, -1):
        j = int(math.floor(rnd() * (i + 1)))
        a[i], a[j] = a[j], a[i]
    return a


def is_single(record: dict) -> bool:
    return record.get("type") in (None, "", "single")


# --------------------------------------------------------------------------- #
# scheduler
# --------------------------------------------------------------------------- #
def new_card(today) -> dict:
    return {"due": as_date(today).isoformat(), "interval_days": 0, "ease": START_EASE, "reps": 0, "lapses": 0,
            "last_result": None}


def schedule(card: dict | None, correct: bool, today) -> dict:
    """Return the card after one answer (the input is not modified)."""
    d = as_date(today)
    c = dict(new_card(d), **(card or {}))
    ease = float(c.get("ease") or START_EASE)
    if correct:
        reps = int(c.get("reps") or 0) + 1
        if reps <= len(FIRST_INTERVALS):
            interval = FIRST_INTERVALS[reps - 1]
        else:
            interval = _round_half_up(max(int(c.get("interval_days") or 1), 1) * ease)
        interval = min(interval, MAX_INTERVAL)
        c.update(reps=reps, interval_days=interval, ease=_round2(min(MAX_EASE, ease + EASE_UP)), last_result="right")
    else:
        interval = 1
        c.update(reps=0, interval_days=interval, lapses=int(c.get("lapses") or 0) + 1,
                 ease=_round2(max(MIN_EASE, ease - EASE_DOWN)), last_result="wrong")
    c["due"] = (d + timedelta(days=interval)).isoformat()
    return c


def record_answer(srs: dict, qid: str, correct: bool, today, enroll_correct: bool = True) -> dict | None:
    """
    Update ``srs`` (a dict of id → card) in place for one answer and return the new card.

    ``enroll_correct=False`` (exam results): a right answer on a question with no
    card yet is not scheduled; misses always are.
    """
    if not qid:
        return None
    if qid not in srs and correct and not enroll_correct:
        return None
    srs[qid] = schedule(srs.get(qid), bool(correct), today)
    return srs[qid]


def touch_streak(streak: dict | None, today) -> dict:
    """Streak after studying on ``today``: same day keeps it, the next day adds 1, a gap restarts at 1."""
    d = as_date(today)
    s = {"last_day": None, "count": 0, **(streak or {})}
    last = s.get("last_day")
    if last == d.isoformat():
        return s
    try:
        gap = (d - as_date(last)).days if last else None
    except ValueError:
        gap = None
    count = int(s.get("count") or 0) + 1 if gap == 1 else 1
    if gap is not None and gap < 0:            # clock went backwards: keep what we have
        return s
    return {"last_day": d.isoformat(), "count": count}


def current_streak(streak: dict | None, today) -> int:
    """Streak to display today: still alive if the last study day was today or yesterday."""
    s = streak or {}
    if not s.get("last_day"):
        return 0
    try:
        gap = (as_date(today) - as_date(s["last_day"])).days
    except ValueError:
        return 0
    return int(s.get("count") or 0) if gap in (0, 1) else 0


def due_ids(srs: dict, today, bank_ids=None) -> list[str]:
    """Ids due on or before ``today``, oldest due first, ties by id."""
    t = as_date(today).isoformat()
    items = [(c.get("due") or t, q) for q, c in (srs or {}).items()
             if (c.get("due") or t) <= t and (bank_ids is None or q in bank_ids)]
    return [q for _, q in sorted(items)]


def due_by_day(srs: dict, today, days: int = 7, bank_ids=None) -> dict[str, int]:
    """Count of cards due on each of the next ``days`` days; today's count includes overdue cards."""
    d = as_date(today)
    out = {(d + timedelta(days=i)).isoformat(): 0 for i in range(days)}
    first, last = d.isoformat(), (d + timedelta(days=days - 1)).isoformat()
    for q, c in (srs or {}).items():
        if bank_ids is not None and q not in bank_ids:
            continue
        due = c.get("due") or first
        if due <= first:
            out[first] += 1
        elif due <= last:
            out[due] += 1
    return out


# --------------------------------------------------------------------------- #
# session builder
# --------------------------------------------------------------------------- #
def mastery(objectives: dict, objective: str) -> float:
    s = (objectives or {}).get(objective) or {}
    return (int(s.get("correct") or 0) + 1) / (int(s.get("attempted") or 0) + 2)


def _raw_pct(objectives: dict, objective: str):
    s = (objectives or {}).get(objective) or {}
    a = int(s.get("attempted") or 0)
    return _round_half_up(100 * int(s.get("correct") or 0) / a) if a else None


def _question(r: dict, reason: str, kind: str) -> dict:
    return {"id": r["id"], "prompt": r["stem"], "context": "", "choices": list(r["choices"]), "answer": r["answer"],
            "explanation": r["explanation"], "objective": r["objective"], "reason": reason, "kind": kind}


def build_session(progress_data: dict, bank, today, size: int = DEFAULT_SIZE, seed=None) -> dict:
    """
    Today's study session: due reviews first, then new questions from the weakest objectives.

    ``progress_data`` is the progress.json dict (``objectives``, optional ``srs``),
    ``bank`` the exam-bank records. Returns the questions (each with a plain-English
    ``reason``) plus counts for the summary.
    """
    d = as_date(today)
    size = max(1, int(size))
    seed = int(d.strftime("%Y%m%d")) if seed in (None, "") else int(seed)
    data = progress_data or {}
    srs = data.get("srs") or {}
    objectives = data.get("objectives") or {}
    by_id = {r["id"]: r for r in bank if is_single(r)}

    due = due_ids(srs, d, by_id)
    out = []
    for q in due[:size]:
        c = srs[q]
        why = "Due for review (missed last time)" if c.get("last_result") == "wrong" else "Due for review"
        out.append(_question(by_id[q], why, "review"))

    # new questions, grouped by objective
    groups: dict[str, list[dict]] = {}
    for r in sorted(by_id.values(), key=lambda r: r["id"]):
        if r["id"] not in srs:
            groups.setdefault(r["objective"], []).append(r)
    ranked = sorted(groups, key=lambda o: (mastery(objectives, o), o))
    rnd = mulberry32(seed)
    for o in ranked:
        groups[o] = shuffle(groups[o], rnd)

    def reason(o: str) -> str:
        p = _raw_pct(objectives, o)
        if p is None:
            return f"New: {o} not practised yet"
        if o == ranked[0]:
            return f"New: {o} is your weakest objective ({p}%)"
        return f"New: {o} is one of your weakest objectives ({p}%)"

    queue = list(ranked)
    active = [queue.pop(0) for _ in range(min(WEAK_OBJECTIVES, len(queue)))]
    while len(out) < size and active:
        for o in list(active):
            if len(out) >= size:
                break
            out.append(_question(groups[o].pop(0), reason(o), "new"))
            if not groups[o]:
                i = active.index(o)
                if queue:
                    active[i] = queue.pop(0)
                else:
                    active.pop(i)
    new_count = sum(1 for q in out if q["kind"] == "new")
    return {"today": d.isoformat(), "seed": seed, "size": size, "questions": out,
            "due_total": len(due), "review_count": len(out) - new_count, "new_count": new_count,
            "due_by_day": due_by_day(srs, d, 7, by_id), "tracked": sum(1 for q in srs if q in by_id),
            "streak": {**{"last_day": None, "count": 0}, **(data.get("streak") or {}),
                       "current": current_streak(data.get("streak"), d)}}
