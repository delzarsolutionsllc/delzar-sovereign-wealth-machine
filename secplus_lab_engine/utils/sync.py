"""
Move your progress between devices: export it to a file, import (merge) it elsewhere.

The web app keeps progress in each browser (or progress.json when run locally), so a
phone and a laptop each have their own. Export writes one JSON file; import merges it
into what is already there. The web app's My progress page and the CLI use the same
rules (keep the two in step with ``mergeProgress`` in web/index.html):

* objective scores: per objective, the side with MORE answers wins (never added together,
  so importing the same file twice changes nothing);
* daily-review cards: per question, the card reviewed MOST RECENTLY wins (last review =
  due date minus interval), ties go to the one with more misses;
* objective quizzes: best = the higher best, attempts = the larger count, last score from
  the most recent day;
* watched videos: union (sorted); recent sessions: union by time, activity and score (last 50 kept);
* streak: the most recent day wins; on the same day, the longer streak.

    python main.py progress --export my-progress.json
    python main.py progress --import my-progress.json            # merge
    python main.py progress --import my-progress.json --replace  # overwrite
"""

from __future__ import annotations

import json
import re
from datetime import date, datetime, timedelta, timezone

FORMAT = 1
APP = "IdentityOps Lab"
MAX_SESSIONS = 50
_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_OBJ = re.compile(r"^[1-5]\.[1-9]$")
_KEY = re.compile(r"^[\w.\-]{1,40}$")


def empty() -> dict:
    return {"objectives": {}, "sessions": [], "watched": [], "srs": {}, "streak": {"last_day": None, "count": 0},
            "quizzes": {}}


def export(data: dict) -> dict:
    """The file written by Export: the app name, a format number, when, and the progress."""
    return {"app": APP, "format": FORMAT, "exported": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "progress": clean(data)}


def _int(v, lo=0, hi=10 ** 7) -> int:
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return lo


def _day(v):
    return v if isinstance(v, str) and _ISO.match(v) else None


def clean(raw) -> dict:
    """
    A safe copy of progress data from a file: unknown keys dropped, numbers clamped, bad
    entries skipped. Accepts the export envelope or bare progress. Raises ValueError if it
    is not progress data at all.
    """
    if isinstance(raw, dict) and isinstance(raw.get("progress"), dict):
        raw = raw["progress"]
    if not isinstance(raw, dict) or not any(k in raw for k in ("objectives", "srs", "sessions", "watched", "quizzes")):
        raise ValueError("this file does not contain IdentityOps Lab progress")
    out = empty()
    for o, s in (raw.get("objectives") or {}).items() if isinstance(raw.get("objectives"), dict) else []:
        if _OBJ.match(str(o)) and isinstance(s, dict):
            a = _int(s.get("attempted"))
            out["objectives"][o] = {"attempted": a, "correct": min(a, _int(s.get("correct")))}
    for qid, c in (raw.get("srs") or {}).items() if isinstance(raw.get("srs"), dict) else []:
        if _KEY.match(str(qid)) and isinstance(c, dict) and _day(c.get("due")):
            out["srs"][qid] = {"due": c["due"], "interval_days": _int(c.get("interval_days"), 0, 3650),
                               "ease": max(1.3, min(2.8, float(c.get("ease", 2.5)) if isinstance(c.get("ease"), (int, float)) else 2.5)),
                               "reps": _int(c.get("reps"), 0, 10000), "lapses": _int(c.get("lapses"), 0, 10000),
                               "last_result": c.get("last_result") if c.get("last_result") in ("right", "wrong") else None}
    for s in raw.get("sessions") or [] if isinstance(raw.get("sessions"), list) else []:
        if isinstance(s, dict) and isinstance(s.get("ts"), str):
            out["sessions"].append({"ts": s["ts"][:25], "lab": str(s.get("lab", ""))[:40], "score": str(s.get("score", ""))[:40]})
    out["sessions"] = out["sessions"][-MAX_SESSIONS:]
    w = raw.get("watched") if isinstance(raw.get("watched"), list) else []
    out["watched"] = list(dict.fromkeys(v for v in w if isinstance(v, str) and _KEY.match(v)))
    st = raw.get("streak") if isinstance(raw.get("streak"), dict) else {}
    out["streak"] = {"last_day": _day(st.get("last_day")), "count": _int(st.get("count"), 0, 100000)}
    for qz, s in (raw.get("quizzes") or {}).items() if isinstance(raw.get("quizzes"), dict) else []:
        if _KEY.match(str(qz)) and isinstance(s, dict):
            out["quizzes"][qz] = {"best": _int(s.get("best"), 0, 100), "last": _int(s.get("last"), 0, 100),
                                  "attempts": _int(s.get("attempts")), "last_day": _day(s.get("last_day"))}
    return out


def _last_review(card: dict) -> str:
    d = date.fromisoformat(card["due"]) - timedelta(days=int(card.get("interval_days", 0)))
    return d.isoformat()


def merge(mine: dict, theirs: dict) -> dict:
    """Merge two progress records (both already ``clean``). Order does not matter; merging twice is a no-op."""
    a, b = clean(mine), clean(theirs)
    out = empty()
    for o in sorted(set(a["objectives"]) | set(b["objectives"])):
        x, y = a["objectives"].get(o), b["objectives"].get(o)
        out["objectives"][o] = max([s for s in (x, y) if s], key=lambda s: (s["attempted"], s["correct"]))
    for q in sorted(set(a["srs"]) | set(b["srs"])):
        x, y = a["srs"].get(q), b["srs"].get(q)
        out["srs"][q] = max([c for c in (x, y) if c], key=lambda c: (_last_review(c), c["lapses"], c["reps"], c["due"]))
    seen, sessions = set(), []
    for s in sorted(a["sessions"] + b["sessions"], key=lambda s: s["ts"]):
        k = (s["ts"], s["lab"], s["score"])
        if k not in seen:
            seen.add(k)
            sessions.append(s)
    out["sessions"] = sessions[-MAX_SESSIONS:]
    out["watched"] = sorted(set(a["watched"]) | set(b["watched"]))
    sa, sb = a["streak"], b["streak"]
    out["streak"] = max((sa, sb), key=lambda s: (s["last_day"] or "", s["count"]))
    for qz in sorted(set(a["quizzes"]) | set(b["quizzes"])):
        x, y = a["quizzes"].get(qz), b["quizzes"].get(qz)
        both = [s for s in (x, y) if s]
        latest = max(both, key=lambda s: (s["last_day"] or "", s["attempts"]))
        out["quizzes"][qz] = {"best": max(s["best"] for s in both), "last": latest["last"],
                              "attempts": max(s["attempts"] for s in both), "last_day": latest["last_day"]}
    return out


def import_into(current: dict, raw, replace: bool = False) -> dict:
    """The progress after importing ``raw`` (a file's parsed JSON) into ``current``."""
    incoming = clean(raw)
    return incoming if replace else merge(current, incoming)


def read_file(path) -> dict:
    from pathlib import Path
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"not a JSON file: {e}") from None
