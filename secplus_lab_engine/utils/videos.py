"""
Video course index: Professor Messer's free SY0-701 playlist, mapped to the labs.

``data/video_course.json`` holds only metadata (playlist order, YouTube video ID,
title, length, exam objective). The course links to each video on YouTube; it
never downloads, re-hosts or transcribes them. The videos belong to Professor
Messer (https://www.professormesser.com).

Every video carries one SY0-701 objective (taken from its title), so it can be
matched to the labs that exercise that objective, to practice questions, and to
your weakest objectives in progress.json.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache

from utils.loader import ROOT

VIDEO_FILE = ROOT / "data" / "video_course.json"
_OBJ_RE = re.compile(r"\b([1-5]\.\d)\b")


@lru_cache(maxsize=1)
def course() -> dict:
    return json.loads(VIDEO_FILE.read_text(encoding="utf-8"))


def videos() -> list[dict]:
    return course()["videos"]


def url(video: dict, in_playlist: bool = True) -> str:
    """Watch link. In playlist mode YouTube's autoplay continues to the next lesson."""
    base = f"https://www.youtube.com/watch?v={video['id']}"
    return f"{base}&list={course()['source']['playlist_id']}&index={video['n']}" if in_playlist else base


def duration(seconds: int) -> str:
    h, rem = divmod(int(seconds), 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"


def lab_objectives(module) -> list[str]:
    """Objective codes a lab covers, in the order its OBJECTIVES string lists them."""
    seen: list[str] = []
    for code in _OBJ_RE.findall(module.OBJECTIVES):
        if code not in seen:
            seen.append(code)
    return seen


def for_objective(objective: str) -> list[dict]:
    return [v for v in videos() if v["objective"] == objective]


def for_lab(module) -> list[dict]:
    """Videos for every objective the lab covers, in playlist order."""
    objs = set(lab_objectives(module))
    return [v for v in videos() if v["objective"] in objs]


def labs_for_objective(objective: str) -> list[int]:
    from labs import LABS
    return [n for n, (mod, _) in LABS.items() if objective in lab_objectives(mod)]


def study_plan() -> list[dict]:
    """
    The playlist grouped by objective, each step followed by the labs to practise
    it in: watch -> run the lab -> practise. Objectives with no lab yet are marked.
    """
    plan, order = [], []
    for v in videos():
        if v["objective"] not in order:
            order.append(v["objective"])
    for obj in order:
        vs = for_objective(obj)
        plan.append({"objective": obj, "videos": vs, "seconds": sum(v["seconds"] for v in vs),
                     "labs": [] if obj == "intro" else labs_for_objective(obj)})
    return plan


def recommend(progress_rows: list[list], limit: int = 3) -> list[dict]:
    """
    Videos for your weakest objectives (progress rows are sorted weakest first:
    [objective, attempted, correct, pct, status]). Objectives already at PASS
    are skipped.
    """
    out = []
    for obj, *_rest, status in progress_rows:
        if status == "PASS":
            continue
        vs = for_objective(obj)
        if vs:
            out.append({"objective": obj, "status": status, "videos": vs})
        if len(out) >= limit:
            break
    return out


def link_text(objective: str, limit: int = 2) -> str:
    """Short 'watch this' line for hints and flashcards."""
    vs = for_objective(objective)[:limit]
    if not vs:
        return ""
    return "Watch: " + "; ".join(f"{v['title']} ({duration(v['seconds'])}) {url(v, False)}" for v in vs)
