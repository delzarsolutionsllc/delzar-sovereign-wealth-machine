"""No option-length cue: in single-answer questions the correct answer must not be predictable from
its length rank (writers who avoid 'longest = right' tend to pad one distractor, making
'second-longest = right'). Targets per bank file, as in the add-certification-module skill:
uniquely longest 18-30 %, second-longest at most 32 %, third or fourth at least 30 %, and no
single rank above 40 % (so 'third-longest' does not become the new cue)."""

from __future__ import annotations

import json

import pytest

from utils.loader import ROOT

COURSES = ("sc300", "okta", "spadmin", "speng")
FILES = sorted([p for c in COURSES for p in (ROOT / "data" / "courses" / c / "exam_bank").glob("domain*.json")]
               + list((ROOT / "data" / "exam_bank").glob("domain*.json")))          # Security+


def ranks(path) -> dict:
    counts = {1: 0, 2: 0, 3: 0, 4: 0, "tie": 0}
    n = 0
    for q in json.loads(path.read_text(encoding="utf-8"))["questions"]:
        if q.get("type", "single") != "single":
            continue
        n += 1
        lengths = [len(c) for c in q["choices"]]
        a = len(q["answer"])
        if lengths.count(a) > 1:
            counts["tie"] += 1
        else:
            counts[sorted(lengths, reverse=True).index(a) + 1] += 1
    return {k: 100 * v / n for k, v in counts.items()}


@pytest.mark.parametrize("path", FILES, ids=lambda p: f"{p.parent.parent.name if p.parent.name == 'exam_bank' and p.parent.parent.name != 'data' else 'secplus'}/{p.name}")
def test_answer_length_gives_no_clue(path):
    r = ranks(path)
    assert 18 <= round(r[1]) <= 30, r
    assert round(r[2]) <= 32, r
    assert round(r[3]) + round(r[4]) >= 30, r
    assert max(round(r[k]) for k in (1, 2, 3, 4)) <= 40, r
