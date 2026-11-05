"""Objective quizzes (utils/quizzes.py): several short quizzes per objective, one per concept plus mixed sets."""

from __future__ import annotations

import json
from collections import Counter

import pytest

import main
import webapi
from utils import challenge as ch
from utils import exam_bank, quizzes
from utils.terminal_ui import UI

BANK = list(exam_bank.load_bank())
CAT = quizzes.catalog()


@pytest.fixture(autouse=True)
def no_real_progress(monkeypatch, tmp_path):
    monkeypatch.setattr(ch, "DEFAULT_PROGRESS_PATH", tmp_path / "default-progress.json")
    monkeypatch.setattr(ch.Progress.__init__, "__defaults__", (tmp_path / "default-progress.json",))


def test_extra_bank_files_are_valid():
    extras = [f for f in exam_bank.bank_files() if "-" in f.stem]
    assert len(extras) >= 6
    for f in extras:
        data = json.loads(f.read_text(encoding="utf-8"))
        d = f.stem[len("domain")]
        assert data["domain"] == d and "Not from exam dumps" in data["note"]
        assert exam_bank.validate(data["questions"], d) == [], f.name


def test_ids_and_stems_unique_across_all_files():
    ids = [q["id"] for q in BANK]
    assert len(ids) == len(set(ids))
    stems = Counter(" ".join(q["stem"].lower().split()) for q in BANK)
    assert max(stems.values()) == 1


def test_every_question_has_a_topic_from_its_objectives_list():
    topics, _ = exam_bank.load_topics()
    for q in BANK:
        assert q.get("topic") in topics.get(q["objective"], []), q["id"]


def test_every_objective_has_enough_questions_and_concepts():
    assert set(CAT) == exam_bank.VALID_OBJECTIVES
    for o, c in CAT.items():
        assert c["count"] >= 30, o
        assert 3 <= len(c["topics"]) <= 8, o
        assert all(t["count"] >= 5 for t in c["topics"]), o
        assert c["name"], o


def test_sets_cover_each_question_exactly_once_and_topics_partition_it():
    for o, c in CAT.items():
        mine = sorted(q["id"] for q in BANK if q["objective"] == o)
        sets = [q for q in c["quizzes"] if q["kind"] == "set"]
        topic_qs = [q for q in c["quizzes"] if q["kind"] == "topic"]
        assert len(sets) >= 3, o                                       # "multiple quizzes per subdomain"
        assert sorted(i for s in sets for i in s["qids"]) == mine
        assert sorted(i for t in topic_qs for i in t["qids"]) == mine
        assert all(8 <= len(s["qids"]) <= 14 for s in sets), (o, [len(s["qids"]) for s in sets])
        assert [q["kind"] for q in c["quizzes"]] == ["topic"] * len(topic_qs) + ["set"] * len(sets)   # concepts first


def test_sets_mix_the_topics():
    for o, c in CAT.items():
        by = {q["id"]: q["topic"] for q in BANK}
        for s in (q for q in c["quizzes"] if q["kind"] == "set"):
            assert len({by[i] for i in s["qids"]}) >= min(3, len(c["topics"])), (o, s["id"])


def test_quiz_ids_are_stable_and_findable():
    for c in CAT.values():
        for q in c["quizzes"]:
            assert quizzes.QUIZ_ID.match(q["id"]) and quizzes.find(q["id"]) is q
    for bad in ("", "9.9-set1", "1.1-set99", "1.1-x1", "../etc"):
        with pytest.raises(ValueError):
            quizzes.find(bad)


def test_questions_are_shuffled_but_answers_kept():
    qid = "2.4-set1"
    a, b = quizzes.questions(qid, 1), quizzes.questions(qid, 2)
    assert sorted(q.qid for q in a) == sorted(q.qid for q in b) == sorted(quizzes.find(qid)["qids"])
    assert [q.qid for q in a] != [q.qid for q in b] or [q.choices for q in a] != [q.choices for q in b]
    by = {r["id"]: r for r in BANK}
    for q in a:
        if q.kind == "single":
            assert q.answer == by[q.qid]["answer"] and sorted(q.choices) == sorted(by[q.qid]["choices"])
    assert [q.qid for q in quizzes.questions(qid, 5)] == [q.qid for q in quizzes.questions(qid, 5)]


def test_api_quiz_and_record(tmp_path):
    path = tmp_path / "p.json"
    got = webapi.dispatch("quiz", {"quiz": "1.1-t1", "seed": 3}, progress_path=path)
    qs = got["questions"]
    assert got["objective"] == "1.1" and got["quiz"]["kind"] == "topic" and "qids" not in got["quiz"]
    assert all(q["topic"] == got["quiz"]["topic"] for q in qs)
    results = [{"objective": q["objective"], "correct": k % 2 == 0, "qid": q["id"]} for k, q in enumerate(qs)]
    r1 = webapi.dispatch("quiz_record", {"quiz": "1.1-t1", "results": results, "today": "2026-11-05"}, progress_path=path)
    want = int(100 * sum(r["correct"] for r in results) / len(results) + 0.5)
    assert r1["quiz_score"] == {"best": want, "last": want, "attempts": 1, "last_day": "2026-11-05"}
    assert r1["objectives"]["1.1"]["attempted"] == len(qs)
    missed = [r["qid"] for r in results if not r["correct"]]
    assert all(r1["srs"][q]["due"] == "2026-11-06" for q in missed)          # misses enter the daily review
    perfect = [{**r, "correct": True} for r in results]
    r2 = webapi.quiz_record("1.1-t1", perfect, "2026-11-06", path)
    assert r2["quiz_score"]["best"] == 100 and r2["quiz_score"]["attempts"] == 2
    r3 = webapi.quiz_record("1.1-t1", results, "2026-11-07", path)
    assert r3["quiz_score"]["best"] == 100 and r3["quiz_score"]["last"] == want
    assert r3["sessions"][-1]["lab"] == "quiz 1.1-t1"


def test_quiz_record_rejects_foreign_questions(tmp_path):
    other = CAT["2.1"]["quizzes"][0]["qids"][0]
    for bad in ([], [{"objective": "1.1", "correct": True, "qid": other}], "x", [{"correct": True}]):
        with pytest.raises(ValueError):
            webapi.quiz_record("1.1-t1", bad, "2026-11-05", tmp_path / "p.json")
    with pytest.raises(ValueError):
        webapi.dispatch("quiz", {"quiz": "nope"})


def test_catalog_and_bundle_carry_the_quizzes(policies):
    cat = webapi.catalog(policies)
    assert cat["objective_quizzes"] == CAT and cat["quiz_set_size"] == quizzes.SET_SIZE
    from tools.build_web_bundle import build
    b = build(1)
    ids = {r["id"] for r in b["exam_bank"]}
    assert all(i in ids for c in b["catalog"]["objective_quizzes"].values() for q in c["quizzes"] for i in q["qids"])
    assert all(r.get("topic") for r in b["exam_bank"])


def test_cli_lists_and_runs_a_quiz(tmp_path):
    path = str(tmp_path / "p.json")
    ui = UI(plain=True, quiet=True)
    assert main.quiz(ui, None, progress_path=path) is None
    assert main.quiz(ui, "4.6", progress_path=path) is None
    assert main.quiz(ui, "9.9", progress_path=path) is None
    qs = quizzes.questions("4.6-set2", 11)
    answers = iter([q.answer if q.kind == "single" else "1" for q in qs])
    out = main.quiz(ui, "4.6", set_n=2, ask=lambda _: next(answers), progress_path=path, seed=11, today="2026-11-05")
    singles = sum(q.kind == "single" for q in qs)
    assert out["quiz"] == "4.6-set2" and out["total"] == len(qs) and out["correct"] >= singles
    saved = json.loads((tmp_path / "p.json").read_text())
    assert saved["quizzes"]["4.6-set2"]["attempts"] == 1


def test_cli_parser_has_quiz():
    a = main.build_parser().parse_args(["quiz", "2.4", "--topic", "3"])
    assert (a.command, a.objective, a.topic_n, a.set_n) == ("quiz", "2.4", 3, None)
    with pytest.raises(SystemExit):
        main.build_parser().parse_args(["quiz", "2.4", "--topic", "3", "--set", "1"])


def test_web_page_has_quiz_views():
    page = (exam_bank.ROOT / "web" / "index.html").read_text(encoding="utf-8")
    for s in ('href="#quizzes"', "function viewQuizzes", "function viewObjective", "function startObjectiveQuiz",
              "quizRecord(", 'post("quiz"', "#obj-", "#quiz-"):
        assert s in page, s
