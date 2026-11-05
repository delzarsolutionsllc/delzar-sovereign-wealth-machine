"""Spaced repetition and the adaptive daily review (utils/review.py, webapi, CLI, web app)."""

import json
from collections import Counter
from datetime import date

import pytest

import main
import webapi
from utils import challenge as ch
from utils import review
from utils.exam_bank import load_bank
from utils.terminal_ui import UI

TODAY = "2026-11-05"
BANK = [r for r in load_bank() if review.is_single(r)]
BY_ID = {r["id"]: r for r in BANK}


@pytest.fixture(autouse=True)
def no_real_progress(monkeypatch, tmp_path):
    """Never touch the real progress.json: the default path points into tmp for every test here."""
    monkeypatch.setattr(ch, "DEFAULT_PROGRESS_PATH", tmp_path / "default-progress.json")
    monkeypatch.setattr(ch.Progress.__init__, "__defaults__", (tmp_path / "default-progress.json",))


def _rec(qid, objective):
    return {"id": qid, "objective": objective, "stem": f"Question {qid}?", "choices": ["a", "b", "c", "d"],
            "answer": "a", "explanation": "because"}


# --------------------------------------------------------------------------- scheduler
def test_right_answers_grow_interval_1_3_7_then_ease():
    c = None
    seen = []
    for _ in range(5):
        c = review.schedule(c, True, TODAY)
        seen.append(c["interval_days"])
    assert seen[:3] == [1, 3, 7]
    assert seen[3] == round(7 * 2.65) and seen[4] > seen[3]      # ease 2.5 +0.05 per right answer
    assert c["reps"] == 5 and c["lapses"] == 0 and c["last_result"] == "right"
    assert review.schedule(None, True, TODAY)["due"] == "2026-11-06"


def test_wrong_answer_resets_and_counts_lapse():
    c = review.schedule(None, True, TODAY)
    c = review.schedule(c, True, TODAY)
    c = review.schedule(c, False, "2026-11-10")
    assert c["reps"] == 0 and c["lapses"] == 1 and c["interval_days"] == 1 and c["due"] == "2026-11-11"
    assert c["last_result"] == "wrong" and c["ease"] == pytest.approx(2.4)
    nxt = review.schedule(c, True, "2026-11-11")
    assert nxt["interval_days"] == 1                               # starts over at 1 day


def test_ease_stays_in_bounds_and_interval_capped():
    c = None
    for _ in range(12):
        c = review.schedule(c, False, TODAY)
    assert c["ease"] == review.MIN_EASE and c["lapses"] == 12
    c = None
    for _ in range(40):
        c = review.schedule(c, True, TODAY)
    assert c["ease"] == review.MAX_EASE and c["interval_days"] == review.MAX_INTERVAL


def test_schedule_does_not_mutate_and_accepts_dates():
    c = review.schedule(None, True, date(2026, 11, 5))
    before = dict(c)
    review.schedule(c, False, TODAY)
    assert c == before
    with pytest.raises(ValueError):
        review.schedule(None, True, "tomorrow")


def test_exam_rule_only_enrolls_misses():
    srs = {}
    assert review.record_answer(srs, "D1-001", True, TODAY, enroll_correct=False) is None and srs == {}
    review.record_answer(srs, "D1-001", False, TODAY, enroll_correct=False)
    assert srs["D1-001"]["lapses"] == 1
    review.record_answer(srs, "D1-001", True, "2026-11-06", enroll_correct=False)   # existing card is updated
    assert srs["D1-001"]["reps"] == 1


def test_due_ordering_oldest_first_and_counts():
    srs = {"B": {"due": "2026-11-03"}, "A": {"due": "2026-11-03"}, "C": {"due": "2026-11-01"},
           "D": {"due": "2026-11-06"}, "E": {"due": "2026-12-30"}}
    assert review.due_ids(srs, TODAY) == ["C", "A", "B"]
    by_day = review.due_by_day(srs, TODAY, 7)
    assert list(by_day)[0] == TODAY and by_day[TODAY] == 3 and by_day["2026-11-06"] == 1 and sum(by_day.values()) == 4


# --------------------------------------------------------------------------- streak
def test_streak_rules():
    s = review.touch_streak(None, TODAY)
    assert s == {"last_day": TODAY, "count": 1}
    assert review.touch_streak(s, TODAY) == s                              # same day: unchanged
    s2 = review.touch_streak(s, "2026-11-06")
    assert s2["count"] == 2
    assert review.touch_streak(s2, "2026-11-09")["count"] == 1             # gap restarts
    assert review.current_streak(s2, "2026-11-07") == 2                    # alive the next day
    assert review.current_streak(s2, "2026-11-08") == 0
    assert review.current_streak({}, TODAY) == 0


# --------------------------------------------------------------------------- session builder
def test_session_due_first_then_new():
    srs = {BANK[5]["id"]: {"due": "2026-11-04", "last_result": "wrong"}, BANK[2]["id"]: {"due": "2026-11-01"},
           BANK[9]["id"]: {"due": "2026-11-20"}}
    s = review.build_session({"objectives": {}, "srs": srs}, BANK, TODAY, 15, seed=3)
    ids = [q["id"] for q in s["questions"]]
    assert ids[:2] == [BANK[2]["id"], BANK[5]["id"]]
    assert s["questions"][1]["reason"] == "Due for review (missed last time)"
    assert s["questions"][0]["reason"] == "Due for review"
    assert len(ids) == 15 and len(set(ids)) == 15 and BANK[9]["id"] not in ids     # not due, already seen
    assert s["review_count"] == 2 and s["new_count"] == 13 and s["due_total"] == 2
    assert all(q["kind"] == "new" and q["id"] not in srs for q in s["questions"][2:])


def test_session_caps_reviews_at_size():
    srs = {r["id"]: {"due": "2026-10-01"} for r in BANK[:30]}
    s = review.build_session({"srs": srs}, BANK, TODAY, 10)
    assert s["review_count"] == 10 and s["new_count"] == 0 and s["due_total"] == 30


def test_weakest_objective_first_and_interleaved():
    objs = {o: {"attempted": 10, "correct": 9} for o in {r["objective"] for r in BANK}}
    objs["3.3"] = {"attempted": 5, "correct": 2}          # 40%: weakest
    objs["2.4"] = {"attempted": 10, "correct": 6}
    s = review.build_session({"objectives": objs}, BANK, TODAY, 15, seed=1)
    qs = s["questions"]
    assert qs[0]["objective"] == "3.3" and qs[0]["reason"] == "New: 3.3 is your weakest objective (40%)"
    assert qs[1]["objective"] == "2.4" and "one of your weakest objectives (60%)" in qs[1]["reason"]
    counts = Counter(q["objective"] for q in qs)
    assert max(counts.values()) <= 4 and len(counts) >= 4                     # never all one objective
    assert all(qs[i]["objective"] != qs[i + 1]["objective"] for i in range(len(qs) - 1))


def test_unseen_objectives_count_as_weak():
    objs = {o: {"attempted": 10, "correct": 9} for o in {r["objective"] for r in BANK} if o != "5.6"}
    s = review.build_session({"objectives": objs}, BANK, TODAY, 4, seed=1)
    assert s["questions"][0]["objective"] == "5.6" and s["questions"][0]["reason"] == "New: 5.6 not practised yet"


def test_exhausted_objective_is_replaced():
    bank = [_rec("X-1", "1.1"), _rec("X-2", "1.2"), _rec("X-3", "1.2"), _rec("X-4", "1.2"), _rec("X-5", "1.3")]
    s = review.build_session({}, bank, TODAY, 10, seed=1)
    assert sorted(q["id"] for q in s["questions"]) == ["X-1", "X-2", "X-3", "X-4", "X-5"]
    assert [q["objective"] for q in s["questions"]][:3] == ["1.1", "1.2", "1.3"]


def test_session_is_deterministic_per_seed_and_day():
    a = review.build_session({}, BANK, TODAY, 15, seed=7)
    b = review.build_session({}, BANK, TODAY, 15, seed=7)
    c = review.build_session({}, BANK, TODAY, 15, seed=8)
    assert a == b and [q["id"] for q in a["questions"]] != [q["id"] for q in c["questions"]]
    d = review.build_session({}, BANK, TODAY, 15)
    assert d["seed"] == 20261105 and d == review.build_session({}, BANK, date(2026, 11, 5), 15)


def test_non_single_questions_are_skipped():
    bank = [_rec("X-1", "1.1"), {**_rec("X-2", "1.1"), "type": "multi"}, {**_rec("X-3", "1.1"), "type": "single"}]
    s = review.build_session({"srs": {"X-2": {"due": "2026-01-01"}}}, bank, TODAY, 10)
    assert [q["id"] for q in s["questions"]] == ["X-1", "X-3"] or [q["id"] for q in s["questions"]] == ["X-3", "X-1"]
    assert s["due_total"] == 0


def test_mulberry32_matches_reference_sequence():
    # first outputs of the web app's mulberry32(1) (computed with JavaScript)
    for seed, expected in ((1, [0.6270739406, 0.0027357212, 0.5274470400]),
                           (20261105, [0.1020412447, 0.6270352604, 0.2273622984])):
        r = review.mulberry32(seed)
        assert [round(r(), 10) for _ in range(3)] == expected


# --------------------------------------------------------------------------- progress storage
def test_old_progress_file_is_upgraded(tmp_path):
    path = tmp_path / "old.json"
    path.write_text(json.dumps({"objectives": {"1.1": {"attempted": 2, "correct": 1}}, "sessions": []}))
    p = ch.Progress(path)
    assert p.data["srs"] == {} and p.data["streak"] == {"last_day": None, "count": 0}
    p.record("1.1", True)                                      # old two-argument call still works
    p.save()
    assert json.loads(path.read_text())["objectives"]["1.1"] == {"attempted": 3, "correct": 2}
    path.write_text("[1, 2]")                                  # not a dict: start fresh
    assert ch.Progress(path).data["objectives"] == {}


def test_progress_record_with_qid_schedules(tmp_path):
    p = ch.Progress(tmp_path / "p.json")
    p.record("3.3", False, "D3-031", TODAY)
    p.record("3.3", True, "D3-032", TODAY)                     # exam right answer, no card: not enrolled
    p.record("3.3", True, "D3-033", TODAY, review=True)
    assert set(p.data["srs"]) == {"D3-031", "D3-033"} and p.data["streak"]["count"] == 1
    assert p.data["srs"]["D3-031"]["due"] == "2026-11-06"


# --------------------------------------------------------------------------- API
def test_api_review_session_and_answer(tmp_path):
    path = tmp_path / "p.json"
    s = webapi.dispatch("review_session", {"today": TODAY, "seed": 4}, progress_path=path)
    assert len(s["questions"]) == 15 and s["review_count"] == 0 and s["streak"]["current"] == 0
    q = s["questions"][0]
    r = webapi.dispatch("review_answer", {"qid": q["id"], "correct": False, "today": TODAY}, progress_path=path)
    assert r["card"]["due"] == "2026-11-06" and r["streak"]["count"] == 1 and r["due_by_day"]["2026-11-06"] == 1
    r = webapi.dispatch("review_answer", {"qid": s["questions"][1]["id"], "correct": True, "today": TODAY},
                        progress_path=path)
    assert r["due_by_day"]["2026-11-06"] == 2
    nxt = webapi.dispatch("review_session", {"today": "2026-11-06"}, progress_path=path)
    assert [x["id"] for x in nxt["questions"][:2]] == sorted([q["id"], s["questions"][1]["id"]])
    assert nxt["streak"]["current"] == 1
    g = webapi.dispatch("progress_get", {}, progress_path=path)
    assert len(g["srs"]) == 2 and g["objectives"][q["objective"]]["attempted"] >= 1
    assert "review_session" in webapi.METHODS and "review_answer" in webapi.METHODS


def test_api_rejects_bad_review_input(tmp_path):
    path = tmp_path / "p.json"
    with pytest.raises(ValueError):
        webapi.dispatch("review_answer", {"qid": "NOPE-1", "correct": True, "today": TODAY}, progress_path=path)
    with pytest.raises(ValueError):
        webapi.dispatch("review_answer", {"qid": BANK[0]["id"], "correct": "yes", "today": TODAY}, progress_path=path)
    with pytest.raises(ValueError):
        webapi.dispatch("review_session", {"today": "05/11/2026"}, progress_path=path)
    with pytest.raises(ValueError):
        webapi.dispatch("review_session", {"size": 0}, progress_path=path)
    assert not path.exists()


def test_exam_misses_enter_review_via_progress_record(tmp_path):
    path = tmp_path / "p.json"
    a, b = BANK[0], BANK[1]
    webapi.dispatch("progress_record", {"label": "exam", "today": TODAY, "results": [
        {"objective": a["objective"], "correct": False, "qid": a["id"]},
        {"objective": b["objective"], "correct": True, "qid": b["id"]},
        {"objective": "4.6", "correct": False, "qid": ""},                 # lab question: no id
        {"objective": "4.6", "correct": False, "qid": "NOT-IN-BANK"}]}, progress_path=path)
    srs = json.loads(path.read_text())["srs"]
    assert list(srs) == [a["id"]] and srs[a["id"]]["due"] == "2026-11-06"
    s = webapi.review_session(path, "2026-11-06")
    assert s["questions"][0]["id"] == a["id"] and s["questions"][0]["reason"].startswith("Due for review")


def test_reset_clears_review_state(tmp_path):
    path = tmp_path / "p.json"
    webapi.review_answer(BANK[0]["id"], False, TODAY, path)
    out = webapi.progress_reset(path)
    assert out["srs"] == {} and out["streak"]["count"] == 0


# --------------------------------------------------------------------------- CLI
def test_cli_review_scripted(tmp_path):
    path = str(tmp_path / "p.json")
    s = review.build_session({}, load_bank(), TODAY, 5, seed=2)
    script = iter([q["answer"] if i % 2 == 0 else "nonsense" for i, q in enumerate(s["questions"])])
    out = main.review(UI(plain=True, quiet=True), 5, 2, ask=lambda _: next(script), progress_path=path, today=TODAY)
    assert out["done"] == 5 and out["correct"] == 3
    assert out["due_by_day"]["2026-11-06"] == 5
    data = json.loads((tmp_path / "p.json").read_text())
    assert data["streak"] == {"last_day": TODAY, "count": 1} and data["sessions"][-1]["lab"] == "daily review"
    assert sum(c["lapses"] for c in data["srs"].values()) == 2


def test_cli_review_stops_early_on_eof(tmp_path):
    path = str(tmp_path / "p.json")
    answers = iter(["1"])

    def ask(_):
        try:
            return next(answers)
        except StopIteration:
            raise EOFError
    out = main.review(UI(plain=True, quiet=True), 5, 1, ask=ask, progress_path=path, today=TODAY)
    assert out["done"] == 1


def test_cli_parser_and_menu_key():
    args = main.build_parser().parse_args(["review", "--count", "10", "--seed", "3"])
    assert args.command == "review" and args.count == 10 and args.seed == 3
    import inspect
    assert '"rv"' in inspect.getsource(main.interactive_menu)


# --------------------------------------------------------------------------- web app wiring
def test_web_app_has_review_view_and_rules():
    html = (main.ROOT / "web" / "index.html").read_text(encoding="utf-8")
    nav = html[html.index('<nav class="nav"'):html.index("</nav>")]
    assert nav.index('href="#review"') < nav.index('href="#home"')       # first in the nav
    for needle in ("function buildReviewSession", "function srsSchedule", "reviewSession(", "reviewAnswer(",
                   'if (h === "review") return viewReview();', "Today: ${s.due_total} due",
                   "srsRecord(d.srs, r.qid, r.correct, today, false)"):
        assert needle in html, needle
    for const in ("start: 2.5", "min: 1.3", "max: 2.8", "up: 0.05", "down: 0.2", "first: [1, 3, 7]", "cap: 180", "weak: 4"):
        assert const in html, const


def test_other_question_types_are_stored_but_not_shown(tmp_path):
    other = [r for r in load_bank() if not review.is_single(r)]
    if not other:
        pytest.skip("bank has only single-answer questions")
    path = tmp_path / "p.json"
    webapi.progress_record([{"objective": other[0]["objective"], "correct": False, "qid": other[0]["id"]}], "exam",
                           path, TODAY)
    s = webapi.review_session(path, "2026-11-06")
    assert other[0]["id"] in json.loads(path.read_text())["srs"]
    assert s["due_total"] == 0 and other[0]["id"] not in [q["id"] for q in s["questions"]]
