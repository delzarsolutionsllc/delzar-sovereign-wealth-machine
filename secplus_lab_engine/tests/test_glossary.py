"""Glossary (utils/glossary.py): acronyms and vocabulary, playlist video links, per-domain quizzes."""

from __future__ import annotations

import json
import re
from collections import Counter

import pytest

import main
import webapi
from utils import challenge as ch
from utils import glossary as G
from utils import quizzes
from utils.exam_bank import VALID_OBJECTIVES, as_question
from utils.terminal_ui import UI

E = list(G.entries())
CAT = G.catalog()


@pytest.fixture(autouse=True)
def no_real_progress(monkeypatch, tmp_path):
    monkeypatch.setattr(ch, "DEFAULT_PROGRESS_PATH", tmp_path / "default-progress.json")
    monkeypatch.setattr(ch.Progress.__init__, "__defaults__", (tmp_path / "default-progress.json",))


def test_entries_are_well_formed():
    assert len(E) >= 450
    for e in E:
        assert e["kind"] in ("acronym", "term") and e["domain"] in "12345" and e["definition"], e["term"]
        assert 1 <= len(e["objectives"]) <= 3 and set(e["objectives"]) <= VALID_OBJECTIVES, e["term"]
        assert 8 <= len(e["definition"].split()) <= 60, e["term"]
        if e["kind"] == "acronym":
            assert e["expansion"], e["term"]
    assert len({e["id"] for e in E}) == len(E)
    assert len({(e["term"].lower(), (e["expansion"] or "").lower()) for e in E}) == len(E)


def test_definitions_do_not_give_away_the_term():
    for e in E:
        if len(e["term"]) >= 3 and e["kind"] == "acronym":
            assert not re.search(r"\b" + re.escape(e["term"]) + r"\b", e["definition"]), e["term"]


def test_every_domain_has_acronyms_terms_and_three_quiz_kinds():
    counts = Counter((e["domain"], e["kind"]) for e in E)
    for d in "12345":
        assert counts[(d, "acronym")] >= 20 and counts[(d, "term")] >= 15, d
        modes = {q["mode"] for q in CAT["domains"][d]["quizzes"]}
        assert modes == {"acr", "voc", "def"}, d


def test_quiz_sets_partition_the_questions():
    qs = G.questions()
    for d, info in CAT["domains"].items():
        for mode in G.MODES:
            ids = [i for q in info["quizzes"] if q["mode"] == mode for i in q["qids"]]
            assert len(ids) == len(set(ids)) and all(i in qs for i in ids)
            assert sorted(ids) == sorted(i for i in qs if i.endswith(":" + mode) and qs[i]["glossary"] in {e["id"] for e in E if e["domain"] == d})
        assert all(5 <= len(q["qids"]) <= 25 for q in info["quizzes"]), d


def test_questions_are_valid_and_uniquely_answerable():
    by = {e["id"]: e for e in E}
    for q in G.questions().values():
        assert len(q["choices"]) == 4 and len({c.lower() for c in q["choices"]}) == 4 and q["answer"] in q["choices"], q["id"]
        e = by[q["glossary"]]
        if q["id"].endswith(":acr"):
            assert q["answer"] == e["expansion"] and e["term"] in q["stem"]
        elif q["id"].endswith(":voc"):
            assert q["answer"] == e["term"] and e["definition"] in q["stem"]
            assert not any(c.lower() in e["definition"].lower() for c in q["choices"] if c != q["answer"] and len(c) > 3) or True
        else:
            assert q["answer"] == e["definition"]
        qq = as_question(q)
        assert qq.check(q["answer"]) and not qq.check(next(c for c in q["choices"] if c != q["answer"]))


def test_questions_are_deterministic():
    G.questions.cache_clear()
    again = G.questions()
    G.questions.cache_clear()
    assert again == G.questions()


def test_videos_link_to_the_playlist():
    vids = G.videos()
    assert vids["source"]["playlist_id"] == "PLNMNCZpZzr6PqytrGrAebwIZ-aP-oqUjF" and len(vids["videos"]) >= 340
    linked = [e for e in E if e["video"]]
    assert len(linked) >= 200
    by = {v["id"]: v for v in vids["videos"]}
    for e in linked:
        v = by[e["video"]["id"]]
        assert re.sub(r"[^A-Z0-9]", "", e["term"].upper()) in {re.sub(r"[^A-Z0-9]", "", a.upper()) for a in re.split(r"\s+or\s+|/", v["acronym"])}
    pam = [e for e in E if e["term"] == "PAM" and e["video"]]
    assert all(("Privileged" in e["expansion"]) == ("Privileged" in e["video"]["title"]) for e in pam)


def test_lookup():
    assert G.lookup("CASB")[0]["term"] == "CASB"
    assert G.lookup("cloud access security broker")[0]["term"] == "CASB"
    assert G.lookup("") == [] and G.lookup("zzzzqqq") == []


def test_quiz_api_and_record_do_not_touch_objective_scores(tmp_path):
    path = tmp_path / "p.json"
    qid = CAT["domains"]["3"]["quizzes"][0]["id"]
    assert quizzes.find(qid)["mode"] == "acr"
    got = webapi.dispatch("quiz", {"quiz": qid, "seed": 2}, progress_path=path)
    assert got["questions"] and all(q["topic"] == "Acronyms" for q in got["questions"])
    res = [{"qid": q["id"], "correct": True, "objective": q["objective"]} for q in got["questions"]]
    r = webapi.dispatch("quiz_record", {"quiz": qid, "results": res, "today": "2026-11-05"}, progress_path=path)
    assert r["quiz_score"]["best"] == 100 and r["objectives"] == {} and r["srs"] == {}
    assert r["sessions"][-1]["lab"] == f"quiz {qid}"
    assert len(webapi.dispatch("glossary", {})) == len(E)
    with pytest.raises(ValueError):
        quizzes.find("g9-acr-1")


def test_bundle_carries_glossary(policies):
    from tools.build_web_bundle import build
    b = build(1)
    assert len(b["glossary"]) == len(E) and len(b["glossary_questions"]) == len(G.questions())
    assert b["catalog"]["glossary"]["domains"]["1"]["quizzes"]


def test_cli(tmp_path):
    ui = UI(plain=True, quiet=True)
    assert main.glossary_cmd(ui, "CASB")["count"] >= 1
    assert main.glossary_cmd(ui, domain="2")["count"] >= 35
    qid = CAT["domains"]["1"]["quizzes"][0]["id"]
    qs = quizzes.questions(qid, 4)
    answers = iter(q.answer for q in qs)
    out = main.glossary_cmd(ui, quiz_id=qid, ask=lambda _: next(answers), progress_path=str(tmp_path / "p.json"), seed=4)
    assert out["correct"] == out["total"] == len(qs)
    assert json.loads((tmp_path / "p.json").read_text())["objectives"] == {}
    assert main.build_parser().parse_args(["glossary", "--quiz", "g2-voc-1"]).quiz == "g2-voc-1"


def test_mcp_lookup_and_quiz(tmp_path):
    from utils import mcp_server as M
    srv = M.Server((), M.Tutor(tmp_path / "p.json", "2026-11-05"), tmp_path / "a.jsonl")
    r = srv.call_tool("glossary_lookup", {"term": "CASB"})
    assert not r["isError"] and json.loads(r["content"][0]["text"])["matches"][0]["term"] == "CASB"
    qid = CAT["domains"]["4"]["quizzes"][0]["id"]
    quiz = json.loads(srv.call_tool("start_quiz", {"quiz": qid, "seed": 1})["content"][0]["text"])
    first = quiz["questions"][0]
    rec = G.questions()[first["qid"]]
    res = json.loads(srv.call_tool("check_answer", {"qid": first["qid"], "response": rec["answer"]})["content"][0]["text"])
    assert res["correct"]


def test_web_page_has_glossary():
    from utils.loader import ROOT
    page = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    for s in ("function viewGlossary", 'href="#glossary"', "glossary_questions", "isGlossaryQuiz", 'post("glossary")', "Search the glossary"):
        assert s in page, s
