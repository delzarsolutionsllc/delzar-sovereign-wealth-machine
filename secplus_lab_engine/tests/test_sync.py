"""Moving progress between devices: export, clean, merge, import (utils/sync.py, API, CLI, web app)."""

from __future__ import annotations

import json

import pytest

import main
import webapi
from utils import challenge as ch
from utils import sync
from utils.terminal_ui import UI


@pytest.fixture(autouse=True)
def no_real_progress(monkeypatch, tmp_path):
    monkeypatch.setattr(ch, "DEFAULT_PROGRESS_PATH", tmp_path / "default-progress.json")
    monkeypatch.setattr(ch.Progress.__init__, "__defaults__", (tmp_path / "default-progress.json",))


def card(due, interval, lapses=0, reps=1, result="right"):
    return {"due": due, "interval_days": interval, "ease": 2.5, "reps": reps, "lapses": lapses, "last_result": result}


A = {"objectives": {"1.1": {"attempted": 10, "correct": 7}, "2.4": {"attempted": 3, "correct": 1}},
     "srs": {"D1-001": card("2026-11-10", 7), "D2-001": card("2026-11-06", 1, 1, 0, "wrong")},
     "sessions": [{"ts": "2026-11-01T10:00:00", "lab": "exam", "score": "50/90"}],
     "watched": ["vidA"], "streak": {"last_day": "2026-11-04", "count": 3},
     "quizzes": {"1.1-t1": {"best": 80, "last": 60, "attempts": 3, "last_day": "2026-11-03"}}}
B = {"objectives": {"1.1": {"attempted": 4, "correct": 4}, "3.3": {"attempted": 5, "correct": 2}},
     "srs": {"D1-001": card("2026-11-12", 3), "D3-001": card("2026-11-08", 3)},
     "sessions": [{"ts": "2026-11-01T10:00:00", "lab": "exam", "score": "50/90"},
                  {"ts": "2026-11-02T09:00:00", "lab": "daily review", "score": "12/15"}],
     "watched": ["vidB", "vidA"], "streak": {"last_day": "2026-11-05", "count": 1},
     "quizzes": {"1.1-t1": {"best": 70, "last": 70, "attempts": 1, "last_day": "2026-11-05"},
                 "2.4-set1": {"best": 50, "last": 50, "attempts": 1, "last_day": "2026-11-05"}}}


def test_merge_rules():
    m = sync.merge(A, B)
    assert m["objectives"] == {"1.1": {"attempted": 10, "correct": 7}, "2.4": A["objectives"]["2.4"], "3.3": B["objectives"]["3.3"]}
    assert m["srs"]["D1-001"] == B["srs"]["D1-001"]            # last reviewed 11-09 beats 11-03
    assert set(m["srs"]) == {"D1-001", "D2-001", "D3-001"}
    assert [s["lab"] for s in m["sessions"]] == ["exam", "daily review"]
    assert m["watched"] == ["vidA", "vidB"] and m["streak"] == {"last_day": "2026-11-05", "count": 1}
    assert m["quizzes"]["1.1-t1"] == {"best": 80, "last": 70, "attempts": 3, "last_day": "2026-11-05"}
    assert m["quizzes"]["2.4-set1"]["best"] == 50


def test_merge_is_symmetric_and_idempotent():
    m = sync.merge(A, B)
    assert sync.merge(B, A) == m
    assert sync.merge(m, B) == m and sync.merge(m, A) == m and sync.merge(m, m) == m


def test_srs_tie_goes_to_more_misses():
    a = {"srs": {"Q": card("2026-11-10", 5, lapses=0)}}
    b = {"srs": {"Q": card("2026-11-10", 5, lapses=2)}}
    assert sync.merge(a, b)["srs"]["Q"]["lapses"] == 2 == sync.merge(b, a)["srs"]["Q"]["lapses"]


def test_clean_drops_bad_data_and_accepts_envelope():
    raw = {"app": "Delzar Certification Academy", "format": 1, "progress": {
        "objectives": {"1.1": {"attempted": "5", "correct": 9}, "bad": {"attempted": 1}, "9.9": {}, "2.2": "x"},
        "srs": {"Q1": card("2026-11-10", 3), "<script>": card("2026-11-10", 3), "Q2": {"due": "soon"}},
        "sessions": [{"ts": "2026-11-01T10:00:00", "lab": "x" * 100, "score": 1}, "junk"],
        "watched": ["ok", 5, "../x/../y" * 9], "streak": {"last_day": "yesterday", "count": -3},
        "quizzes": {"1.1-t1": {"best": 150, "last": -5, "attempts": 2}}, "evil": {"__proto__": 1}}}
    c = sync.clean(raw)
    assert c["objectives"] == {"1.1": {"attempted": 5, "correct": 5}}
    assert list(c["srs"]) == ["Q1"] and len(c["sessions"]) == 1 and len(c["sessions"][0]["lab"]) == 40
    assert c["watched"] == ["ok"] and c["streak"] == {"last_day": None, "count": 0}
    assert c["quizzes"]["1.1-t1"] == {"best": 100, "last": 0, "attempts": 2, "last_day": None}
    assert "evil" not in c
    for bad in (None, [], "text", {"hello": 1}, {"progress": "x"}):
        with pytest.raises(ValueError):
            sync.clean(bad)


def test_api_export_import_roundtrip(tmp_path):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps(A)); b.write_text(json.dumps(B))
    exported = webapi.dispatch("progress_export", {}, progress_path=a)
    assert exported["app"] == "Delzar Certification Academy" and exported["format"] == sync.FORMAT
    got = webapi.dispatch("progress_import", {"data": exported}, progress_path=b)
    assert got["objectives"]["1.1"]["attempted"] == 10 and "3.3" in got["objectives"]
    again = webapi.dispatch("progress_import", {"data": exported}, progress_path=b)
    assert again["objectives"] == got["objectives"] and again["srs"] == got["srs"]
    rep = webapi.dispatch("progress_import", {"data": exported, "replace": True}, progress_path=b)
    assert "3.3" not in rep["objectives"]
    with pytest.raises(ValueError):
        webapi.dispatch("progress_import", {"data": {"nothing": 1}}, progress_path=b)


def test_cli_export_and_import(tmp_path):
    ui = UI(plain=True, quiet=True)
    src, dst, f = tmp_path / "src.json", tmp_path / "dst.json", tmp_path / "out.json"
    src.write_text(json.dumps(A)); dst.write_text(json.dumps(B))
    assert main.progress_file(ui, export=str(f), progress_path=str(src)) == 0
    assert json.loads(f.read_text())["progress"]["objectives"]["1.1"]["attempted"] == 10
    assert main.progress_file(ui, import_=str(f), progress_path=str(dst)) == 0
    assert json.loads(dst.read_text())["quizzes"]["1.1-t1"]["best"] == 80
    (tmp_path / "bad.json").write_text("{not json")
    assert main.progress_file(ui, import_=str(tmp_path / "bad.json"), progress_path=str(dst)) == 1
    a = main.build_parser().parse_args(["progress", "--import", "x.json", "--replace"])
    assert a.import_ == "x.json" and a.replace


def test_web_page_ports_the_same_rules():
    from utils.loader import ROOT
    page = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    for s in ("function cleanProgress", "function mergeProgress", "Export my progress", "Import a progress file",
              'post("progress_import"', 'post("progress_export"', "SYNC_MAX_SESSIONS = 50"):
        assert s in page, s
    assert sync.MAX_SESSIONS == 50
