"""Video course index (Professor Messer's SY0-701 playlist) and how it is wired into the course."""

from __future__ import annotations

import re

import pytest

import webapi
from labs import LABS
from utils import videos

OBJECTIVES = {f"{d}.{n}" for d, k in {1: 4, 2: 5, 3: 4, 4: 9, 5: 6}.items() for n in range(1, k + 1)}


def test_index_is_complete_and_well_formed():
    vs = videos.videos()
    assert len(vs) == 121 and [v["n"] for v in vs] == list(range(1, 122))
    assert len({v["id"] for v in vs}) == 121
    assert all(re.fullmatch(r"[A-Za-z0-9_-]{11}", v["id"]) for v in vs)            # YouTube video id shape
    assert all(v["seconds"] > 60 for v in vs)
    assert {v["objective"] for v in vs} == OBJECTIVES | {"intro"}                   # every SY0-701 objective has a video
    src = videos.course()["source"]
    assert src["author"] == "Professor Messer" and src["playlist_id"] in src["url"]


def test_objectives_in_playlist_order():
    order = [v["objective"] for v in videos.videos() if v["objective"] != "intro"]
    assert order == sorted(order, key=lambda o: tuple(map(int, o.split("."))))


def test_every_lab_has_videos():
    for n, (mod, _) in LABS.items():
        objs = videos.lab_objectives(mod)
        assert objs, f"lab {n} lists no objectives"
        vs = videos.for_lab(mod)
        assert vs and {v["objective"] for v in vs} == set(objs) & {v["objective"] for v in videos.videos()}


def test_study_plan_links_labs():
    plan = videos.study_plan()
    assert plan[0]["objective"] == "intro" and sum(len(s["videos"]) for s in plan) == 121
    pki = next(s for s in plan if s["objective"] == "1.4")
    assert 17 in pki["labs"] and pki["seconds"] == sum(v["seconds"] for v in pki["videos"])


def test_urls_and_duration():
    v = videos.videos()[11]
    assert videos.url(v, False) == f"https://www.youtube.com/watch?v={v['id']}"
    assert videos.url(v).endswith(f"&list={videos.course()['source']['playlist_id']}&index=12")
    assert videos.duration(65) == "1:05" and videos.duration(3725) == "1:02:05"


def test_recommend_skips_passed_objectives():
    rows = [["2.3", 4, 1, "25%", "FAIL"], ["1.4", 5, 5, "100%", "PASS"], ["4.4", 1, 0, "0%", "LOW"]]
    recs = videos.recommend(rows)
    assert [r["objective"] for r in recs] == ["2.3", "4.4"]
    assert all(v["objective"] == r["objective"] for r in recs for v in r["videos"])


def test_catalog_carries_videos(policies):
    c = webapi.catalog(policies)
    ids = {v["id"] for v in c["video_course"]["videos"]}
    assert len(ids) == 121
    for lab in c["labs"]:
        assert lab["videos"] and set(lab["videos"]) <= ids and lab["objective_codes"]


def test_progress_watch_roundtrip(tmp_path):
    path = tmp_path / "p.json"
    vid = videos.videos()[0]["id"]
    assert webapi.progress_watch(vid, True, path)["watched"] == [vid]
    assert webapi.progress_watch(vid, True, path)["watched"] == [vid]                # idempotent
    assert webapi.progress_watch(vid, False, path)["watched"] == []
    with pytest.raises(ValueError):
        webapi.progress_watch("not-a-video", True, path)
    webapi.progress_watch(vid, True, path)
    assert webapi.progress_reset(path)["watched"] == []


def test_dispatch_progress_watch(tmp_path):
    vid = videos.videos()[5]["id"]
    out = webapi.dispatch("progress_watch", {"video": vid, "watched": True}, progress_path=tmp_path / "p.json")
    assert vid in out["watched"]


def test_cli_videos(tmp_path, capsys):
    import main
    from utils.terminal_ui import UI
    ui = UI(plain=True)
    vid = videos.for_objective("1.4")[0]["id"]
    assert main.show_videos(ui, mark=vid, progress_path=str(tmp_path / "p.json")) == 0
    out = capsys.readouterr().out
    assert "121 videos" in out and "watched 1/121" in out and "Lab 17" in out
    main.show_videos(ui, lab=17, progress_path=str(tmp_path / "p.json"))
    assert "Certificates" in capsys.readouterr().out
    assert main.show_videos(ui, mark="nope", progress_path=str(tmp_path / "p.json")) == 1


def test_link_text_in_exports():
    from tools.export_ctfd import build_challenges
    c = build_challenges()[0]
    assert "youtube.com/watch?v=" in c["hints"][0]["content"] and c["hints"][0]["cost"] == 0
    assert videos.link_text("intro") .startswith("Watch: ")
