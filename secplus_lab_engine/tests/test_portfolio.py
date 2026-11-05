"""Work-ticket briefings, IAM career tracks and portfolio case studies."""

from __future__ import annotations

import pytest

import webapi
from labs import LABS
from utils import portfolio

KEYS = {"lab", "ticket", "type", "priority", "requested_by", "title", "situation", "your_task", "why_it_matters",
        "done_when", "glossary", "job_roles", "talking_point"}
TYPES = {"Service request", "Incident", "Change request", "Audit finding", "Project task"}


@pytest.mark.parametrize("n", sorted(LABS))
def test_every_lab_has_a_plain_english_briefing(n):
    b = portfolio.briefing(n)
    assert b is not None, f"data/briefings/lab{n:02d}.json missing"
    assert KEYS <= set(b) and b["lab"] == n and b["type"] in TYPES
    assert 2 <= len(b["your_task"]) <= 6 and 1 <= len(b["done_when"]) <= 5 and len(b["glossary"]) >= 3
    assert b["ticket"][:4] in {"REQ-", "INC-", "CHG-", "AUD-", "PRJ-"}
    assert len(b["situation"]) > 60 and len(b["talking_point"]) > 30


def test_career_tracks_point_at_real_labs():
    c = portfolio.career()
    assert [p["step"] for p in c["path"]] == [1, 2, 3]
    for t in c["tracks"]:
        for a in t["areas"]:
            assert a["labs"] and all(n in LABS for n in a["labs"]), a["name"]
            assert a["plain"]
    assert portfolio.career_tags(1) and portfolio.career_tags(25) and portfolio.career_tags(26)


def test_summarize_readable_rows():
    assert portfolio.summarize({"sod_conflicts": 4, "quarantined": ["bot"]}) == [("SoD conflicts", "4"), ("Quarantined", "bot")]
    rows = portfolio.summarize({"A": "BLOCK", "B": "ALLOW", "C": "BLOCK", "D": "ALLOW", "E": "BLOCK"})
    assert rows[0] == ("Block", "3 of 5")


@pytest.mark.parametrize("n", [1, 2, 25, 26])
def test_case_study_is_honest_and_complete(policies, n):
    md = portfolio.case_study_markdown(n, policies)
    assert "Simulated lab with fictional" in md and "## Results" in md and "## Skills demonstrated" in md
    assert "## What I did" in md and "## Talking point" in md
    page = portfolio.case_study_html(n, policies)
    assert page.startswith("<!doctype html>") and "Simulated lab" in page and "<script" not in page


def test_case_study_cli_and_api(tmp_path, policies):
    import main
    assert main.main(["--plain", "case-study", "1", "26", "--out", str(tmp_path)]) in (0, None)
    assert sorted(f.name for f in tmp_path.iterdir()) == ["lab01-case-study.html", "lab01-case-study.md",
                                                          "lab26-case-study.html", "lab26-case-study.md"]
    cs = webapi.dispatch("case_study", {"lab": 2}, policies)
    assert cs["lab"] == 2 and cs["results"] and cs["briefing"]["ticket"]
    cat = webapi.catalog(policies)
    assert "career_tracks" in cat and all(lab["briefing"] for lab in cat["labs"])
