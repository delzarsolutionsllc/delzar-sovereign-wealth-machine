"""Interview prep: data quality, mock-interview picking, CLI, web catalog and the MCP tutor tools."""

from collections import Counter

import pytest

from labs import LABS
from utils import interview


def test_interview_data_is_valid():
    assert interview.validate(lab_numbers=set(LABS)) == []


def test_every_category_has_enough_questions():
    counts = Counter(q["category"] for q in interview.questions())
    assert set(counts) == set(interview.CATEGORIES)
    assert min(counts.values()) >= 12, counts
    levels = Counter(q["level"] for q in interview.questions())
    assert all(levels[lv] >= 10 for lv in interview.LEVELS), levels


def test_behavioral_answers_use_star():
    for q in interview.questions():
        if q["kind"] == "behavioral":
            assert "[" in q["model_answer"], f"{q['id']}: STAR answer needs [brackets] for the learner's own detail"


def test_roles_point_at_real_categories_and_labs():
    rs = interview.roles()
    assert len(rs) >= 4
    for r in rs:
        assert set(r["focus"]) <= set(interview.CATEGORIES), r["id"]
        assert set(r["labs"]) <= set(LABS), r["id"]
        assert interview.pick(6, role=r["id"], seed=1), r["id"]


def test_pick_is_deterministic_and_spread():
    a = interview.pick(9, seed=7)
    assert [q["id"] for q in a] == [q["id"] for q in interview.pick(9, seed=7)]
    assert len({q["category"] for q in a}) == 9          # round-robin across the nine areas
    assert len({q["id"] for q in a}) == 9
    only = interview.pick(5, category="okta", level="entry", seed=3)
    assert only and all(q["category"] == "okta" and q["level"] == "entry" for q in only)
    with pytest.raises(ValueError):
        interview.pick(3, category="nope")


def test_public_view_hides_the_answer_key():
    q = interview.questions()[0]
    pub = interview.public(q)
    assert "model_answer" not in pub and "listen_for" not in pub and pub["question"] == q["question"]
    prompt = interview.claude_prompt(q, "my answer")
    assert q["question"] in prompt and "my answer" in prompt


def test_catalog_reaches_the_web_app():
    import webapi
    from utils.loader import load_policies
    cat = webapi.catalog(load_policies())["interview"]
    assert len(cat["questions"]) == len(interview.questions()) and cat["roles"]


def test_cli_mock_interview_runs():
    import main
    from utils.terminal_ui import UI
    answers = iter(["I would check the sign-in logs first.", "4"] * 3)
    got = main.interview_cmd(UI(plain=True, quiet=True), count=3, seed=2, ask=lambda _p: next(answers))
    assert got == {"done": 3, "average": 4.0}


def test_mcp_interview_tools(tmp_path):
    from utils import mcp_server as M
    srv = M.Server(audit_path=tmp_path / "audit.jsonl")
    started = srv.call_tool("interview_start", {"count": 4, "role": "iga_engineer", "seed": 5})
    assert not started["isError"]
    qs = started["structuredContent"]["questions"]
    assert len(qs) == 4 and all("model_answer" not in q for q in qs)
    rub = srv.call_tool("interview_rubric", {"qid": qs[0]["id"]})
    assert not rub["isError"] and rub["structuredContent"]["model_answer"]
    assert srv.call_tool("interview_rubric", {"qid": "IV-XXX-999"})["isError"]
    assert srv.call_tool("interview_start", {"role": "ceo"})["isError"]          # enum enforced
    assert not srv.call_tool("interview_roles", {})["isError"]


def test_ai_tutor_function_grades_every_question_file_and_holds_no_key():
    """functions/api/tutor.js bundles the interview files; a new file must be imported there too."""
    src = (interview.DIR.parent.parent / "functions" / "api" / "tutor.js").read_text(encoding="utf-8")
    for f in sorted(interview.DIR.glob("questions-*.json")):
        assert f'"../../data/interview/{f.name}"' in src, f.name
    assert "env.ANTHROPIC_API_KEY" in src and "sk-ant" not in src
    assert "Cf-Access-Authenticated-User-Email" in src          # signed-in users only
