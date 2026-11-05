"""The course registry and the SC-300 course. SC-300 checks run in a fresh process with
DELZAR_COURSE=sc300, because the engine reads the active course when it is imported."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap

import pytest

from utils import course
from utils.loader import ROOT


def run_in(code: str, script: str, timeout: int = 180) -> dict:
    """Run ``script`` with course ``code`` active; it must print one JSON line (its last line)."""
    env = {**os.environ, course.ENV: code, "PYTHONPATH": str(ROOT)}
    out = subprocess.run([sys.executable, "-c", textwrap.dedent(script)], capture_output=True, text=True,
                         env=env, cwd=ROOT, timeout=timeout)
    assert out.returncode == 0, out.stderr[-3000:]
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_registry_lists_both_courses_and_validates():
    assert {"secplus", "sc300"} <= set(course.available())
    for code in course.available():
        c = course.load(code)
        assert abs(sum(d["weight"] for d in c["domains"]) - 1) < 1e-9, code
        doms = {d["id"] for d in c["domains"]}
        assert all(o.split(".")[0] in doms for o in c["objectives"]), code
        assert c["notice"].startswith("Independent study project, not affiliated") and c["vendor"] in c["notice"]
        assert c["pass_scaled"] > c["scale"][0] and c["pass_scaled"] < c["scale"][1]
        assert c["facts_checked"] and c["exam_target"]["source"].startswith("https://")
    with pytest.raises(ValueError):
        course.load("nope")


def test_secplus_is_the_default_and_unchanged():
    assert course.code() == "secplus"
    from utils import exam, exam_bank
    assert exam.DOMAIN_WEIGHTS == {"1": 0.12, "2": 0.22, "3": 0.18, "4": 0.28, "5": 0.20} and exam.PASS_SCALED == 750
    assert exam_bank.OBJECTIVES == {"1": 4, "2": 5, "3": 4, "4": 9, "5": 6}
    assert exam_bank.BANK_DIR == ROOT / "data" / "exam_bank"


SC300_CORE = """
import json
from utils import course, exam, exam_bank, quizzes, glossary
from utils.challenge import DEFAULT_PROGRESS_PATH
import webapi
from utils.loader import load_policies
pol = load_policies()
cat = webapi.catalog(pol)
ex = webapi.exam(pol, 50, 3)
dt = webapi.exam(pol, 30, 4, domain="2")
r = exam.ExamResult(10, 7, 10, False, {}, [])
print(json.dumps({
  "code": course.code(), "objectives": exam_bank.OBJECTIVES, "weights": exam.DOMAIN_WEIGHTS, "pass": exam.PASS_SCALED,
  "scaled70": r.scaled, "progress": DEFAULT_PROGRESS_PATH.name,
  "labs": {str(l["n"]): l["objective_codes"] for l in cat["labs"]}, "course": cat["course"]["exam_code"],
  "videos": len(cat["video_course"]["videos"]), "retires": cat["exam_target"]["retires"],
  "problems": exam_bank.validate(list(exam_bank.load_bank())),
  "bank": len(exam_bank.load_bank()), "exam": len(ex["questions"]), "exam_domains": sorted({q["objective"][0] for q in ex["questions"]}),
  "domain_test": sorted({q["objective"] for q in dt["questions"]}),
  "per_obj": {o: c["count"] for o, c in quizzes.catalog().items()},
  "topics_ok": all(len(c["topics"]) >= 3 and all(t["count"] >= 5 for t in c["topics"]) for c in quizzes.catalog().values()),
  "glossary": len(glossary.entries()), "gloss_domains": sorted({e["domain"] for e in glossary.entries()}),
  "gloss_quiz_modes": sorted({q["mode"] for d in glossary.catalog()["domains"].values() for q in d["quizzes"]}),
}))
"""


@pytest.fixture(scope="module")
def sc300():
    return run_in("sc300", SC300_CORE)


def test_sc300_registry_and_engine(sc300):
    assert sc300["code"] == "sc300" and sc300["course"] == "SC-300"
    assert sc300["objectives"] == {"1": 4, "2": 4, "3": 4, "4": 4}
    assert sc300["weights"] == {"1": 0.24, "2": 0.28, "3": 0.24, "4": 0.24} and sc300["pass"] == 700
    assert sc300["scaled70"] == 700                       # 70 % on the 1-1000 scale
    assert sc300["progress"] == "progress-sc300.json"     # separate from Security+ progress
    assert sc300["labs"] == {"1": ["1.2", "4.2"], "2": ["2.2", "2.3"], "25": ["2.2", "4.3"], "26": ["4.2", "4.1"]}
    assert sc300["videos"] == 0 and sc300["retires"] is None


def test_sc300_question_bank(sc300):
    assert sc300["problems"] == []
    assert len(sc300["per_obj"]) == 16 and min(sc300["per_obj"].values()) >= 30, sc300["per_obj"]
    assert sc300["topics_ok"]
    assert sc300["bank"] >= 16 * 34
    assert sc300["exam"] == 50 and sc300["exam_domains"] == ["1", "2", "3", "4"]
    assert sc300["domain_test"] == ["2.1", "2.2", "2.3", "2.4"]


def test_sc300_glossary(sc300):
    assert sc300["glossary"] >= 180 and sc300["gloss_domains"] == ["1", "2", "3", "4"]
    assert sc300["gloss_quiz_modes"] == ["acr", "def", "voc"]


def test_sc300_lab_practice_scores_under_sc300_objectives():
    got = run_in("sc300", """
        import json, webapi
        from utils.loader import load_policies
        q = webapi.challenge(load_policies(), 25, seed=1)["questions"]
        print(json.dumps(sorted({x["objective"] for x in q})))
    """)
    assert got == ["2.2"]


def test_sc300_cli_and_bundle(tmp_path):
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    env.pop(course.ENV, None)
    out = subprocess.run([sys.executable, "main.py", "--course", "sc300", "--plain", "quiz"], capture_output=True, text=True,
                         cwd=ROOT, env=env, timeout=120)
    assert out.returncode == 0 and "Microsoft Entra" in out.stdout, out.stderr[-2000:]
    b = tmp_path / "b.json"
    out = subprocess.run([sys.executable, "tools/build_web_bundle.py", "--course", "sc300", "--variants", "0", "--out", str(b)],
                         capture_output=True, text=True, cwd=ROOT, env=env, timeout=180)
    assert out.returncode == 0, out.stderr[-2000:]
    data = json.loads(b.read_text())
    assert data["catalog"]["course"]["code"] == "sc300" and sorted(data["labs"]) == ["1", "2", "25", "26"]
    assert data["exam_bank"] and data["glossary"] and data["catalog"]["objectives"]["2.2"] == "Microsoft Entra Conditional Access"
