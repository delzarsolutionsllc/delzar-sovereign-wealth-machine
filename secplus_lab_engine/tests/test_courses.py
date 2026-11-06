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
  "code": course.code(), "objectives": exam_bank.OBJECTIVES, "objectives_all": list(course.objectives()), "weights": exam.DOMAIN_WEIGHTS, "pass": exam.PASS_SCALED,
  "scaled70": r.scaled, "progress": DEFAULT_PROGRESS_PATH.name,
  "labs": {str(l["n"]): l["objective_codes"] for l in cat["labs"]}, "course": cat["course"]["exam_code"],
  "videos": len(cat["video_course"]["videos"]), "retires": cat["exam_target"]["retires"],
  "problems": exam_bank.validate(list(exam_bank.load_bank())),
  "bank": len(exam_bank.load_bank()), "exam": len(ex["questions"]), "exam_domains": sorted({q["objective"].split(".")[0] for q in ex["questions"]}, key=int),
  "domain_test": sorted({q["objective"] for q in dt["questions"]}),
  "per_obj": {o: c["count"] for o, c in quizzes.catalog().items()},
  "topics_ok": all(len(c["topics"]) >= 3 and all(t["count"] >= 5 for t in c["topics"]) for c in quizzes.catalog().values()),
  "glossary": len(glossary.entries()), "gloss_domains": sorted({e["domain"] for e in glossary.entries()}, key=int),
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
    assert sc300["labs"] == {"1": ["1.2", "4.2"], "2": ["2.2", "2.3"], "25": ["2.2", "4.3"], "26": ["4.2", "4.1"],
                             "27": ["4.1", "1.3"], "28": ["3.3", "3.2", "3.4"], "29": ["3.1", "4.3"], "30": ["1.4", "2.1"],
                             "31": ["4.4", "2.3"], "32": ["1.3", "2.2"], "33": ["2.1", "2.2"], "34": ["2.4", "2.2"],
                             "35": ["1.1", "1.2"]}
    covered = {o for codes in sc300["labs"].values() for o in codes}
    assert covered == set(sc300["objectives_all"]), "every SC-300 objective has a hands-on lab"
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


def test_sc300_only_labs_stay_out_of_security_plus():
    from labs import LABS
    from webapi import course_labs
    assert course_labs() == list(range(1, 27))
    assert all(getattr(LABS[n][0], "COURSES", None) == ("sc300",) for n in range(27, 36))


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
    assert data["catalog"]["course"]["code"] == "sc300" and sorted(data["labs"], key=int) == ["1", "2", *map(str, range(25, 36))]
    assert data["exam_bank"] and data["glossary"] and data["catalog"]["objectives"]["2.2"] == "Microsoft Entra Conditional Access"


# --------------------------------------------------------------------------- Okta Certified Professional
@pytest.fixture(scope="module")
def okta():
    return run_in("okta", SC300_CORE.replace('domain="2"', 'domain="4"'))


def test_okta_registry_and_engine(okta):
    assert okta["code"] == "okta" and okta["course"] == "Okta Professional"
    assert okta["objectives"] == {"1": 3, "2": 2, "3": 2, "4": 4, "5": 2, "6": 2}
    assert okta["weights"] == {"1": 0.26, "2": 0.10, "3": 0.08, "4": 0.38, "5": 0.12, "6": 0.06} and okta["pass"] == 70
    assert okta["scaled70"] == 70 and okta["progress"] == "progress-okta.json"
    assert okta["videos"] == 0 and okta["retires"] is None
    assert sorted(okta["labs"], key=int) == ["1", *map(str, range(36, 43))]
    covered = {o for codes in okta["labs"].values() for o in codes}
    assert covered == set(okta["objectives_all"]), "every Okta objective has a hands-on lab"


def test_okta_question_bank(okta):
    assert okta["problems"] == []
    assert len(okta["per_obj"]) == 15 and min(okta["per_obj"].values()) >= 30, okta["per_obj"]
    assert okta["topics_ok"]
    assert okta["bank"] >= 15 * 34
    assert okta["exam"] == 50 and okta["exam_domains"] == ["1", "2", "3", "4", "5", "6"]
    assert okta["domain_test"] == ["4.1", "4.2", "4.3", "4.4"]


def test_okta_glossary(okta):
    assert okta["glossary"] >= 200 and okta["gloss_domains"] == ["1", "2", "3", "4", "5", "6"]
    assert okta["gloss_quiz_modes"] == ["acr", "def", "voc"]


def test_okta_labs_stay_in_okta():
    from labs import LABS
    from webapi import course_labs
    assert course_labs() == list(range(1, 27))
    assert all(getattr(LABS[n][0], "COURSES", None) == ("okta",) for n in range(36, 43))
    got = run_in("okta", """
        import json, webapi
        from utils.loader import load_policies
        q = webapi.challenge(load_policies(), 40, seed=1)["questions"]
        print(json.dumps(sorted({x["objective"] for x in q})))
    """)
    assert set(got) <= {"4.3", "4.2", "4.1"} and got


def test_domains_beyond_five_work_everywhere():
    """Okta has a domain 6 (and SailPoint Engineer will have 10): quiz ids, glossary quizzes,
    progress import and the MCP schemas must accept them."""
    got = run_in("okta", """
        import json
        from utils import quizzes, glossary, sync
        q = quizzes.find("6.1-t1"); g = glossary.find("g6-voc-1")
        c = sync.clean({"objectives": {"6.2": {"attempted": 3, "correct": 2}, "10.1": {"attempted": 1, "correct": 1}}})
        print(json.dumps({"quiz": bool(q), "gloss": bool(g), "objs": sorted(c["objectives"])}))
    """)
    assert got == {"quiz": True, "gloss": True, "objs": ["10.1", "6.2"]}
    from utils import mcp_server
    import re
    assert re.match(mcp_server.OBJ["pattern"], "10.3") and re.match(mcp_server.QUIZ["pattern"], "10.2-t1")
    assert re.match(mcp_server.QUIZ["pattern"], "g10-acr-1")


# --------------------------------------------------------------------------- SailPoint Identity Security Cloud
@pytest.fixture(scope="module", params=["spadmin", "speng"])
def sailpoint(request):
    return request.param, run_in(request.param, SC300_CORE.replace('domain="2"', 'domain="1"'))


def test_sailpoint_courses(sailpoint):
    code, c = sailpoint
    n_obj = {"spadmin": 20, "speng": 24}[code]
    n_dom = {"spadmin": 8, "speng": 10}[code]
    assert c["code"] == code and c["pass"] == 70 and c["progress"] == f"progress-{code}.json"
    assert sum(c["objectives"].values()) == n_obj and len(c["weights"]) == n_dom
    assert c["problems"] == [] and len(c["per_obj"]) == n_obj and min(c["per_obj"].values()) >= 30, c["per_obj"]
    assert c["topics_ok"] and c["bank"] >= n_obj * 34
    assert c["exam_domains"] == list(map(str, range(1, n_dom + 1)))
    assert c["glossary"] >= 240 and c["gloss_domains"] == list(map(str, range(1, n_dom + 1)))
    assert {"43", "44", "45", "46", "47", "48", "49", "50"} <= set(c["labs"])
    assert c["videos"] == 0 and c["retires"] is None


def test_sailpoint_labs_stay_in_sailpoint():
    from labs import LABS
    from webapi import course_labs
    assert course_labs() == list(range(1, 27))
    assert all(getattr(LABS[n][0], "COURSES", None) == ("spadmin", "speng") for n in range(43, 51))
