"""Course web app: shared API, local server security, desktop shortcuts, hosted bundle."""

from __future__ import annotations

import http.client
import json
import stat
import threading

import pytest

import webapi
from labs import LABS
from utils.desktop import install_shortcut, launcher
from utils.webserver import make_server


# =========================================================================== #
# webapi
# =========================================================================== #
def test_catalog_lists_every_lab(policies):
    c = webapi.catalog(policies)
    assert [l["n"] for l in c["labs"]] == sorted(LABS)
    assert {d["id"] for d in c["domains"]} == {"1", "2", "3", "4", "5"}
    for lab in c["labs"]:
        assert lab["lesson_html"] and lab["insight"]["ai_governance"] and lab["primary_domain"] in "12345"
    assert sum(d["weight"] for d in c["domains"]) == pytest.approx(1.0)


def test_docstring_html_structures():
    doc = "Title\n=====\n\nHeading\n-------\n* one\n  continued\n* two\n\nPara ``code`` here::\n\n    block line\n\nEnd."
    h = webapi.docstring_html(doc)
    assert "<h3>Heading</h3>" in h and "<li>one continued</li>" in h
    assert "<pre>block line</pre>" in h and "<code>code</code>" in h and "Title" not in h


def test_docstring_html_escapes():
    assert "&lt;script&gt;" in webapi.docstring_html("T\n=\n\n<script>x</script>")


def test_run_returns_report_text(policies):
    r = webapi.run(policies, 17)
    assert "Exam & Architectural Insight" in r["text"] and r["summary"]["P-01"] == "TRUSTED"
    r2 = webapi.run(policies, 9, True, 5)
    assert r2["random"] and r2["text"]


def test_challenge_is_seeded_and_valid(policies):
    a = webapi.challenge(policies, 11, seed=3)["questions"]
    b = webapi.challenge(policies, 11, seed=3)["questions"]
    assert a == b and all(q["answer"] in q["choices"] for q in a)
    with pytest.raises(ValueError):
        webapi.challenge(policies, 3, randomize=True, seed=1)        # lab 3 has no generator


def test_exam_bounds(policies):
    assert len(webapi.exam(policies, 20, seed=1)["questions"]) == 20
    assert len(webapi.exam(policies, 1, seed=1)["questions"]) == 5     # clamped to the minimum


def test_progress_roundtrip(tmp_path):
    path = tmp_path / "p.json"
    out = webapi.progress_record([{"objective": "1.4", "correct": True}, {"objective": "1.4", "correct": False}], "lab 17", path)
    assert out["objectives"]["1.4"] == {"attempted": 2, "correct": 1} and out["sessions"][-1]["score"] == "1/2"
    assert webapi.progress_reset(path)["objectives"] == {}


def test_dispatch_rejects_unknown_and_bad_args(tmp_path):
    with pytest.raises(ValueError):
        webapi.dispatch("os_system", {})
    with pytest.raises(ValueError):
        webapi.dispatch("progress_record", {"results": "nope"}, progress_path=tmp_path / "p.json")


# =========================================================================== #
# local server
# =========================================================================== #
@pytest.fixture
def server(policies, tmp_path):
    httpd = make_server(0, policies, progress_path=tmp_path / "progress.json")
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield httpd.server_address[1]
    httpd.shutdown()
    httpd.server_close()


def request(port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
    h = {"Host": f"127.0.0.1:{port}"}
    h.update(headers or {})
    conn.request(method, path, body=body, headers=h)
    r = conn.getresponse()
    data = r.read()
    conn.close()
    return r.status, data, r


def test_server_binds_localhost_only(server, policies):
    httpd = make_server(0, policies)
    assert httpd.server_address[0] == "127.0.0.1"
    httpd.server_close()


def test_index_served_in_live_mode(server):
    status, data, resp = request(server, "GET", "/")
    page = data.decode()
    assert status == 200 and page.startswith("<!doctype html>")
    assert 'window.SECPLUS_API = "/api"' in page and "<!--SECPLUS_MODE-->" not in page
    assert resp.getheader("X-Frame-Options") == "DENY"


def test_api_call(server):
    status, data, _ = request(server, "POST", "/api/catalog", "{}", {"Content-Type": "application/json"})
    assert status == 200 and len(json.loads(data)["labs"]) == len(LABS)


def test_api_progress_uses_server_path(server, tmp_path):
    body = json.dumps({"results": [{"objective": "4.3", "correct": True}], "label": "t"})
    status, data, _ = request(server, "POST", "/api/progress_record", body, {"Content-Type": "application/json"})
    assert status == 200 and json.loads(data)["objectives"]["4.3"]["correct"] == 1
    assert (tmp_path / "progress.json").exists()


@pytest.mark.parametrize("host", ["evil.example.com", "attacker.test:8765", "192.168.1.5"])
def test_foreign_host_header_rejected(server, host):
    assert request(server, "GET", "/", headers={"Host": host})[0] == 403
    assert request(server, "POST", "/api/catalog", "{}", {"Host": host, "Content-Type": "application/json"})[0] == 403


def test_non_json_post_rejected(server):
    # a cross-site form or text/plain fetch (no CORS preflight) must not reach the API
    assert request(server, "POST", "/api/catalog", "{}", {"Content-Type": "text/plain"})[0] == 415
    assert request(server, "POST", "/api/catalog", "a=1", {"Content-Type": "application/x-www-form-urlencoded"})[0] == 415


def test_unknown_method_and_paths(server):
    assert request(server, "POST", "/api/shutdown", "{}", {"Content-Type": "application/json"})[0] == 400
    assert request(server, "GET", "/../config/default_policies.json")[0] == 404
    assert request(server, "GET", "/web/course_data.json")[0] == 404


def test_no_cors_headers(server):
    _, _, resp = request(server, "POST", "/api/catalog", "{}", {"Content-Type": "application/json", "Origin": "https://evil.example.com"})
    assert resp.getheader("Access-Control-Allow-Origin") is None


# =========================================================================== #
# desktop shortcut
# =========================================================================== #
@pytest.mark.parametrize("platform,name", [("windows", "Security+ Lab Engine.bat"),
                                           ("macos", "Security+ Lab Engine.command"),
                                           ("linux", "security-plus-lab-engine.desktop")])
def test_install_shortcut(tmp_path, platform, name):
    path = install_shortcut(tmp_path / "Desktop", platform, root=tmp_path / "engine")
    assert path.name == name and path.exists()
    text = path.read_text()
    assert "main.py web" in text and str((tmp_path / "engine").resolve()) in text
    if platform != "windows":
        assert path.stat().st_mode & stat.S_IXUSR


def test_windows_launcher_uses_crlf():
    _, body = launcher("windows", __import__("pathlib").Path("C:/x"))
    assert "\r\n" in body and "py -3 main.py web" in body


# =========================================================================== #
# hosted bundle
# =========================================================================== #
def test_bundle_builder(tmp_path):
    from tools.build_web_bundle import build
    b = build(variants=1)
    assert set(b["labs"]) == {str(n) for n in LABS}
    for n, lab in b["labs"].items():
        assert lab["sample"]["run"] and lab["sample"]["questions"]
        assert len(lab["variants"]) == (1 if lab_has_generator(int(n)) else 0)
    json.dumps(b)                                                     # serialisable


def lab_has_generator(n):
    from utils.scenario_generator import GENERATORS
    return n in GENERATORS


def test_committed_bundle_matches_labs():
    from utils.loader import ROOT
    data = json.loads((ROOT / "web" / "course_data.json").read_text())
    assert set(data["labs"]) == {str(n) for n in LABS}, "re-run: python tools/build_web_bundle.py"


def test_single_file_desktop_app():
    from tools.build_desktop_app import build_html
    html = build_html(variants=1)
    assert html.startswith("<!doctype html>") and "window.SECPLUS_BUNDLE = " in html
    data_script = html.split("<script>window.SECPLUS_BUNDLE = ", 1)[1].split("</script>", 1)[0]
    json.loads(data_script.rstrip(";").replace("<\\/", "</"))      # the embedded bundle is intact JSON
    assert "<title>Security+ Lab Engine</title>" in html


def test_anki_export(tmp_path):
    pytest.importorskip("genanki")
    import sqlite3
    import zipfile
    from tools.export_anki import build_package, collect, question_key
    qs = collect(variants=0)
    assert len({question_key(q) for q in qs}) == len(qs)                     # de-duplicated
    # same prompt + context with different choices are different questions and are all kept
    assert len({(q["prompt"], q["context"]) for q in qs}) < len(qs)
    pkg, n_cards, n_decks = build_package(variants=0)
    out = tmp_path / "deck.apkg"
    pkg.write_to_file(str(out))
    with zipfile.ZipFile(out) as z:
        z.extract("collection.anki2", tmp_path)
    db = sqlite3.connect(tmp_path / "collection.anki2")
    assert db.execute("select count(*) from notes").fetchone()[0] == n_cards == len(qs)
    assert n_decks >= 15
    # stable GUIDs: a second export produces the same note ids for the same questions
    pkg2, _, _ = build_package(variants=0)
    g1 = sorted(n.guid for d in pkg.decks for n in d.notes)
    g2 = sorted(n.guid for d in pkg2.decks for n in d.notes)
    assert g1 == g2


# =========================================================================== #
# CTFd export
# =========================================================================== #
def _ctfd_accepts(flags, submission):
    """CTFd's static-flag check: exact match, or case-insensitive when data says so."""
    for f in flags:
        if f["data"] == "case_insensitive" and f["content"].lower() == submission.strip().lower():
            return True
        if f["content"] == submission.strip():
            return True
    return False


@pytest.mark.parametrize("variants", [0, 2])
def test_ctfd_export_round_trip(tmp_path, variants):
    import csv
    import string as _s
    import sys as _sys
    from tools.export_anki import collect
    from tools.export_ctfd import CSV_FIELDS, build_challenges, write_all
    chals = build_challenges(variants=variants)
    assert len(chals) == len(collect(variants)) and len({c["name"] for c in chals}) == len(chals)
    write_all(tmp_path, chals, 100, 25)
    csv.field_size_limit(_sys.maxsize)
    with (tmp_path / "challenges.csv").open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == len(chals) and list(rows[0]) == CSV_FIELDS
    from tools.export_anki import question_key
    questions = {question_key(q): q for q in collect(variants)}
    for row, c in zip(rows, chals):
        # what CTFd's load_challenges_csv does: JSON flag/hint lists, comma-split tags
        flags = json.loads(row["flags"])
        assert all(isinstance(f, dict) and f["type"] == "static" for f in flags)
        assert all(isinstance(h, dict) and int(h["cost"]) >= 0 for h in json.loads(row["hints"]))
        assert row["tags"].split(",") == c["tags"] and row["category"].startswith("D")
        assert int(row["value"]) == 100 and row["type"] == "standard" and row["state"] == "visible"
        # play it: the right answer (text, and letter when offered) wins; every wrong choice loses
        q = c["_question"]
        assert questions[question_key(q)] == q
        assert _ctfd_accepts(flags, q["answer"]) and _ctfd_accepts(flags, q["answer"].upper())
        for i, choice in enumerate(q["choices"]):
            if choice != q["answer"]:
                assert not _ctfd_accepts(flags, choice)
                if len(flags) > 1:
                    assert not _ctfd_accepts(flags, _s.ascii_uppercase[i])
    ymls = sorted(tmp_path.glob("challenges/*/challenge.yml"))
    assert len(ymls) == len(chals)
    spec = json.loads(ymls[0].read_text().split("\n", 1)[1])           # JSON is valid YAML
    assert {"name", "category", "description", "value", "flags", "hints", "version"} <= set(spec)


def test_ctfd_letters_dropped_when_ambiguous():
    from tools.export_ctfd import describe, flags
    q = {"objective": "1.4", "lab": 17, "context": "", "prompt": "Pick", "choices": ["A", "B", "Neither"],
         "answer": "B", "explanation": "x"}
    assert flags(q, False) == [{"type": "static", "content": "B", "data": "case_insensitive"}]
    assert "Submit the exact answer text" in describe(q, False)


def test_ctfd_mc_plugin_mode():
    from tools.export_ctfd import build_challenges
    c = build_challenges(mc_plugin=True)[0]
    assert c["type"] == "multiple_choice" and "* () " in c["description"] and len(c["flags"]) == 1
