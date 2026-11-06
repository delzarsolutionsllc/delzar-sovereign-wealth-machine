"""AI tutor MCP server (utils/mcp_server.py): protocol, deny-by-default authorization, validation, audit, tools."""

from __future__ import annotations

import io
import json
import subprocess
import sys

import pytest

from utils import challenge as ch
from utils import mcp_server as M
from utils.exam_bank import load_bank
from utils.loader import ROOT

TODAY = "2026-11-05"


@pytest.fixture(autouse=True)
def no_real_progress(monkeypatch, tmp_path):
    monkeypatch.setattr(ch, "DEFAULT_PROGRESS_PATH", tmp_path / "default-progress.json")
    monkeypatch.setattr(ch.Progress.__init__, "__defaults__", (tmp_path / "default-progress.json",))


@pytest.fixture
def server(tmp_path):
    return M.Server((), M.Tutor(tmp_path / "p.json", TODAY), tmp_path / "audit.jsonl")


def call(srv, name, args=None, mid=1):
    r = srv.handle({"jsonrpc": "2.0", "id": mid, "method": "tools/call", "params": {"name": name, "arguments": args or {}}})
    return r["result"]


def data(result):
    assert not result["isError"], result["content"][0]["text"]
    return json.loads(result["content"][0]["text"])


def audit(tmp_path):
    return [json.loads(l) for l in (tmp_path / "audit.jsonl").read_text().splitlines()]


def test_policy_is_deny_by_default_and_complete():
    p = M.load_policy()
    assert p["default"] == "deny" and set(p["default_grants"]) == {"read", "quiz"}
    listed = [t for tools in p["scopes"].values() for t in tools]
    assert sorted(listed) == sorted(M.TOOLS) and len(listed) == len(set(listed))     # every tool in exactly one scope
    with pytest.raises(ValueError):
        M.load_policy(_write_tmp({**p, "default": "allow"}))


def _write_tmp(obj):
    import tempfile
    f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(obj, f); f.close()
    return f.name


def test_initialize_and_lists(server):
    r = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}})["result"]
    assert r["protocolVersion"] == "2024-11-05" and r["serverInfo"]["name"] == "delzar-academy-tutor"
    assert "tools" in r["capabilities"] and "prompts" in r["capabilities"]
    r = server.handle({"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {"protocolVersion": "1999-01-01"}})["result"]
    assert r["protocolVersion"] == M.PROTOCOL_VERSIONS[0]
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None and server.initialized
    names = [t["name"] for t in server.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})["result"]["tools"]]
    assert "start_quiz" in names and "record_answer" not in names            # ungranted scopes are not even listed
    assert server.handle({"jsonrpc": "2.0", "id": 4, "method": "ping"})["result"] == {}
    assert server.handle({"jsonrpc": "2.0", "id": 5, "method": "nope"})["error"]["code"] == -32601
    assert server.handle({"id": 6, "method": "ping"})["error"]["code"] == -32600


def test_denied_tools_are_refused_and_audited(server, tmp_path):
    for name in ("record_answer", "delete_everything", "__init__", "_bank", None):
        res = call(server, name, {"qid": "D1-001", "correct": True})
        assert res["isError"] and "Access denied" in res["content"][0]["text"]
    log = audit(tmp_path)
    assert [x["decision"] for x in log] == ["deny"] * 5
    assert log[0]["scope"] == "progress:write" and log[1]["reason"] == "not on the allow-list"
    assert all(set(x) == {"ts", "tool", "scope", "decision", "reason", "arg_names"} for x in log)   # names only, no values


def test_granting_progress_write_allows_saving(tmp_path):
    srv = M.Server(("progress:write",), M.Tutor(tmp_path / "p.json", TODAY), tmp_path / "audit.jsonl")
    out = data(call(srv, "record_answer", {"qid": "D1-001", "correct": False}))
    assert out["next_due"] == "2026-11-06"
    assert json.loads((tmp_path / "p.json").read_text())["srs"]["D1-001"]["lapses"] == 1
    with pytest.raises(ValueError):
        M.Server(("root",))


def test_argument_validation(server):
    bad = [("run_lab", {"lab": "1; rm -rf /"}), ("run_lab", {"lab": 99}), ("run_lab", {"lab": 1, "extra": 1}),
           ("get_lesson", {}), ("list_quizzes", {"objective": "../../etc"}), ("start_quiz", {"quiz": "2.4-set1", "seed": -1}),
           ("check_answer", {"qid": "x" * 300, "response": "A"}), ("daily_review", {"size": True})]
    for name, args in bad:
        res = call(server, name, args)
        assert res["isError"] and res["content"][0]["text"].startswith("Invalid arguments"), (name, args)


def test_quiz_hides_answers_until_checked(server):
    q = data(call(server, "start_quiz", {"quiz": "2.4-t1", "seed": 4}))
    assert q["count"] == len(q["questions"]) >= 5
    blob = json.dumps(q)
    assert '"answer' not in blob and "explanation" not in blob
    bank = {r["id"]: r for r in load_bank()}
    first = q["questions"][0]
    rec = bank[first["qid"]]
    right = data(call(server, "check_answer", {"qid": first["qid"], "response": rec["answer"]}))
    assert right["correct"] and right["correct_answer"] == rec["answer"] and right["explanation"] == rec["explanation"]
    wrong = next(c for c in rec["choices"] if c != rec["answer"])
    assert not data(call(server, "check_answer", {"qid": first["qid"], "response": wrong}))["correct"]
    letter = "ABCD"[rec["choices"].index(rec["answer"])]
    assert data(call(server, "check_answer", {"qid": first["qid"], "response": letter}))["correct"]


def test_check_answer_for_pbq_kinds(server):
    bank = load_bank()
    multi = next(r for r in bank if r.get("type") == "multi")
    order = next(r for r in bank if r.get("type") == "order")
    match = next(r for r in bank if r.get("type") == "match")
    assert data(call(server, "check_answer", {"qid": multi["id"], "response": list(reversed(multi["answers"]))}))["correct"]
    assert data(call(server, "check_answer", {"qid": order["id"], "response": order["items"]}))["correct"]
    assert not data(call(server, "check_answer", {"qid": order["id"], "response": list(reversed(order["items"]))}))["correct"]
    assert data(call(server, "check_answer", {"qid": match["id"], "response": {p["item"]: p["match"] for p in match["pairs"]}}))["correct"]
    assert call(server, "check_answer", {"qid": order["id"], "response": "A"})["isError"]
    assert call(server, "check_answer", {"qid": "ZZ-999", "response": "A"})["isError"]


def test_read_tools(server):
    ov = data(call(server, "course_overview"))
    assert ov["exam"]["code"] == "SY0-701" and ov["exam"]["days_left"] == 218 and len(ov["objectives"]) == 28
    assert data(call(server, "get_lesson", {"lab": 25}))["title"].startswith("Lab 25")
    run = data(call(server, "run_lab", {"lab": 11}))
    assert run["report"] and run["random"] is False
    assert data(call(server, "run_lab", {"lab": 9, "random": True, "seed": 3}))["seed"] == 3
    assert call(server, "run_lab", {"lab": 1, "random": True})["isError"]               # lab 1 has no generator
    assert "Case study" in data(call(server, "case_study", {"lab": 1}))["markdown"]
    lq = data(call(server, "list_quizzes", {"objective": "4.6"}))
    assert lq["quizzes"][0]["quiz"] == "4.6-t1" and lq["quizzes"][0]["best"] is None
    ps = data(call(server, "progress_summary"))
    assert ps["objectives_practised"] == 0 and ps["due_today"] == 0
    dr = data(call(server, "daily_review", {"size": 5}))
    assert len(dr["questions"]) == 5 and "answer" not in json.dumps(dr).replace("how_to_answer", "")


def test_prompts(server):
    names = [p["name"] for p in server.handle({"jsonrpc": "2.0", "id": 1, "method": "prompts/list"})["result"]["prompts"]]
    assert names == ["quiz_me", "plan_my_day", "mock_interview", "explain_lab"]
    r = server.handle({"jsonrpc": "2.0", "id": 2, "method": "prompts/get", "params": {"name": "quiz_me", "arguments": {"objective": "2.4<script>"}}})
    text = r["result"]["messages"][0]["content"]["text"]
    assert "objective 2.4script" in text and "<" not in text
    assert server.handle({"jsonrpc": "2.0", "id": 3, "method": "prompts/get", "params": {"name": "quiz_me"}})["error"]["code"] == -32602


def test_stdio_transport(tmp_path):
    msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "list_quizzes", "arguments": {"objective": "1.1"}}}]
    inp = "\n".join(json.dumps(m) for m in msgs) + "\nnot json\n"
    out = subprocess.run([sys.executable, str(ROOT / "main.py"), "mcp", "--audit", str(tmp_path / "a.jsonl")], input=inp,
                         capture_output=True, text=True, timeout=60, cwd=tmp_path)
    lines = [json.loads(l) for l in out.stdout.splitlines()]
    assert [l.get("id") for l in lines] == [1, 2, None] and lines[2]["error"]["code"] == -32700
    assert not lines[1]["result"]["isError"]


def test_serve_handles_batches(server):
    out = io.StringIO()
    server.serve(io.StringIO(json.dumps([{"jsonrpc": "2.0", "id": 1, "method": "ping"}, {"jsonrpc": "2.0", "method": "notifications/initialized"}]) + "\n"), out)
    assert json.loads(out.getvalue()) == [{"jsonrpc": "2.0", "id": 1, "result": {}}]
