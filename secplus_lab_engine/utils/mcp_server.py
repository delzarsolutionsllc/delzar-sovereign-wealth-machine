"""
AI tutor: an MCP server that lets an AI assistant (Claude Desktop, Claude Code or any
Model Context Protocol client) quiz you, explain a lab or plan your study day, using
this course's own engines and question bank.

    python main.py mcp                          # read + quiz tools (default grants)
    python main.py mcp --grant progress:write   # also let the tutor save your answers
    claude mcp add delzar-academy -- python /path/to/secplus_lab_engine/main.py mcp

It doubles as a small identity-and-authorization showcase:

* **Deny by default.** Only tools on the allow-list in ``config/mcp_policy.json`` exist;
  each tool belongs to one scope, and a call succeeds only if that scope is granted.
  ``progress:write`` (saving answers) is off unless you pass ``--grant progress:write``.
* **Least privilege for the AI.** Quiz tools hand out questions WITHOUT answers; the
  answer and explanation come back only through ``check_answer`` after the learner
  responds, so the assistant quizzes rather than reveals.
* **Input validation.** Every argument is checked against the tool's schema (types,
  ranges, enums, no unknown fields) before any engine runs.
* **Audit trail.** Every call, allowed or denied, is appended to an audit log (JSON
  lines: time, tool, scope, decision, argument names) — like a PEP writing to a SIEM.

Transport: JSON-RPC 2.0 over stdio, one message per line (MCP stdio transport).
Standard library only.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Callable

from utils.loader import ROOT

PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
SERVER_INFO = {"name": "delzar-academy-tutor", "title": "Delzar Academy tutor", "version": "1.0.0"}
POLICY_FILE = ROOT / "config" / "mcp_policy.json"
DEFAULT_AUDIT = ROOT / "mcp_audit.jsonl"
MAX_TEXT = 12000
INSTRUCTIONS = (
    "You are a patient certification tutor for Delzar Certification Academy (the active course is in course_overview). Quiz the learner with start_quiz "
    "(questions come without answers): show one question at a time, wait for their answer, then call "
    "check_answer and explain. Never invent answers; use the tools. Use progress_summary to find weak "
    "objectives and daily_review for today's spaced-repetition questions. Practice questions are original, "
    "not real exam questions; the project is not affiliated with CompTIA.")


# --------------------------------------------------------------------------- schema + validation
def _obj(props: dict, required=()) -> dict:
    return {"type": "object", "properties": props, "required": list(required), "additionalProperties": False}


LAB = {"type": "integer", "minimum": 1, "maximum": 26, "description": "Lab number 1-26"}
OBJ = {"type": "string", "pattern": r"^[1-5]\.[1-9]$", "description": "Exam objective, e.g. 2.4"}
QID = {"type": "string", "pattern": r"^[A-Z0-9]{1,4}-\d{3}$|^G-[a-z0-9-]{1,80}:(acr|voc|def)$", "description": "Question id, e.g. D2-014"}
QUIZ = {"type": "string", "pattern": r"^[1-5]\.[1-9]-(set|t)\d{1,2}$|^g[1-5]-(acr|voc|def)-\d{1,2}$",
        "description": "Quiz id from list_quizzes (e.g. 2.4-t1) or a glossary quiz (e.g. g3-acr-1)"}
SEED = {"type": "integer", "minimum": 0, "maximum": 2 ** 31 - 1}


def validate_args(schema: dict, args) -> list[str]:
    """The subset of JSON Schema the tools use: object, required, additionalProperties, types, ranges, pattern, enum."""
    if not isinstance(args, dict):
        return ["arguments must be an object"]
    errs = [f"missing '{k}'" for k in schema.get("required", []) if k not in args]
    props = schema.get("properties", {})
    errs += [f"unknown argument '{k}'" for k in args if k not in props]
    for k, v in args.items():
        s = props.get(k)
        if not s:
            continue
        t = s.get("type")
        ok = {"integer": isinstance(v, int) and not isinstance(v, bool), "boolean": isinstance(v, bool),
              "string": isinstance(v, str), "array": isinstance(v, list), "object": isinstance(v, dict)}.get(t, True)
        if not ok:
            errs.append(f"'{k}' must be {t}")
            continue
        if t == "integer" and (v < s.get("minimum", v) or v > s.get("maximum", v)):
            errs.append(f"'{k}' out of range")
        if t == "string" and (len(v) > s.get("maxLength", 200) or ("pattern" in s and not re.match(s["pattern"], v))):
            errs.append(f"'{k}' has an invalid value")
        if "enum" in s and v not in s["enum"]:
            errs.append(f"'{k}' must be one of {s['enum']}")
        if t == "array" and len(v) > s.get("maxItems", 20):
            errs.append(f"'{k}' has too many items")
    return errs


# --------------------------------------------------------------------------- tools
class Tutor:
    """The tool implementations. ``progress_path`` lets tests use a temporary file."""

    def __init__(self, progress_path=None, today: str | None = None):
        self.progress_path = progress_path
        self.today = today
        self._policies = None

    @property
    def policies(self):
        if self._policies is None:
            from utils.loader import load_policies
            self._policies = load_policies()
        return self._policies

    def _day(self) -> str:
        return self.today or date.today().isoformat()

    def _bank(self) -> dict:
        from utils import glossary
        from utils.exam_bank import load_bank
        return {**{r["id"]: r for r in load_bank()}, **glossary.questions()}

    def glossary_lookup(self, term: str) -> dict:
        from utils import glossary
        hits = glossary.lookup(term)[:10]
        if not hits:
            raise ValueError(f"nothing in the glossary for '{term}'")
        return {"matches": [{k: e.get(k) for k in ("term", "expansion", "definition", "domain", "objectives")} for e in hits],
                "glossary_quizzes": [q["id"] for q in glossary.catalog()["domains"][hits[0]["domain"]]["quizzes"]]}

    # read -------------------------------------------------------------------
    def course_overview(self) -> dict:
        import webapi
        from utils import quizzes
        from utils.exam import DOMAIN_NAMES, DOMAIN_WEIGHTS
        from labs import LABS
        from utils import videos
        cat = quizzes.catalog()
        t = webapi.EXAM_TARGET
        days = (date.fromisoformat(t["retires"]) - date.fromisoformat(self._day())).days
        return {"exam": {**t, "days_left": days},
                "domains": [{"id": d, "name": DOMAIN_NAMES[d], "weight_pct": int(w * 100)} for d, w in DOMAIN_WEIGHTS.items()],
                "objectives": [{"objective": o, "name": c["name"], "questions": c["count"],
                                "topics": [x["name"] for x in c["topics"]], "quizzes": len(c["quizzes"]),
                                "labs": [n for n in webapi.course_labs() if o in webapi._lab_codes(n, LABS[n][0])]}
                               for o, c in cat.items()],
                "course": {k: webapi._course.active().get(k) for k in ("code", "name", "vendor", "exam_code")},
                "labs": [{"lab": n, "title": LABS[n][0].TITLE.split(" — ", 1)[-1], "objectives": webapi._lab_codes(n, LABS[n][0])}
                         for n in webapi.course_labs()]}

    def get_lesson(self, lab: int) -> dict:
        from labs import LABS
        from utils import portfolio
        m = LABS[lab][0]
        b = portfolio.briefing(lab) or {}
        return {"lab": lab, "title": m.TITLE, "objectives": m.OBJECTIVES, "lesson": (m.__doc__ or "").strip()[:MAX_TEXT],
                "insight": m.INSIGHT,
                "work_ticket": {k: b.get(k) for k in ("title", "situation", "your_task", "why_it_matters", "done_when", "glossary")} if b else None}

    def run_lab(self, lab: int, random: bool = False, seed: int | None = None) -> dict:
        import webapi
        from utils.scenario_generator import GENERATORS
        if random and lab not in GENERATORS:
            raise ValueError(f"lab {lab} has no random scenario generator")
        r = webapi.run(self.policies, lab, random, seed if random else None)
        text = r["text"]
        return {"lab": lab, "random": random, "seed": r["seed"], "report": text[:MAX_TEXT],
                "truncated": len(text) > MAX_TEXT, "summary": r["summary"]}

    def case_study(self, lab: int) -> dict:
        from utils import portfolio
        return {"lab": lab, "markdown": portfolio.case_study_markdown(lab, self.policies)}

    def list_quizzes(self, objective: str) -> dict:
        from utils import quizzes
        c = quizzes.catalog().get(objective)
        if not c:
            raise ValueError("unknown objective")
        done = self._progress().get("quizzes", {})
        return {"objective": objective, "name": c["name"],
                "quizzes": [{"quiz": q["id"], "title": q["title"] if q["kind"] == "set" else f"Concept: {q['title']}",
                             "questions": len(q["qids"]), "best": done.get(q["id"], {}).get("best")} for q in c["quizzes"]]}

    def progress_summary(self) -> dict:
        from utils import review
        from utils.challenge import Progress
        p = Progress(self.progress_path) if self.progress_path is not None else Progress()
        day = review.as_date(self._day())
        ids = {q for q, r in self._bank().items() if review.is_single(r)}
        rows = p.rows()
        return {"weakest_first": [{"objective": r[0], "answered": r[1], "correct": r[2], "score": r[3], "status": r[4]} for r in rows[:10]],
                "objectives_practised": len(rows), "due_today": len(review.due_ids(p.data["srs"], day, ids)),
                "streak_days": review.current_streak(p.data.get("streak"), day),
                "quizzes_taken": len(p.data.get("quizzes", {})),
                "recent_sessions": p.data.get("sessions", [])[-5:]}

    def _progress(self) -> dict:
        from utils.challenge import Progress
        return (Progress(self.progress_path) if self.progress_path is not None else Progress()).data

    # quiz (questions without answers; answers only through check_answer) ---------
    @staticmethod
    def _public(q, topic=None) -> dict:
        out = {"qid": q.qid, "objective": q.objective, "kind": q.kind, "question": q.prompt}
        if topic:
            out["topic"] = topic
        if q.kind == "match":
            out["items"] = [i for i, _ in q.pairs]
            out["options"] = list(q.choices)
            out["how_to_answer"] = "Give an object mapping each item to one option."
        elif q.kind == "order":
            out["steps_shuffled"] = list(q.choices)
            out["how_to_answer"] = "Give the steps as a list, first to last."
        elif q.kind == "multi":
            out["choices"] = list(q.choices)
            out["how_to_answer"] = f"Give a list of exactly {q.select} choices."
        else:
            out["choices"] = list(q.choices)
            out["how_to_answer"] = "Give the exact choice text (or its letter A-D)."
        return out

    def start_quiz(self, quiz: str, seed: int | None = None) -> dict:
        from utils import quizzes
        q = quizzes.find(quiz)
        bank = self._bank()
        qs = quizzes.questions(quiz, seed)
        return {"quiz": quiz, "title": q["title"], "objective": quiz.split("-")[0], "count": len(qs),
                "note": "Answers are hidden. After the learner answers, call check_answer with the qid and their response.",
                "questions": [self._public(x, bank[x.qid].get("topic")) for x in qs]}

    def daily_review(self, size: int = 10) -> dict:
        import webapi
        s = webapi.review_session(self.progress_path, self._day(), size)
        bank = self._bank()
        from utils.exam_bank import as_question
        return {"today": s["today"], "due_total": s["due_total"], "review_count": s["review_count"], "new_count": s["new_count"],
                "questions": [{**self._public(as_question(bank[q["id"]]), bank[q["id"]].get("topic")), "choices": q["choices"],
                               "why_today": q["reason"]} for q in s["questions"]]}

    def check_answer(self, qid: str, response) -> dict:
        from utils.challenge import check
        from utils.exam import parse_answer
        from utils.exam_bank import as_question
        rec = self._bank().get(qid)
        if not rec:
            raise ValueError("unknown question id")
        q = as_question(rec)
        if isinstance(response, str):
            resp = parse_answer(q, response) if q.kind == "single" else None
        elif isinstance(response, list) and q.kind in ("multi", "order"):
            resp = [str(x) for x in response]
        elif isinstance(response, dict) and q.kind == "match":
            resp = {str(k): str(v) for k, v in response.items()}
        else:
            resp = None
        if resp is None:
            raise ValueError("response does not fit this question type: " + self._public(q)["how_to_answer"])
        return {"qid": qid, "correct": check(q, resp), "correct_answer": q.answer, "explanation": q.explanation,
                "objective": q.objective, "topic": rec.get("topic")}

    # progress:write -----------------------------------------------------------
    def record_answer(self, qid: str, correct: bool) -> dict:
        import webapi
        r = webapi.review_answer(qid, correct, self._day(), self.progress_path)
        return {"qid": qid, "correct": correct, "next_due": r["card"]["due"], "streak_days": r["streak"]["current"]}

    def record_quiz(self, quiz: str, results: list) -> dict:
        import webapi
        bank = self._bank()
        rows = [{"qid": str(r.get("qid")), "correct": bool(r.get("correct")),
                 "objective": bank.get(str(r.get("qid")), {}).get("objective", "?")} for r in results if isinstance(r, dict)]
        got = webapi.quiz_record(quiz, rows, self._day(), self.progress_path)
        return {"quiz": quiz, "score": got["quiz_score"]}


TOOLS: dict[str, dict] = {
    "course_overview": {"description": "Exam target and countdown, the five domains, every objective with its topics, quizzes and labs.",
                        "schema": _obj({})},
    "get_lesson": {"description": "A lab's lesson text, key concepts, exam tips and plain-English work ticket.", "schema": _obj({"lab": LAB}, ["lab"])},
    "run_lab": {"description": "Run a lab's engine on its sample scenario (or a seeded random one) and return its report.",
                "schema": _obj({"lab": LAB, "random": {"type": "boolean"}, "seed": SEED}, ["lab"])},
    "case_study": {"description": "A one-page portfolio case study (Markdown) built from a lab's real results.", "schema": _obj({"lab": LAB}, ["lab"])},
    "list_quizzes": {"description": "The concept quizzes and mixed sets for one objective, with the learner's best scores.",
                     "schema": _obj({"objective": OBJ}, ["objective"])},
    "glossary_lookup": {"description": "Look up an acronym or term of the active course: expansion, plain-English definition, objectives, and the domain's glossary quizzes.",
                        "schema": _obj({"term": {"type": "string", "maxLength": 60}}, ["term"])},
    "progress_summary": {"description": "The learner's weakest objectives, reviews due today, streak and recent sessions.", "schema": _obj({})},
    "start_quiz": {"description": "Questions of one quiz WITHOUT answers. Ask them one at a time; check each with check_answer.",
                   "schema": _obj({"quiz": QUIZ, "seed": SEED}, ["quiz"])},
    "daily_review": {"description": "Today's spaced-repetition questions (due first, then weakest objectives), without answers.",
                     "schema": _obj({"size": {"type": "integer", "minimum": 1, "maximum": 30}})},
    "check_answer": {"description": "Check the learner's answer: right or wrong, the correct answer and why.",
                     "schema": _obj({"qid": QID, "response": {"description": "choice text or letter; a list for select-TWO/order; an object for match"}},
                                    ["qid", "response"])},
    "record_answer": {"description": "Save one answer to the learner's progress (schedules the daily review). Needs progress:write.",
                      "schema": _obj({"qid": QID, "correct": {"type": "boolean"}}, ["qid", "correct"])},
    "record_quiz": {"description": "Save a finished quiz's results to the learner's progress. Needs progress:write.",
                    "schema": _obj({"quiz": QUIZ, "results": {"type": "array", "maxItems": 20, "items": {"type": "object"}}}, ["quiz", "results"])},
}

PROMPTS = {
    "quiz_me": {"description": "Quiz me on one objective, one concept at a time.",
                "arguments": [{"name": "objective", "description": "Objective, e.g. 2.4", "required": True}],
                "text": "Quiz me on Security+ objective {objective}. Call list_quizzes for {objective}, start with the first concept quiz I have not passed (best below 85%), ask one question at a time, wait for my answer, then use check_answer and explain in plain English. At the end, give my score and the concept to revisit."},
    "plan_my_day": {"description": "A 30-minute study plan from my progress.", "arguments": [],
                    "text": "Look at progress_summary and course_overview, then plan 30 minutes of study for today: due reviews first, then one concept quiz for my weakest objective, then one lab to run. Explain why for each step."},
    "explain_lab": {"description": "Walk me through a lab like a senior colleague.",
                    "arguments": [{"name": "lab", "description": "Lab number 1-26", "required": True}],
                    "text": "Explain lab {lab} to me like a senior colleague on my first week: call get_lesson and run_lab for lab {lab}, describe the work ticket, walk through two decisions the engine made and why, and connect them to the exam objectives and to an IAM job."},
}


# --------------------------------------------------------------------------- policy, audit, dispatch
def load_policy(path: Path = POLICY_FILE) -> dict:
    p = json.loads(Path(path).read_text(encoding="utf-8"))
    if p.get("default") != "deny":
        raise ValueError("the MCP policy must be deny-by-default")
    return p


class Server:
    def __init__(self, grants=(), tutor: Tutor | None = None, audit_path=DEFAULT_AUDIT, policy: dict | None = None,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        self.policy = policy or load_policy()
        self.scope_of = {t: s for s, tools in self.policy["scopes"].items() for t in tools}
        unknown = set(grants) - set(self.policy["scopes"])
        if unknown:
            raise ValueError(f"unknown scope(s): {sorted(unknown)}")
        self.granted = set(self.policy.get("default_grants", [])) | set(grants)
        self.tutor = tutor or Tutor()
        self.audit_path = Path(audit_path) if audit_path else None
        self.clock = clock
        self.initialized = False

    def visible_tools(self) -> list[str]:
        """Only allow-listed tools whose scope is granted are even listed."""
        return [t for t in TOOLS if self.scope_of.get(t) in self.granted]

    def authorize(self, tool: str) -> tuple[bool, str, str | None]:
        scope = self.scope_of.get(tool)
        if tool not in TOOLS or scope is None:
            return False, "not on the allow-list", None
        if scope not in self.granted:
            return False, f"scope '{scope}' not granted", scope
        return True, "allowed", scope

    def audit(self, tool: str, scope, decision: str, reason: str, args) -> None:
        if not self.audit_path:
            return
        rec = {"ts": self.clock().isoformat(timespec="seconds"), "tool": str(tool)[:60], "scope": scope,
               "decision": decision, "reason": reason, "arg_names": sorted(args)[:10] if isinstance(args, dict) else []}
        try:
            with self.audit_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec) + "\n")
        except OSError:
            pass

    def call_tool(self, name, args) -> dict:
        args = {} if args is None else args
        ok, reason, scope = self.authorize(name)
        if not ok:
            self.audit(name, scope, "deny", reason, args)
            return _tool_error(f"Access denied: {name} ({reason}).")
        errs = validate_args(TOOLS[name]["schema"], args)
        if errs:
            self.audit(name, scope, "deny", "invalid arguments", args)
            return _tool_error("Invalid arguments: " + "; ".join(errs))
        try:
            result = getattr(self.tutor, name)(**args)
        except (ValueError, KeyError) as e:
            self.audit(name, scope, "error", str(e)[:120], args)
            return _tool_error(str(e))
        self.audit(name, scope, "allow", "ok", args)
        text = json.dumps(result, ensure_ascii=False, default=str)
        return {"content": [{"type": "text", "text": text}], "structuredContent": result, "isError": False}

    def handle(self, msg) -> dict | None:
        """One JSON-RPC message in, the response out (None for notifications)."""
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
            return _rpc_error(msg.get("id") if isinstance(msg, dict) else None, -32600, "Invalid Request")
        mid, method, params = msg.get("id"), msg["method"], msg.get("params") or {}
        if "id" not in msg:                                   # notification
            if method == "notifications/initialized":
                self.initialized = True
            return None
        if method == "initialize":
            asked = params.get("protocolVersion")
            version = asked if asked in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]
            return _ok(mid, {"protocolVersion": version, "serverInfo": SERVER_INFO, "instructions": INSTRUCTIONS,
                             "capabilities": {"tools": {"listChanged": False}, "prompts": {"listChanged": False}}})
        if method == "ping":
            return _ok(mid, {})
        if method == "tools/list":
            return _ok(mid, {"tools": [{"name": t, "description": TOOLS[t]["description"] + f" [scope: {self.scope_of[t]}]",
                                        "inputSchema": TOOLS[t]["schema"]} for t in self.visible_tools()]})
        if method == "tools/call":
            return _ok(mid, self.call_tool(params.get("name"), params.get("arguments")))
        if method == "prompts/list":
            return _ok(mid, {"prompts": [{"name": n, "description": p["description"], "arguments": p["arguments"]} for n, p in PROMPTS.items()]})
        if method == "prompts/get":
            p = PROMPTS.get(params.get("name"))
            if not p:
                return _rpc_error(mid, -32602, "unknown prompt")
            a = params.get("arguments") or {}
            missing = [x["name"] for x in p["arguments"] if x.get("required") and not str(a.get(x["name"], "")).strip()]
            if missing:
                return _rpc_error(mid, -32602, f"missing argument(s): {missing}")
            vals = {x["name"]: re.sub(r"[^\w. -]", "", str(a.get(x["name"], "")))[:20] for x in p["arguments"]}
            return _ok(mid, {"description": p["description"],
                             "messages": [{"role": "user", "content": {"type": "text", "text": p["text"].format(**vals)}}]})
        return _rpc_error(mid, -32601, f"Method not found: {method}")

    def serve(self, stdin=sys.stdin, stdout=sys.stdout) -> None:
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                resp = _rpc_error(None, -32700, "Parse error")
            else:
                resp = [r for r in map(self.handle, msg) if r] if isinstance(msg, list) else self.handle(msg)
            if resp:
                stdout.write(json.dumps(resp) + "\n")
                stdout.flush()


def _ok(mid, result) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _rpc_error(mid, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def _tool_error(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": True}


def main(grants=(), audit=None, progress_path=None) -> int:
    Server(grants, Tutor(progress_path), audit if audit is not None else DEFAULT_AUDIT).serve()
    return 0
