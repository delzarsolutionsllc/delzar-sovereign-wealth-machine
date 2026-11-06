"""
JSON API for the course web app.

One set of functions feeds both ways of using the app:

* ``python main.py web`` serves ``web/index.html`` locally and answers
  ``POST /api/<method>`` by calling :func:`dispatch` (live engine, offline).
* ``tools/build_web_bundle.py`` calls the same functions ahead of time to
  write ``web/course_data.json`` for the hosted, Python-free version.

Every function returns plain JSON-serialisable data.
"""

from __future__ import annotations

import contextlib
import html
import io
import json
import random
import re

from labs import LABS
from utils.challenge import Progress
from utils.exam import DOMAIN_NAMES, DOMAIN_TEST_TARGET, DOMAIN_WEIGHTS, PASS_SCALED, build_domain_test, build_exam
from utils.loader import load_data, load_policies
from utils.scenario_generator import GENERATORS, generate
from utils import glossary, portfolio, quizzes, review, sync, videos
from utils.terminal_ui import UI


# --------------------------------------------------------------------------- #
# Lesson text: turn a lab's module docstring into simple HTML
# --------------------------------------------------------------------------- #
def docstring_html(doc: str) -> str:
    """
    Convert the docstring conventions used by the labs into HTML:
    ``Heading`` + ``-----`` underline → <h3>, ``* item`` → list, indented or
    ``::``-introduced blocks → <pre>, blank-line separated paragraphs → <p>.
    The first title block (``Lab N — …`` + ``====``) is dropped (the app shows it).
    """
    lines = (doc or "").strip("\n").splitlines()
    if len(lines) >= 2 and set(lines[1].strip()) <= {"="}:
        lines = lines[2:]
    out: list[str] = []
    para: list[str] = []
    items: list[str] = []
    pre: list[str] = []
    in_pre = False

    def flush_para():
        if para:
            out.append("<p>" + html.escape(" ".join(s.strip() for s in para)) + "</p>")
            para.clear()

    def flush_items():
        if items:
            out.append("<ul>" + "".join(f"<li>{html.escape(i)}</li>" for i in items) + "</ul>")
            items.clear()

    def flush_pre():
        nonlocal in_pre
        if pre:
            out.append("<pre>" + html.escape("\n".join(pre).strip("\n").rstrip()) + "</pre>")
            pre.clear()
        in_pre = False

    i = 0
    while i < len(lines):
        line = lines[i]
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        if in_pre:
            if line.strip() == "" or line.startswith("    "):
                pre.append(line[4:] if line.startswith("    ") else "")
                i += 1
                continue
            flush_pre()
        if line.strip() and nxt.strip() and set(nxt.strip()) <= {"-"} and len(nxt.strip()) >= 3:
            flush_para(); flush_items()
            out.append(f"<h3>{html.escape(line.strip())}</h3>")
            i += 2
            continue
        if line.lstrip().startswith("* "):
            flush_para()
            items.append(line.lstrip()[2:].strip())
        elif line.startswith("  ") and items and line.strip():
            items[-1] += " " + line.strip()          # continuation of an open bullet
        elif line.startswith("    ") and line.strip():
            flush_para(); flush_items()
            in_pre = True
            pre.append(line[4:])
        elif not line.strip():
            flush_para(); flush_items()
        else:
            if line.rstrip().endswith("::"):
                para.append(line.rstrip()[:-1])
                flush_para(); flush_items()
                in_pre = True
            else:
                flush_items()
                para.append(line)
        i += 1
    flush_pre(); flush_para(); flush_items()
    # tidy inline ``code`` and **bold** used in docstrings
    body = "\n".join(out)
    body = re.sub(r"``(.+?)``", r"<code>\1</code>", body)
    body = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", body)
    return body


def lab_domains(module) -> list[str]:
    """Domains a lab covers, in the order its OBJECTIVES string mentions them."""
    seen: list[str] = []
    for d in re.findall(r"\b([1-5])\.\d\b", module.OBJECTIVES):
        if d not in seen:
            seen.append(d)
    return seen


def _q(q) -> dict:
    """A question as JSON. ``kind`` says how to render and score it; ``choices`` is the display order."""
    out = {"prompt": q.prompt, "context": q.context, "choices": list(q.choices), "answer": q.answer,
           "explanation": q.explanation, "objective": q.objective, "id": q.qid, "kind": q.kind}
    if q.kind == "multi":
        out.update(answers=list(q.answers), select=q.select)
    elif q.kind == "order":
        out["items"] = list(q.items)                                  # the correct order
    elif q.kind == "match":
        out["pairs"] = [[i, m] for i, m in q.pairs]                    # listed in display order
    return out


def _json_safe(obj):
    return json.loads(json.dumps(obj, default=str))


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
def _lab_codes(n: int, module) -> list[str]:
    """The active course's objective codes for a lab (Security+: the lab's own SY0-701 codes)."""
    return _course.lab_objectives(n, videos.lab_objectives(module))


def course_labs() -> list[int]:
    return _course.lab_numbers(LABS)


def catalog(policies: dict) -> dict:
    labs = []
    secplus = _course.code() == _course.DEFAULT
    names = _course.objectives()
    for n in course_labs():
        m, data_file = LABS[n]
        codes = _lab_codes(n, m)
        doms = lab_domains(m) if secplus else list(dict.fromkeys(c.split(".")[0] for c in codes))
        objectives = m.OBJECTIVES if secplus else f"{_course.active()['exam_code']} " + " · ".join(f"{c} {names.get(c, '')}" for c in codes)
        labs.append({"n": n, "title": m.TITLE, "objectives": objectives, "domains": doms,
                     "primary_domain": doms[0] if doms else "1", "has_generator": n in GENERATORS,
                     "data_file": data_file, "lesson_html": docstring_html(m.__doc__), "insight": m.INSIGHT,
                     "objective_codes": codes, "videos": [v["id"] for v in videos.for_lab(m)] if _course.active().get("videos") else [],
                     "briefing": portfolio.briefing(n), "career": portfolio.career_tags(n)})
    vc = {"source": videos.course()["source"], "videos": videos.videos()} if _course.active().get("videos") \
        else {"source": None, "videos": []}
    return {"labs": labs, "pass_scaled": PASS_SCALED, "domain_test_target": DOMAIN_TEST_TARGET,
            "exam_target": EXAM_TARGET, "course": _course.summary(), "objectives": names,
            "video_course": vc,
            "career_tracks": portfolio.career(),
            "objective_quizzes": quizzes.catalog(), "quiz_set_size": quizzes.SET_SIZE,
            "glossary": glossary.catalog(),
            "domains": [{"id": d, "name": DOMAIN_NAMES[d], "weight": w} for d, w in DOMAIN_WEIGHTS.items()]}


def _data(policies: dict, lab: int, randomize: bool, seed) -> dict:
    if lab not in LABS:
        raise ValueError(f"unknown lab {lab}")
    if randomize:
        if lab not in GENERATORS:
            raise ValueError(f"lab {lab} has no random scenario generator")
        return generate(lab, policies, seed)
    return load_data(LABS[lab][1])


def run(policies: dict, lab: int, randomize: bool = False, seed=None, data: dict | None = None) -> dict:
    """Run a lab's scenario; return the plain-text report and its summary."""
    module = LABS[lab][0]
    data = data if data is not None else _data(policies, lab, randomize, seed)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        summary = module.run_demo(UI(plain=True), policies, data)
    return {"lab": lab, "random": randomize, "seed": seed, "text": buf.getvalue(), "summary": _json_safe(summary)}


def challenge(policies: dict, lab: int, randomize: bool = False, seed=None, data: dict | None = None) -> dict:
    module = LABS[lab][0]
    data = data if data is not None else _data(policies, lab, randomize, seed)
    qs = [_q(q) for q in module.build_challenges(policies, data)]
    if _course.code() != _course.DEFAULT:            # score lab practice under this course's objective for the lab
        codes = _lab_codes(lab, module)
        if codes:
            qs = [q if q.get("objective") in codes else {**q, "objective": codes[0]} for q in qs]   # keep a code the course knows
    random.Random(seed).shuffle(qs)
    return {"lab": lab, "random": randomize, "seed": seed, "questions": qs}


def exam(policies: dict, count: int = 90, seed=None, randomize: bool = True, domain=None, source: str = "bank") -> dict:
    """Full exam (weighted by domain) or, with ``domain``, a single-domain test."""
    count = max(5, min(int(count), 150))
    source = source if source in ("bank", "labs") else "bank"
    if domain not in (None, ""):
        qs, per_obj = build_domain_test(policies, str(domain), count, seed, randomize, source)
        return {"questions": [_q(q) for q in qs], "domain": str(domain), "allocation": per_obj,
                "shortfall": {}, "target": DOMAIN_TEST_TARGET, "source": source}
    qs, alloc, short = build_exam(policies, count, seed, randomize, source)
    return {"questions": [_q(q) for q in qs], "allocation": alloc, "shortfall": short, "source": source}


def progress_get(path=None) -> dict:
    p = Progress(path) if path is not None else Progress()
    return {"objectives": p.data["objectives"], "sessions": p.data["sessions"][-20:], "rows": p.rows(),
            "watched": p.data.get("watched", []), "srs": p.data.get("srs", {}),
            "streak": p.data.get("streak", {"last_day": None, "count": 0}), "quizzes": p.data.get("quizzes", {})}


def progress_watch(video_id: str, watched: bool = True, path=None) -> dict:
    """Mark a course video as watched (or not). Only IDs from the video index are accepted."""
    if video_id not in {v["id"] for v in videos.videos()}:
        raise ValueError("unknown video")
    p = Progress(path) if path is not None else Progress()
    seen = [v for v in p.data.get("watched", []) if v != video_id]
    if watched:
        seen.append(video_id)
    p.data["watched"] = seen
    p.save()
    return progress_get(path)


def progress_record(results: list[dict], label: str, path=None, today=None) -> dict:
    """results = [{"objective": "4.3", "correct": true, "qid": "D4-012"}, ...]

    A result whose ``qid`` is an exam-bank id also schedules spaced repetition, so
    exam misses enter the daily review automatically (see utils/review.py).
    """
    p = Progress(path) if path is not None else Progress()
    ids = _bank_ids()
    day = review.as_date(today) if today not in (None, "") else None
    correct = 0
    for r in results:
        if not isinstance(r, dict):
            raise ValueError("each result must be an object")
        ok = bool(r.get("correct"))
        correct += ok
        qid = str(r.get("qid") or "")
        p.record(str(r.get("objective", "?")), ok, qid if qid in ids else "", day)
    from datetime import datetime, timezone
    p.data["sessions"].append({"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                               "lab": str(label)[:40], "score": f"{correct}/{len(results)}"})
    p.save()
    return progress_get(path)


def progress_reset(path=None) -> dict:
    p = Progress(path) if path is not None else Progress()
    p.data = sync.empty()
    p.save()
    return progress_get(path)


def progress_export(path=None) -> dict:
    """Everything needed to move progress to another device (the web app saves it as a file)."""
    p = Progress(path) if path is not None else Progress()
    return sync.export(p.data)


def progress_import(data, replace: bool = False, path=None) -> dict:
    """Merge (or, with ``replace``, overwrite) progress from an exported file's JSON. Rules: utils/sync.py."""
    p = Progress(path) if path is not None else Progress()
    p.data = sync.import_into(p.data, data, bool(replace))
    p.save()
    return progress_get(path)


# --------------------------------------------------------------------------- #
# Objective quizzes (several short quizzes per objective; utils/quizzes.py)
# --------------------------------------------------------------------------- #
def quiz(quiz_id: str, seed=None) -> dict:
    q = quizzes.find(quiz_id)
    topic = {r["id"]: r.get("topic") for r in quizzes.records(quiz_id)}
    return {"quiz": {k: v for k, v in q.items() if k != "qids"}, "objective": quiz_id.split("-")[0],
            "questions": [{**_q(x), "topic": topic.get(x.qid)} for x in quizzes.questions(quiz_id, seed)]}


def quiz_record(quiz_id: str, results: list[dict], today=None, path=None) -> dict:
    """Score one finished quiz: answers count per objective and feed the daily review; the quiz keeps best/last."""
    q = quizzes.find(quiz_id)
    if not isinstance(results, list) or not results:
        raise ValueError("results must be a non-empty list")
    allowed = set(q["qids"])
    if any(not isinstance(r, dict) or r.get("qid") not in allowed for r in results):
        raise ValueError("every result needs the qid of a question in this quiz")
    if quizzes.is_glossary(quiz_id):
        # vocabulary drills: logged as a session and a quiz score, not counted toward objective scores
        from datetime import datetime, timezone
        p = Progress(path) if path is not None else Progress()
        p.data["sessions"].append({"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "lab": f"quiz {quiz_id}",
                                   "score": f"{sum(bool(r.get('correct')) for r in results)}/{len(results)}"})
        p.save()
    else:
        progress_record(results, f"quiz {quiz_id}", path, today)
    p = Progress(path) if path is not None else Progress()
    day = _today(today).isoformat()
    slot = quizzes.record(p.data, quiz_id, sum(bool(r.get("correct")) for r in results), len(results), day)
    p.save()
    return {**progress_get(path), "quiz_score": slot}


# --------------------------------------------------------------------------- #
# Daily review (spaced repetition over the exam bank; rules in utils/review.py)
# --------------------------------------------------------------------------- #
def _bank():
    from utils.exam_bank import load_bank
    return load_bank()


def _bank_ids() -> set:
    return {r["id"] for r in _bank()}


def _today(today):
    from datetime import date
    return review.as_date(today) if today not in (None, "") else date.today()


def review_session(path=None, today=None, size: int = review.DEFAULT_SIZE, seed=None) -> dict:
    """Today's session: due reviews first, then new questions from the weakest objectives."""
    size = int(size)
    if not 1 <= size <= 50:
        raise ValueError("size must be between 1 and 50")
    p = Progress(path) if path is not None else Progress()
    return review.build_session(p.data, _bank(), _today(today), size, seed)


def review_answer(qid: str, correct: bool, today=None, path=None) -> dict:
    """Record one review answer: schedules the card, counts the objective and the daily streak."""
    by_id = {r["id"]: r for r in _bank()}
    if not isinstance(qid, str) or qid not in by_id:
        raise ValueError("unknown question id")
    if not isinstance(correct, bool):
        raise ValueError("correct must be true or false")
    day = _today(today)
    p = Progress(path) if path is not None else Progress()
    p.record(by_id[qid]["objective"], correct, qid, day, review=True)
    p.save()
    ids = {q for q, r in by_id.items() if review.is_single(r)}      # what a session can show today
    return {"qid": qid, "correct": correct, "card": p.data["srs"][qid],
            "streak": {**p.data["streak"], "current": review.current_streak(p.data["streak"], day)},
            "due_total": len(review.due_ids(p.data["srs"], day, ids)),
            "due_by_day": review.due_by_day(p.data["srs"], day, 7, ids)}


# The exam this platform prepares for (owner's choice, 2026-11-05). Dates from CompTIA, checked 2026-11-05.
from utils import course as _course

EXAM_TARGET = _course.active()["exam_target"]     # exam dates and their source (data/courses/<code>/course.json)

METHODS = {"catalog", "run", "challenge", "exam", "progress_get", "progress_record", "progress_reset", "progress_watch",
           "case_study", "review_session", "review_answer", "progress_export", "progress_import", "quiz", "quiz_record", "glossary"}


def dispatch(method: str, args: dict, policies: dict | None = None, progress_path=None) -> dict:
    """Single entry point for the local server. Unknown methods and bad arguments raise ValueError."""
    if method not in METHODS:
        raise ValueError(f"unknown method '{method}'")
    policies = policies or load_policies()
    a = args or {}
    seed = a.get("seed")
    seed = int(seed) if seed not in (None, "") else None
    if method == "catalog":
        return catalog(policies)
    if method == "run":
        return run(policies, int(a["lab"]), bool(a.get("random")), seed)
    if method == "challenge":
        return challenge(policies, int(a["lab"]), bool(a.get("random")), seed)
    if method == "exam":
        return exam(policies, int(a.get("count", 90)), seed, not a.get("fixed"), a.get("domain"),
                    (a.get("source") or "bank") if _course.code() == _course.DEFAULT else "bank")
    if method == "progress_get":
        return progress_get(progress_path)
    if method == "progress_record":
        res = a.get("results")
        if not isinstance(res, list):
            raise ValueError("results must be a list")
        return progress_record(res, a.get("label", "web"), progress_path, a.get("today"))
    if method == "review_session":
        return review_session(progress_path, a.get("today"), a.get("size", review.DEFAULT_SIZE), seed)
    if method == "review_answer":
        return review_answer(a.get("qid"), a.get("correct"), a.get("today"), progress_path)
    if method == "progress_export":
        return progress_export(progress_path)
    if method == "progress_import":
        return progress_import(a.get("data"), bool(a.get("replace")), progress_path)
    if method == "quiz":
        return quiz(str(a.get("quiz", "")), seed)
    if method == "quiz_record":
        return quiz_record(str(a.get("quiz", "")), a.get("results"), a.get("today"), progress_path)
    if method == "glossary":
        return list(glossary.entries())
    if method == "case_study":
        return portfolio.case_study(int(a["lab"]), policies)
    if method == "progress_watch":
        return progress_watch(str(a.get("video", "")), bool(a.get("watched", True)), progress_path)
    return progress_reset(progress_path)
