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
from utils import portfolio, videos
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
    return {"prompt": q.prompt, "context": q.context, "choices": list(q.choices), "answer": q.answer,
            "explanation": q.explanation, "objective": q.objective, "id": q.qid}


def _json_safe(obj):
    return json.loads(json.dumps(obj, default=str))


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
def catalog(policies: dict) -> dict:
    labs = []
    for n, (m, data_file) in LABS.items():
        doms = lab_domains(m)
        labs.append({"n": n, "title": m.TITLE, "objectives": m.OBJECTIVES, "domains": doms,
                     "primary_domain": doms[0] if doms else "1", "has_generator": n in GENERATORS,
                     "data_file": data_file, "lesson_html": docstring_html(m.__doc__), "insight": m.INSIGHT,
                     "objective_codes": videos.lab_objectives(m), "videos": [v["id"] for v in videos.for_lab(m)],
                     "briefing": portfolio.briefing(n), "career": portfolio.career_tags(n)})
    return {"labs": labs, "pass_scaled": PASS_SCALED, "domain_test_target": DOMAIN_TEST_TARGET,
            "video_course": {"source": videos.course()["source"], "videos": videos.videos()},
            "career_tracks": portfolio.career(),
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
            "watched": p.data.get("watched", [])}


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


def progress_record(results: list[dict], label: str, path=None) -> dict:
    """results = [{"objective": "4.3", "correct": true}, ...]"""
    p = Progress(path) if path is not None else Progress()
    correct = 0
    for r in results:
        ok = bool(r.get("correct"))
        correct += ok
        p.record(str(r.get("objective", "?")), ok)
    from datetime import datetime, timezone
    p.data["sessions"].append({"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                               "lab": str(label)[:40], "score": f"{correct}/{len(results)}"})
    p.save()
    return progress_get(path)


def progress_reset(path=None) -> dict:
    p = Progress(path) if path is not None else Progress()
    p.data = {"objectives": {}, "sessions": [], "watched": []}
    p.save()
    return progress_get(path)


METHODS = {"catalog", "run", "challenge", "exam", "progress_get", "progress_record", "progress_reset", "progress_watch",
           "case_study"}


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
                    a.get("source") or "bank")
    if method == "progress_get":
        return progress_get(progress_path)
    if method == "progress_record":
        res = a.get("results")
        if not isinstance(res, list):
            raise ValueError("results must be a list")
        return progress_record(res, a.get("label", "web"), progress_path)
    if method == "case_study":
        return portfolio.case_study(int(a["lab"]), policies)
    if method == "progress_watch":
        return progress_watch(str(a.get("video", "")), bool(a.get("watched", True)), progress_path)
    return progress_reset(progress_path)
