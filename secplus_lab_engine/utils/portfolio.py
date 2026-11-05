"""
Work tickets, career tracks and portfolio case studies.

* ``data/briefings/labNN.json``: a plain-English "work ticket" for each lab
  (who asked, the situation, your task, why it matters, done-when, glossary,
  job roles, an interview talking point).
* ``data/career_tracks.json``: how the labs map to an IAM career path
  (Security+ -> SC-300 -> SailPoint-style identity governance).
* ``case_study_markdown(n)`` / ``case_study_html(n)``: a one-page portfolio case
  study built from the lab's briefing and its REAL results, clearly labelled as
  a simulated lab with fictional data.

    python main.py case-study 1          # dist/portfolio/lab01-case-study.md + .html
    python main.py case-study --all
"""

from __future__ import annotations

import html
import json
from collections import Counter
from functools import lru_cache
from pathlib import Path

from utils.loader import ROOT

BRIEFING_DIR = ROOT / "data" / "briefings"
CAREER_FILE = ROOT / "data" / "career_tracks.json"
SIMULATION_NOTE = ("Simulated lab with fictional people, systems and data, built with the open-source "
                   "IdentityOps Lab (practice aligned to the CompTIA Security+ SY0-701 exam objectives). Results come from running the lab's engine on its sample scenario.")


def briefing(n: int) -> dict | None:
    f = BRIEFING_DIR / f"lab{n:02d}.json"
    return json.loads(f.read_text(encoding="utf-8")) if f.exists() else None


@lru_cache(maxsize=1)
def career() -> dict:
    return json.loads(CAREER_FILE.read_text(encoding="utf-8"))


def career_tags(n: int) -> dict[str, list[str]]:
    """Track name -> skill areas this lab practises."""
    out: dict[str, list[str]] = {}
    for t in career()["tracks"]:
        areas = [a["name"] for a in t["areas"] if n in a["labs"]]
        if areas:
            out[t["name"]] = areas
    return out


_ACRONYMS = {"signins": "Sign-ins", "sod": "SoD", "hitl": "HITL", "mfa": "MFA", "ip": "IP", "ips": "IPs", "rto": "RTO", "rpo": "RPO",
             "kev": "KEV", "sla": "SLA", "dlp": "DLP", "iam": "IAM", "ale": "ALE", "pim": "PIM", "ca": "CA", "pct": "%"}


def _label(key) -> str:
    words = str(key).replace("_", " ").split()
    words = [_ACRONYMS.get(w.lower(), w) for w in words]
    if words and words[0] == words[0].lower():
        words[0] = words[0].capitalize()
    return " ".join(words)


def summarize(summary) -> list[tuple[str, str]]:
    """Turn a lab's run_demo summary into readable (label, value) rows."""
    rows: list[tuple[str, str]] = []
    if not isinstance(summary, dict):
        return [("Result", str(summary))]
    values = list(summary.values())
    if values and all(isinstance(v, str) for v in values) and len(values) > 3:
        # {item_id: decision} -> decision counts
        for decision, count in Counter(values).most_common():
            rows.append((_label(decision.lower()), f"{count} of {len(values)}"))
        return rows
    for k, v in summary.items():
        label = _label(k)
        if isinstance(v, (list, tuple)):
            v = ", ".join(map(str, v)) or "none"
        elif isinstance(v, dict) and v and all(isinstance(x, str) for x in v.values()):
            counts = Counter(v.values())
            v = f"{len(v)} total: " + ", ".join(f"{_label(d.lower())} {c}" for d, c in counts.most_common())
        elif isinstance(v, dict) and v and not any(isinstance(x, dict) for x in v.values()):
            v = ", ".join(f"{_label(a).lower() if i else _label(a)}: {', '.join(map(str, b)) if isinstance(b, (list, tuple)) else b}"
                          for i, (a, b) in enumerate(v.items()))
        elif isinstance(v, dict):
            v = f"{len(v)}: " + ", ".join(map(str, v)) if v else "none"
        rows.append((label, str(v)))
    return rows


def _lab(n: int, policies: dict | None):
    import webapi
    from labs import LABS
    from utils.loader import load_policies
    if n not in LABS:
        raise ValueError(f"unknown lab {n}")
    policies = policies or load_policies()
    module = LABS[n][0]
    return module, webapi.run(policies, n)


def case_study(n: int, policies: dict | None = None) -> dict:
    """Everything a case study needs, as plain data (also used by the web app)."""
    module, run = _lab(n, policies)
    b = briefing(n) or {}
    return {
        "lab": n, "title": module.TITLE.split(" — ", 1)[-1], "objectives": module.OBJECTIVES,
        "briefing": b, "results": summarize(run["summary"]), "career": career_tags(n),
        "lessons": list(module.INSIGHT.get("failure_modes", []))[:3],
        "governance": list(module.INSIGHT.get("ai_governance", []))[:2],
        "note": SIMULATION_NOTE,
    }


def case_study_markdown(n: int, policies: dict | None = None) -> str:
    cs = case_study(n, policies)
    b = cs["briefing"]
    lines = [f"# Case study: {b.get('title') or cs['title']}", "",
             f"*{cs['title']}* · {cs['objectives']}", "",
             f"> {cs['note']}", ""]
    if b:
        lines += [f"**Ticket {b['ticket']}** ({b['type']}, {b['priority']}) · requested by {b['requested_by']}", "",
                  "## The situation", b["situation"], "",
                  "## What I did", *[f"1. {s}" for s in b["your_task"]], "",
                  "## Why it mattered", b["why_it_matters"], ""]
    lines += ["## Results", "| Measure | Result |", "|---|---|", *[f"| {k} | {v} |" for k, v in cs["results"]], ""]
    if b.get("done_when"):
        lines += ["## Acceptance criteria", *[f"- {d}" for d in b["done_when"]], ""]
    if cs["lessons"]:
        lines += ["## What usually goes wrong (and what this prevents)", *[f"- {x}" for x in cs["lessons"]], ""]
    if cs["career"]:
        lines += ["## Skills demonstrated"]
        for track, areas in cs["career"].items():
            lines.append(f"- **{track}:** {'; '.join(areas)}")
        lines.append(f"- **Security+:** {cs['objectives'].replace('SY0-701 ', '')}")
        lines.append("")
    if b.get("talking_point"):
        lines += ["## Talking point", b["talking_point"], ""]
    return "\n".join(lines).rstrip() + "\n"


PAGE_CSS = """
:root { --ink:#17202b; --muted:#56606c; --line:#d9dee5; --accent:#1d5c8f; --bg:#ffffff; --chip:#eef3f8; }
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) { --ink:#e3e9f0; --muted:#a3adb8; --line:#2b3542; --accent:#7fb6e6; --bg:#121820; --chip:#1c2632; } }
body { margin:0; background:var(--bg); color:var(--ink); font:16px/1.55 system-ui,-apple-system,'Segoe UI',sans-serif; }
main { max-width: 780px; margin: 0 auto; padding: 32px 16px 48px; }
.kicker { font-size:12px; letter-spacing:.08em; text-transform:uppercase; color:var(--muted); }
h1 { font-size: 1.7rem; margin: 6px 0 4px; } h2 { font-size: 1.05rem; margin: 22px 0 6px; color: var(--accent); }
.note { border-left:3px solid var(--accent); padding:6px 12px; color:var(--muted); font-size:.9rem; }
.ticket { border:1px solid var(--line); border-radius:8px; padding:10px 14px; font-size:.92rem; }
table { border-collapse: collapse; width:100%; } td, th { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); }
.chip { display:inline-block; background:var(--chip); border-radius:999px; padding:2px 10px; margin:2px 4px 2px 0; font-size:.85rem; }
@media print { body { background:#fff; color:#000; } .note { color:#333; } }
"""


def case_study_html(n: int, policies: dict | None = None) -> str:
    cs = case_study(n, policies)
    b, e = cs["briefing"], html.escape
    parts = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
             f"<title>Case study: {e(b.get('title') or cs['title'])}</title><style>{PAGE_CSS}</style></head><body><main>",
             f"<div class='kicker'>Portfolio case study · Lab {n}</div><h1>{e(b.get('title') or cs['title'])}</h1>",
             f"<div class='kicker'>{e(cs['title'])} · {e(cs['objectives'])}</div>",
             f"<p class='note'>{e(cs['note'])}</p>"]
    if b:
        parts += [f"<div class='ticket'><b>{e(b['ticket'])}</b> · {e(b['type'])} · {e(b['priority'])} · requested by {e(b['requested_by'])}</div>",
                  f"<h2>The situation</h2><p>{e(b['situation'])}</p>",
                  "<h2>What I did</h2><ol>" + "".join(f"<li>{e(s)}</li>" for s in b["your_task"]) + "</ol>",
                  f"<h2>Why it mattered</h2><p>{e(b['why_it_matters'])}</p>"]
    parts.append("<h2>Results</h2><table>" + "".join(f"<tr><td>{e(k)}</td><td>{e(v)}</td></tr>" for k, v in cs["results"]) + "</table>")
    if b.get("done_when"):
        parts.append("<h2>Acceptance criteria</h2><ul>" + "".join(f"<li>{e(d)}</li>" for d in b["done_when"]) + "</ul>")
    if cs["career"]:
        parts.append("<h2>Skills demonstrated</h2>" + "".join(
            f"<p><b>{e(t)}</b><br>" + "".join(f"<span class='chip'>{e(a)}</span>" for a in areas) + "</p>"
            for t, areas in cs["career"].items()))
    if b.get("talking_point"):
        parts.append(f"<h2>Talking point</h2><p>{e(b['talking_point'])}</p>")
    parts.append("</main></body></html>")
    return "".join(parts)


def write_case_studies(labs: list[int], out_dir: Path | None = None, policies: dict | None = None) -> list[Path]:
    out_dir = Path(out_dir or ROOT / "dist" / "portfolio")
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for n in labs:
        md = out_dir / f"lab{n:02d}-case-study.md"
        md.write_text(case_study_markdown(n, policies), encoding="utf-8")
        page = out_dir / f"lab{n:02d}-case-study.html"
        page.write_text(case_study_html(n, policies), encoding="utf-8")
        written += [md, page]
    return written
