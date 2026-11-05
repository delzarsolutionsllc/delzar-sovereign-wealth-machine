"""
Glossary: the SY0-701 acronyms and key vocabulary, with plain-English definitions,
grouped by exam domain, plus acronym / vocabulary / definition quizzes per domain.

Data (original definitions, written for this course):

* ``data/glossary/acronyms_*.json`` and ``data/glossary/vocabulary.json``:
  ``{"entries": [{"term", "kind": "acronym"|"term", "expansion", "definition", "domain", "objectives"}]}``
* ``data/glossary/videos.json``: an index (titles, IDs, lengths only) of Geekus Maximus's free
  "CompTIA Security+ Exam 601 & 701 Acronyms & Definitions" YouTube playlist, so each acronym
  can link to its short video. Videos play on YouTube; nothing is copied.

Quizzes per domain (ids like ``g3-acr-1``):

* **Acronyms** ("What does CASB stand for?"): pick the expansion.
* **Vocabulary** ("Which term matches this description?"): read a definition, pick the term.
* **Definitions** ("Which BEST describes tokenization?"): pick the definition of a term or acronym.

Wrong options come from the same domain (same objective first), so they are plausible.
Quizzes are dealt into sets of about ``SET_SIZE`` questions. Answers do not count toward
objective scores (they test vocabulary, not judgement); each quiz keeps its best and last score.

    python main.py glossary CASB          # look a term up
    python main.py glossary --domain 3    # every entry in a domain
    python main.py glossary --quiz g3-acr-1
"""

from __future__ import annotations

import hashlib
import json
import re
from functools import lru_cache

from utils.loader import ROOT

GLOSSARY_DIR = ROOT / "data" / "glossary"
VIDEOS_FILE = GLOSSARY_DIR / "videos.json"
SET_SIZE = 15
MODES = {"acr": "Acronyms", "voc": "Vocabulary", "def": "Definitions"}
QUIZ_ID = re.compile(r"^g([1-5])-(acr|voc|def)-(\d{1,2})$")
DOMAIN_NAMES = {"1": "General Security Concepts", "2": "Threats, Vulnerabilities & Mitigations",
                "3": "Security Architecture", "4": "Security Operations", "5": "Security Program Management"}


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def _norm(s: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", (s or "").upper())


def _words(s: str) -> set:
    return {w for w in re.findall(r"[a-z0-9]+", (s or "").lower()) if w not in {"and", "of", "the", "for", "to", "a", "or", "in", "on"}}


@lru_cache(maxsize=1)
def videos() -> dict:
    return json.loads(VIDEOS_FILE.read_text(encoding="utf-8")) if VIDEOS_FILE.exists() else {"source": None, "videos": []}


def _match_video(term: str, expansion: str | None, vids: list[dict]):
    """The playlist video for an acronym: same letters, and (when the acronym has several meanings) the closest expansion."""
    cands = [v for v in vids if v.get("acronym") and _norm(term) in {_norm(a) for a in re.split(r"\s+or\s+|/", v["acronym"])}]
    if not cands:
        return None
    if expansion:
        best = max(cands, key=lambda v: len(_words(expansion) & _words(v.get("expansion"))))
        if len(cands) > 1 and not _words(expansion) & _words(best.get("expansion")):
            return None
        return best
    return cands[0]


@lru_cache(maxsize=1)
def entries() -> tuple[dict, ...]:
    """Every glossary entry with a stable ``id`` and, for acronyms, its playlist video (if any)."""
    raw = []
    for f in sorted(GLOSSARY_DIR.glob("*.json")):
        if f.name == VIDEOS_FILE.name:
            continue
        raw += json.loads(f.read_text(encoding="utf-8")).get("entries", [])
    counts: dict[str, int] = {}
    for e in raw:
        counts[_slug(e["term"])] = counts.get(_slug(e["term"]), 0) + 1
    vids = videos()["videos"]
    out = []
    for e in raw:
        s = _slug(e["term"])
        eid = "G-" + s + ("--" + _slug(e.get("expansion") or e["definition"][:20]) if counts[s] > 1 else "")
        v = _match_video(e["term"], e.get("expansion"), vids) if e.get("kind") == "acronym" else None
        out.append({**e, "id": eid, "expansion": e.get("expansion") or None,
                    "video": {"id": v["id"], "n": v["n"], "seconds": v.get("seconds"), "title": v["title"]} if v else None})
    out.sort(key=lambda e: (e["term"].lower(), e.get("expansion") or ""))
    return tuple(out)


def lookup(text: str) -> list[dict]:
    """Entries whose term or expansion matches ``text`` (exact first, then contains)."""
    t = (text or "").strip().lower()
    if not t:
        return []
    exact = [e for e in entries() if e["term"].lower() == t or (e.get("expansion") or "").lower() == t]
    rest = [e for e in entries() if e not in exact and (t in e["term"].lower() or t in (e.get("expansion") or "").lower())]
    return exact + rest


# --------------------------------------------------------------------------- quizzes
def _rank(seed: str, items: list) -> list:
    return sorted(items, key=lambda x: hashlib.sha256((seed + "|" + x).encode()).hexdigest())


def _question(e: dict, mode: str, pool: list[dict]) -> dict | None:
    """One four-option question about ``e``; distractors from ``pool`` (same domain), same objective first."""
    if mode == "acr":
        if e["kind"] != "acronym" or not e.get("expansion"):
            return None
        stem, answer = f"What does {e['term']} stand for?", e["expansion"]
        others = [p for p in pool if p["kind"] == "acronym" and p.get("expansion") and p["id"] != e["id"]]
        text = lambda p: p["expansion"]
    elif mode == "voc":
        if e["kind"] != "term":
            return None
        stem, answer = f"Which term matches this description? {e['definition']}", e["term"]
        others = [p for p in pool if p["kind"] == "term" and p["id"] != e["id"]]
        text = lambda p: p["term"]
    else:
        label = f"{e['term']} ({e['expansion']})" if e.get("expansion") else e["term"]
        stem, answer = f"Which of the following BEST describes {label}?", e["definition"]
        others = [p for p in pool if p["id"] != e["id"]]
        text = lambda p: p["definition"]
    near = [p for p in others if set(p.get("objectives", [])) & set(e.get("objectives", []))]
    far = [p for p in others if p not in near]
    seen, picks = {answer.lower()}, []
    for group in (near, far):
        for t in _rank(e["id"] + mode, [text(p) for p in group]):
            if t.lower() not in seen and t.lower() != e["term"].lower():
                seen.add(t.lower())
                picks.append(t)
            if len(picks) == 3:
                break
        if len(picks) == 3:
            break
    if len(picks) < 3:
        return None
    choices = _rank(e["id"] + mode + "order", [answer, *picks])
    expl = (f"{e['term']} stands for {e['expansion']}. " if e.get("expansion") else f"{e['term']}: ") + e["definition"]
    return {"id": f"{e['id']}:{mode}", "objective": (e.get("objectives") or [e["domain"] + ".1"])[0], "topic": MODES[mode],
            "stem": stem, "choices": choices, "answer": answer, "explanation": expl, "glossary": e["id"]}


@lru_cache(maxsize=1)
def questions() -> dict[str, dict]:
    """Every generated glossary question by id."""
    out = {}
    for d in DOMAIN_NAMES:
        pool = [e for e in entries() if e["domain"] == d]
        for mode in MODES:
            for e in pool:
                q = _question(e, mode, pool)
                if q:
                    out[q["id"]] = q
    return out


@lru_cache(maxsize=1)
def catalog() -> dict:
    """``{"domains": {d: {"name", "entries", "acronyms", "terms", "quizzes": [{id, mode, title, qids}]}}, "videos": source}``."""
    qs = questions()
    doms = {}
    for d, name in DOMAIN_NAMES.items():
        mine = [e for e in entries() if e["domain"] == d]
        quizzes = []
        for mode, label in MODES.items():
            ids = [f"{e['id']}:{mode}" for e in mine if f"{e['id']}:{mode}" in qs]
            if not ids:
                continue
            n = max(1, round(len(ids) / SET_SIZE))
            for k in range(n):
                quizzes.append({"id": f"g{d}-{mode}-{k + 1}", "mode": mode, "title": f"{label} · Set {k + 1}",
                                "qids": ids[k::n]})
        doms[d] = {"name": name, "entries": len(mine), "acronyms": sum(e["kind"] == "acronym" for e in mine),
                   "terms": sum(e["kind"] == "term" for e in mine), "quizzes": quizzes}
    return {"domains": doms, "videos": videos()["source"], "set_size": SET_SIZE}


def find(quiz_id: str) -> dict:
    m = QUIZ_ID.match(str(quiz_id or ""))
    quiz = next((q for q in catalog()["domains"][m.group(1)]["quizzes"] if q["id"] == quiz_id), None) if m else None
    if not quiz:
        raise ValueError(f"unknown glossary quiz '{quiz_id}'")
    return quiz


def as_records(quiz_id: str) -> list[dict]:
    qs = questions()
    return [qs[i] for i in find(quiz_id)["qids"]]
