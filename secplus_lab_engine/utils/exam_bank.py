"""
Exam-style question bank (data/exam_bank/domain1.json ... domain5.json).

The lab questions test the engines ("what does the DLP gate decide for DF-5?").
The real SY0-701 asks short workplace scenarios in plain language with four
options and a qualifier (BEST / MOST likely / FIRST). This bank holds original
questions written in that style, one file per domain, and is what the practice
exam and the domain tests draw from.

Every question is original (no exam dumps or copied commercial questions).

Record format::

    {"id": "D3-031", "objective": "3.3",
     "stem": "A hospital wants analysts to work with patient records without seeing real names...",
     "choices": ["Tokenization", "Hashing", "Encryption", "Masking"],
     "answer": "Tokenization",
     "explanation": "Why the answer is right, and why the most tempting wrong option is wrong."}

Question types (``type``, default "single"). data/exam_bank/pbq.json holds the
other kinds the real exam uses, across all five domains:

* ``multi`` (select TWO): ``choices`` (5-6), ``answers`` (exactly ``select`` of them), ``select`` (2).
* ``order`` (performance-based): ``items``, 4-6 steps in the CORRECT order (shown shuffled).
* ``match`` (performance-based): ``pairs`` [{"item", "match"}] (4-6), optional ``targets_extra``
  (distractor targets that match nothing).

Their stems may be an instruction ending with "." ("Put the steps in order.").

Extra questions per domain may sit beside the main file (``domain3-extra.json``), and
``data/exam_bank/topics/*.json`` tags every question with a concept topic of its
objective (used by the objective quizzes, utils/quizzes.py).

Check a file:  python -m utils.exam_bank data/exam_bank/domain3.json
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from functools import lru_cache
from pathlib import Path

from utils import course
from utils.loader import ROOT

BANK_DIR = course.data_dir("exam_bank")                          # the active course's bank (Security+: data/exam_bank)
PBQ_FILE = BANK_DIR / "pbq.json"                                 # multi / order / match questions
TYPES = ("single", "multi", "order", "match")
OBJECTIVES = course.objectives_per_domain()                      # objectives per domain, e.g. {"1": 4, "2": 5, ...}
VALID_OBJECTIVES = {f"{d}.{n}" for d, k in OBJECTIVES.items() for n in range(1, k + 1)}
# Wording that belongs to the labs, not to the exam: ids like DF-5, IAC-T1, SIEM-004, P-03, rule names in CAPS_WITH_UNDERSCORES.
_REAL_TERMS = r"(?!(?:SHA|AES|RSA|DES|3DES|MD|RC|ECC|ECDSA|ECDHE|DH|CVE|CWE|ISO|IEC|NIST|SP|PCI|TLS|SSL|WPA|IEEE|RFC|EAP|PEAP|SOC|FIPS|OWASP|HMAC|CIS|SMB|SMBV|HTTP|DOCSIS|X)-)"
_JARGON = re.compile(r"\b(?:" + _REAL_TERMS + r"[A-Z]{1,5}-\d{1,3}|[A-Z]{2,}-[A-Z]\d|[A-Z]+_[A-Z_]{3,})\b"
                     r"|(?i:\blab\s?\d+\b|\bgate decide\b)")
_BANNED_CHOICES = {"all of the above", "none of the above", "both a and b"}


def validate(questions: list[dict], domain: str | None = None) -> list[str]:
    """Return a list of problems (empty = valid). Each record is checked by its ``type``."""
    problems, seen_ids, seen_stems = [], set(), set()
    for i, q in enumerate(questions):
        where = q.get("id", f"#{i}")
        kind = q.get("type", "single")
        if kind not in TYPES:
            problems.append(f"{where}: unknown type '{kind}'")
            continue
        for k in ("id", "objective", "stem", *_REQUIRED[kind], "explanation"):
            if not q.get(k):
                problems.append(f"{where}: missing '{k}'")
        if problems and problems[-1].startswith(f"{where}: missing"):
            continue
        if q["id"] in seen_ids:
            problems.append(f"{where}: duplicate id")
        seen_ids.add(q["id"])
        norm = re.sub(r"\W+", " ", q["stem"].lower()).strip()
        if norm in seen_stems:
            problems.append(f"{where}: duplicate stem")
        seen_stems.add(norm)
        if q["objective"] not in VALID_OBJECTIVES:
            problems.append(f"{where}: unknown objective {q['objective']}")
        if domain and not q["objective"].startswith(f"{domain}."):
            problems.append(f"{where}: objective {q['objective']} is not in domain {domain}")
        ch = _options(q)
        problems += [f"{where}: {p}" for p in _KIND_CHECKS[kind](q)]
        if any(c.strip().isdigit() for c in ch):
            problems.append(f"{where}: a choice is a bare number (write e.g. '3 days')")
        if any(c.strip().lower() in _BANNED_CHOICES for c in ch):
            problems.append(f"{where}: 'all/none of the above' style choice")
        stem = q["stem"].rstrip()
        if not (stem.endswith("?") or (kind in ("order", "match") and stem.endswith("."))):
            problems.append(f"{where}: stem should end with a question"
                            + (" or an instruction ending with '.'" if kind in ("order", "match") else ""))
        if len(q["stem"]) < 40 or len(q["stem"]) > 600:
            problems.append(f"{where}: stem length {len(q['stem'])} outside 40-600 characters")
        if len(q["explanation"]) < 40:
            problems.append(f"{where}: explanation too short")
        for field in ("stem", *ch):
            text = q["stem"] if field == "stem" else field
            m = _JARGON.search(text)
            if m:
                problems.append(f"{where}: lab-style jargon '{m.group(0)}' in {'stem' if field == 'stem' else 'a choice'}")
                break
    return problems


_REQUIRED = {"single": ("choices", "answer"), "multi": ("choices", "answers", "select"),
             "order": ("items",), "match": ("pairs",)}


def _options(q: dict) -> list[str]:
    """Every option text a learner sees (for the shared bare-number / jargon / banned-choice checks)."""
    kind = q.get("type", "single")
    if kind == "order":
        return list(q.get("items", []))
    if kind == "match":
        return [s for p in q.get("pairs", []) for s in (p.get("item", ""), p.get("match", ""))] + list(q.get("targets_extra", []))
    return list(q.get("choices", []))


def _distinct(xs) -> bool:
    return len(set(x.strip().lower() for x in xs)) == len(xs)


def _check_single(q: dict) -> list[str]:
    out, ch = [], q["choices"]
    if len(ch) != 4 or not _distinct(ch):
        out.append("needs exactly 4 distinct choices")
    if q["answer"] not in ch:
        out.append("answer not among choices")
    return out


def _check_multi(q: dict) -> list[str]:
    out, ch, ans, sel = [], q["choices"], q["answers"], q["select"]
    if not 5 <= len(ch) <= 6 or not _distinct(ch):
        out.append("multi needs 5-6 distinct choices")
    if sel != 2:
        out.append("multi 'select' must be 2 (select TWO)")
    if not isinstance(ans, list) or len(ans) != sel or len(set(ans)) != len(ans):
        out.append(f"multi needs exactly {sel} distinct answers")
    elif not set(ans) <= set(ch):
        out.append("an answer is not among the choices")
    if "TWO" not in q["stem"]:
        out.append("multi stem should say 'TWO'")
    return out


def _check_order(q: dict) -> list[str]:
    items = q["items"]
    return [] if 4 <= len(items) <= 6 and _distinct(items) else ["order needs 4-6 distinct items"]


def _check_match(q: dict) -> list[str]:
    out, pairs, extra = [], q["pairs"], q.get("targets_extra", [])
    if not 4 <= len(pairs) <= 6 or not all(isinstance(p, dict) and p.get("item") and p.get("match") for p in pairs):
        return ["match needs 4-6 pairs of {item, match}"]
    if not _distinct([p["item"] for p in pairs]):
        out.append("match items must be distinct")
    targets = {p["match"].strip().lower() for p in pairs}
    if not isinstance(extra, list) or not _distinct(extra) or targets & {e.strip().lower() for e in extra}:
        out.append("targets_extra must be distinct and match no item")
    return out


_KIND_CHECKS = {"single": _check_single, "multi": _check_multi, "order": _check_order, "match": _check_match}


def answer_position_spread(questions: list[dict]) -> Counter:
    """Where the answer sits (A-D) in single-answer questions; other kinds are shuffled per exam."""
    return Counter("ABCD"[q["choices"].index(q["answer"])] for q in questions
                   if q.get("type", "single") == "single" and q.get("answer") in q.get("choices", []))


def bank_files() -> list[Path]:
    """domain1.json, domain1-extra.json, ... domain5*.json, pbq.json, then pbq-*.json (e.g. the lab-built PBQs)."""
    files: list[Path] = []
    for d in sorted(OBJECTIVES):
        main = BANK_DIR / f"domain{d}.json"
        files += ([main] if main.exists() else []) + sorted(BANK_DIR.glob(f"domain{d}-*.json"))
    return files + ([PBQ_FILE] if PBQ_FILE.exists() else []) + sorted(BANK_DIR.glob("pbq-*.json"))


@lru_cache(maxsize=1)
def load_topics() -> tuple[dict, dict]:
    """
    Concept topics per objective, from data/exam_bank/topics/*.json:
    ``({"2.4": ["Malware", ...]}, {"D2-001": "Malware", ...})``. Each topic file holds
    ``{"topics": {objective: [names]}, "tags": {question id: topic}}``; new questions may
    instead carry their own ``topic`` field.
    """
    topics: dict[str, list[str]] = {}
    tags: dict[str, str] = {}
    folder = BANK_DIR / "topics"
    for f in sorted(folder.glob("*.json")) if folder.exists() else []:
        data = json.loads(f.read_text(encoding="utf-8"))
        for obj, names in data.get("topics", {}).items():
            topics.setdefault(obj, [])
            topics[obj] += [n for n in names if n not in topics[obj]]
        tags.update(data.get("tags", {}))
    return topics, tags


@lru_cache(maxsize=1)
def load_bank() -> tuple[dict, ...]:
    """All bank questions (empty if the bank has not been built yet), each with its ``topic`` when known."""
    out: list[dict] = []
    _, tags = load_topics()
    for f in bank_files():
        for q in json.loads(f.read_text(encoding="utf-8"))["questions"]:
            if not q.get("topic") and q.get("id") in tags:
                q = {**q, "topic": tags[q["id"]]}
            out.append(q)
    return tuple(out)


def as_question(r: dict):
    """One bank record as a challenge ``Question`` (any type)."""
    from utils.challenge import Question, answer_text
    kind = r.get("type", "single")
    common = dict(prompt=r["stem"], explanation=r["explanation"], objective=r["objective"], context="", qid=r["id"], kind=kind)
    if kind == "multi":
        return Question(choices=list(r["choices"]), answer=answer_text(kind, answers=r["answers"]),
                        answers=tuple(r["answers"]), **common)
    if kind == "order":
        return Question(choices=list(r["items"]), answer=answer_text(kind, items=r["items"]), items=tuple(r["items"]), **common)
    if kind == "match":
        pairs = tuple((p["item"], p["match"]) for p in r["pairs"])
        targets = list(dict.fromkeys([m for _, m in pairs] + list(r.get("targets_extra", []))))
        return Question(choices=sorted(targets), answer=answer_text(kind, pairs=pairs), pairs=pairs, **common)
    return Question(choices=list(r["choices"]), answer=r["answer"], **common)


def as_questions(records=None) -> list:
    """Bank records as challenge ``Question`` objects (no lab context)."""
    return [as_question(r) for r in (load_bank() if records is None else records)]


def main(argv=None) -> int:
    files = [Path(a) for a in (argv or sys.argv[1:])] or bank_files()
    bad = 0
    for f in files:
        data = json.loads(f.read_text(encoding="utf-8"))
        dom = re.search(r"domain(\d)", f.name)
        qs = data["questions"]
        probs = validate(qs, dom.group(1) if dom else None)
        per_obj = Counter(q.get("objective") for q in qs)
        kinds = dict(sorted(Counter(q.get("type", "single") for q in qs).items()))
        print(f"{f.name}: {len(qs)} questions {kinds} · per objective {dict(sorted(per_obj.items()))} · "
              f"answer positions {dict(sorted(answer_position_spread(qs).items()))}")
        for p in probs:
            print("  PROBLEM", p)
        bad += len(probs)
    print("OK" if not bad else f"{bad} problem(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
