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

Check a file:  python -m utils.exam_bank data/exam_bank/domain3.json
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from functools import lru_cache
from pathlib import Path

from utils.loader import ROOT

BANK_DIR = ROOT / "data" / "exam_bank"
OBJECTIVES = {"1": 4, "2": 5, "3": 4, "4": 9, "5": 6}          # objectives per domain
VALID_OBJECTIVES = {f"{d}.{n}" for d, k in OBJECTIVES.items() for n in range(1, k + 1)}
# Wording that belongs to the labs, not to the exam: ids like DF-5, IAC-T1, SIEM-004, P-03, rule names in CAPS_WITH_UNDERSCORES.
_REAL_TERMS = r"(?!(?:SHA|AES|RSA|DES|3DES|MD|RC|ECC|ECDSA|ECDHE|DH|CVE|CWE|ISO|IEC|NIST|SP|PCI|TLS|SSL|WPA|IEEE|RFC|EAP|PEAP|SOC|FIPS|OWASP|HMAC|CIS|SMB|SMBV|HTTP|DOCSIS|X)-)"
_JARGON = re.compile(r"\b(?:" + _REAL_TERMS + r"[A-Z]{1,5}-\d{1,3}|[A-Z]{2,}-[A-Z]\d|[A-Z]+_[A-Z_]{3,})\b"
                     r"|(?i:\blab\s?\d+\b|\bgate decide\b)")
_BANNED_CHOICES = {"all of the above", "none of the above", "both a and b"}


def validate(questions: list[dict], domain: str | None = None) -> list[str]:
    """Return a list of problems (empty = valid)."""
    problems, seen_ids, seen_stems = [], set(), set()
    for i, q in enumerate(questions):
        where = q.get("id", f"#{i}")
        for k in ("id", "objective", "stem", "choices", "answer", "explanation"):
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
        ch = q["choices"]
        if len(ch) != 4 or len(set(c.strip().lower() for c in ch)) != 4:
            problems.append(f"{where}: needs exactly 4 distinct choices")
        if q["answer"] not in ch:
            problems.append(f"{where}: answer not among choices")
        if any(c.strip().isdigit() for c in ch):
            problems.append(f"{where}: a choice is a bare number (write e.g. '3 days')")
        if any(c.strip().lower() in _BANNED_CHOICES for c in ch):
            problems.append(f"{where}: 'all/none of the above' style choice")
        if not q["stem"].rstrip().endswith("?"):
            problems.append(f"{where}: stem should end with a question")
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


def answer_position_spread(questions: list[dict]) -> Counter:
    return Counter("ABCD"[q["choices"].index(q["answer"])] for q in questions if q.get("answer") in q.get("choices", []))


@lru_cache(maxsize=1)
def load_bank() -> tuple[dict, ...]:
    """All bank questions (empty if the bank has not been built yet)."""
    out: list[dict] = []
    for d in sorted(OBJECTIVES):
        f = BANK_DIR / f"domain{d}.json"
        if f.exists():
            out += json.loads(f.read_text(encoding="utf-8"))["questions"]
    return tuple(out)


def as_questions(records=None) -> list:
    """Bank records as challenge ``Question`` objects (no lab context)."""
    from utils.challenge import Question
    return [Question(prompt=r["stem"], choices=list(r["choices"]), answer=r["answer"],
                     explanation=r["explanation"], objective=r["objective"], context="")
            for r in (load_bank() if records is None else records)]


def main(argv=None) -> int:
    files = [Path(a) for a in (argv or sys.argv[1:])] or sorted(BANK_DIR.glob("domain*.json"))
    bad = 0
    for f in files:
        data = json.loads(f.read_text(encoding="utf-8"))
        dom = re.search(r"domain(\d)", f.name)
        qs = data["questions"]
        probs = validate(qs, dom.group(1) if dom else None)
        per_obj = Counter(q.get("objective") for q in qs)
        print(f"{f.name}: {len(qs)} questions · per objective {dict(sorted(per_obj.items()))} · "
              f"answer positions {dict(sorted(answer_position_spread(qs).items()))}")
        for p in probs:
            print("  PROBLEM", p)
        bad += len(probs)
    print("OK" if not bad else f"{bad} problem(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
