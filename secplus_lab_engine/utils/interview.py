"""
IAM job-interview prep: original interview questions with what interviewers listen for,
a model answer, follow-ups and red flags, plus role guides (IAM Analyst, Entra admin,
Okta admin, IGA/SailPoint engineer, IAM engineer).

Data lives in ``data/interview/`` (``questions-*.json`` and ``roles.json``) and is shared by
every course. The web app shows it under "Interview prep"; ``python main.py interview``
runs a mock interview in the terminal; the MCP tutor exposes it to Claude.
"""

from __future__ import annotations

import json
import random
import re
from functools import lru_cache

from utils.loader import ROOT

DIR = ROOT / "data" / "interview"

CATEGORIES = {
    "fundamentals": ("IAM fundamentals", "Authentication vs authorization, least privilege, RBAC/ABAC, joiner-mover-leaver, SoD, zero trust."),
    "protocols": ("Protocols & MFA", "SAML, OAuth 2.0, OpenID Connect, JWT, SCIM, Kerberos, LDAP and phishing-resistant MFA."),
    "pam": ("Privileged & non-human access", "PAM, vaulting, just-in-time access, break-glass, service accounts and workload identities."),
    "entra": ("Microsoft Entra ID", "Conditional Access, PIM, hybrid sync, guests, app registrations, access reviews."),
    "okta": ("Okta", "Policies, authenticators, group rules, app integrations, provisioning, admin roles, System Log."),
    "iga": ("Identity governance & SailPoint", "Sources, identity profiles, transforms, roles, certifications, SoD, workflows."),
    "troubleshooting": ("Troubleshooting walk-throughs", "Live 'how would you fix it' scenarios: sign-in, SSO, MFA, provisioning, offboarding."),
    "behavioral": ("Behavioral (STAR)", "Tell me about a time... answers in Situation, Task, Action, Result form."),
    "projects": ("Your projects & first 90 days", "Talk about your hands-on work (this academy's labs), metrics and how you would start."),
}
LEVELS = ("entry", "mid", "senior")
KINDS = ("technical", "scenario", "behavioral")
ID_RE = re.compile(r"^IV-[A-Z]{3}-\d{3}$")


@lru_cache(maxsize=1)
def questions() -> tuple[dict, ...]:
    out = []
    for f in sorted(DIR.glob("questions-*.json")):
        out.extend(json.loads(f.read_text(encoding="utf-8"))["questions"])
    return tuple(out)


@lru_cache(maxsize=1)
def roles() -> tuple[dict, ...]:
    f = DIR / "roles.json"
    return tuple(json.loads(f.read_text(encoding="utf-8"))["roles"]) if f.exists() else ()


def by_id() -> dict[str, dict]:
    return {q["id"]: q for q in questions()}


def validate(qs=None, lab_numbers=None) -> list[str]:
    """Problems with the interview data (empty list = OK)."""
    qs = questions() if qs is None else qs
    errs, seen, stems = [], set(), set()
    for q in qs:
        qid = q.get("id", "?")
        if not ID_RE.match(qid):
            errs.append(f"{qid}: bad id")
        if qid in seen:
            errs.append(f"{qid}: duplicate id")
        seen.add(qid)
        if q.get("category") not in CATEGORIES:
            errs.append(f"{qid}: unknown category {q.get('category')!r}")
        if q.get("level") not in LEVELS:
            errs.append(f"{qid}: bad level")
        if q.get("kind") not in KINDS:
            errs.append(f"{qid}: bad kind")
        text = (q.get("question") or "").strip()
        if not text.endswith("?"):
            errs.append(f"{qid}: question must end with ?")
        if text.lower() in stems:
            errs.append(f"{qid}: duplicate question")
        stems.add(text.lower())
        if not 3 <= len(q.get("listen_for") or []) <= 6:
            errs.append(f"{qid}: listen_for needs 3-6 points")
        words = len((q.get("model_answer") or "").split())
        if not 40 <= words <= 200:
            errs.append(f"{qid}: model_answer has {words} words")
        for k in ("follow_ups", "red_flags"):
            if not 1 <= len(q.get(k) or []) <= 4:
                errs.append(f"{qid}: {k} needs 1-4 items")
        if lab_numbers is not None:
            for n in q.get("labs") or []:
                if n not in lab_numbers:
                    errs.append(f"{qid}: unknown lab {n}")
    return errs


def pick(n: int = 8, category: str | None = None, level: str | None = None, role: str | None = None,
         seed: int | None = None) -> list[dict]:
    """A mock interview: n questions, spread across categories (round-robin), filtered by
    category, level or role focus. Deterministic for a given seed."""
    qs = list(questions())
    if role:
        r = next((x for x in roles() if x["id"] == role), None)
        if r is None:
            raise ValueError(f"unknown role {role!r}")
        qs = [q for q in qs if q["category"] in r["focus"]]
    if category:
        if category not in CATEGORIES:
            raise ValueError(f"unknown category {category!r}")
        qs = [q for q in qs if q["category"] == category]
    if level:
        if level not in LEVELS:
            raise ValueError(f"unknown level {level!r}")
        qs = [q for q in qs if q["level"] == level]
    rng = random.Random(seed)
    groups: dict[str, list] = {}
    for q in qs:
        groups.setdefault(q["category"], []).append(q)
    for g in groups.values():
        rng.shuffle(g)
    order = list(groups)
    rng.shuffle(order)
    out = []
    while len(out) < n and any(groups.values()):
        for c in order:
            if groups[c] and len(out) < n:
                out.append(groups[c].pop())
    return out


def public(q: dict) -> dict:
    """A question without its answer key (for the AI tutor to ask first)."""
    return {k: q[k] for k in ("id", "category", "level", "kind", "question")}


def catalog() -> dict:
    """Everything the web app needs (questions are shown answer-last by the UI)."""
    counts: dict[str, int] = {}
    for q in questions():
        counts[q["category"]] = counts.get(q["category"], 0) + 1
    return {"categories": [{"id": c, "name": n, "about": a, "count": counts.get(c, 0)} for c, (n, a) in CATEGORIES.items()],
            "roles": list(roles()), "questions": list(questions())}


def claude_prompt(q: dict, answer: str = "") -> str:
    """A ready-to-paste prompt that asks Claude to grade a practice answer (free: uses the
    learner's own Claude plan; nothing is sent anywhere by this app)."""
    lines = [
        "You are a senior IAM hiring manager running a mock interview. Grade my answer honestly.",
        f"Question ({CATEGORIES[q['category']][0]}, {q['level']} level): {q['question']}",
        "A strong answer covers: " + "; ".join(q["listen_for"]) + ".",
        "Red flags: " + "; ".join(q["red_flags"]) + ".",
    ]
    lines.append(f"My answer: {answer.strip()}" if answer.strip() else
                 "Ask me the question, wait for my answer, then grade it.")
    lines.append("Give: a score out of 5, what I covered, what I missed, one sentence I could add, "
                 "then ask me one of these follow-ups: " + " | ".join(q["follow_ups"]))
    return "\n".join(lines)
