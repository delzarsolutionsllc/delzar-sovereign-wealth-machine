"""
Lab 16 — Security Control Classifier
====================================

Security+ SY0-701 objectives
----------------------------
* 1.1  Compare and contrast various types of security controls:
       categories (technical, managerial, operational, physical) and
       control types (preventive, deterrent, detective, corrective,
       compensating, directive).

How it classifies
-----------------
Each description is scored against keyword/phrase weights in
``config/default_policies.json → control_classification`` (whole-word, case
insensitive). Category and type are scored independently. The highest score
wins only if it is UNIQUE; a tie or zero evidence returns ``Unclassified``
(deny by default: no guessing). Every result lists the phrases that drove it,
so you can argue with the classifier, and improve the weights when it is wrong.

Run it
------
    python main.py lab 16
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

TITLE = "Lab 16 — Security Control Classifier (category × type)"
OBJECTIVES = "SY0-701 1.1 Security control categories and types"
UNCLASSIFIED = "Unclassified"


@dataclass
class ControlResult:
    id: str
    description: str
    category: str
    type: str
    category_evidence: list[str] = field(default_factory=list)
    type_evidence: list[str] = field(default_factory=list)
    category_scores: dict = field(default_factory=dict)
    type_scores: dict = field(default_factory=dict)


def _hits(text: str, phrases: dict) -> tuple[int, list[str]]:
    found = [p for p in phrases if re.search(r"\b" + re.escape(p.lower()) + r"\b", text)]
    return sum(phrases[p] for p in found), found


def pick(text: str, table: dict) -> tuple[str, list[str], dict]:
    """Best label by score; unique winner required, otherwise Unclassified."""
    scored = {label: _hits(text, phrases) for label, phrases in table.items()}
    scores = {k: v[0] for k, v in scored.items()}
    best = max(scores.values())
    winners = [k for k, s in scores.items() if s == best]
    if best == 0 or len(winners) > 1:
        return UNCLASSIFIED, [], scores
    return winners[0], scored[winners[0]][1], scores


def classify(control: dict, cfg: dict) -> ControlResult:
    text = control["description"].lower()
    cat, cev, cscores = pick(text, cfg["categories"])
    typ, tev, tscores = pick(text, cfg["types"])
    return ControlResult(control["id"], control["description"], cat, typ, cev, tev, cscores, tscores)


def classify_all(data: dict, policies: dict) -> list[ControlResult]:
    return [classify(c, policies["control_classification"]) for c in data["controls"]]


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SY0-701 1.1 Control categories (technical, managerial, operational, physical) and types.",
    "concepts": [
        "CATEGORY = who/what implements it: technology (technical), people management and policy (managerial), people doing it (operational), the physical world (physical).",
        "TYPE = what it does: prevent, deter, detect, correct, compensate for another control, or direct behaviour.",
        "Every control has BOTH: a door lock is physical + preventive; a log review by managers is managerial + detective.",
        "Compensating controls stand in when the primary control cannot be used (unpatchable server → isolate it).",
    ],
    "failure_modes": [
        "Only buying preventive controls; nothing detects or corrects when prevention fails.",
        "Writing policies (directive) with no technical enforcement or monitoring behind them.",
        "Calling a compensating control 'temporary' and never removing the underlying gap.",
        "Mapping controls inconsistently, so audits find gaps that were only labelling errors.",
    ],
    "ai_governance": [
        "An AI GRC assistant can draft control mappings, but must show the evidence (phrases) behind each label.",
        "Ambiguous controls should come back 'Unclassified' for a human, not be forced into a category.",
        "AI agents themselves need controls of every type: preventive (allow-lists), detective (ledger), corrective (kill switch).",
        "Policy statements for agents are directive; enforce them technically (Lab 5) or they are only wishes.",
    ],
    "exam_tips": [
        "Signs: 'Authorized personnel only' = directive; 'trespassers will be prosecuted' = deterrent.",
        "Backups/restore = corrective; logs/alarms/motion detectors = detective; firewall/locks = preventive.",
        "Guards on patrol = operational (people performing the control).",
        "Separation of duties is managerial; used in place of a missing control it becomes compensating.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    res = classify_all(data, policies)
    ui.section("Classification (category × type)")
    rows, agree, judged = [], 0, 0
    for c, r in zip(data["controls"], res):
        exp = (c.get("expected_category"), c.get("expected_type"))
        ok = None
        if exp[0]:
            judged += 1
            ok = (r.category, r.type) == exp
            agree += ok
        rows.append([r.id, r.description, r.category, r.type,
                     "PASS" if ok else ("FAIL" if ok is False else "-")])
    ui.table("Controls", ["ID", "Description", "Category", "Type", "vs key"], rows)
    ui.section("Evidence")
    for r in res:
        ev = ", ".join(r.category_evidence + r.type_evidence) or "no matching phrases → left for a human"
        ui.bullet(f"{r.id}: {ev}")
    if judged:
        ui.status("Classifier agreement with answer key", "PASS" if agree == judged else "WARN", f"{agree}/{judged}")
    ui.insight(INSIGHT)
    return {"classified": sum(r.category != UNCLASSIFIED for r in res), "agreement": f"{agree}/{judged}"}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question

    cfg = policies["control_classification"]
    cats, types = sorted(cfg["categories"]), sorted(cfg["types"])
    qs: list = []
    for r in classify_all(data, policies):
        if r.category != UNCLASSIFIED:
            qs.append(Question(prompt="What CATEGORY of control is this?", context=r.description, choices=cats,
                               answer=r.category, explanation=f"evidence: {', '.join(r.category_evidence)}",
                               objective="1.1"))
        if r.type != UNCLASSIFIED:
            qs.append(Question(prompt="What TYPE of control is this?", context=r.description, choices=types,
                               answer=r.type, explanation=f"evidence: {', '.join(r.type_evidence)}", objective="1.1"))
    return qs
