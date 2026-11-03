"""
Lab 15 — Third-Party / Vendor Risk Assessor
===========================================

Security+ SY0-701 objectives
----------------------------
* 5.3  Third-party risk assessment and management: vendor assessment
       (penetration testing, right-to-audit clause, evidence of internal
       audits, independent assessments, supply chain analysis), vendor
       selection (due diligence, conflict of interest), agreement types
       (SLA, MOA, MOU, MSA, WO/SOW, NDA, BPA), vendor monitoring,
       questionnaires, rules of engagement.

Model
-----
    inherent  = data sensitivity (1–4) × access level (1–4) × business criticality (1–3)
    controls  = questionnaire score 0–100 % (yes = full weight, partial = half, unanswered = no)
    residual  = inherent × (1 − 0.7 × controls)   (controls never remove ALL third-party risk)

Required contract clauses depend on what the vendor touches (data class,
network/privileged access, partnership). Hard rules REJECT when:
* the vendor handles confidential/regulated data and we can neither audit it
  (no right-to-audit clause) nor rely on an independent assessment;
* a conflict of interest was not disclosed;
* residual risk is HIGH.

Otherwise missing clauses or SLA shortfalls mean APPROVE_WITH_CONDITIONS,
and a clean result means APPROVE. Each vendor also gets a monitoring cadence.

Run it
------
    python main.py lab 15
"""

from __future__ import annotations

from dataclasses import dataclass, field

TITLE = "Lab 15 — Third-Party / Vendor Risk Assessor"
OBJECTIVES = "SY0-701 5.3 Third-party risk: assessment, selection, agreements, monitoring"
DECISIONS = ["APPROVE", "APPROVE_WITH_CONDITIONS", "REJECT"]
ANSWER_CREDIT = {"yes": 1.0, "partial": 0.5, "no": 0.0}


@dataclass
class VendorAssessment:
    id: str
    name: str
    inherent: int
    inherent_band: str
    control_score: float
    residual: float
    residual_band: str
    decision: str
    missing_clauses: list[str] = field(default_factory=list)
    reject_reasons: list[str] = field(default_factory=list)
    conditions: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)          # questionnaire items not fully met
    monitoring: str = ""


def band(value: float, bands: dict, top: str = "high") -> str:
    """bands = {'low': x, 'medium': y} or {'high': x, 'medium': y} (thresholds)."""
    if "low" in bands:
        return "low" if value <= bands["low"] else "medium" if value <= bands["medium"] else top
    return "high" if value >= bands["high"] else "medium" if value >= bands["medium"] else "low"


def questionnaire_score(answers: dict, questionnaire: dict) -> tuple[float, list[str]]:
    total = sum(q["weight"] for q in questionnaire.values())
    earned, gaps = 0.0, []
    for qid, q in questionnaire.items():
        a = answers.get(qid, "no")                          # unanswered = no (deny by default)
        credit = ANSWER_CREDIT.get(a, 0.0)
        earned += q["weight"] * credit
        if credit < 1:
            gaps.append(f"{qid} {q['text']}: {'unanswered' if qid not in answers else a}")
    return round(100 * earned / total, 1), gaps


def required_clauses(vendor: dict, rules: dict) -> list[str]:
    req = list(rules["all"])
    for key in (vendor["data"], vendor["access"], vendor.get("relationship")):
        req += rules.get(key, [])
    return list(dict.fromkeys(req))


def assess(vendor: dict, cfg: dict) -> VendorAssessment:
    inherent = (cfg["data_sensitivity"][vendor["data"]] * cfg["access_level"][vendor["access"]]
                * cfg["criticality"][vendor["criticality"]])
    score, gaps = questionnaire_score(vendor.get("answers", {}), cfg["questionnaire"])
    residual = round(inherent * (1 - cfg["max_control_reduction"] * score / 100), 2)
    rband = band(residual, cfg["residual_bands"])
    ibband = band(inherent, cfg["inherent_bands"])

    contract = vendor.get("contract", {})
    clauses = set(contract.get("clauses", []))
    missing = [c for c in required_clauses(vendor, cfg["required_clauses"]) if c not in clauses]
    rejects, conditions = [], []

    answers = vendor.get("answers", {})
    sensitive = vendor["data"] in ("confidential", "regulated")
    if sensitive and "right_to_audit" not in clauses and answers.get(cfg["independent_assessment_question"]) != "yes":
        rejects.append("handles sensitive data but we can neither audit it (no right-to-audit) "
                       "nor rely on an independent assessment (no SOC 2 / ISO 27001)")
    if answers.get(cfg["conflict_of_interest_question"]) != "yes":
        rejects.append("conflict of interest not disclosed/cleared: due diligence failed")
    if rband == "high":
        rejects.append(f"residual risk {residual} is HIGH")

    for c in missing:
        note = " (an MOU is a non-binding statement of intent and does not replace it)" if c == "BPA" and "MOU" in clauses else ""
        conditions.append(f"add the missing '{c}' clause/agreement{note}")
    sla = contract.get("sla", {})
    if "SLA" in clauses:
        need = cfg["sla_min_uptime"][vendor["criticality"]]
        if sla.get("uptime", 0) < need:
            conditions.append(f"SLA uptime {sla.get('uptime')}% below the {need}% required for {vendor['criticality']} criticality")
    if sensitive and sla.get("breach_notification_hours", 10**6) > cfg["max_breach_notification_hours"]:
        conditions.append(f"breach notification {sla.get('breach_notification_hours')}h exceeds "
                          f"{cfg['max_breach_notification_hours']}h")
    if rband == "medium":
        conditions.append(f"residual risk {residual} is MEDIUM: agree a remediation plan for the questionnaire gaps")

    decision = "REJECT" if rejects else "APPROVE_WITH_CONDITIONS" if conditions else "APPROVE"
    return VendorAssessment(vendor["id"], vendor["name"], inherent, ibband, score, residual, rband, decision,
                            missing, rejects, conditions, gaps, cfg["monitoring_cadence"][ibband])


def assess_all(data: dict, policies: dict) -> list[VendorAssessment]:
    return [assess(v, policies["vendor_risk"]) for v in data["vendors"]]


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SY0-701 5.3 Third-party risk: assessment, due diligence, agreement types, monitoring.",
    "concepts": [
        "Inherent vendor risk comes from what the vendor touches: data sensitivity, network/privileged access, criticality.",
        "Questionnaires, independent assessments (SOC 2, ISO 27001), pen tests and right-to-audit are how you VERIFY a vendor.",
        "Agreements: MSA (umbrella terms), SOW/WO (specific work), SLA (measurable service), NDA, BPA (partnership), MOU/MOA (intent/agreement).",
        "Vendor risk is continuous: monitor on a cadence matching the risk, and analyse their suppliers too (fourth parties).",
    ],
    "failure_modes": [
        "Giving an HVAC contractor network access with no security requirements (how the 2013 Target breach began).",
        "Signing a non-binding MOU where a binding agreement (BPA/MSA) was needed.",
        "No right-to-audit and no independent assessment: you are trusting a marketing slide.",
        "Skipping conflict-of-interest checks during selection.",
    ],
    "ai_governance": [
        "AI vendors are third parties too: assess model providers for data use, retention, subprocessors and audit rights.",
        "An AI procurement assistant can pre-score questionnaires, but approval and contract sign-off are human decisions.",
        "Vendor answers are untrusted input: an agent reading questionnaires must not follow instructions embedded in them.",
        "Keep agent-derived scores reproducible: same answers + same policy = same score, with every gap listed.",
    ],
    "exam_tips": [
        "'Allows the customer to inspect the vendor's security controls' = right-to-audit clause.",
        "'Defines expected uptime and response times' = SLA. 'Umbrella contract for future work' = MSA.",
        "MOU = intent, typically not legally binding. BPA = partner responsibilities and profit sharing.",
        "Supply chain analysis looks at the vendor's own vendors and components (e.g. SBOM).",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    res = assess_all(data, policies)
    ui.section("Step 1 — Inherent vs residual risk")
    ui.table("Vendors", ["ID", "Vendor", "Data/Access/Crit", "Inherent", "Controls", "Residual", "Decision"],
             [[a.id, a.name, f"{v['data']}/{v['access']}/{v['criticality']}", f"{a.inherent} ({a.inherent_band})",
               f"{a.control_score}%", f"{a.residual} ({a.residual_band})", a.decision]
              for a, v in zip(res, data["vendors"])])
    ui.section("Step 2 — Findings, conditions and monitoring")
    for a in res:
        ui.print(f"[bold]{a.id} {a.name}[/bold] → {a.decision} · monitoring: {a.monitoring}")
        for r in a.reject_reasons:
            ui.bullet(f"REJECT: {r}", style="red")
        for c in a.conditions:
            ui.bullet(f"CONDITION: {c}", style="yellow")
        if a.gaps:
            ui.bullet(f"{len(a.gaps)} questionnaire gap(s), e.g. {a.gaps[0]}", style="dim")
    ui.insight(INSIGHT)
    return {a.id: a.decision for a in res}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["vendor_risk"]
    qs: list = []
    all_clauses = sorted({c for v in cfg["required_clauses"].values() for c in v})
    for v, a in zip(data["vendors"], assess_all(data, policies)):
        ctx = (f"{a.name}: {v['service']} · data={v['data']} access={v['access']} criticality={v['criticality']} "
               f"relationship={v.get('relationship')}\nanswers={v.get('answers')}\ncontract={v.get('contract')}"
               + (f"\nnotes: {v['notes']}" if v.get("notes") else ""))
        qs.append(Question(prompt=f"{a.id}: what is the onboarding decision?", context=ctx, choices=DECISIONS,
                           answer=a.decision,
                           explanation="; ".join(a.reject_reasons or a.conditions or ["all requirements met"]),
                           objective="5.3"))
        qs.append(Question(prompt=f"{a.id}: what is the INHERENT risk band (before controls)?",
                           context=f"data={v['data']} access={v['access']} criticality={v['criticality']}; "
                                   f"high ≥ {cfg['inherent_bands']['high']}, medium ≥ {cfg['inherent_bands']['medium']}",
                           choices=["high", "medium", "low"], answer=a.inherent_band,
                           explanation=f"{cfg['data_sensitivity'][v['data']]} × {cfg['access_level'][v['access']]} × "
                                       f"{cfg['criticality'][v['criticality']]} = {a.inherent}", objective="5.3"))
        if len(a.missing_clauses) == 1:
            m = a.missing_clauses[0]
            have = v.get("contract", {}).get("clauses", [])
            qs.append(Question(prompt=f"{a.id}: which required agreement/clause is missing?", context=ctx,
                               choices=choices_with(m, all_clauses, exclude=have, key=a.id), answer=m,
                               explanation=a.conditions[0], objective="5.3"))
    for name, definition in sorted(cfg["agreement_types"].items()):
        qs.append(Question(prompt=f"Which agreement is this? \"{definition.split(':', 1)[1].strip()}\"",
                           choices=sorted(cfg["agreement_types"]), answer=name, explanation=definition,
                           objective="5.3"))
    return qs
