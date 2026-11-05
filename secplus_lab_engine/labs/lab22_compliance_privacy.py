"""
Lab 22 — Compliance & Privacy Obligations Tracker
=================================================

Security+ SY0-701 objectives
----------------------------
* 5.4  Effective security compliance: compliance reporting (internal,
       external), consequences of non-compliance (fines, sanctions,
       reputational damage, loss of license, contractual impacts),
       compliance monitoring (due diligence/care, attestation and
       acknowledgement, internal and external, automation), privacy (legal
       implications: local/regional, national, global; data subject;
       controller vs processor; ownership; data inventory and retention;
       right to be forgotten).
* 5.1  Roles and responsibilities for data: owners, controllers,
       processors, custodians/stewards.

Model
-----
Time is a plain integer: ``as_of_day`` (hours = day × 24). There is no real
clock. Every deadline, period and margin comes from the ``compliance`` policy.
The regimes ("GDPR-style" 30 days / 72 h, a fictional "state privacy law"
45 days) are configurable ILLUSTRATIONS for learning, NOT legal advice.

Each case is evaluated to one status, with reasons, a rule code, a
consequence category and the reporting it needs (internal / external / none):

* COMPLIANT      obligation met, or on track with time to spare
* AT_RISK        open, and the deadline falls within the policy margin
* NON_COMPLIANT  deadline missed or a required step missing
* EXEMPT         a valid, DOCUMENTED exception (legal hold, retention duty)

Case kinds: data subject requests (access / erasure "right to be forgotten" /
rectification), breach notifications, data retention, attestations.
Unknown regime/type or a missing required field → NON_COMPLIANT (deny by default).

Run it
------
    python main.py lab 22
"""

from __future__ import annotations

from dataclasses import dataclass, field

TITLE = "Lab 22 — Compliance & Privacy Obligations Tracker"
OBJECTIVES = ("SY0-701 5.4 Compliance reporting, consequences, monitoring, privacy (subject, controller vs processor, "
              "retention, right to be forgotten) · 5.1 Data roles: owner, controller, processor, custodian/steward")
DECISIONS = ["COMPLIANT", "AT_RISK", "NON_COMPLIANT", "EXEMPT"]
REPORTING = ["internal", "external", "none"]


@dataclass
class CaseResult:
    id: str
    kind: str
    status: str
    code: str
    reasons: list[str] = field(default_factory=list)
    consequence: str = "none"
    reporting: str = "none"


def _missing(case: dict, fields: list[str]) -> list[str]:
    return [f for f in fields if case.get(f) is None]


def _deadline(remaining: int, margin: int, unit: str, late: str, soon: str) -> tuple[str, str, str]:
    if remaining < 0:
        return "NON_COMPLIANT", late, f"deadline missed by {-remaining} {unit}"
    if remaining <= margin:
        return "AT_RISK", soon, f"{remaining} {unit} left (margin {margin} {unit})"
    return "COMPLIANT", "ON_TRACK", f"on track: {remaining} {unit} left"


def eval_dsr(c: dict, cfg: dict, today: int) -> tuple[str, str, list[str]]:
    regime = cfg["regimes"][c["regime"]]
    if c["request_type"] not in cfg["dsr_types"]:
        return "NON_COMPLIANT", "UNKNOWN_TYPE", [f"request type '{c['request_type']}' is not a known DSR type"]
    why = []
    if c["received_by"] == "processor":
        if not c.get("forwarded_to_controller"):
            return "NON_COMPLIANT", "NOT_FORWARDED", ["received by a PROCESSOR, which acts only on the controller's "
                                                      "instructions: it must forward the request to the controller"]
        why.append("processor forwarded the request to the controller (controller is accountable for the answer)")
    done = c.get("completed_day")
    if done is not None and not c["identity_verified"]:
        return "NON_COMPLIANT", "UNVERIFIED_IDENTITY", ["request fulfilled without verifying the data subject's "
                                                        "identity: possible disclosure to an impostor"]
    if c["request_type"] == "erasure" and c.get("hold"):
        if c["hold"] in cfg["erasure_exemption_grounds"] and c.get("hold_documented"):
            return "EXEMPT", "DOCUMENTED_EXCEPTION", why + [
                f"erasure suspended by a documented {c['hold'].replace('_', ' ')}: data kept, not silently deleted; "
                "tell the subject why"]
        return "NON_COMPLIANT", "UNDOCUMENTED_EXCEPTION", why + [
            f"'{c['hold']}' claimed as an exception but not a documented, recognised ground"]
    due = c["received_day"] + regime["dsr_days"]
    why.append(f"{regime['label']}: respond within {regime['dsr_days']} days (due day {due})")
    if done is not None:
        if done <= due:
            return "COMPLIANT", "MET", why + [f"completed on day {done}"]
        return "NON_COMPLIANT", "DSR_LATE", why + [f"completed on day {done}: {done - due} days late"]
    status, code, note = _deadline(due - today, cfg["at_risk_margin"]["dsr_days"], "days", "DSR_LATE", "DSR_DUE_SOON")
    if not c["identity_verified"]:
        why.append("identity not yet verified: verify before fulfilling")
        if status == "COMPLIANT":
            status, code = "AT_RISK", "DSR_DUE_SOON"
    return status, code, why + [note]


def eval_breach(c: dict, cfg: dict, today: int) -> tuple[str, str, list[str]]:
    regime = cfg["regimes"][c["regime"]]
    risk, why = c["risk"], []
    if risk in regime["subject_notify_risk"] and not c.get("subjects_notified"):
        return "NON_COMPLIANT", "SUBJECTS_NOT_NOTIFIED", [
            f"{risk} risk to individuals: {regime['label']} requires notifying affected data subjects"]
    if risk not in regime["regulator_notify_risk"]:
        return "COMPLIANT", "NOT_REQUIRED", [f"{risk} risk: regulator notification not required by {regime['label']}; "
                                             "record the breach in the internal register"]
    limit, sent = regime["breach_hours"], c.get("regulator_notified_hour")
    why.append(f"{regime['label']}: notify the regulator within {limit} h of discovery")
    if sent is not None:
        took = sent - c["discovered_hour"]
        if took <= limit:
            return "COMPLIANT", "MET", why + [f"regulator notified after {took} h"]
        return "NON_COMPLIANT", "BREACH_LATE", why + [f"regulator notified after {took} h: {took - limit} h late"]
    left = c["discovered_hour"] + limit - today * 24
    status, code, note = _deadline(left, cfg["at_risk_margin"]["breach_hours"], "h", "BREACH_LATE", "BREACH_DUE_SOON")
    return status, code, why + ["regulator not yet notified", note]


def eval_retention(c: dict, cfg: dict, today: int) -> tuple[str, str, list[str]]:
    rule = cfg["retention_schedule"].get(c["record_type"])
    if rule is None:
        return "NON_COMPLIANT", "UNKNOWN_TYPE", [f"record type '{c['record_type']}' is not in the data inventory / "
                                                 "retention schedule"]
    lo, hi = rule["min_days"], rule["max_days"]
    why = [f"{c['record_type']}: keep at least {lo} and at most {hi} days"]
    gone = c.get("destroyed_day")
    if gone is not None:
        age = gone - c["created_day"]
        if c.get("legal_hold"):
            return "NON_COMPLIANT", "DESTROYED_UNDER_HOLD", why + ["destroyed while under legal hold (spoliation)"]
        if age < lo:
            return "NON_COMPLIANT", "EARLY_DESTRUCTION", why + [f"destroyed after {age} days: {lo - age} days early"]
        return "COMPLIANT", "MET", why + [f"destroyed after {age} days, inside the window"]
    age = today - c["created_day"]
    if c.get("legal_hold"):
        if age > hi:
            return "EXEMPT", "DOCUMENTED_EXCEPTION", why + [f"{age} days old but under legal hold: keep until released"]
        return "COMPLIANT", "ON_TRACK", why + [f"{age} days old, under legal hold"]
    status, code, note = _deadline(hi - age, cfg["at_risk_margin"]["retention_days"], "days",
                                   "OVER_RETENTION", "RETENTION_DUE_SOON")
    if code == "OVER_RETENTION":
        note = f"{age} days old with no hold: over-retained by {age - hi} days (minimisation)"
    elif code == "RETENTION_DUE_SOON":
        note += ": schedule secure destruction"
    return status, code, why + [note]


def eval_attestation(c: dict, cfg: dict, today: int) -> tuple[str, str, list[str]]:
    rule = cfg["attestations"].get(c["attestation"])
    if rule is None:
        return "NON_COMPLIANT", "UNKNOWN_TYPE", [f"attestation '{c['attestation']}' is not defined in policy"]
    why = [f"{rule['label']} ({rule['scope']}), valid {rule['valid_days']} days"]
    exc = c.get("exception") or {}
    if exc.get("documented"):
        return "EXEMPT", "DOCUMENTED_EXCEPTION", why + [f"documented exception: {exc.get('reason', 'n/a')}"]
    if c.get("signed_day") is None:
        return "NON_COMPLIANT", "ATTESTATION_MISSING", why + ["never signed/acknowledged"]
    expires = c["signed_day"] + rule["valid_days"]
    status, code, note = _deadline(expires - today, cfg["at_risk_margin"]["attestation_days"], "days",
                                   "ATTESTATION_EXPIRED", "ATTESTATION_DUE_SOON")
    return status, code, why + [f"signed day {c['signed_day']}, expires day {expires}", note]


EVALUATORS = {"dsr": eval_dsr, "breach": eval_breach, "retention": eval_retention, "attestation": eval_attestation}


def evaluate(c: dict, cfg: dict, today: int) -> CaseResult:
    kind, cid = c.get("kind"), c.get("id", "?")
    if kind not in EVALUATORS:
        return CaseResult(cid, str(kind), "NON_COMPLIANT", "UNKNOWN_TYPE", [f"unknown case kind '{kind}'"],
                          cfg["consequence_by_code"]["UNKNOWN_TYPE"], "internal")
    miss = _missing(c, cfg[f"{kind}_required_fields"])
    if miss:
        status, code, why = "NON_COMPLIANT", "MISSING_FIELDS", [f"missing required field(s): {', '.join(miss)}"]
    elif kind in ("dsr", "breach") and c["regime"] not in cfg["regimes"]:
        status, code, why = "NON_COMPLIANT", "UNKNOWN_REGIME", [f"regime '{c['regime']}' is not in the policy"]
    else:
        status, code, why = EVALUATORS[kind](c, cfg, today)
    consequence = "none"
    if status in ("NON_COMPLIANT", "AT_RISK"):
        consequence = cfg["consequence_by_code"].get(code, "fines")
        if kind == "attestation" and cfg["attestations"].get(c.get("attestation"), {}).get("scope") == "external":
            consequence = cfg["external_attestation_consequence"]
    external = ((kind == "breach" and status != "EXEMPT" and code not in ("NOT_REQUIRED", "MISSING_FIELDS", "UNKNOWN_REGIME"))
                or (kind == "attestation" and status in ("NON_COMPLIANT", "AT_RISK")
                    and cfg["attestations"].get(c.get("attestation"), {}).get("scope") == "external"))
    reporting = "external" if external else "none" if status == "COMPLIANT" and code != "NOT_REQUIRED" else "internal"
    return CaseResult(cid, kind, status, code, why, consequence, reporting)


def evaluate_all(data: dict, policies: dict) -> list[CaseResult]:
    cfg = policies["compliance"]
    return [evaluate(c, cfg, data["as_of_day"]) for c in data["cases"]]


def report_summary(results: list[CaseResult]) -> dict:
    return {"by_status": {d: sum(r.status == d for r in results) for d in DECISIONS},
            "reporting": {k: sum(r.reporting == k for r in results) for k in REPORTING}}


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SY0-701 5.4 Compliance reporting, consequences, monitoring and privacy (with 5.1 data roles).",
    "concepts": [
        "Deadlines here are configurable illustrations (GDPR-style 30 days / 72 h), not legal advice; real law varies by local, regional, national and global scope.",
        "The controller decides why/how data is processed and answers data subject requests; a processor acts only on its instructions.",
        "Right to be forgotten is not absolute: a documented legal hold or retention obligation suspends erasure.",
        "A data inventory plus a retention schedule (minimum AND maximum periods) drives lawful keeping and destruction.",
        "Compliance monitoring: attestation and acknowledgement, internal and external audits, and automation of the checks.",
    ],
    "failure_modes": [
        "Silently deleting data that is under legal hold (sanctions for spoliation).",
        "Keeping data 'just in case' long after its retention period (over-retention increases breach impact).",
        "A processor answering a subject request directly instead of forwarding it to the controller.",
        "Missing the regulator breach notification window while the investigation drags on.",
        "Annual policy acknowledgements tracked on paper and quietly expiring.",
    ],
    "ai_governance": [
        "An AI agent that handles DSRs must verify identity before disclosing or erasing anything.",
        "Agents need the data inventory too: training data and prompts are personal data with retention limits.",
        "Exceptions (holds) must be documented records an agent can check, never a free-text excuse it accepts.",
        "Automated compliance checks are monitoring, but attestation sign-off stays with an accountable human.",
    ],
    "exam_tips": [
        "Internal reporting goes to management/board/compliance; external reporting goes to regulators, customers or auditors.",
        "Consequences of non-compliance: fines, sanctions, reputational damage, loss of license, contractual impacts.",
        "Due diligence = investigate and verify; due care = act as a reasonable, prudent organisation would.",
        "Controller vs processor: the controller is accountable; the processor processes on the controller's behalf.",
        "Data subject = the person the data is about; right to be forgotten = erasure request.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    res = evaluate_all(data, policies)
    ui.section(f"Step 1 — Obligations as of day {data['as_of_day']} (illustrative deadlines, not legal advice)")
    ui.table("Cases", ["ID", "Kind", "Summary", "Status", "Rule", "Consequence", "Reporting"],
             [[r.id, r.kind, c.get("summary", ""), r.status, r.code, r.consequence, r.reporting]
              for r, c in zip(res, data["cases"])])
    ui.section("Step 2 — Reasons")
    for r in res:
        ui.status(f"{r.id} {r.kind}", r.status, r.code)
        for why in r.reasons:
            ui.bullet(why, style="red" if r.status == "NON_COMPLIANT" else "yellow" if r.status == "AT_RISK" else None)
    ui.section("Step 3 — Compliance report summary")
    s = report_summary(res)
    ui.panel("Report", "  ".join(f"{k}: {v}" for k, v in s["by_status"].items())
             + "\nReporting needed: " + ", ".join(f"{k} {v}" for k, v in s["reporting"].items()))
    ui.insight(INSIGHT)
    return {r.id: r.status for r in res}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def _policy_hint(c: dict, cfg: dict) -> str:
    m = cfg["at_risk_margin"]
    if c.get("kind") in ("dsr", "breach"):
        r = cfg["regimes"].get(c.get("regime"))
        if r is None:
            return f"known regimes: {', '.join(sorted(cfg['regimes']))}"
        if c["kind"] == "dsr":
            return f"{r['label']}: {r['dsr_days']} days; AT_RISK within {m['dsr_days']} days; holds: {cfg['erasure_exemption_grounds']}"
        return (f"{r['label']}: regulator within {r['breach_hours']} h for risk {r['regulator_notify_risk']}; "
                f"subjects for risk {r['subject_notify_risk']}; AT_RISK within {m['breach_hours']} h")
    if c.get("kind") == "retention":
        return f"schedule {cfg['retention_schedule'].get(c.get('record_type'), 'not in inventory')}; AT_RISK within {m['retention_days']} days"
    a = cfg["attestations"].get(c.get("attestation"), {})
    return f"valid {a.get('valid_days', '?')} days, scope {a.get('scope', '?')}; AT_RISK within {m['attestation_days']} days"


def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["compliance"]
    labels, qs = cfg["rule_labels"], []
    cons = sorted(cfg["consequences"])
    for c, r in zip(data["cases"], evaluate_all(data, policies)):
        ctx = (f"as_of_day={data['as_of_day']} · " + ", ".join(f"{k}={v}" for k, v in c.items() if k != "id")
               + f"\npolicy: {_policy_hint(c, cfg)}")
        qs.append(Question(prompt=f"{r.id}: what is the compliance status?", context=ctx, choices=DECISIONS,
                           answer=r.status, explanation="; ".join(r.reasons), objective="5.4"))
        if r.status == "NON_COMPLIANT" and r.code in labels:
            qs.append(Question(prompt=f"{r.id}: which rule makes it NON_COMPLIANT?", context=ctx,
                               choices=choices_with(labels[r.code], labels.values(), key=r.id),
                               answer=labels[r.code], explanation="; ".join(r.reasons), objective="5.4"))
            qs.append(Question(prompt=f"{r.id}: which consequence category does policy map this failure to?",
                               context=ctx, choices=cons, answer=r.consequence,
                               explanation=f"{r.code} → {r.consequence}: {cfg['consequences'][r.consequence]}",
                               objective="5.4"))
        if r.kind in ("breach", "attestation"):
            qs.append(Question(prompt=f"{r.id}: what reporting does this case need?", context=ctx, choices=REPORTING,
                               answer=r.reporting, explanation="external = regulator/customer/auditor; internal = "
                               f"management/compliance; none = compliant. Reasons: {'; '.join(r.reasons)}",
                               objective="5.4"))
    for table, obj in (("data_roles", "5.1"), ("consequences", "5.4"), ("diligence_terms", "5.4")):
        for name, definition in sorted(cfg[table].items()):
            qs.append(Question(prompt=f"Which term matches? \"{definition}\"", choices=sorted(cfg[table]),
                               answer=name, explanation=f"{name}: {definition}", objective=obj))
    return qs
