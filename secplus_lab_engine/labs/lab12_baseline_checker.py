"""
Lab 12 — Secure Baseline & Hardening Checker
============================================

Security+ SY0-701 objectives
----------------------------
* 4.1  Apply common security techniques to computing resources: secure
       baselines (establish, deploy, maintain), hardening targets (servers,
       workstations, network devices…), password policy, removal of
       unnecessary services/software, logging/auditing, host firewall, EDR,
       patching, configuration enforcement.

What it does
------------
Each host profile (``windows_server``, ``linux_server``) has a CIS-style
baseline in ``config/default_policies.json → hardening_baselines``. A check is
``{setting, op, value}`` with ops ``eq``, ``ge``, ``le``, ``between``,
``includes`` (list must contain all values) and ``excludes`` (list must contain
none of them).

For every host the checker reports:

* **PASS / FAIL / MISSING / EXCEPTION** per check. MISSING means the setting
  wasn't reported and counts as a failure (deny by default). EXCEPTION is a
  documented, ticketed, unexpired deviation.
* **Weighted compliance %** (high 10, medium 5, low 2). A host is COMPLIANT
  only if it scores ≥ 90% AND has no failed high-severity checks.
* **Drift** against the previous approved scan: REGRESSED (pass → fail) and
  REMEDIATED (fail → pass).
* **Remediation steps** taken from the baseline.

Run it
------
    python main.py lab 12
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

TITLE = "Lab 12 — Secure Baseline & Hardening Checker"
OBJECTIVES = "SY0-701 4.1 Secure baselines & hardening"

STATUSES = ["PASS", "FAIL", "MISSING", "EXCEPTION"]


@dataclass
class CheckResult:
    check_id: str
    title: str
    category: str
    severity: str
    status: str
    actual: object
    expected: str
    remediation: str
    note: str = ""


@dataclass
class HostReport:
    name: str
    profile: str
    compliance: float
    verdict: str                     # COMPLIANT | NON_COMPLIANT
    results: list[CheckResult] = field(default_factory=list)
    regressed: list[str] = field(default_factory=list)
    remediated: list[str] = field(default_factory=list)

    def by_id(self, cid: str) -> CheckResult:
        return next(r for r in self.results if r.check_id == cid)


def describe(check: dict) -> str:
    op, v = check["op"], check["value"]
    if op == "between":
        return f"between {v[0]} and {v[1]}"
    return {"eq": f"= {v}", "ge": f"≥ {v}", "le": f"≤ {v}", "includes": f"includes {v}",
            "excludes": f"none of {v}"}.get(op, f"{op} {v} (unknown operator)")


def evaluate_check(check: dict, settings: dict) -> tuple[str, object]:
    """Return (PASS|FAIL|MISSING, actual value). Unknown operators fail closed."""
    key = check["setting"]
    if key not in settings:
        return "MISSING", None
    actual, op, v = settings[key], check["op"], check["value"]
    try:
        ok = {
            "eq": lambda: actual == v,
            "ge": lambda: actual >= v,
            "le": lambda: actual <= v,
            "between": lambda: v[0] <= actual <= v[1],
            "includes": lambda: all(x in actual for x in v),
            "excludes": lambda: not any(x in actual for x in v),
        }[op]()
    except (KeyError, TypeError):
        ok = False                               # malformed check or wrong type → fail closed
    if op == "excludes" and not ok:
        actual = sorted(set(actual) & set(v))    # show only the offending items
    elif op == "includes" and not ok:
        actual = f"missing {sorted(set(v) - set(actual))}"
    return ("PASS" if ok else "FAIL"), actual


def valid_deviation(check_id: str, deviations: list[dict], as_of: date) -> dict | None:
    for d in deviations:
        if d["check"] == check_id and d.get("ticket") and date.fromisoformat(d["expires"]) >= as_of:
            return d
    return None


def check_host(host: dict, cfg: dict, as_of: date) -> HostReport:
    baseline = cfg["profiles"].get(host["profile"])
    if baseline is None:
        raise ValueError(f"no baseline for profile '{host['profile']}'")
    weights = cfg["severity_weight"]
    results: list[CheckResult] = []
    earned = possible = 0
    for chk in baseline:
        status, actual = evaluate_check(chk, host["settings"])
        note = ""
        if status != "PASS":
            dev = valid_deviation(chk["id"], host.get("approved_deviations", []), as_of)
            expired = [d for d in host.get("approved_deviations", []) if d["check"] == chk["id"] and d is not dev]
            if dev:
                status, note = "EXCEPTION", f"{dev['ticket']}: {dev['reason']} (expires {dev['expires']})"
            elif expired:
                note = f"deviation {expired[0].get('ticket')} expired {expired[0]['expires']}"
        results.append(CheckResult(chk["id"], chk["title"], chk["category"], chk["severity"], status, actual,
                                   describe(chk), chk["remediation"], note))
        if status == "EXCEPTION":
            continue                                  # documented exceptions are excluded from the score
        possible += weights[chk["severity"]]
        earned += weights[chk["severity"]] if status == "PASS" else 0
    pct = round(100 * earned / possible, 1) if possible else 100.0
    high_fail = any(r.severity == "high" and r.status in ("FAIL", "MISSING") for r in results)
    verdict = "COMPLIANT" if pct >= cfg["compliant_min_percent"] and not high_fail else "NON_COMPLIANT"

    regressed, remediated = [], []
    prev = host.get("previous_settings")
    if prev is not None:
        for chk in baseline:
            before, _ = evaluate_check(chk, prev)
            now = next(r for r in results if r.check_id == chk["id"]).status
            if before == "PASS" and now in ("FAIL", "MISSING"):
                regressed.append(chk["id"])
            elif before in ("FAIL", "MISSING") and now == "PASS":
                remediated.append(chk["id"])
    return HostReport(host["name"], host["profile"], pct, verdict, results, regressed, remediated)


def check_all(data: dict, policies: dict) -> list[HostReport]:
    cfg = policies["hardening_baselines"]
    as_of = date.fromisoformat(data["as_of"])
    return [check_host(h, cfg, as_of) for h in data["hosts"]]


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SY0-701 4.1 Secure baselines: establish, deploy, maintain; hardening targets and techniques.",
    "concepts": [
        "A secure baseline is the approved minimum configuration; deploy it with GPO/MDM/config management, then measure drift.",
        "Hardening = reduce attack surface: remove unneeded services, enforce password/lockout policy, enable host firewall, EDR and auditing.",
        "Unknown is non-compliant: a setting the scanner can't read is treated as failed until proven otherwise.",
        "Exceptions are documented, ticketed, compensated and time-boxed, never silent.",
    ],
    "failure_modes": [
        "Hardening once at build time and never re-scanning, so configuration drift goes unnoticed.",
        "Someone re-enables Print Spooler on a domain controller 'to print one report' (PrintNightmare).",
        "Turning off the host firewall or EDR to troubleshoot and never turning it back on.",
        "Baselines kept in a PDF instead of enforced as code.",
    ],
    "ai_governance": [
        "A remediation agent may apply baseline settings, but only via change control with rollback (Lab 4).",
        "Agents must never weaken a baseline (disable firewall/EDR/auditing); that is a Lab 5 protected-control BLOCK.",
        "Drift alerts are a great agent job: detect, explain, open a ticket, attach the remediation step.",
        "Approving a deviation (exception) stays a human decision with an expiry date.",
    ],
    "exam_tips": [
        "'Establish → deploy → maintain' is the secure-baseline lifecycle.",
        "Disabling unnecessary ports/services and default accounts is classic hardening.",
        "Configuration drift = systems slowly diverging from the baseline; detect with periodic scans.",
        "Group Policy (Windows) and SELinux (Linux mandatory access control) both appear in 4.1.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    reports = check_all(data, policies)
    ui.section(f"Step 1 — Compliance summary (as of {data['as_of']})")
    ui.table("Hosts", ["Host", "Profile", "Compliance", "Verdict", "Failed (high)", "Regressed", "Remediated"],
             [[r.name, r.profile, f"{r.compliance}%", r.verdict,
               f"{sum(x.status in ('FAIL', 'MISSING') for x in r.results)} "
               f"({sum(x.status in ('FAIL', 'MISSING') and x.severity == 'high' for x in r.results)})",
               ", ".join(r.regressed) or "-", ", ".join(r.remediated) or "-"] for r in reports])

    for r in reports:
        ui.section(f"{r.name} — {r.verdict} ({r.compliance}%)")
        bad = [x for x in r.results if x.status != "PASS"]
        ui.table("Non-passing checks", ["Check", "Sev", "Title", "Status", "Actual", "Expected", "Remediation / note"],
                 [[x.check_id, x.severity, x.title, x.status, x.actual, x.expected, x.note or x.remediation] for x in bad]
                 or [["-", "-", "all checks pass", "PASS", "-", "-", "-"]])
        if r.regressed:
            ui.bullet(f"DRIFT: regressed since last approved scan → {r.regressed}", style="red")

    ui.insight(INSIGHT)
    return {"verdicts": {r.name: r.verdict for r in reports},
            "compliance": {r.name: r.compliance for r in reports},
            "regressed": {r.name: r.regressed for r in reports if r.regressed}}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["hardening_baselines"]
    qs: list = []
    for host, r in zip(data["hosts"], check_all(data, policies)):
        baseline = {c["id"]: c for c in cfg["profiles"][host["profile"]]}
        qs.append(Question(
            prompt=f"{r.name} ({host['role']}): COMPLIANT or NON_COMPLIANT?",
            context=f"Settings: {host['settings']}\nApproved deviations: {host.get('approved_deviations') or 'none'}\n"
                    f"Rule: ≥{cfg['compliant_min_percent']}% weighted AND no failed high-severity check",
            choices=["COMPLIANT", "NON_COMPLIANT"], answer=r.verdict,
            explanation=f"{r.compliance}% weighted; failing: "
                        + (", ".join(f"{x.check_id}({x.severity})" for x in r.results if x.status in ("FAIL", "MISSING")) or "none"),
            objective="4.1"))
        fails = [x for x in r.results if x.status != "PASS"][:2]
        passes = [x for x in r.results if x.status == "PASS"][:1]
        for x in fails + passes:
            c = baseline[x.check_id]
            qs.append(Question(
                prompt=f"{r.name}: result of {x.check_id} '{x.title}'?",
                context=f"Baseline: {c['setting']} {describe(c)} · host reports: "
                        f"{host['settings'].get(c['setting'], '<not reported>')} · deviations: "
                        f"{[d['check'] + ' until ' + d['expires'] for d in host.get('approved_deviations', [])] or 'none'} · "
                        f"as of {data['as_of']}",
                choices=STATUSES, answer=x.status,
                explanation=x.note or (f"actual {x.actual} vs expected {x.expected}" if x.status != "MISSING"
                                       else "not reported → treated as non-compliant (deny by default)"),
                objective="4.1"))
        if len(r.regressed) == 1:
            reg = r.regressed[0]
            titles = [baseline[cid]["title"] for cid in baseline]
            qs.append(Question(
                prompt=f"{r.name}: which baseline check REGRESSED since the last approved scan?",
                context=f"Previous: {host['previous_settings']}\nCurrent:  {host['settings']}",
                choices=choices_with(baseline[reg]["title"], titles, key=r.name,
                                     exclude=[baseline[c]["title"] for c in baseline
                                              if r.by_id(c).status != "PASS"]),
                answer=baseline[reg]["title"],
                explanation=f"{reg} passed last scan and fails now: configuration drift.", objective="4.1"))
    return qs
