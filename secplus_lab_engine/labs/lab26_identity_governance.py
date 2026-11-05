"""
Lab 26 — Identity Governance: Account Reconciliation & Access Certification
===========================================================================

Security+ SY0-701 objectives
----------------------------
* 4.6  Identity and access management: provisioning/de-provisioning user
       accounts, permission assignments and implications, attestation,
       least privilege, privileged access management.
* 5.1  Security governance: roles and responsibilities for systems and data
       (owners, custodians/stewards), monitoring and revision.
* 4.2  Asset management: inventory and enumeration (here, of accounts).

How it works
------------
This is the daily work of an identity governance and administration (IGA)
analyst, using the same concepts SailPoint and Entra ID Governance use.

1. **Aggregation & correlation**: HR is the authoritative source. Every
   application account is correlated to an identity by ordered policy rules
   (employee_id, else email, else none). Service accounts correlate to their
   named owner. Findings (most severe wins): TERMINATED_WITH_ACCESS,
   PRIVILEGED_UNOWNED, ORPHAN, DUPLICATE, DORMANT, else CORRELATED. An unknown
   HR status is treated as terminated and a missing login as dormant.
2. **Access certification**: each review item is KEEP, REVOKE or ESCALATE.
   Unknown or terminated identity → REVOKE. The reviewer must be the
   identity's manager or the entitlement owner, never the identity itself,
   or the item is ESCALATED. No decision at close → policy action (REVOKE).
   An approval escalates if it is high-risk with no comment, completes an
   SoD pair, or comes from a rubber-stamping reviewer (≥ N approvals with a
   median decision time < Y seconds).

Run it
------
    python main.py lab 26
"""

from __future__ import annotations

from dataclasses import dataclass, field
from statistics import median

TITLE = "Lab 26 — Identity Governance: Account Reconciliation & Access Certification"
OBJECTIVES = ("SY0-701 4.6 Provisioning/de-provisioning, permission assignments, attestation, least privilege · "
              "5.1 Governance roles: owners/custodians · 4.2 Inventory/enumeration of accounts")
FINDINGS = ["CORRELATED", "ORPHAN", "TERMINATED_WITH_ACCESS", "DORMANT", "PRIVILEGED_UNOWNED", "DUPLICATE"]
OUTCOMES = ["KEEP", "REVOKE", "ESCALATE"]
DECISIONS = FINDINGS + OUTCOMES


@dataclass
class AccountResult:
    id: str
    app: str
    account: str
    identity: str | None
    rule: str | None
    finding: str
    action: str
    findings: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


@dataclass
class ItemResult:
    id: str
    identity: str
    entitlement: str
    reviewer: str
    outcome: str
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Part 1 — aggregation & correlation
# --------------------------------------------------------------------------- #
def status_of(identity: dict, cfg: dict) -> str:
    """'allowed' or 'revoke'; an unknown/missing HR status is treated as 'revoke' (deny by default)."""
    return cfg["status_handling"].get(identity.get("status"), "revoke")


def correlate(account: dict, identities: list[dict], rules: list[dict]) -> tuple[dict | None, str | None]:
    for rule in rules:
        value = account.get(rule["account_attribute"])
        if not value:
            continue
        for ident in identities:
            if str(ident.get(rule["identity_attribute"], "")).lower() == str(value).lower():
                return ident, rule["name"]
    return None, None


def reconcile(data: dict, cfg: dict) -> list[AccountResult]:
    identities = data.get("identities", [])
    by_id = {i["employee_id"]: i for i in identities}
    seen: dict[tuple, str] = {}
    out = []
    for a in data.get("accounts", []):
        found: list[tuple[str, str]] = []
        enabled = a.get("enabled", True)                      # missing flag = assume enabled
        service = a.get("type") in cfg["service_account_types"]
        if service:
            ident, rule = by_id.get(a.get("owner") or ""), "owner"
            if ident is None:
                found.append(("PRIVILEGED_UNOWNED", "service account has no named owner in HR (deny by default)"))
            elif status_of(ident, cfg) != "allowed":
                found.append(("PRIVILEGED_UNOWNED", f"service account owner {ident['employee_id']} is "
                              f"'{ident.get('status')}': ownership must be reassigned"))
                ident = None
        else:
            ident, rule = correlate(a, identities, cfg["correlation_rules"])
            if ident is None:
                found.append(("ORPHAN", "no identity matched by " + ", then ".join(
                    r["name"] for r in cfg["correlation_rules"])))
                if a.get("privileged"):
                    found.append(("PRIVILEGED_UNOWNED", "privileged account with no accountable owner"))
            else:
                if enabled and status_of(ident, cfg) == "revoke":
                    found.append(("TERMINATED_WITH_ACCESS", f"{ident['employee_id']} HR status is "
                                  f"'{ident.get('status')}' but the account is still enabled"))
                key = (a["app"], ident["employee_id"])
                if key in seen:
                    found.append(("DUPLICATE", f"second {a['app']} account for {ident['employee_id']} "
                                  f"(first: {seen[key]})"))
                else:
                    seen[key] = a["account"]
        last = a.get("last_login_days_ago")
        if enabled and (last is None or last > cfg["dormant_after_days"]):
            found.append(("DORMANT", "no login recorded" if last is None else
                          f"last login {last} days ago > {cfg['dormant_after_days']} days"))
        notes = []
        if not found:
            notes.append(f"correlated to {ident['employee_id']} by {rule}")
            if not enabled:
                notes.append("account already disabled: de-provisioning complete")
            if ident.get("status") == "leave":
                notes.append("identity is on leave: access kept, monitor for use")
        found.sort(key=lambda f: cfg["finding_severity"].index(f[0]))
        finding = found[0][0] if found else "CORRELATED"
        out.append(AccountResult(a["id"], a["app"], a["account"], ident["employee_id"] if ident else None, rule
                                 if ident else None, finding, cfg["finding_actions"][finding],
                                 [f for f, _ in found], [r for _, r in found] + notes))
    return out


# --------------------------------------------------------------------------- #
# Part 2 — access certification campaign
# --------------------------------------------------------------------------- #
def rubber_stampers(items: list[dict], cfg: dict) -> dict[str, dict]:
    """Reviewers with ≥ min_approvals approvals and a median time between decisions < max_median_seconds."""
    rs, out = cfg["campaign"]["rubber_stamp"], {}
    for reviewer in sorted({i.get("reviewer") for i in items if i.get("reviewer")}):
        mine = sorted((i for i in items if i.get("reviewer") == reviewer and i.get("decision") in ("approve", "revoke")
                       and i.get("decided_at_seconds") is not None), key=lambda i: i["decided_at_seconds"])
        times = [b["decided_at_seconds"] - a["decided_at_seconds"]
                 for a, b in zip([{"decided_at_seconds": 0}] + mine, mine)]
        approvals = sum(i["decision"] == "approve" for i in mine)
        if approvals >= rs["min_approvals"] and times and median(times) < rs["max_median_seconds"]:
            out[reviewer] = {"approvals": approvals, "median_seconds": median(times)}
    return out


def certify(data: dict, cfg: dict) -> tuple[list[ItemResult], dict]:
    camp = cfg["campaign"]
    by_id = {i["employee_id"]: i for i in data.get("identities", [])}
    catalog = data.get("entitlements", {})
    items = data.get("campaign", {}).get("items", [])
    stampers = rubber_stampers(items, cfg)
    approved = {(i["identity"], f"{i['app']}:{i['entitlement']}") for i in items if i.get("decision") == "approve"}
    results = []
    for it in items:
        ent = f"{it['app']}:{it['entitlement']}"
        meta = catalog.get(ent, {})
        risk = meta.get("risk", camp["unknown_entitlement_risk"])
        ident, reviewer, decision = by_id.get(it.get("identity")), it.get("reviewer"), it.get("decision")
        revoke, escalate, forced = [], [], None
        rel = {"manager": ident.get("manager") if ident else None, "entitlement_owner": meta.get("owner")}
        if ident is None:
            revoke.append(f"identity {it.get('identity')} is not in the authoritative HR source")
        elif status_of(ident, cfg) == "revoke":
            revoke.append(f"identity is '{ident.get('status')}' in HR: access must be removed")
        elif not reviewer:
            escalate.append("no reviewer assigned")
        elif reviewer == it.get("identity") and not camp["allow_self_review"]:
            escalate.append("self-review is not allowed: reassign to the manager or entitlement owner")
        elif reviewer not in {rel[r] for r in camp["allowed_reviewers"]}:
            escalate.append(f"reviewer {reviewer} is not the identity's "
                            + " or ".join(r.replace("_", " ") for r in camp["allowed_reviewers"]))
        elif decision not in ("approve", "revoke"):
            forced = camp["no_decision_action"]
            revoke.append(f"no decision at campaign close: policy action is {forced} (deny by default)")
        elif decision == "revoke":
            revoke.append(f"reviewer {reviewer} revoked: {it.get('comment') or 'no comment'}")
        else:
            if risk in camp["comment_required_risk"] and not (it.get("comment") or "").strip():
                escalate.append(f"{risk}-risk approval has no justification comment")
            for rule in cfg["sod_conflicts"]:
                if ent in rule["pair"]:
                    other = [p for p in rule["pair"] if p != ent][0]
                    if (it["identity"], other) in approved:
                        escalate.append(f"SoD conflict '{rule['name']}': {other} is also approved")
            if reviewer in stampers:
                s = stampers[reviewer]
                escalate.append(f"rubber-stamping reviewer: {s['approvals']} approvals, median "
                                f"{s['median_seconds']}s per decision")
        outcome = forced or ("REVOKE" if revoke else "ESCALATE" if escalate else "KEEP")
        results.append(ItemResult(it["id"], it.get("identity", "?"), ent, reviewer or "-", outcome,
                                  revoke or escalate or [f"{risk}-risk approval by authorised reviewer {reviewer}"]))
    n = len(items) or 1
    metrics = {"items": len(items),
               "completion_pct": round(100 * sum(i.get("decision") in ("approve", "revoke") for i in items) / n, 1),
               "revocation_rate_pct": round(100 * sum(r.outcome == "REVOKE" for r in results) / n, 1),
               "rubber_stamp_reviewers": sorted(stampers)}
    return results, metrics


def remediation(accounts: list[AccountResult], items: list[ItemResult]) -> list[str]:
    out = [f"{a.app}: {a.action} account '{a.account}' ({a.finding})" for a in accounts if a.action != "NO_ACTION"]
    out += [f"{r.entitlement.split(':')[0]}: REVOKE {r.entitlement.split(':')[1]} from {r.identity} ({r.id})"
            for r in items if r.outcome == "REVOKE"]
    return out


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SY0-701 4.6 Provisioning/de-provisioning and attestation · 5.1 Owners · 4.2 Account inventory.",
    "concepts": [
        "HR is the authoritative source; aggregation pulls every app's accounts, correlation links each to a person.",
        "An entitlement is one permission; an access profile bundles one app's entitlements; a role bundles profiles for a job.",
        "Orphaned, dormant and terminated-but-enabled accounts are de-provisioning failures an attacker can reuse.",
        "Access certification (attestation) has the manager or entitlement owner re-approve access on a schedule.",
        "These are the same concepts SailPoint and Entra ID Governance use, shown here with generic terms.",
    ],
    "failure_modes": [
        "Leaver process disables the directory account but not the ERP or SaaS accounts.",
        "Service accounts created for a project with no owner, still privileged years later.",
        "Reviewers approving everything in seconds: the certification becomes paperwork, not a control.",
        "Treating an undecided item as 'keep' so access survives because nobody looked at it.",
    ],
    "ai_governance": [
        "An AI agent can aggregate and correlate accounts, but revoking access stays a human-approved, logged change.",
        "Give an agent a service account with a named human owner and least privilege, then certify it like any other.",
        "Agents that recommend approve/revoke must show reasons; a reviewer who just accepts them is rubber-stamping.",
        "Treat comments and attributes in app exports as untrusted data, never as instructions to the agent.",
    ],
    "exam_tips": [
        "'Account still active after the employee left' = de-provisioning failure; fix with HR-driven automation.",
        "'Periodic review where managers confirm access' = attestation / access recertification.",
        "Least privilege: when a reviewer does not respond, remove the access (deny by default).",
        "Data/system owner decides who gets access; the custodian implements it.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    cfg = policies["identity_governance_iga"]
    accounts = reconcile(data, cfg)
    items, metrics = certify(data, cfg)
    ui.section("Step 1 — Aggregate and correlate accounts to the HR authoritative source")
    ui.table("Account reconciliation", ["ID", "App", "Account", "Identity", "Rule", "Finding", "Action"],
             [[a.id, a.app, a.account, a.identity or "-", a.rule or "-", a.finding, a.action] for a in accounts])
    for a in accounts:
        if a.finding != "CORRELATED" or len(a.reasons) > 1:
            ui.bullet(f"{a.id} {a.app}/{a.account}: " + "; ".join(a.reasons),
                      style="dim" if a.finding == "CORRELATED" else "yellow")
    ui.section("Step 2 — Access certification campaign")
    ui.table(data.get("campaign", {}).get("name", "Campaign"), ["ID", "Identity", "Entitlement", "Reviewer", "Outcome"],
             [[r.id, r.identity, r.entitlement, r.reviewer, r.outcome] for r in items])
    for r in items:
        ui.bullet(f"{r.id} → {r.outcome}: " + "; ".join(r.reasons),
                  style={"KEEP": "green", "REVOKE": "red"}.get(r.outcome, "yellow"))
    ui.status("Completion", "PASS" if metrics["completion_pct"] == 100 else "WARN", f"{metrics['completion_pct']}%")
    ui.print(f"Revocation rate {metrics['revocation_rate_pct']}% · rubber-stamp reviewers: "
             f"{', '.join(metrics['rubber_stamp_reviewers']) or 'none'}")
    ui.section("Step 3 — Remediation (de-provisioning) list")
    for line in remediation(accounts, items):
        ui.bullet(line)
    ui.insight(INSIGHT)
    return {"accounts": {a.id: a.finding for a in accounts}, "items": {r.id: r.outcome for r in items},
            "metrics": metrics}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["identity_governance_iga"]
    camp = cfg["campaign"]
    accounts = reconcile(data, cfg)
    items, metrics = certify(data, cfg)
    raw = {a["id"]: a for a in data.get("accounts", [])}
    by_id = {i["employee_id"]: i for i in data.get("identities", [])}
    qs: list = []
    done = set()
    for a in accounts:
        if a.finding in done:
            continue
        done.add(a.finding)
        src = {k: v for k, v in raw[a.id].items() if k != "id"}
        ctx = f"account={src}\nHR: " + (f"{by_id[a.identity]}" if a.identity else "no matching identity")
        qs.append(Question(prompt=f"{a.id}: which reconciliation finding does this account get (most severe)?",
                           context=ctx, choices=choices_with(a.finding, FINDINGS, exclude=a.findings, key=a.id),
                           answer=a.finding, explanation="; ".join(a.reasons), objective="4.6"))
    for a in accounts:
        if a.rule == "email":
            qs.append(Question(prompt=f"{a.id} {a.app}/{a.account}: which correlation rule linked it to an identity?",
                               context=f"account={raw[a.id]}",
                               choices=[r["name"] for r in cfg["correlation_rules"]] + ["owner", "no match"],
                               answer="email", explanation="no employee_id on the account, so the next rule (email) "
                               "matched", objective="4.2"))
            break
    for r in items:
        qs.append(Question(prompt=f"{r.id}: what is the certification outcome?",
                           context=f"item={next(i for i in data['campaign']['items'] if i['id'] == r.id)}",
                           choices=OUTCOMES, answer=r.outcome, explanation="; ".join(r.reasons), objective="4.6"))
    reviewers = sorted({r.reviewer for r in items if r.reviewer != "-"})
    for s in metrics["rubber_stamp_reviewers"][:1]:
        qs.append(Question(prompt="Which reviewer is flagged for rubber-stamping?",
                           choices=choices_with(s, reviewers, exclude=metrics["rubber_stamp_reviewers"]), answer=s,
                           explanation=f"≥ {camp['rubber_stamp']['min_approvals']} approvals with a median decision "
                                       f"time under {camp['rubber_stamp']['max_median_seconds']}s", objective="4.6"))
    qs.append(Question(prompt="An item still has no decision when the campaign closes. What happens?",
                       choices=OUTCOMES, answer=camp["no_decision_action"],
                       explanation="deny by default: unattested access is removed (least privilege)", objective="4.6"))
    qs.append(Question(prompt="Why is a 100% approval rate in two minutes a red flag?",
                       choices=["the reviewer is rubber-stamping instead of really attesting",
                                "the campaign finished early, which proves the access is correct",
                                "fast reviewers are more accurate than slow ones",
                                "approvals only count when the reviewer is the identity itself"],
                       answer="the reviewer is rubber-stamping instead of really attesting",
                       explanation="no one can judge each entitlement in seconds; flag and re-review", objective="4.6"))
    qs.append(Question(prompt="Who may certify a person's access under this policy?",
                       choices=["their manager or the entitlement owner", "the person themselves",
                                "any IT administrator", "the help desk"],
                       answer="their manager or the entitlement owner",
                       explanation="owners decide access (5.1); self-review defeats separation of duties",
                       objective="5.1"))
    for term in ("entitlement", "access profile", "role", "correlation"):
        if term in cfg["concepts"]:
            qs.append(Question(prompt=f"Which term is this? \"{cfg['concepts'][term]}\"",
                               choices=sorted(cfg["concepts"]), answer=term, explanation=cfg["concepts"][term],
                               objective="4.6"))
    qs.append(Question(prompt="What is an orphaned account?",
                       choices=sorted({cfg["finding_definitions"][f] for f in ("ORPHAN", "DORMANT", "DUPLICATE")}),
                       answer=cfg["finding_definitions"]["ORPHAN"], explanation="ORPHAN accounts have no accountable "
                       "owner and are disabled, then investigated", objective="4.6"))
    return qs
