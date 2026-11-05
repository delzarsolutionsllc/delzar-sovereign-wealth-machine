"""
Lab 25 — Conditional Access & Just-in-Time Privileged Access
============================================================

Security+ SY0-701 objectives
----------------------------
* 4.6  Identity and access management: multifactor authentication,
       attribute-based / conditional access, least privilege, privileged
       access management tools (just-in-time permissions, password vaulting,
       ephemeral credentials).
* 1.2  Zero trust: adaptive identity, policy-driven access control, Policy
       Engine (decides) and Policy Enforcement Point (enforces).
* 2.4  Indicators of malicious activity: impossible travel, concurrent
       session usage.

Model
-----
Part 1 is a Conditional Access evaluator (the same model as Microsoft Entra
Conditional Access, written with generic names). A policy *applies* to a
sign-in when its users, apps and every condition match (sign-in risk, device
platform, named/trusted location, client app type). Exclusions beat
inclusions. Then:

* every applicable policy is evaluated; ANY applicable block wins → BLOCK;
* otherwise the grant requirements of ALL applicable policies must be met
  (AND across policies; inside one policy "require one of" or "require all");
* only MFA is missing → INTERRUPTED_MFA_REQUIRED (the user is prompted);
  any other control missing (e.g. compliant device) → BLOCK;
* met, and MFA was one of the requirements → ALLOW_AFTER_MFA, else ALLOW;
* report-only policies are evaluated and logged ("would have ..."), never enforced;
* no enforced policy applies → ALLOW with a coverage-gap flag for sensitive
  apps, or BLOCK for apps listed in ``block_if_no_policy_for`` (deny by default).

Missing data is unsafe: unknown risk = high, unknown client app = legacy,
missing device compliance / MFA / approved app / terms of use = not satisfied.

Part 2 is just-in-time privileged role activation (PIM-style). Requests are
APPROVE / PENDING_APPROVAL / DENY from per-role settings (eligibility, max
duration, justification, ticket, MFA on activation, approval by someone
other than the requester). Permanent active admin roles are standing-privilege
findings; break-glass accounts must be excluded from every policy and alerted on.

Run it
------
    python main.py lab 25
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

TITLE = "Lab 25 — Conditional Access & Just-in-Time Privileged Access"
OBJECTIVES = ("SY0-701 4.6 IAM: MFA, conditional access, least privilege, PAM (JIT, vaulting, ephemeral credentials)"
              " · 1.2 Zero trust adaptive identity, policy engine/enforcement · 2.4 Impossible travel, concurrent sessions")
SIGNIN_OUTCOMES = ["ALLOW", "ALLOW_AFTER_MFA", "INTERRUPTED_MFA_REQUIRED", "BLOCK"]
ACTIVATION_DECISIONS = ["APPROVE", "PENDING_APPROVAL", "DENY"]
DECISIONS = SIGNIN_OUTCOMES + ACTIVATION_DECISIONS
ASSIGNMENT_VERDICTS = ["STANDING_PRIVILEGE", "BREAK_GLASS_OK", "BREAK_GLASS_FINDING", "TIME_BOUND"]


@dataclass
class SignInResult:
    id: str
    user: str
    app: str
    location: str
    outcome: str
    applied: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    report_only: dict = field(default_factory=dict)        # policy name -> would-be outcome
    session: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)


@dataclass
class Activation:
    id: str
    user: str
    role: str
    decision: str
    reasons: list[str] = field(default_factory=list)


@dataclass
class AssignmentFinding:
    user: str
    role: str
    verdict: str
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Part 1 — Conditional Access
# --------------------------------------------------------------------------- #
def resolve_location(ip, cfg: dict) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except (TypeError, ValueError):
        return "unknown"
    for name, nets in cfg["named_locations"].items():
        if any(addr in ipaddress.ip_network(n) for n in nets):
            return name
    return "untrusted"


def _loc_match(entries, loc: str, cfg: dict) -> bool:
    trusted = loc in cfg["trusted_locations"]
    return any(e == "any" or (e == "trusted" and trusted) or e == loc for e in entries)


def policy_applies(p: dict, s: dict, cfg: dict) -> tuple[bool, str]:
    """Does policy p apply to sign-in s? Returns (applies, why)."""
    who = {s.get("user"), *s.get("groups", [])}
    users, apps, cond = p.get("users", {}), p.get("apps", {}), p.get("conditions", {})
    if who & set(users.get("exclude", [])):
        return False, f"excluded ({', '.join(sorted(who & set(users['exclude'])))})"
    if "all" not in users.get("include", []) and not who & set(users.get("include", [])):
        return False, "user/group not included"
    if s.get("app") in apps.get("exclude", []):
        return False, "app excluded"
    if "all" not in apps.get("include", []) and s.get("app") not in apps.get("include", []):
        return False, "app not targeted"
    risk = s.get("risk") if s.get("risk") in cfg["risk_levels"] else "high"
    if "sign_in_risk" in cond and risk not in cond["sign_in_risk"]:
        return False, f"risk '{risk}' not in {cond['sign_in_risk']}"
    platform = s.get("device", {}).get("platform", "unknown")
    if "platforms" in cond and platform not in cond["platforms"]:
        return False, f"platform '{platform}' not targeted"
    loc = resolve_location(s.get("ip"), cfg)
    if "locations" in cond:
        if not _loc_match(cond["locations"].get("include", ["any"]), loc, cfg):
            return False, f"location '{loc}' not included"
        if _loc_match(cond["locations"].get("exclude", []), loc, cfg):
            return False, f"location '{loc}' is excluded (trusted)"
    client = cfg["client_app_categories"].get(s.get("client_app"), "legacy")
    if "client_apps" in cond and client not in cond["client_apps"]:
        return False, f"client app type '{client}' not targeted"
    return True, "all assignments and conditions match"


def control_ok(control: str, s: dict) -> bool:
    return {"mfa": s.get("mfa_satisfied"), "compliant_device": s.get("device", {}).get("compliant"),
            "approved_app": s.get("approved_app"), "terms_of_use": s.get("tou_accepted")}.get(control) is True


def grant_outcome(pols: list[dict], s: dict) -> tuple[str, list[str]]:
    """Combine the grant controls of several applicable policies (block wins, then AND)."""
    blocks = [p["name"] for p in pols if p.get("grant", {}).get("block") or not p.get("grant", {}).get("require")]
    if blocks:
        return "BLOCK", [f"{n}: block control (any applicable block wins)" for n in blocks]
    reasons, missing_all, mfa_used = [], [], False
    for p in pols:
        req, one = p["grant"]["require"], p["grant"].get("operator", "all") == "one"
        met = [c for c in req if control_ok(c, s)]
        ok = bool(met) if one else len(met) == len(req)
        mfa_used |= "mfa" in met
        label = ("one of " if one else "all of ") + ", ".join(req)
        if ok:
            reasons.append(f"{p['name']}: requires {label} → satisfied ({', '.join(met)})")
        else:
            missing = req if one else [c for c in req if c not in met]
            missing_all.append((one, req, missing))
            reasons.append(f"{p['name']}: requires {label} → NOT satisfied (missing {', '.join(missing)})")
    if not missing_all:
        return ("ALLOW_AFTER_MFA" if mfa_used else "ALLOW"), reasons
    if all(("mfa" in req) if one else missing == ["mfa"] for one, req, missing in missing_all):
        return "INTERRUPTED_MFA_REQUIRED", reasons + ["only MFA is missing: user is prompted to complete MFA"]
    return "BLOCK", reasons + ["a required control other than MFA cannot be met in this sign-in"]


def evaluate_signin(s: dict, cfg: dict, break_glass=frozenset(), alerted=frozenset()) -> SignInResult:
    loc = resolve_location(s.get("ip"), cfg)
    r = SignInResult(s.get("id", "?"), s.get("user", "?"), s.get("app", "?"), loc, "BLOCK")
    if not s.get("user") or not s.get("app"):
        r.reasons.append("missing user or app: denied by default")
        return r
    if s.get("risk") not in cfg["risk_levels"]:
        r.reasons.append("sign-in risk missing/unknown: treated as high")
    on, ro = [], []
    for p in cfg["policies"]:
        state = p.get("state", "on")
        if state == "off" or not policy_applies(p, s, cfg)[0]:
            continue
        (ro if state == "report_only" else on).append(p)
    for p in ro:
        r.report_only[p["name"]] = grant_outcome([p], s)[0]
    r.applied = [p["name"] for p in on]
    r.session = [f"{p['name']}: sign-in frequency {p['session']['sign_in_frequency_hours']}h"
                 for p in on if p.get("session", {}).get("sign_in_frequency_hours")]
    if on:
        r.outcome, more = grant_outcome(on, s)
        r.reasons += more
    elif s["app"] in cfg["block_if_no_policy_for"]:
        r.reasons.append(f"no policy applies and '{s['app']}' is in block_if_no_policy_for: deny by default")
    else:
        r.outcome = "ALLOW"
        r.reasons.append("no enforced policy applies: allowed with primary authentication only")
        if s["app"] in cfg["sensitive_apps"] and s["user"] not in break_glass:
            r.flags.append(f"COVERAGE GAP: sensitive app '{s['app']}' reached with no Conditional Access policy")
    if s["user"] in break_glass:
        r.flags.append("break-glass account used: emergency sign-in must alert the SOC and be reviewed"
                       + ("" if s["user"] in alerted else " (NO ALERT RULE CONFIGURED)"))
    return r


def detect_indicators(signins: list[dict], cfg: dict) -> dict:
    """Impossible travel (different country within N min) and concurrent sessions (different IP within M min)."""
    ind, flags, last = cfg["indicators"], {}, {}
    for s in sorted(signins, key=lambda x: (str(x.get("user")), x.get("minute", 0))):
        prev = last.get(s.get("user"))
        if prev:
            gap = s.get("minute", 0) - prev.get("minute", 0)
            if s.get("country") != prev.get("country") and gap <= ind["impossible_travel_minutes"]:
                flags.setdefault(s["id"], []).append(f"IMPOSSIBLE TRAVEL: {prev.get('country')} → {s.get('country')} "
                                                     f"in {gap} min (after {prev['id']})")
            elif s.get("ip") != prev.get("ip") and gap <= ind["concurrent_session_minutes"]:
                flags.setdefault(s["id"], []).append(f"CONCURRENT SESSIONS: {prev['id']} and {s['id']} from different IPs")
        last[s.get("user")] = s
    return flags


def evaluate_all(data: dict, policies: dict) -> list[SignInResult]:
    cfg = policies["conditional_access"]
    bg = data.get("break_glass_accounts", [])
    users, alerted = {b["user"] for b in bg}, {b["user"] for b in bg if b.get("alert_on_signin")}
    ind = detect_indicators(data["signins"], cfg)
    out = []
    for s in data["signins"]:
        r = evaluate_signin(s, cfg, frozenset(users), frozenset(alerted))
        r.flags += ind.get(r.id, [])
        out.append(r)
    return out


def what_if(s: dict, cfg: dict) -> list[list[str]]:
    """Per-policy what-if rows: [policy, state, applies?, why, would-be result]."""
    rows = []
    for p in cfg["policies"]:
        ok, why = policy_applies(p, s, cfg)
        if p.get("state", "on") == "off":
            ok, why = False, "policy is off: never evaluated"
        rows.append([p["name"], p.get("state", "on"), "yes" if ok else "no", why,
                     grant_outcome([p], s)[0] if ok else "-"])
    return rows


# --------------------------------------------------------------------------- #
# Part 2 — Just-in-time privileged access
# --------------------------------------------------------------------------- #
def decide_activation(req: dict, cfg: dict, assignments: list[dict]) -> Activation:
    a = Activation(req.get("id", "?"), req.get("user", "?"), req.get("role", "?"), "DENY")
    rs = cfg["role_settings"].get(req.get("role"))
    if rs is None:
        a.reasons.append(f"no activation settings for role '{req.get('role')}': denied by default")
        return a
    if not any(x.get("user") == req.get("user") and x.get("role") == req.get("role") and x.get("type") == "eligible"
               for x in assignments):
        a.reasons.append("user is not ELIGIBLE for this role: only eligible users can activate")
        return a
    deny = []
    hours = req.get("duration_hours")
    if not isinstance(hours, (int, float)) or hours <= 0 or hours > rs["max_hours"]:
        deny.append(f"duration {hours}h is outside 1-{rs['max_hours']}h allowed for this role")
    if rs["require_justification"] and not str(req.get("justification", "")).strip():
        deny.append("justification required but missing")
    if rs["require_ticket"] and not str(req.get("ticket", "")).strip():
        deny.append("ticket number required but missing")
    if rs["require_mfa"] and req.get("mfa_done") is not True:
        deny.append("MFA on activation required but not completed")
    approver = req.get("approver")
    if rs["require_approval"] and approver:
        if approver == req.get("user"):
            deny.append("requester cannot approve their own activation (separation of duties)")
        elif approver not in rs["approvers"]:
            deny.append(f"'{approver}' is not an authorised approver for this role")
    if deny:
        a.reasons = deny
    elif rs["require_approval"] and not approver:
        a.decision = "PENDING_APPROVAL"
        a.reasons.append(f"high-privilege role: waiting for approval by one of {rs['approvers']}")
    else:
        a.decision = "APPROVE"
        a.reasons.append(f"activated for {hours}h, then removed automatically (just-in-time)"
                         + (f"; approved by {approver}" if rs["require_approval"] else ""))
    return a


def assess_assignments(data: dict, policies: dict) -> list[AssignmentFinding]:
    cfg = policies["conditional_access"]
    bg = {b["user"]: b for b in data.get("break_glass_accounts", [])}
    out = []
    for x in data.get("assignments", []):
        if x.get("type") != "active":
            continue
        if x["user"] in bg:
            b, problems = bg[x["user"]], []
            who = {b["user"], *b.get("groups", [])}
            not_excluded = [p["name"] for p in cfg["policies"] if p.get("state") != "off"
                            and ("all" in p["users"].get("include", []) or who & set(p["users"].get("include", [])))
                            and not who & set(p["users"].get("exclude", []))]
            if not_excluded:
                problems.append(f"not excluded from {len(not_excluded)} policies (lockout risk), e.g. {not_excluded[0]}")
            if not b.get("alert_on_signin"):
                problems.append("no sign-in alert: emergency account use would go unnoticed")
            out.append(AssignmentFinding(x["user"], x["role"], "BREAK_GLASS_FINDING" if problems else "BREAK_GLASS_OK",
                                         problems or ["excluded from every policy and alerted on use: correct"]))
        elif x.get("permanent") is not False and not x.get("end_day") and x["role"] in cfg["privileged_roles"]:
            out.append(AssignmentFinding(x["user"], x["role"], "STANDING_PRIVILEGE",
                                         ["permanent active privileged role: convert to eligible (just-in-time)"]))
        else:
            out.append(AssignmentFinding(x["user"], x["role"], "TIME_BOUND",
                                         [f"active until day {x.get('end_day')} or not privileged: acceptable"]))
    return out


def decide_all(data: dict, policies: dict) -> list[Activation]:
    cfg = policies["conditional_access"]
    return [decide_activation(r, cfg, data.get("assignments", [])) for r in data.get("activation_requests", [])]


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SY0-701 4.6 Conditional access, MFA, least privilege, PAM (JIT) · 1.2 Adaptive identity, PE/PEP · 2.4 Impossible travel.",
    "concepts": [
        "Conditional access is if-then policy: IF user, app, risk, device, location and client app match, THEN block or require controls.",
        "All applicable policies are combined: any block wins, otherwise every required control from every policy must be met.",
        "Exclusions beat inclusions; report-only mode logs what a policy would do before you enforce it.",
        "PAM: just-in-time permissions replace standing admin roles; password vaulting and ephemeral credentials limit what can be stolen.",
        "Same model as Microsoft Entra Conditional Access / PIM (SC-300), described here with generic terms.",
    ],
    "failure_modes": [
        "Leaving legacy authentication (IMAP/POP/basic SMTP) open: it cannot do MFA, so password spraying bypasses MFA policies.",
        "Permanent Global Administrator assignments that an attacker inherits the moment one account is phished.",
        "Locking everyone out with a new policy because break-glass accounts were not excluded (or testing without report-only).",
        "Assuming 'no policy matched' means 'blocked': without a deny-by-default rule it means allowed with a password only.",
        "Letting requesters approve their own privileged activation.",
    ],
    "ai_governance": [
        "Give AI agents eligible, time-boxed roles: they activate a scope for one task and lose it automatically afterwards.",
        "An agent's own identity should face conditional access too (workload identity, trusted location, short-lived tokens).",
        "An agent may draft activation requests, but a human approver who is not the requester must approve high-privilege roles.",
        "Run new agent access policies in report-only mode first and review the 'would have blocked' log.",
    ],
    "exam_tips": [
        "'Access changes based on location, device health and risk' = conditional / context-aware access, adaptive identity.",
        "'Admin rights granted only for the time needed, then revoked' = just-in-time permissions (PAM).",
        "'Credentials that exist for one session' = ephemeral credentials; 'checked out from a vault' = password vaulting.",
        "Two logins from distant countries minutes apart = impossible travel (an indicator of compromised credentials).",
        "Policy Engine decides, Policy Enforcement Point enforces; conditional access is the policy engine for sign-ins.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    cfg = policies["conditional_access"]
    res = evaluate_all(data, policies)
    ui.section("Step 1 — Conditional Access policies")
    ui.table("Policies", ["Policy", "State", "Grant"],
             [[p["name"], p.get("state", "on"), "block" if p["grant"].get("block") else
               f"{p['grant'].get('operator', 'all')} of {', '.join(p['grant'].get('require', []))}"]
              for p in cfg["policies"]])
    ui.section("Step 2 — Sign-in outcomes")
    ui.table("Sign-ins", ["ID", "User", "App", "Location", "Applied (enforced)", "Outcome"],
             [[r.id, r.user, r.app, r.location, ", ".join(n.split()[0] for n in r.applied) or "none", r.outcome]
              for r in res])
    for r in res:
        ui.print(f"[bold]{r.id} {r.user} → {r.app}[/bold]: {r.outcome}")
        for x in r.reasons:
            ui.bullet(x)
        for n, o in r.report_only.items():
            ui.bullet(f"REPORT-ONLY {n} would have: {o} (not enforced)", style="yellow")
        for x in r.session:
            ui.bullet(f"session control: {x}", style="dim")
        for x in r.flags:
            ui.bullet(x, style="red")
    pick = next((s for s in data["signins"] if evaluate_signin(s, cfg).report_only), data["signins"][0])
    ui.section(f"Step 3 — What-if for {pick.get('id')} ({pick.get('user')} → {pick.get('app')})")
    ui.table("What-if", ["Policy", "State", "Applies", "Why", "Result alone"], what_if(pick, cfg))
    ui.section("Step 4 — Standing privilege and break-glass accounts")
    found = assess_assignments(data, policies)
    ui.table("Active assignments", ["User", "Role", "Verdict", "Reason"],
             [[f.user, f.role, f.verdict, "; ".join(f.reasons)] for f in found])
    ui.section("Step 5 — Just-in-time role activation")
    acts = decide_all(data, policies)
    for a in acts:
        ui.status(f"{a.id} {a.user} → {a.role}", a.decision, "; ".join(a.reasons))
    ui.insight(INSIGHT)
    return {"signins": {r.id: r.outcome for r in res},
            "report_only": {r.id: r.report_only for r in res if r.report_only},
            "assignments": {f"{f.user}:{f.role}": f.verdict for f in found},
            "activations": {a.id: a.decision for a in acts}}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def _semantics_questions(cfg: dict) -> list:
    """Plain-language concept questions whose answers are computed by running the engine."""
    from utils.challenge import Question

    base = {"id": "T", "user": "u1", "groups": ["Staff"], "app": "Wiki", "ip": "10.20.0.5", "risk": "low",
            "client_app": "browser", "device": {"platform": "windows", "compliant": False}, "mfa_satisfied": True}
    mfa = {"name": "P-A require MFA", "users": {"include": ["all"]}, "apps": {"include": ["all"]},
           "grant": {"require": ["mfa"]}}
    dev = {"name": "P-B require compliant device", "users": {"include": ["all"]}, "apps": {"include": ["all"]},
           "grant": {"require": ["compliant_device"]}}
    blk = {"name": "P-C block", "users": {"include": ["all"], "exclude": ["u1"]}, "apps": {"include": ["all"]},
           "grant": {"block": True}}
    run = lambda pols, s=base: evaluate_signin(s, {**cfg, "policies": pols, "block_if_no_policy_for": []}).outcome
    texts = {"BLOCK": "Access is blocked", "ALLOW": "Access is allowed",
             "ALLOW_AFTER_MFA": "Access is allowed after MFA", "INTERRUPTED_MFA_REQUIRED": "The user is prompted for MFA"}
    ch = sorted(texts.values())
    cases = [
        ("Two applicable policies require different controls: one MFA, one a compliant device. The user did MFA "
         "but the laptop is NOT compliant. What happens?", [mfa, dev], base,
         "Requirements are combined with AND across policies: every policy's controls must be met."),
        ("One applicable policy requires MFA (completed) and another applicable policy blocks. What happens?",
         [mfa, {**blk, "users": {"include": ["all"]}}], base, "Any applicable block wins over every grant."),
        ("A user is in a policy's include list (all users) AND its exclude list. The policy blocks. What happens?",
         [blk], base, "Exclusions beat inclusions, so the block policy does not apply; nothing else applies."),
        ("The only matching policy blocks, but it is in report-only mode. What happens to the sign-in?",
         [{**blk, "users": {"include": ["all"]}, "state": "report_only"}], base,
         "Report-only policies are logged as 'would have blocked' but never enforced."),
    ]
    return [Question(prompt=p, choices=ch, answer=texts[run(pols, s)], explanation=e, objective="4.6")
            for p, pols, s, e in cases]


def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["conditional_access"]
    qs: list = []
    for s, r in zip(data["signins"], evaluate_all(data, policies)):
        ctx = (f"{s.get('user')} groups={s.get('groups')} app={s.get('app')} ip={s.get('ip')} ({r.location}) "
               f"device={s.get('device')} client={s.get('client_app')} risk={s.get('risk', 'missing')} "
               f"mfa={s.get('mfa_satisfied')} approved_app={s.get('approved_app')} tou={s.get('tou_accepted')}")
        qs.append(Question(prompt=f"{r.id}: what is the Conditional Access outcome?", context=ctx,
                           choices=SIGNIN_OUTCOMES, answer=r.outcome, explanation="; ".join(r.reasons), objective="4.6"))
        if r.outcome == "BLOCK" and len(r.applied) == 1:
            names = [p["name"] for p in cfg["policies"]]
            qs.append(Question(prompt=f"{r.id}: which policy blocked this sign-in?", context=ctx,
                               choices=choices_with(r.applied[0], names, key=r.id), answer=r.applied[0],
                               explanation=r.reasons[0], objective="4.6"))
        for n, o in r.report_only.items():
            qs.append(Question(prompt=f"{r.id}: the report-only policy '{n}' matched. What does it do to this sign-in?",
                               context=ctx, choices=[f"Nothing enforced; logs 'would have {o}'", f"Enforces {o}",
                                                     "Blocks the user permanently"],
                               answer=f"Nothing enforced; logs 'would have {o}'",
                               explanation="report-only policies are evaluated and logged but never enforced", objective="1.2"))
        for f in r.flags:
            if f.startswith(("IMPOSSIBLE TRAVEL", "CONCURRENT")):
                ans = "Impossible travel" if f.startswith("IMPOSSIBLE") else "Concurrent session usage"
                qs.append(Question(prompt=f"{r.id}: which indicator of compromise does this sign-in show?",
                                   context=ctx + f"\nprevious: {f}", choices=sorted({ans, "Impossible travel",
                                   "Concurrent session usage", "Resource consumption", "Account lockout"}),
                                   answer=ans, explanation=f, objective="2.4"))
    for a in decide_all(data, policies):
        req = next(x for x in data["activation_requests"] if x.get("id") == a.id)
        rs = cfg["role_settings"].get(a.role, {})
        qs.append(Question(prompt=f"{a.id}: {a.user} asks to activate '{a.role}'. Decision?",
                           context=f"request={ {k: v for k, v in req.items() if k != 'id'} }\nrole settings={rs}",
                           choices=ACTIVATION_DECISIONS, answer=a.decision, explanation="; ".join(a.reasons),
                           objective="4.6"))
    for f in assess_assignments(data, policies):
        qs.append(Question(prompt=f"Active assignment {f.user} → {f.role}: what is the verdict?",
                           context=f"break-glass accounts: {data.get('break_glass_accounts', [])}",
                           choices=ASSIGNMENT_VERDICTS, answer=f.verdict, explanation="; ".join(f.reasons),
                           objective="4.6"))
    for term, definition in sorted(cfg["concepts"].items()):
        qs.append(Question(prompt=f"Which term is this? \"{definition}\"",
                           choices=choices_with(term, cfg["concepts"], k=3, key=term), answer=term,
                           explanation=f"{term}: {definition}", objective="1.2" if term == "adaptive identity" else "4.6"))
    return qs + _semantics_questions(cfg)
