"""
Lab 27 — Entitlement Management: Access Packages & Assignment Policies
=====================================================================

SC-300 objectives
-----------------
* 4.1  Plan and implement entitlement management: catalogs, access packages,
       assignment policies (who can request, approval, expiration, access
       reviews), connected organizations, separation of duties.
* 1.3  Implement and manage identities for external users and tenants:
       connected organizations, external user lifecycle (block, then remove).

The setting
-----------
Microsoft Entra entitlement management (part of Microsoft Entra ID
Governance) lets people request the access they need instead of filing a
ticket. Resources (groups, applications, SharePoint sites) live in a
**catalog**; an **access package** bundles resource roles from one catalog;
each package has one or more **assignment policies** that say who can
request it, who approves, whether a justification is needed, when access
expires and how often it is reviewed. This module is a generic rule engine
that follows that model; it is not the Microsoft implementation.

How it works
------------
Access requests are evaluated in this order (first match decides):

1. Unknown requester → DENIED (deny by default).
2. Unknown access package or catalog → DENIED (deny by default).
3. Requester scope: the first assignment policy whose scope includes the
   requester is used. ``internal_users`` = members only;
   ``connected_organizations`` = externals from the listed organizations;
   ``all_connected_organizations`` = externals from organizations in the
   *configured* state (a *proposed* organization does not count);
   ``any_external`` = any external user; ``admin_only`` = nobody.
   No policy fits → DENIED (not in scope).
4. An external requester and a catalog not enabled for external users →
   DENIED.
5. Separation of duties: the requester already holds an active assignment
   to a package listed as *incompatible* on the requested package → DENIED.
   The check uses the requested package's list only, so a one-way
   incompatibility leaves a gap (reported in the package audit).
6. Justification required and missing or shorter than the policy minimum →
   DENIED.
7. Approval: no stages → AUTO_APPROVED. Otherwise each stage's approvers are
   resolved (``manager``, ``internal_sponsor``, ``external_sponsor`` or a
   user id); the requester is always removed (nobody approves their own
   request); an empty stage uses its fallback approvers; still empty →
   DENIED (``approver_is_requester`` if the requester was the only
   candidate, else ``no_approver``). All stages resolved → PENDING_APPROVAL.

Assignment lifecycle: unknown user or package → INVALID; ended early →
REMOVED; end date passed → EXPIRED; ends within ``expiring_soon_days`` →
EXPIRING_SOON; otherwise (or no end date) → ACTIVE.

External user lifecycle (in-directory guests only): any ACTIVE or
EXPIRING_SOON assignment → GUEST_ACTIVE; guest not added by entitlement
management → GUEST_NOT_MANAGED; last assignment ended less than
``guest_removal_after_days`` ago → GUEST_BLOCKED (blocked from sign-in);
otherwise, or no assignment history at all → GUEST_REMOVAL_DUE.

Run it
------
    python main.py --course sc300 lab 27
"""

from __future__ import annotations

from dataclasses import dataclass, field

TITLE = "Lab 27 — Entitlement Management: Access Packages & Assignment Policies"
OBJECTIVES = "SC-300 4.1 Entitlement management · 1.3 Identities for external users and tenants"
COURSES = ("sc300",)

REQUEST_OUTCOMES = ["AUTO_APPROVED", "PENDING_APPROVAL", "DENIED"]
DENY_RULES = ["unknown_requester", "unknown_package", "not_in_scope", "catalog_not_external", "sod_conflict",
              "missing_justification", "approver_is_requester", "no_approver"]
ALLOW_RULES = ["auto_approval", "single_stage", "two_stage"]
ASSIGNMENT_OUTCOMES = ["ACTIVE", "EXPIRING_SOON", "EXPIRED", "REMOVED", "INVALID"]
GUEST_OUTCOMES = ["GUEST_ACTIVE", "GUEST_BLOCKED", "GUEST_REMOVAL_DUE", "GUEST_NOT_MANAGED"]
PACKAGE_RISKS = ["CATALOG_NOT_EXTERNAL", "EXTERNAL_NO_REVIEW", "EXTERNAL_AUTO_APPROVE", "NO_EXPIRY", "NO_FALLBACK",
                 "SOD_ONE_WAY", "TOO_MANY_STAGES", "UNKNOWN_RESOURCE"]
EXTERNAL_SCOPES = ("connected_organizations", "all_connected_organizations", "any_external")


@dataclass
class RequestResult:
    id: str
    requester: str
    package: str
    outcome: str
    rule: str
    policy: str | None = None
    approvers: list[list[str]] = field(default_factory=list)   # one list per stage
    reasons: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)


@dataclass
class AssignmentResult:
    id: str
    user: str
    package: str
    outcome: str
    reasons: list[str] = field(default_factory=list)


@dataclass
class GuestResult:
    user: str
    organization: str | None
    outcome: str
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Lookups
# --------------------------------------------------------------------------- #
def _index(items) -> dict:
    return {i["id"]: i for i in items or [] if isinstance(i, dict) and i.get("id")}


def _ctx(data: dict) -> dict:
    return {"users": _index(data.get("users")), "orgs": _index(data.get("connected_organizations")),
            "catalogs": _index(data.get("catalogs")), "packages": _index(data.get("access_packages"))}


def is_external(user: dict) -> bool:
    # Anything that is not explicitly a member is treated as external (the stricter scope).
    return user.get("type") != "member"


# --------------------------------------------------------------------------- #
# Part 1 — package configuration audit
# --------------------------------------------------------------------------- #
def audit_packages(data: dict, cfg: dict) -> dict[str, list[tuple[str, str]]]:
    """package id -> [(risk, reason)]; an empty list means no configuration risk found."""
    c = _ctx(data)
    out: dict[str, list[tuple[str, str]]] = {}
    for pid, pkg in c["packages"].items():
        risks: list[tuple[str, str]] = []
        cat = c["catalogs"].get(pkg.get("catalog"), {})
        in_catalog = {r.get("id") for r in cat.get("resources", [])}
        for rid in pkg.get("resources", []):
            if rid not in in_catalog:
                risks.append(("UNKNOWN_RESOURCE", f"resource {rid} is not in catalog {pkg.get('catalog')}"))
        for pol in pkg.get("policies", []):
            pname = pol.get("id", "?")
            scope = (pol.get("scope") or {}).get("type")
            stages = (pol.get("approval") or {}).get("stages", [])
            if scope in EXTERNAL_SCOPES:
                if not cat.get("enabled_for_external_users"):
                    risks.append(("CATALOG_NOT_EXTERNAL", f"{pname} targets external users but catalog "
                                  f"{pkg.get('catalog')} is not enabled for external users"))
                if not pol.get("access_review"):
                    risks.append(("EXTERNAL_NO_REVIEW", f"{pname} lets external users in with no recurring "
                                  "access review"))
                if not stages:
                    risks.append(("EXTERNAL_AUTO_APPROVE", f"{pname} auto-approves external users"))
            if pol.get("expiry_days") is None and scope != "admin_only":
                risks.append(("NO_EXPIRY", f"{pname} assignments never expire"))
            if len(stages) > cfg["max_approval_stages"]:
                risks.append(("TOO_MANY_STAGES", f"{pname} has {len(stages)} stages; this policy allows "
                              f"{cfg['max_approval_stages']}"))
            for n, st in enumerate(stages, 1):
                if not st.get("fallback"):
                    risks.append(("NO_FALLBACK", f"{pname} stage {n} has no fallback approver"))
        for other_id, other in c["packages"].items():
            if pid in other.get("incompatible_packages", []) and other_id not in pkg.get("incompatible_packages", []):
                risks.append(("SOD_ONE_WAY", f"{other_id} lists {pid} as incompatible but {pid} does not list "
                              f"{other_id}: a holder of {other_id} can still request {pid}"))
        out[pid] = risks
    return out


# --------------------------------------------------------------------------- #
# Part 2 — access requests
# --------------------------------------------------------------------------- #
def in_scope(policy: dict, user: dict, orgs: dict) -> tuple[bool, str]:
    scope = policy.get("scope") or {}
    kind = scope.get("type")
    org_id = user.get("organization")
    if kind == "internal_users":
        return (not is_external(user), "requester is a member" if not is_external(user)
                else "policy is for members of the directory only")
    if kind == "connected_organizations":
        ok = is_external(user) and org_id in scope.get("organizations", [])
        return ok, (f"requester's organization {org_id} is listed" if ok
                    else f"organization {org_id or 'none'} is not one of {scope.get('organizations', [])}")
    if kind == "all_connected_organizations":
        org = orgs.get(org_id)
        ok = is_external(user) and org is not None and org.get("state") == "configured"
        why = ("connected organization is configured" if ok else "requester is a member" if not is_external(user)
               else f"organization {org_id or 'none'} is not a configured connected organization"
               + (f" (state '{org.get('state')}')" if org else ""))
        return ok, why
    if kind == "any_external":
        return (is_external(user), "any external user may request" if is_external(user)
                else "policy is for external users only")
    if kind == "admin_only":
        return False, "administrator direct assignment only"
    return False, f"unknown scope type '{kind}' (deny by default)"


def resolve(tokens, requester: dict, ctx: dict) -> tuple[list[str], list[str]]:
    """(approver ids, notes). Unknown tokens and users are dropped with a note."""
    org = ctx["orgs"].get(requester.get("organization")) or {}
    out, notes = [], []
    for t in tokens or []:
        if t == "manager":
            ids = [requester["manager"]] if requester.get("manager") else []
            if not ids:
                notes.append("requester has no manager")
        elif t in ("internal_sponsor", "external_sponsor"):
            ids = list(org.get(t + "s", []))
            if not ids:
                notes.append(f"no {t.replace('_', ' ')} for organization {requester.get('organization') or 'none'}")
        else:
            ids = [t]
        for i in ids:
            if i not in ctx["users"]:
                notes.append(f"approver {i} is not a known user")
            elif i not in out:
                out.append(i)
    return out, notes


def evaluate_request(req: dict, data: dict, cfg: dict, active: set[tuple[str, str]] | None = None,
                     ctx: dict | None = None) -> RequestResult:
    ctx = ctx or _ctx(data)
    active = active if active is not None else active_assignments(data, cfg)
    rid, uid, pid = req.get("id", "?"), req.get("requester"), req.get("package")

    def deny(rule, reason, policy=None):
        return RequestResult(rid, uid or "?", pid or "?", "DENIED", rule, policy, [], [reason])

    user = ctx["users"].get(uid)
    if not user:
        return deny("unknown_requester", f"requester {uid or '(missing)'} is not a known user (deny by default)")
    pkg = ctx["packages"].get(pid)
    if not pkg or pkg.get("catalog") not in ctx["catalogs"]:
        return deny("unknown_package", f"access package {pid or '(missing)'} "
                    + ("does not exist" if not pkg else "has no known catalog") + " (deny by default)")
    policies = pkg.get("policies", [])
    if req.get("policy"):
        policies = [p for p in policies if p.get("id") == req["policy"]]
    policy, misses = None, []
    for p in policies:
        ok, why = in_scope(p, user, ctx["orgs"])
        if ok:
            policy = p
            break
        misses.append(f"{p.get('id')}: {why}")
    if policy is None:
        return deny("not_in_scope", "no assignment policy includes the requester: " + ("; ".join(misses)
                                                                                        or "package has no policy"))
    pol_id = policy.get("id")
    cat = ctx["catalogs"][pkg["catalog"]]
    if is_external(user) and not cat.get("enabled_for_external_users"):
        return deny("catalog_not_external", f"catalog {cat['id']} is not enabled for external users", pol_id)
    for other in pkg.get("incompatible_packages", []):
        if (uid, other) in active:
            return deny("sod_conflict", f"requester already holds {other}, which {pid} lists as incompatible", pol_id)
    if policy.get("require_justification", True):     # missing flag = required (deny by default)
        text = (req.get("justification") or "").strip()
        if len(text) < cfg["min_justification_chars"]:
            return deny("missing_justification", "justification is required and "
                        + (f"'{text}' is shorter than {cfg['min_justification_chars']} characters" if text
                           else "none was given"), pol_id)
    flags = []
    for other_id, other in ctx["packages"].items():
        if pid in other.get("incompatible_packages", []) and (uid, other_id) in active \
                and other_id not in pkg.get("incompatible_packages", []):
            flags.append(f"one-way SoD gap: requester holds {other_id}, which lists {pid} as incompatible, "
                         f"but {pid} does not list {other_id}")
    stages = (policy.get("approval") or {}).get("stages", [])
    if not stages:
        return RequestResult(rid, uid, pid, "AUTO_APPROVED", "auto_approval", pol_id, [],
                             [f"policy {pol_id} ({policy.get('scope', {}).get('type')}) needs no approval"
                              + (f"; access expires in {policy['expiry_days']} days" if policy.get("expiry_days")
                                 else "; assignment never expires")], flags)
    resolved, reasons = [], [f"policy {pol_id} applies"]
    for n, st in enumerate(stages, 1):
        primary, notes = resolve(st.get("approvers"), user, ctx)
        self_seen = uid in primary
        primary = [a for a in primary if a != uid]
        if self_seen:
            notes.append("requester removed from the approvers (cannot approve own request)")
        chosen = primary
        if not chosen:
            fb, fb_notes = resolve(st.get("fallback"), user, ctx)
            self_seen = self_seen or uid in fb
            chosen = [a for a in fb if a != uid]
            notes += fb_notes
            if chosen:
                notes.append(f"fallback approver(s) {', '.join(chosen)} used")
        if not chosen:
            rule = "approver_is_requester" if self_seen else "no_approver"
            why = (f"stage {n}: the only approver left is the requester, who can never approve their own request"
                   if self_seen else f"stage {n}: no approver or fallback approver could be found")
            return RequestResult(rid, uid, pid, "DENIED", rule, pol_id, [], [why] + notes, flags)
        resolved.append(chosen)
        reasons.append(f"stage {n} approver(s): {', '.join(chosen)}" + (f" ({'; '.join(notes)})" if notes else ""))
    rule = "single_stage" if len(stages) == 1 else "two_stage"
    return RequestResult(rid, uid, pid, "PENDING_APPROVAL", rule, pol_id, resolved, reasons, flags)


def evaluate_requests(data: dict, cfg: dict) -> list[RequestResult]:
    ctx, active = _ctx(data), active_assignments(data, cfg)
    return [evaluate_request(r, data, cfg, active, ctx) for r in data.get("requests", [])]


# --------------------------------------------------------------------------- #
# Part 3 — assignment and external user lifecycle
# --------------------------------------------------------------------------- #
def _ended_days_ago(a: dict) -> int | None:
    if a.get("removed_days_ago") is not None:
        return a["removed_days_ago"]
    exp = a.get("expires_in_days")
    return -exp if exp is not None and exp < 0 else None


def assess_assignment(a: dict, cfg: dict, ctx: dict) -> AssignmentResult:
    aid, uid, pid = a.get("id", "?"), a.get("user"), a.get("package")
    if uid not in ctx["users"] or pid not in ctx["packages"]:
        missing = f"user {uid}" if uid not in ctx["users"] else f"package {pid}"
        return AssignmentResult(aid, uid or "?", pid or "?", "INVALID",
                                [f"{missing} is unknown: remove the assignment (deny by default)"])
    if a.get("removed_days_ago") is not None:
        return AssignmentResult(aid, uid, pid, "REMOVED", [f"ended early {a['removed_days_ago']} days ago"])
    exp = a.get("expires_in_days")
    if exp is not None and exp < 0:
        return AssignmentResult(aid, uid, pid, "EXPIRED", [f"end date passed {-exp} days ago: access removed"])
    if exp is not None and exp <= cfg["expiring_soon_days"]:
        return AssignmentResult(aid, uid, pid, "EXPIRING_SOON", [f"ends in {exp} days (warning window "
                                f"{cfg['expiring_soon_days']} days): extend or lose access"])
    return AssignmentResult(aid, uid, pid, "ACTIVE", ["no end date: covered only by access reviews"
                                                      if exp is None else f"ends in {exp} days"])


def assess_assignments(data: dict, cfg: dict) -> list[AssignmentResult]:
    ctx = _ctx(data)
    return [assess_assignment(a, cfg, ctx) for a in data.get("assignments", [])]


def active_assignments(data: dict, cfg: dict) -> set[tuple[str, str]]:
    return {(r.user, r.package) for r in assess_assignments(data, cfg) if r.outcome in ("ACTIVE", "EXPIRING_SOON")}


def assess_guests(data: dict, cfg: dict) -> list[GuestResult]:
    assessed = assess_assignments(data, cfg)
    raw = {a.get("id"): a for a in data.get("assignments", [])}
    out = []
    for u in data.get("users", []):
        if not is_external(u) or not u.get("in_directory", True):
            continue
        mine = [r for r in assessed if r.user == u.get("id")]
        live = [r.package for r in mine if r.outcome in ("ACTIVE", "EXPIRING_SOON")]
        org = u.get("organization")
        if live:
            out.append(GuestResult(u["id"], org, "GUEST_ACTIVE", [f"active assignment(s): {', '.join(live)}"]))
            continue
        if not u.get("added_by_entitlement_management"):
            out.append(GuestResult(u["id"], org, "GUEST_NOT_MANAGED", [
                "invited outside entitlement management: lifecycle settings do not apply; review the guest "
                "with an access review"]))
            continue
        ended = [d for d in (_ended_days_ago(raw[r.id]) for r in mine) if d is not None]
        limit = cfg["guest_removal_after_days"]
        if not ended:
            out.append(GuestResult(u["id"], org, "GUEST_REMOVAL_DUE", [
                "no assignment history: treated as ended long ago (deny by default)"]))
        elif min(ended) < limit:
            out.append(GuestResult(u["id"], org, "GUEST_BLOCKED", [
                f"last assignment ended {min(ended)} days ago: blocked from sign-in, removed in "
                f"{limit - min(ended)} days"]))
        else:
            out.append(GuestResult(u["id"], org, "GUEST_REMOVAL_DUE", [
                f"last assignment ended {min(ended)} days ago (≥ {limit}): remove the guest account"]))
    return out


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SC-300 4.1 Entitlement management · 1.3 Identities for external users and tenants.",
    "concepts": [
        "Catalog → access packages → assignment policies: resources live in a catalog, packages bundle their roles, "
        "policies decide who may request, who approves and when access ends.",
        "Resource types in a package include groups (and Teams), enterprise applications and SharePoint Online sites.",
        "One package can carry several policies, e.g. auto-approved for employees and sponsor-approved for a partner.",
        "Connected organizations let partner users request access; 'all configured connected organizations' "
        "excludes organizations still in the proposed state.",
        "When an external user's last assignment ends, entitlement management can block sign-in and then delete the "
        "guest after a set number of days (only for guests it brought in).",
    ],
    "failure_modes": [
        "Granting partners access by hand-inviting guests: nobody owns the guest and nothing ever removes it.",
        "Auto-approving external users with no expiry and no access review: access becomes permanent by default.",
        "Declaring separation of duties on only one of the two packages, leaving the reverse path open.",
        "Using 'manager' as the approver with no fallback: requests from people without a manager stall.",
    ],
    "ai_governance": [
        "Give an AI agent access through an access package with an expiry and a named sponsor, not a permanent group.",
        "An agent may draft justifications, but approval must come from a human who is not the requester.",
        "Have the agent report expiring and orphaned assignments; humans decide extensions and removals.",
        "Treat request justifications as untrusted text, never as instructions to the agent.",
    ],
    "exam_tips": [
        "'Partner users should request access themselves and lose it automatically' = access package + connected "
        "organization + expiry + external user lifecycle settings.",
        "Approval can have multiple stages (Microsoft Entra supports up to three); each stage can have fallback "
        "approvers, and a requester can never approve their own request.",
        "'Users who hold package A must not get package B' = mark the packages incompatible (separation of duties).",
        "External users can only request from a catalog that is enabled for external users.",
        "Access reviews and expiry are set in the assignment policy, so different requester groups can differ.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def _metrics(reqs, assigns, guests, risks) -> dict:
    count = lambda rs, vals: {v: sum(r.outcome == v for r in rs) for v in vals}   # noqa: E731
    return {"requests": len(reqs), "request_outcomes": count(reqs, REQUEST_OUTCOMES),
            "assignments": len(assigns), "assignment_outcomes": count(assigns, ASSIGNMENT_OUTCOMES),
            "guests": len(guests), "guest_outcomes": count(guests, GUEST_OUTCOMES),
            "packages_with_risks": sum(bool(v) for v in risks.values()),
            "sod_gaps_flagged": sum(bool(r.flags) for r in reqs)}


def run_demo(ui, policies: dict, data: dict) -> dict:
    cfg = policies["entitlement_management"]
    ctx = _ctx(data)
    risks = audit_packages(data, cfg)
    reqs = evaluate_requests(data, cfg)
    assigns = assess_assignments(data, cfg)
    guests = assess_guests(data, cfg)

    ui.section("Step 1 — Catalogs, access packages and assignment policies")
    rows = []
    for pid, p in ctx["packages"].items():
        cat = ctx["catalogs"].get(p.get("catalog"), {})
        pols = "; ".join(f"{q.get('id')}: {(q.get('scope') or {}).get('type')}, "
                         f"{len((q.get('approval') or {}).get('stages', []))} stage(s), "
                         f"{q.get('expiry_days') or 'no'} day expiry" for q in p.get("policies", []))
        rows.append([pid, f"{cat.get('name', '?')}{' (ext)' if cat.get('enabled_for_external_users') else ''}",
                     ", ".join(p.get("resources", [])), pols, ", ".join(p.get("incompatible_packages", [])) or "-",
                     ", ".join(sorted({r for r, _ in risks[pid]})) or "OK"])
    ui.table("Access packages", ["Package", "Catalog", "Resources", "Policies", "Incompatible", "Config risks"], rows)
    for pid, rs in risks.items():
        for risk, why in rs:
            ui.bullet(f"{pid} {risk}: {why}", style="yellow")

    ui.section("Step 2 — Evaluate access requests")
    ui.table("Requests", ["ID", "Requester", "Package", "Policy", "Rule", "Outcome"],
             [[r.id, r.requester, r.package, r.policy or "-", r.rule, r.outcome] for r in reqs])
    for r in reqs:
        ui.bullet(f"{r.id} → {r.outcome} ({r.rule}): " + "; ".join(r.reasons + r.flags),
                  style={"AUTO_APPROVED": "green", "DENIED": "red"}.get(r.outcome, "yellow"))

    ui.section("Step 3 — Assignment lifecycle and external users")
    ui.table("Assignments", ["ID", "User", "Package", "Outcome", "Reason"],
             [[a.id, a.user, a.package, a.outcome, "; ".join(a.reasons)] for a in assigns])
    ui.table("External users in the directory", ["User", "Organization", "Outcome", "Reason"],
             [[g.user, g.organization or "-", g.outcome, "; ".join(g.reasons)] for g in guests])
    m = _metrics(reqs, assigns, guests, risks)
    ro = m["request_outcomes"]
    ui.print(f"Requests {m['requests']}: {ro['AUTO_APPROVED']} auto-approved, {ro['PENDING_APPROVAL']} pending, "
             f"{ro['DENIED']} denied · packages with config risks: {m['packages_with_risks']}")
    ui.insight(INSIGHT)
    return {"requests": {r.id: r.outcome for r in reqs}, "request_rules": {r.id: r.rule for r in reqs},
            "assignments": {a.id: a.outcome for a in assigns}, "guests": {g.user: g.outcome for g in guests},
            "package_risks": {k: sorted({r for r, _ in v}) for k, v in risks.items()}, "metrics": m}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["entitlement_management"]
    ctx = _ctx(data)
    reqs = evaluate_requests(data, cfg)
    assigns = assess_assignments(data, cfg)
    guests = assess_guests(data, cfg)
    risks = audit_packages(data, cfg)
    raw_req = {r.get("id"): r for r in data.get("requests", [])}
    raw_asg = {a.get("id"): a for a in data.get("assignments", [])}
    defs = cfg["rule_definitions"]

    def obj_for(uid):
        u = ctx["users"].get(uid)
        return "1.3" if u and is_external(u) else "4.1"

    def req_ctx(r):
        src = raw_req.get(r.id, {})
        u = ctx["users"].get(src.get("requester"))
        p = ctx["packages"].get(src.get("package"))
        lines = [f"request={ {k: v for k, v in src.items() if k != 'id'} }",
                 "requester: " + (str({k: v for k, v in u.items() if k != 'name'}) if u else "not found"),
                 "package: " + (str({k: p[k] for k in ('catalog', 'incompatible_packages', 'policies') if k in p})
                                if p else "not found")]
        held = sorted(pk for (us, pk) in active_assignments(data, cfg) if us == src.get("requester"))
        lines.append("requester holds: " + (", ".join(held) or "nothing"))
        return "\n".join(lines)

    qs: list = []
    for r in reqs:
        qs.append(Question(prompt=f"{r.id}: what happens to this access request?", context=req_ctx(r),
                           choices=list(REQUEST_OUTCOMES), answer=r.outcome,
                           explanation="; ".join(r.reasons + r.flags), objective=obj_for(r.requester)))
    seen = set()
    for r in reqs:
        if r.outcome == "DENIED" and r.rule not in seen:
            seen.add(r.rule)
            label = defs[r.rule]
            pool = [defs[k] for k in DENY_RULES]
            qs.append(Question(prompt=f"{r.id} was denied. Which rule fired first?", context=req_ctx(r),
                               choices=choices_with(label, pool, k=3, key=r.id), answer=label,
                               explanation="; ".join(r.reasons), objective=obj_for(r.requester)))
    for r in reqs:
        if r.outcome == "PENDING_APPROVAL":
            ans = " then ".join(", ".join(s) for s in r.approvers)
            wrong = {r.requester, *(a for st in r.approvers for a in st)}
            alts = [r.requester + " (the requester)"] + [u for u in sorted(ctx["users"]) if u not in wrong][:2]
            if ans not in alts and len(set(alts + [ans])) == len(alts) + 1:
                qs.append(Question(prompt=f"{r.id} is pending. Who must approve it?", context=req_ctx(r),
                                   choices=sorted([ans] + alts), answer=ans, explanation="; ".join(r.reasons),
                                   objective=obj_for(r.requester)))
                break
    seen = set()
    for a in assigns:
        if a.outcome not in seen:
            seen.add(a.outcome)
            qs.append(Question(prompt=f"{a.id}: what is the lifecycle status of this assignment?",
                               context=f"assignment={ {k: v for k, v in raw_asg.get(a.id, {}).items() if k != 'id'} }"
                                       f"\nwarning window: {cfg['expiring_soon_days']} days",
                               choices=list(ASSIGNMENT_OUTCOMES), answer=a.outcome, explanation="; ".join(a.reasons),
                               objective="4.1"))
    seen = set()
    users = ctx["users"]
    for g in guests:
        if g.outcome not in seen:
            seen.add(g.outcome)
            mine = [{k: v for k, v in x.items() if k != "id"} for x in data.get("assignments", [])
                    if x.get("user") == g.user]
            qs.append(Question(prompt=f"External user {g.user}: what should happen to this guest account?",
                               context=f"user={ {k: v for k, v in users[g.user].items() if k != 'name'} }\n"
                                       f"assignments={mine}\nremove after: {cfg['guest_removal_after_days']} days",
                               choices=list(GUEST_OUTCOMES), answer=g.outcome, explanation="; ".join(g.reasons),
                               objective="1.3"))
    for pid, rs in risks.items():
        names = sorted({r for r, _ in rs})
        if len(names) == 1:
            qs.append(Question(prompt=f"Which configuration risk does access package {pid} have?",
                               context=str({k: v for k, v in ctx["packages"][pid].items() if k != "name"}),
                               choices=choices_with(names[0], PACKAGE_RISKS, key=pid), answer=names[0],
                               explanation=rs[0][1], objective="4.1"))
    qs.append(Question(prompt="The only approver configured for a stage is the person making the request. "
                              "What should happen?",
                       choices=["the requester approves their own request",
                                "the fallback approvers are used; if there are none the request cannot be approved",
                                "the request is auto-approved because an approver exists",
                                "the stage is skipped and the next stage decides"],
                       answer="the fallback approvers are used; if there are none the request cannot be approved",
                       explanation=defs["approver_is_requester"], objective="4.1"))
    qs.append(Question(prompt="A policy targets 'all configured connected organizations'. A user from an "
                              "organization in the proposed state asks for access. What happens?",
                       choices=["denied: proposed organizations are not configured",
                                "approved: every connected organization counts",
                                "approved after the sponsor signs in", "denied: externals can never request"],
                       answer="denied: proposed organizations are not configured",
                       explanation=cfg["scope_types"]["all_connected_organizations"], objective="1.3"))
    for term in ("catalog", "access package", "assignment policy", "connected organization",
                 "incompatible access package", "external user lifecycle"):
        if term in cfg["concepts"]:
            qs.append(Question(prompt=f"Which term is this? \"{cfg['concepts'][term]}\"",
                               choices=sorted(cfg["concepts"]), answer=term, explanation=cfg["concepts"][term],
                               objective="1.3" if term in ("connected organization", "external user lifecycle")
                               else "4.1"))
    return qs


# --------------------------------------------------------------------------- #
# Seeded scenario generator
# --------------------------------------------------------------------------- #
_FIRST = ["Ava", "Ben", "Cleo", "Dev", "Esme", "Finn", "Gita", "Hugo", "Iris", "Jude", "Kai", "Lior", "Mira", "Nico",
          "Omar", "Pia", "Quinn", "Rosa", "Seth", "Tara"]
_LAST = ["Abara", "Brandt", "Costa", "Dahl", "Eze", "Frost", "Gill", "Hart", "Ilves", "Juarez", "Kato", "Lund",
         "Moreau", "Novak", "Ortiz", "Price", "Quade", "Rios", "Sato", "Toivo"]
_JUST = ["Quarter-end reconciliation work", "Supplier onboarding for the new region", "Shipment planning for spring",
         "Audit sample testing for FY2026", "Pitch deck review with the sales team", "Covering for a colleague on leave"]


def generate_scenario(rng, policies: dict) -> dict:
    cfg = policies["entitlement_management"]
    soon, removal = cfg["expiring_soon_days"], cfg["guest_removal_after_days"]
    names = rng.sample([f"{f} {l}" for f in _FIRST for l in _LAST], 12)
    users = [{"id": "U04", "name": names[0], "type": "member", "department": "Finance (CFO)", "manager": None}]
    users += [{"id": f"U0{i}", "name": names[i], "type": "member", "department": rng.choice(["Finance", "Sales",
               "Supply Chain"]), "manager": "U04" if i == 5 else "U05"} for i in (1, 2, 3, 5)]
    orgs = [{"id": "CO-A", "name": "Alder Freight", "domain": "alder.example", "state": "configured",
             "internal_sponsors": ["U03"], "external_sponsors": ["X01"]},
            {"id": "CO-B", "name": "Birch Assurance", "domain": "birch.example", "state": "configured",
             "internal_sponsors": ["U05"], "external_sponsors": []},
            {"id": "CO-C", "name": "Cedar Studio", "domain": "cedar.example", "state": "proposed",
             "internal_sponsors": ["U03"], "external_sponsors": []}]
    users += [
        {"id": "X01", "name": names[5], "type": "external", "organization": "CO-A", "in_directory": True,
         "added_by_entitlement_management": True},
        {"id": "X02", "name": names[6], "type": "external", "organization": "CO-B", "in_directory": True,
         "added_by_entitlement_management": True},
        {"id": "X03", "name": names[7], "type": "external", "organization": "CO-C", "in_directory": False},
        {"id": "X04", "name": names[8], "type": "external", "organization": "CO-A", "in_directory": True,
         "added_by_entitlement_management": True},
        {"id": "X05", "name": names[9], "type": "external", "organization": None, "in_directory": False},
        {"id": "X06", "name": names[10], "type": "external", "organization": "CO-B", "in_directory": True,
         "added_by_entitlement_management": False}]
    review = lambda: {"every_days": rng.choice([30, 90, 180]), "reviewer": "U04"}   # noqa: E731
    catalogs = [
        {"id": "CAT-FIN", "name": "Finance", "enabled_for_external_users": False, "resources": [
            {"id": "APP-VEN", "type": "application", "name": "Ledger ERP", "role": "Vendor Maintainer"},
            {"id": "APP-PAY", "type": "application", "name": "Ledger ERP", "role": "Payment Approver"},
            {"id": "SPO-FIN", "type": "sharepoint_site", "name": "Finance Hub", "role": "Visitors"}]},
        {"id": "CAT-EXT", "name": "Partners", "enabled_for_external_users": True, "resources": [
            {"id": "SPO-EXT", "type": "sharepoint_site", "name": "Partner Portal", "role": "Members"},
            {"id": "GRP-EXT", "type": "group", "name": "Partner Team", "role": "Member"}]}]
    two_way = rng.random() < 0.5
    pkgs = [
        {"id": "AP-VEN", "name": "Vendor Maintenance", "catalog": "CAT-FIN", "resources": ["APP-VEN"],
         "incompatible_packages": ["AP-PAY"] if two_way else [],
         "policies": [{"id": "POL-VEN", "name": "Finance", "scope": {"type": "internal_users"},
                       "approval": {"stages": [{"approvers": ["manager"], "fallback": ["U04"]}]},
                       "require_justification": True, "expiry_days": rng.choice([90, 180]), "access_review": review()}]},
        {"id": "AP-PAY", "name": "Payment Approval", "catalog": "CAT-FIN", "resources": ["APP-PAY"],
         "incompatible_packages": ["AP-VEN"],
         "policies": [{"id": "POL-PAY", "name": "Finance two-stage", "scope": {"type": "internal_users"},
                       "approval": {"stages": [{"approvers": ["manager"], "fallback": ["U04"]},
                                               {"approvers": ["U04"], "fallback": ["U05"]}]},
                       "require_justification": True, "expiry_days": rng.choice([30, 90]), "access_review": review()}]},
        {"id": "AP-READ", "name": "Finance Reader", "catalog": "CAT-FIN", "resources": ["SPO-FIN"],
         "incompatible_packages": [],
         "policies": [{"id": "POL-READ", "name": "Employees", "scope": {"type": "internal_users"},
                       "approval": {"stages": []}, "require_justification": False, "expiry_days": 365,
                       "access_review": None}]},
        {"id": "AP-AUD", "name": "Audit Space", "catalog": "CAT-FIN", "resources": ["SPO-FIN"],
         "incompatible_packages": [],
         "policies": [{"id": "POL-AUD", "name": "Partners", "scope": {"type": "all_connected_organizations"},
                       "approval": {"stages": [{"approvers": ["internal_sponsor"], "fallback": ["U05"]}]},
                       "require_justification": True, "expiry_days": 60, "access_review": None}]},
        {"id": "AP-PART", "name": "Partner Access", "catalog": "CAT-EXT", "resources": ["SPO-EXT", "GRP-EXT"],
         "incompatible_packages": [],
         "policies": [{"id": "POL-PART-EXT", "name": "Alder staff",
                       "scope": {"type": "connected_organizations", "organizations": ["CO-A"]},
                       "approval": {"stages": [{"approvers": ["external_sponsor"], "fallback": ["U03"]}]},
                       "require_justification": True, "expiry_days": 90, "access_review": review()},
                      {"id": "POL-PART-INT", "name": "Employees", "scope": {"type": "internal_users"},
                       "approval": {"stages": []}, "require_justification": False,
                       "expiry_days": rng.choice([None, 365]), "access_review": None}]},
        {"id": "AP-FEED", "name": "Data Feed", "catalog": "CAT-EXT", "resources": ["GRP-EXT"],
         "incompatible_packages": [],
         "policies": [{"id": "POL-FEED", "name": "Connected partners", "scope": {"type": "all_connected_organizations"},
                       "approval": {"stages": []}, "require_justification": True, "expiry_days": 30,
                       "access_review": None}]},
        {"id": "AP-ROOM", "name": "Guest Room", "catalog": "CAT-EXT", "resources": ["SPO-EXT"],
         "incompatible_packages": [],
         "policies": [{"id": "POL-ROOM", "name": "Any external", "scope": {"type": "any_external"},
                       "approval": {"stages": [{"approvers": ["internal_sponsor"], "fallback": []}]},
                       "require_justification": True, "expiry_days": 30, "access_review": review()}]}]
    j = lambda: rng.choice(_JUST)   # noqa: E731
    reqs = [("U02", "AP-READ", ""), ("U01", "AP-VEN", j()), ("U02", "AP-PAY", j()), ("U04", "AP-VEN", j()),
            ("U01", "AP-PAY", j()), ("U03", "AP-VEN", rng.choice(["", "asap", "pls"])), ("X01", "AP-PART", j()),
            ("X06", "AP-AUD", j()), ("X03", "AP-ROOM", j()), (rng.choice(["U98", "U99"]), "AP-READ", j()),
            ("U03", rng.choice(["AP-OLD", "AP-NONE"]), j()), ("U03", "AP-PART", ""), ("X03", "AP-FEED", j()),
            ("X06", "AP-FEED", j()), ("X05", "AP-ROOM", j())]
    if not two_way:
        reqs.append(("U05", "AP-VEN", j()))
    rng.shuffle(reqs)
    requests = [{"id": f"R{i:02d}", "requester": u, "package": p, "justification": t}
                for i, (u, p, t) in enumerate(reqs, 1)]
    asg = [("U02", "AP-VEN", {"expires_in_days": rng.randint(soon + 1, 170)}),
           ("U01", "AP-READ", {"expires_in_days": rng.randint(0, soon)}),
           ("X01", "AP-FEED", {"expires_in_days": rng.randint(1, soon)}),
           ("X04", "AP-PART", {"expires_in_days": -rng.randint(removal, removal + 60)}),
           ("X02", "AP-FEED", {"expires_in_days": -rng.randint(1, removal - 1)}),
           ("X06", "AP-ROOM", {"expires_in_days": 10, "removed_days_ago": rng.randint(5, 90)}),
           ("U03", "AP-PART", {"expires_in_days": None}),
           (rng.choice(["U07", "U08"]), "AP-READ", {"expires_in_days": rng.randint(30, 300)}),
           ("U05", "AP-PAY", {"expires_in_days": rng.randint(soon + 1, 80)})]
    rng.shuffle(asg)
    assignments = [{"id": f"A{i:02d}", "user": u, "package": p, **extra} for i, (u, p, extra) in enumerate(asg, 1)]
    return {"_description": "Randomly generated entitlement management scenario (fictional).", "as_of": "2026-11-05",
            "users": users, "connected_organizations": orgs, "catalogs": catalogs, "access_packages": pkgs,
            "requests": requests, "assignments": assignments}
