"""
Lab 47 — Roles, Access Profiles & Access Request Approvals
==========================================================

SailPoint ISC objectives
------------------------
* 5.2  Entitlements, roles, automated assignment and access troubleshooting
       (primary): role membership criteria, what a role grants, "why does
       this person have (or not have) this access?".
* 6.1  Access requests, approvals and work reassignment: requestable items,
       reviewer levels, self-approval prevention, out-of-office reassignment,
       reminders, escalation and the fallback approver.
* 5.1  User levels and the types of access: entitlement, access profile and
       role, and how they nest.

For the SailPoint Identity Security Engineer course the same material maps to
8.2 (access request approvers and separation of duties), 3.1 (access
management testing, reminders, escalations) and 2.1 (role assignment
behaviour).

How it works
------------
You are the Identity Security Cloud (ISC) administrator for a fictional
company. The access model nests: an **entitlement** is one permission on one
source, an **access profile** bundles entitlements from ONE source, and a
**role** bundles access profiles (and, optionally, entitlements) for a job.
Two parts, each deny by default:

1. **Automatic role assignment.** A role's membership is either STANDARD
   criteria or an IDENTITY_LIST. Criteria are a tree: a leaf compares one
   identity attribute with EQUALS, NOT_EQUALS, CONTAINS, STARTS_WITH or
   ENDS_WITH; an AND / OR node joins up to the policy's maximum depth
   (3 levels). Each identity is ASSIGNED or NOT_ASSIGNED, with the leaf
   results as reasons. A missing attribute makes its leaf false (also for
   NOT_EQUALS); an unknown operation, an empty AND / OR or a tree that is too
   deep makes the whole role NOT_ASSIGNED; a disabled role assigns nobody.
   An assigned role grants its access profiles, which grant their
   entitlements, with no approval.
2. **Access requests**, checked in this order, first hit wins:
   1. requester and recipient must be known identities in an active
      lifecycle state, else DENIED;
   2. requesting for someone else needs the policy's request-for-others
      right (here: managers for their direct reports), else DENIED;
   3. the item (access profile or role) must exist, else DENIED;
   4. it must be enabled and requestable, else NOT_REQUESTABLE;
   5. if the recipient already holds it (directly or through a role):
      ALREADY_HAS_ACCESS;
   6. every reviewer type must be known for that item type (manager, owner,
      governance_group:<name>), else DENIED;
   7. if the item would complete both sides of a separation of duties (SoD)
      policy: SOD_VIOLATION. With ``sod_action`` "flag" (what ISC does) the
      request still routes and reviewers see the violation; "block" stops it;
   8. reviewer levels run in order; an empty list means no approval is
      required. For each level the reviewer is resolved, then:
      * self-approval prevention: if the reviewer is the requester or the
        recipient, the level goes to that reviewer's manager (unless
        ``auto_approve`` is DIRECT and the reviewer is the requester, which
        approves the level; INDIRECT does the same for a governance group
        that contains the requester); in a governance group they are left
        out;
      * work reassignment: an out-of-office reviewer's work goes to their
        delegate, following the chain; a loop is treated as a missing
        reviewer;
      * a missing reviewer goes to the fallback approver, then the item
        owner; if neither works the request is DENIED;
      * a deny ends the request (DENIED); an approve moves on; no decision
        leaves it PENDING with the current approver. Pending days drive
        reminders, escalation (manager of the assigned reviewer for each
        level of the chain, then the fallback approver) and the timeout
        (DENIED as expired). All levels approved: APPROVED.

Simplifications: string comparisons are case-insensitive; criteria can only
use identity attributes (ISC also allows account attributes and
entitlements); a governance group escalates straight to the fallback
approver (ISC escalates each member to their own manager); the 'block' SoD
action stands in for a workflow; the last step of the missing-reviewer
sequence (an org admin) is replaced by DENIED; each request is evaluated
against today's access, not against other pending requests.

Run it
------
    python main.py --course spadmin lab 47
"""

from __future__ import annotations

from dataclasses import dataclass, field

TITLE = "Lab 47 — Roles, Access Profiles & Access Request Approvals"
OBJECTIVES = ("SailPoint ISC 5.2 Entitlements, roles, automated assignment · 6.1 Access requests, approvals and "
              "work reassignment · 5.1 Types of access")
COURSES = ("spadmin", "speng")

ROLE_OUTCOMES = ["ASSIGNED", "NOT_ASSIGNED"]
REQUEST_OUTCOMES = ["APPROVED", "PENDING", "DENIED", "NOT_REQUESTABLE", "ALREADY_HAS_ACCESS", "SOD_VIOLATION"]
OUTCOMES = ROLE_OUTCOMES + REQUEST_OUTCOMES


@dataclass
class RoleResult:
    identity: str
    role: str
    outcome: str
    reasons: list[str] = field(default_factory=list)


@dataclass
class RequestResult:
    id: str
    requester: str
    beneficiary: str
    item: str
    item_type: str
    outcome: str
    approval_status: str = "-"        # routing result (also computed for a flagged SoD request)
    current_approver: str = "-"
    reminders: int = 0
    escalations: int = 0
    rule: str = ""
    steps: list[dict] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Part 1 — role membership criteria
# --------------------------------------------------------------------------- #
def _norm(v, cfg) -> str:
    s = "" if v is None else str(v)
    return s.lower() if cfg["criteria"].get("case_insensitive", True) else s


def eval_criteria(node, identity: dict, cfg: dict, depth: int = 1) -> tuple[bool, list[str], str | None]:
    """(matched, leaf reasons, error). An error means the criteria cannot be evaluated: never a match."""
    crit = cfg["criteria"]
    if not isinstance(node, dict):
        return False, [], "criteria missing or malformed"
    if depth > crit["max_depth"]:
        return False, [], f"criteria nested deeper than {crit['max_depth']} levels"
    op = node.get("operation")
    if op in crit["logical"]:
        kids = node.get("children") or []
        if not kids:
            return False, [], f"empty {op} group"
        results, reasons = [], []
        for k in kids:
            ok, rs, err = eval_criteria(k, identity, cfg, depth + 1)
            if err:
                return False, reasons + rs, err
            results.append(ok)
            reasons += rs
        return (all(results) if op == "AND" else any(results)), reasons, None
    if op not in crit["operations"]:
        return False, [], f"unknown operation '{op}'"
    attr, want = node.get("attribute"), node.get("value")
    if not attr:
        return False, [], "criteria leaf has no attribute"
    have = identity.get(attr)
    if have is None or have == "":
        # Deny by default: a missing attribute never satisfies a leaf, not even NOT_EQUALS.
        return False, [f"{attr} is missing: '{op} {want}' is false"], None
    h, w = _norm(have, cfg), _norm(want, cfg)
    ok = {"EQUALS": h == w, "NOT_EQUALS": h != w, "CONTAINS": w in h,
          "STARTS_WITH": h.startswith(w), "ENDS_WITH": h.endswith(w)}[op]
    return ok, [f"{attr}='{have}' {op} '{want}': {'true' if ok else 'false'}"], None


def evaluate_role(role: dict, identity: dict, cfg: dict) -> RoleResult:
    iid, rid = identity.get("id", "?"), role.get("id", "?")
    if not role.get("enabled", False):
        return RoleResult(iid, rid, "NOT_ASSIGNED", ["role is disabled (or not marked enabled): it assigns nobody"])
    mem = role.get("membership") or {}
    if mem.get("type") == "IDENTITY_LIST":
        if iid in (mem.get("identities") or []):
            return RoleResult(iid, rid, "ASSIGNED", ["identity is on the role's identity list"])
        return RoleResult(iid, rid, "NOT_ASSIGNED", ["identity is not on the role's identity list"])
    if mem.get("type") != "STANDARD":
        return RoleResult(iid, rid, "NOT_ASSIGNED", [f"unknown membership type '{mem.get('type')}' (deny by default)"])
    ok, reasons, err = eval_criteria(mem.get("criteria"), identity, cfg)
    if err:
        return RoleResult(iid, rid, "NOT_ASSIGNED", [f"criteria cannot be evaluated: {err} (deny by default)"])
    return RoleResult(iid, rid, "ASSIGNED" if ok else "NOT_ASSIGNED",
                      reasons + ["membership criteria match" if ok else "membership criteria do not match"])


def assign_roles(data: dict, cfg: dict) -> list[RoleResult]:
    return [evaluate_role(r, i, cfg) for r in data.get("roles", []) for i in data.get("identities", [])]


def effective_access(data: dict, cfg: dict, role_results: list[RoleResult] | None = None) -> dict[str, dict]:
    """identity -> {'roles', 'access_profiles', 'entitlements', 'via'} after roles grant profiles grant entitlements."""
    role_results = role_results if role_results is not None else assign_roles(data, cfg)
    aps = {a["id"]: a for a in data.get("access_profiles", [])}
    roles = {r["id"]: r for r in data.get("roles", [])}
    out = {}
    for ident in data.get("identities", []):
        iid = ident["id"]
        held_roles = {r.role for r in role_results if r.identity == iid and r.outcome == "ASSIGNED"}
        held_roles |= {r for r in ident.get("roles", []) if roles.get(r, {}).get("enabled")}   # granted by request
        via: dict[str, str] = {}
        held_aps, ents = set(), set()
        for rid in sorted(held_roles):
            for ap in roles[rid].get("access_profiles", []):
                if ap in aps and aps[ap].get("enabled", False):
                    held_aps.add(ap)
                    via.setdefault(ap, f"role {rid}")
            for e in roles[rid].get("entitlements", []):
                ents.add(e)
                via.setdefault(e, f"role {rid}")
        for ap in ident.get("access_profiles", []):
            if ap in aps and aps[ap].get("enabled", False):
                held_aps.add(ap)
                via.setdefault(ap, "direct (requested)")
        for ap in sorted(held_aps):
            for e in aps[ap].get("entitlements", []):
                ents.add(e)
                via.setdefault(e, f"access profile {ap}")
        for e in ident.get("entitlements", []):
            ents.add(e)
            via.setdefault(e, "direct (requested)")
        out[iid] = {"roles": held_roles, "access_profiles": held_aps, "entitlements": ents, "via": via}
    return out


# --------------------------------------------------------------------------- #
# Part 2 — access requests and approvals
# --------------------------------------------------------------------------- #
class _Ctx:
    def __init__(self, data: dict, cfg: dict, req: dict, item: dict | None):
        self.cfg, self.req, self.item = cfg, req, item
        self.people = {i["id"]: i for i in data.get("identities", [])}
        self.groups = data.get("governance_groups", {})
        self.requester, self.beneficiary = req.get("requester"), req.get("beneficiary")

    def name(self, iid) -> str:
        p = self.people.get(iid)
        return f"{p.get('name', iid)} ({iid})" if p else str(iid)

    def manager(self, iid):
        return (self.people.get(iid) or {}).get("manager")

    def usable(self, iid) -> bool:
        return iid in self.people and iid not in (self.requester, self.beneficiary)

    def missing_reviewer(self, why: str, reasons: list[str]):
        """ISC sequence (simplified): fallback approver, then the item owner; else nobody (deny by default)."""
        fb = self.cfg["escalation"].get("fallback_approver")
        for label, cand in (("fallback approver", fb), ("item owner", (self.item or {}).get("owner"))):
            if self.usable(cand):
                reasons.append(f"{why}: routed to the {label} {self.name(cand)}")
                return cand
        reasons.append(f"{why}: no fallback approver or owner can review it (deny by default)")
        return None

    def assign(self, iid, reasons: list[str], allow_auto: bool = True):
        """Apply self-approval prevention and work reassignment. Returns an identity id, 'AUTO' or None."""
        seen: list[str] = []
        hops = 0
        while True:
            if iid not in self.people:
                return self.missing_reviewer(f"reviewer '{iid}' cannot be resolved", reasons)
            if iid == self.requester and allow_auto and self.cfg.get("auto_approve") == "DIRECT":
                reasons.append(f"reviewer {self.name(iid)} is the requester and autoApprove is DIRECT: level approved")
                return "AUTO"
            if iid in (self.requester, self.beneficiary):
                who = "requester" if iid == self.requester else "recipient"
                mgr = self.manager(iid)
                reasons.append(f"self-approval prevention: reviewer {self.name(iid)} is the {who}, so the level "
                               f"goes to their manager" + (f" {self.name(mgr)}" if mgr else ", who is not set"))
                if not mgr:
                    return self.missing_reviewer("no manager for self-approval prevention", reasons)
                iid, allow_auto = mgr, False
                continue
            wr = self.people[iid].get("work_reassignment") or {}
            if wr.get("active") and wr.get("delegate"):
                seen.append(iid)
                hops += 1
                nxt = wr["delegate"]
                if nxt in seen or hops > self.cfg["work_reassignment_max_hops"]:
                    reasons.append("work reassignment loops (" + " → ".join(seen + [nxt]) + "); ISC blocks loops "
                                   "when they are saved, so this is bad data")
                    return self.missing_reviewer("reassignment loop", reasons)
                reasons.append(f"{self.name(iid)} is out of office: work reassigned to {self.name(nxt)}")
                iid = nxt
                continue
            return iid


def find_item(data: dict, item_id) -> tuple[dict | None, str]:
    for a in data.get("access_profiles", []):
        if a.get("id") == item_id:
            return a, "access_profile"
    for r in data.get("roles", []):
        if r.get("id") == item_id:
            return r, "role"
    return None, "unknown"


def item_entitlements(item: dict, kind: str, data: dict) -> set[str]:
    if kind == "access_profile":
        return set(item.get("entitlements", []))
    aps = {a["id"]: a for a in data.get("access_profiles", [])}
    ents = set(item.get("entitlements", []))
    for ap in item.get("access_profiles", []):
        ents |= set(aps.get(ap, {}).get("entitlements", []))
    return ents


def sod_conflicts(current: set[str], adding: set[str], cfg: dict) -> list[str]:
    out = []
    after = current | adding
    for pol in cfg.get("sod_policies", []):
        left, right = set(pol["left"]) & after, set(pol["right"]) & after
        if left and right and (left | right) & (adding - current):
            out.append(f"SoD policy '{pol['name']}': {', '.join(sorted(left))} + {', '.join(sorted(right))}")
    return out


def _escalate(ctx: _Ctx, assignee, days: int, reasons: list[str]) -> tuple[object, int]:
    esc = ctx.cfg["escalation"]
    if not esc.get("enabled") or days < esc["start_after_days"]:
        return assignee, 0
    count = 1 + (days - esc["start_after_days"]) // max(1, esc["frequency_days"])
    fb = esc.get("fallback_approver")
    current, done = assignee, 0
    for level in range(count):
        if current == fb:
            break
        if isinstance(current, tuple):                       # governance group: simplified, straight to fallback
            target, how = fb, "fallback approver (governance group escalation, simplified)"
        elif level < len(esc.get("chain", [])) and ctx.manager(current):
            target, how = ctx.manager(current), f"manager of {ctx.name(current)}"
        else:
            target, how = fb, "fallback approver"
        if target not in ctx.people:
            reasons.append(f"escalation {level + 1}: no valid {how}, the approval stays with the last valid approver")
            break
        sub: list[str] = []
        nxt = ctx.assign(target, sub, allow_auto=False)
        if nxt is None:
            reasons.append(f"escalation {level + 1}: {how} cannot review it, stays with the last valid approver")
            break
        current = nxt
        done += 1
        reasons.append(f"escalation {level + 1} after {esc['start_after_days'] + level * esc['frequency_days']} "
                       f"days: to the {how} → {ctx.name(current)}" + (f" ({'; '.join(sub)})" if sub else ""))
    return current, done


def route(ctx: _Ctx, schemes: list[str], reasons: list[str], steps: list[dict]) -> tuple[str, str, int, int]:
    """(status, current approver, reminders, escalations) for the reviewer levels."""
    req, cfg = ctx.req, ctx.cfg
    if not schemes:
        reasons.append("no approval required for this item: provisioned on submission")
        return "APPROVED", "-", 0, 0
    decisions = req.get("decisions") or {}
    days = req.get("days_pending") or 0
    for level, scheme in enumerate(schemes, 1):
        sr: list[str] = []
        if scheme == "manager":
            target = ctx.manager(ctx.beneficiary)
            label = "manager of the recipient"
            assignee = ctx.assign(target, sr) if target else ctx.missing_reviewer("recipient has no manager", sr)
        elif scheme == "owner":
            label = "item owner"
            assignee = ctx.assign((ctx.item or {}).get("owner"), sr)
        else:
            gname = scheme.split(":", 1)[1]
            label = f"governance group {gname}"
            members = [m for m in ctx.groups.get(gname, []) if m in ctx.people]
            if not members:
                assignee = ctx.missing_reviewer(f"governance group '{gname}' is unknown or empty", sr)
            elif ctx.requester in members and cfg.get("auto_approve") == "INDIRECT":
                sr.append("requester is in the group and autoApprove is INDIRECT: level approved")
                assignee = "AUTO"
            else:
                left = [m for m in members if m not in (ctx.requester, ctx.beneficiary)]
                if len(left) < len(members):
                    sr.append("requester/recipient left out of the group review (self-approval prevention)")
                if not left:
                    mgr = ctx.manager(ctx.requester)
                    sr.append("they were the only members: the level goes to the requester's manager")
                    assignee = ctx.assign(mgr, sr, allow_auto=False) if mgr else \
                        ctx.missing_reviewer("requester has no manager", sr)
                else:
                    who = []
                    for m in left:
                        a = ctx.assign(m, sr, allow_auto=False)
                        if a and a not in who:
                            who.append(a)
                    assignee = ("group", gname, tuple(who)) if who else \
                        ctx.missing_reviewer("no group member can review", sr)
        step = {"level": level, "scheme": scheme, "reviewer": label}
        steps.append(step)
        reasons += [f"level {level} ({label}): {r}" for r in sr]
        if assignee is None:
            step["result"] = "NO_REVIEWER"
            reasons.append(f"level {level}: nobody can review it, request denied (deny by default)")
            return "DENIED", "-", 0, 0
        if assignee == "AUTO":
            step["result"] = "AUTO_APPROVED"
            continue
        who = (f"governance group {assignee[1]} (" + ", ".join(assignee[2]) + ")") if isinstance(assignee, tuple) \
            else ctx.name(assignee)
        step["assigned_to"] = who
        decision = decisions.get(scheme)
        if decision == "deny":
            step["result"] = "DENIED"
            reasons.append(f"level {level}: {who} denied: the review stops and nothing is provisioned")
            return "DENIED", "-", 0, 0
        if decision == "approve":
            step["result"] = "APPROVED"
            reasons.append(f"level {level}: {who} approved")
            continue
        # Pending at this level.
        if days >= cfg["timeout_days"]:
            step["result"] = "EXPIRED"
            reasons.append(f"level {level}: no decision for {days} days ≥ timeout {cfg['timeout_days']} days: "
                           "request expired, nothing is provisioned")
            return "DENIED", "-", 0, 0
        rem = cfg["reminders"]
        reminders = 0
        if rem.get("enabled") and days >= rem["start_after_days"]:
            reminders = min(rem["max_reminders"], 1 + (days - rem["start_after_days"]) // max(1, rem["frequency_days"]))
        esc_reasons: list[str] = []
        assignee, escalations = _escalate(ctx, assignee, days, esc_reasons)
        reasons += [f"level {level}: {r}" for r in esc_reasons]
        who = (f"governance group {assignee[1]} (" + ", ".join(assignee[2]) + ")") if isinstance(assignee, tuple) \
            else ctx.name(assignee)
        step["result"] = "PENDING"
        step["assigned_to"] = who
        reasons.append(f"level {level}: waiting {days} day(s) for {who}; {reminders} reminder(s) sent")
        return "PENDING", who, reminders, escalations
    return "APPROVED", "-", 0, 0


def evaluate_request(req: dict, data: dict, cfg: dict, access: dict | None = None) -> RequestResult:
    access = access if access is not None else effective_access(data, cfg)
    item, kind = find_item(data, req.get("item"))
    ctx = _Ctx(data, cfg, req, item)
    res = RequestResult(req.get("id", "?"), str(req.get("requester")), str(req.get("beneficiary")),
                        str(req.get("item")), kind, "DENIED")

    def done(outcome, rule, *why):
        res.outcome, res.rule = outcome, rule
        res.reasons = list(why) + res.reasons
        return res

    active = cfg["active_lifecycle_states"]
    for role_name, iid in (("requester", ctx.requester), ("recipient", ctx.beneficiary)):
        p = ctx.people.get(iid)
        if p is None:
            return done("DENIED", "identity", f"{role_name} '{iid}' is not a known identity (deny by default)")
        if p.get("cloudLifecycleState") not in active:
            return done("DENIED", "identity", f"{role_name} {ctx.name(iid)} is in lifecycle state "
                        f"'{p.get('cloudLifecycleState')}', not {', '.join(active)}")
    if ctx.requester != ctx.beneficiary:
        mode = cfg.get("request_for_others", "none")
        is_mgr = ctx.manager(ctx.beneficiary) == ctx.requester
        if not (mode == "anyone" or (mode == "managers_only" and is_mgr)):
            return done("DENIED", "request_for_others", f"{ctx.name(ctx.requester)} may not request for "
                        f"{ctx.name(ctx.beneficiary)}: policy '{mode}' and they are not the recipient's manager")
    if item is None:
        return done("DENIED", "item", f"'{req.get('item')}' is not an access profile or role in the catalog "
                    "(deny by default)")
    if not item.get("enabled", False) or not item.get("requestable", False):
        why = "disabled" if not item.get("enabled", False) else "not marked requestable"
        return done("NOT_REQUESTABLE", "requestable", f"{kind.replace('_', ' ')} {item['id']} is {why}: it does "
                    "not appear in the Request Center")
    held = access.get(ctx.beneficiary, {"roles": set(), "access_profiles": set(), "entitlements": set(), "via": {}})
    if (kind == "role" and item["id"] in held["roles"]) or \
            (kind == "access_profile" and item["id"] in held["access_profiles"]):
        via = held["via"].get(item["id"], "role membership criteria" if kind == "role" else "a role")
        return done("ALREADY_HAS_ACCESS", "already_has", f"{ctx.name(ctx.beneficiary)} already holds {item['id']} "
                    f"(via {via})")
    schemes = item.get("approval_schemes", cfg["default_approval_schemes"])
    if schemes is None:
        schemes = cfg["default_approval_schemes"]
    allowed = cfg["reviewer_types"].get(kind, [])
    for s in schemes:
        base = s.split(":", 1)[0] if isinstance(s, str) else None
        if base not in allowed or (base == "governance_group" and not s.split(":", 1)[1:]):
            return done("DENIED", "reviewer_type", f"reviewer type '{s}' is not valid for a {kind.replace('_', ' ')} "
                        f"({', '.join(allowed)}): cannot route the approval (deny by default)")
    conflicts = sod_conflicts(held["entitlements"], item_entitlements(item, kind, data), cfg)
    if conflicts and cfg.get("sod_action") == "block":
        return done("SOD_VIOLATION", "sod", *conflicts, "policy sod_action is 'block': the request is not submitted")
    status, who, rem, esc = route(ctx, list(schemes), res.reasons, res.steps)
    res.approval_status, res.current_approver, res.reminders, res.escalations = status, who, rem, esc
    if conflicts:
        return done("SOD_VIOLATION", "sod", *conflicts, f"sod_action is 'flag': the request still routes and "
                    f"reviewers see the violation (approval status: {status})")
    return done(status, "approval")


def evaluate_requests(data: dict, cfg: dict) -> tuple[list[RoleResult], dict, list[RequestResult]]:
    roles = assign_roles(data, cfg)
    access = effective_access(data, cfg, roles)
    return roles, access, [evaluate_request(r, data, cfg, access) for r in data.get("requests", [])]


def metrics(roles: list[RoleResult], requests: list[RequestResult]) -> dict:
    return {"role_assignments": sum(r.outcome == "ASSIGNED" for r in roles),
            "requests": len(requests),
            "outcomes": {o: sum(r.outcome == o for r in requests) for o in REQUEST_OUTCOMES},
            "reminders_sent": sum(r.reminders for r in requests),
            "escalations": sum(r.escalations for r in requests)}


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SailPoint ISC 5.2 Roles and automated assignment · 6.1 Access requests and approvals · "
                 "5.1 Types of access.",
    "concepts": [
        "Entitlement → access profile (one source) → role (a job): each layer bundles the one below it.",
        "Role membership criteria (AND / OR over identity attributes) assign roles automatically, with no approval.",
        "A requestable access profile or role routes through reviewer levels in order; any deny stops the request.",
        "ISC prevents self-approval: a requester or recipient who is the reviewer is replaced by their manager.",
        "Work reassignment, reminders, escalation and the fallback approver keep requests from stalling.",
    ],
    "failure_modes": [
        "A missing identity attribute (blank location) silently keeps someone out of a birthright role.",
        "Criteria written with OR where AND was meant hand a role to a whole department.",
        "Delegates who are also out of office, so approvals sit with nobody until escalation.",
        "Turning on autoApprove so a manager's request for themselves needs no second pair of eyes.",
        "Treating an SoD warning as noise: reviewers approve the conflict without a mitigating control.",
    ],
    "ai_governance": [
        "An AI agent can propose role criteria from HR data, but a human role owner approves the role before it is enabled.",
        "An agent that recommends approve/deny must show the reasons and must never be the only reviewer level.",
        "Give an agent's own identity least-privilege access, an owner and no ability to approve its own requests.",
        "Treat request comments and justification text as untrusted data, never as instructions to the agent.",
    ],
    "exam_tips": [
        "Access granted through an auto-assigned role or lifecycle state is never sent for approval.",
        "Governance group reviewer: any one member's decision completes the level.",
        "Default escalation: twice to the reviewer's manager, then to the fallback approver; requests time out at 90 days at most.",
        "An access profile holds entitlements from ONE source; a role can span many sources.",
        "If you already hold an item (directly or through a role) you cannot request it again.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    cfg = policies["isc_access_requests"]
    roles, access, requests = evaluate_requests(data, cfg)
    names = {i["id"]: i.get("name", i["id"]) for i in data.get("identities", [])}
    ui.section("Step 1 — Automatic role assignment from membership criteria")
    rows = []
    for role in data.get("roles", []):
        got = [r.identity for r in roles if r.role == role.get("id") and r.outcome == "ASSIGNED"]
        mem = (role.get("membership") or {}).get("type", "?")
        rows.append([role.get("id"), role.get("name", ""), mem, "yes" if role.get("enabled") else "no",
                     len(got), ", ".join(got) or "-"])
    ui.table("Roles", ["Role", "Name", "Membership", "Enabled", "Assigned", "Identities"], rows)
    for r in roles:
        if r.outcome == "NOT_ASSIGNED" and any(k in " ".join(r.reasons) for k in ("missing", "disabled",
                                                                                    "cannot be evaluated")):
            ui.bullet(f"{r.identity} {names.get(r.identity, '')} / {r.role}: NOT_ASSIGNED: {'; '.join(r.reasons)}",
                      style="yellow")
    ui.section("Step 2 — What the roles grant (role → access profile → entitlement)")
    ui.table("Effective access", ["Identity", "Roles", "Access profiles", "Entitlements"],
             [[iid, ", ".join(sorted(a["roles"])) or "-", ", ".join(sorted(a["access_profiles"])) or "-",
               len(a["entitlements"])] for iid, a in access.items()])
    ui.section("Step 3 — Access requests: requestable checks, SoD and reviewer levels")
    ui.table("Access requests", ["ID", "Requester", "For", "Item", "Outcome", "Current approver", "Reminders",
                                 "Escalations"],
             [[r.id, r.requester, r.beneficiary, r.item, r.outcome, r.current_approver, r.reminders, r.escalations]
              for r in requests])
    for r in requests:
        ui.bullet(f"{r.id} → {r.outcome}: " + "; ".join(r.reasons),
                  style={"APPROVED": "green", "DENIED": "red", "SOD_VIOLATION": "red"}.get(r.outcome, "yellow"))
    m = metrics(roles, requests)
    ui.print(f"{m['role_assignments']} automatic role assignments · {m['requests']} requests: " +
             ", ".join(f"{k} {v}" for k, v in m["outcomes"].items()) +
             f" · {m['reminders_sent']} reminders, {m['escalations']} escalation(s)")
    ui.insight(INSIGHT)
    return {"roles": {role.get("id"): [r.identity for r in roles if r.role == role.get("id") and r.outcome == "ASSIGNED"]
                      for role in data.get("roles", [])},
            "requests": {r.id: r.outcome for r in requests},
            "approval_status": {r.id: r.approval_status for r in requests},
            "current_approvers": {r.id: r.current_approver for r in requests if r.current_approver != "-"},
            "metrics": m}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["isc_access_requests"]
    roles, access, requests = evaluate_requests(data, cfg)
    people = {i["id"]: i for i in data.get("identities", [])}
    raw_roles = {r.get("id"): r for r in data.get("roles", [])}
    raw_req = {r.get("id"): r for r in data.get("requests", [])}
    qs: list = []

    def label(iid):
        p = people.get(iid)
        return f"{p.get('name', iid)} ({iid})" if p else str(iid)

    # Role assignment: one ASSIGNED and one NOT_ASSIGNED example per role (tricky ones first).
    for rid, role in raw_roles.items():
        mine = [r for r in roles if r.role == rid]
        picks = []
        for outcome in ROLE_OUTCOMES:
            cands = [r for r in mine if r.outcome == outcome]
            cands.sort(key=lambda r: (not any(k in " ".join(r.reasons) for k in ("missing", "disabled", "'us'")),
                                      r.identity))
            if cands:
                picks.append(cands[0])
        for r in picks:
            p = people.get(r.identity, {})
            attrs = {k: p.get(k) for k in ("department", "location", "title", "cloudLifecycleState")}
            qs.append(Question(prompt=f"Is role {rid} automatically assigned to {label(r.identity)}?",
                               context=f"role membership: {role.get('membership')}\nenabled: {role.get('enabled')}\n"
                                       f"identity attributes: {attrs}",
                               choices=ROLE_OUTCOMES, answer=r.outcome, explanation="; ".join(r.reasons),
                               objective="5.2"))
    # Requests: predict the outcome.
    for r in requests:
        src = {k: v for k, v in raw_req.get(r.id, {}).items() if k != "id"}
        qs.append(Question(prompt=f"{r.id}: what is the outcome of this access request?",
                           context=f"request={src}", choices=choices_with(r.outcome, REQUEST_OUTCOMES, k=4, key=r.id),
                           answer=r.outcome, explanation="; ".join(r.reasons),
                           objective="5.2" if r.outcome in ("ALREADY_HAS_ACCESS", "NOT_REQUESTABLE") else "6.1"))
    # Pending: who holds it now?
    pool = sorted({label(i) for i in people})
    for r in requests:
        if r.outcome == "PENDING" and not r.current_approver.startswith("governance group"):
            qs.append(Question(prompt=f"{r.id} is pending. Who must act on it now?",
                               context=f"request={raw_req.get(r.id)}",
                               choices=choices_with(r.current_approver, pool, key=r.id), answer=r.current_approver,
                               explanation="; ".join(r.reasons), objective="6.1"))
    # Which rule fired, for the first DENIED request of each kind.
    rule_text = {"identity": "requester or recipient unknown or not active",
                 "request_for_others": "not allowed to request for this person",
                 "item": "item not in the catalog", "reviewer_type": "unknown reviewer type",
                 "approval": "a reviewer denied it or it timed out"}
    seen = set()
    for r in requests:
        if r.outcome == "DENIED" and r.rule in rule_text and r.rule not in seen:
            seen.add(r.rule)
            qs.append(Question(prompt=f"{r.id} was DENIED. Which check stopped it?", context=f"request={raw_req.get(r.id)}",
                               choices=sorted(rule_text.values()), answer=rule_text[r.rule],
                               explanation="; ".join(r.reasons), objective="6.1"))
    # Entitlement lineage (types of access).
    for iid, a in access.items():
        aps = sorted(a["access_profiles"])
        for ap in aps:
            via = a["via"].get(ap, "")
            if via.startswith("role "):
                ent = sorted(next(x for x in data["access_profiles"] if x["id"] == ap)["entitlements"])[0]
                rid = via.split(" ", 1)[1]
                ans = f"role {rid} grants access profile {ap}, which grants {ent}"
                wrong = [f"{ent} grants access profile {ap}, which grants role {rid}",
                         f"access profile {ap} grants role {rid}, which grants {ent}",
                         f"{ent} was approved by the manager of {label(iid)} as a request"]
                qs.append(Question(prompt=f"How does {label(iid)} hold entitlement {ent}?",
                                   choices=sorted([ans] + wrong), answer=ans,
                                   explanation=f"{rid} is assigned by membership; it contains {ap}; {ap} contains "
                                               f"{ent}. Access through auto-assigned roles needs no approval.",
                                   objective="5.1"))
                break
        else:
            continue
        break
    # Rule and concept questions computed from the policy.
    mode = cfg.get("auto_approve", "OFF")
    ans = ("the level is approved automatically" if mode == "DIRECT"
           else "the level is reassigned to the requester's manager")
    qs.append(Question(prompt="A manager requests access for themselves and the first reviewer level is the "
                              "requester's own approval as owner. What happens to that level?",
                       context=f"autoApprove = {mode}",
                       choices=["the level is approved automatically", "the level is reassigned to the requester's "
                                "manager", "the requester approves it like any other reviewer",
                                "the request is denied"],
                       answer=ans, explanation="ISC prevents self-approval by default; only autoApprove DIRECT "
                       "approves a level whose reviewer is the requester", objective="6.1"))
    esc = cfg["escalation"]
    qs.append(Question(prompt="An approval has had no decision past the escalation start. Where does the first "
                              "escalation go?",
                       context=f"escalation chain: {esc['chain']}, then fallback approver {esc['fallback_approver']}",
                       choices=["to the manager of the assigned reviewer", "straight to the requester",
                                "to the recipient's manager, always", "nowhere: the request is approved"],
                       answer="to the manager of the assigned reviewer" if esc["chain"] and esc["chain"][0] ==
                       "manager_of" else "nowhere: the request is approved",
                       explanation="each 'manager_of' level moves it to the reviewer's manager; after the chain, "
                                   "the fallback approver", objective="6.1"))
    qs.append(Question(prompt="Which reviewer type is completed by a decision from any single member?",
                       choices=["governance group", "manager", "primary owner", "fallback approver"],
                       answer="governance group", explanation=cfg["concepts"]["governance group"], objective="6.1"))
    qs.append(Question(prompt="An identity receives an access profile through an automatically assigned role. "
                              "Which approvals run?",
                       choices=["none: role assignment by criteria needs no approval",
                                "the access profile's reviewer levels", "the role owner, then the manager",
                                "the fallback approver only"],
                       answer="none: role assignment by criteria needs no approval",
                       explanation="approval schemes apply only to requests; access from auto-assigned roles or "
                                   "lifecycle states has no approval", objective="5.2"))
    for term, obj in (("entitlement", "5.1"), ("access profile", "5.1"), ("role", "5.1"),
                      ("membership criteria", "5.2"), ("work reassignment", "6.1"), ("fallback approver", "6.1"),
                      ("separation of duties policy", "6.1")):
        if term in cfg["concepts"]:
            qs.append(Question(prompt=f"Which term is this? \"{cfg['concepts'][term]}\"",
                               choices=choices_with(term, cfg["concepts"], key=term), answer=term,
                               explanation=cfg["concepts"][term], objective=obj))
    return qs


# --------------------------------------------------------------------------- #
# Scenario generator
# --------------------------------------------------------------------------- #
FIRST = ["Ana", "Bo", "Cyra", "Dario", "Esme", "Femi", "Gus", "Hana", "Ivo", "Jada", "Kenji", "Lior", "Maya",
         "Nils", "Oona", "Pavel", "Rhea", "Sami", "Tova", "Uri"]
LAST = ["Achebe", "Berg", "Costa", "Dahl", "Eze", "Fontaine", "Gupta", "Holm", "Ito", "Jensen", "Kovac", "Laine"]
TEAMS = [("Finance", "ERP", "Invoice Entry"), ("Procurement", "SRM", "Purchase Order Entry")]


def generate_scenario(rng, policies: dict) -> dict:
    dept, src, ap_name = rng.choice(TEAMS)
    loc = rng.choice(["US", "DE", "CA"])
    other_loc = rng.choice([x for x in ("UK", "FR", "MX") if x != loc])
    names = rng.sample(FIRST, 15)
    base = rng.randint(2, 7) * 1000
    ids = [f"E{base + i}" for i in range(1, 16)]
    (staff, other, sales, it_eng, mgr, sales_mgr, it_mgr, exec_, ctrl, it_admin, leaver, blank, mkt, sec,
     desk) = ids

    def person(i, d, title, manager, location=loc, state="active", wr=None):
        p = {"id": ids[i], "name": f"{names[i]} {rng.choice(LAST)}", "department": d, "title": title,
             "cloudLifecycleState": state, "manager": manager}
        if location is not None:
            p["location"] = location
        if wr:
            p["work_reassignment"] = {"active": True, "delegate": wr}
        return p

    identities = [
        person(0, dept, "Specialist", mgr), person(1, dept, "Specialist", mgr, location=other_loc),
        person(2, "Sales", "Account Executive", sales_mgr, location=loc.lower()),
        person(3, "IT", rng.choice(["Systems Engineer", "Network Engineer"]), it_mgr),
        person(4, dept, f"{dept} Manager", exec_), person(5, "Sales", "Sales Manager", exec_, wr=mkt),
        person(6, "IT", "IT Manager", exec_, wr=it_admin), person(7, "Executive", "Chief Operating Officer", None),
        person(8, dept, "Controller", mgr), person(9, "IT", "Directory Administrator", it_mgr, wr=it_mgr),
        person(10, dept, "Specialist", mgr, state=rng.choice(["inactive", "terminated"])),
        person(11, dept, "Analyst", mgr, location=None), person(12, "Marketing", "Account Manager", sales_mgr),
        person(13, "Security", "Security Lead", exec_), person(14, "IT", "Governance Analyst", sec),
    ]
    p = src
    aps = [
        {"id": f"AP-{p}-ENTRY", "name": f"{src} {ap_name}", "source": src, "owner": ctrl, "enabled": True,
         "requestable": True, "entitlements": [f"{p}:ENTRY", f"{p}:VIEW"], "approval_schemes": ["manager", "owner"]},
        {"id": f"AP-{p}-PAY", "name": f"{src} Payment Release", "source": src, "owner": ctrl, "enabled": True,
         "requestable": True, "entitlements": [f"{p}:PAY"],
         "approval_schemes": ["manager", "owner", "governance_group:Controls"]},
        {"id": f"AP-{p}-VENDOR", "name": f"{src} Supplier Maintenance", "source": src, "owner": exec_,
         "enabled": True, "requestable": True, "entitlements": [f"{p}:VENDOR"], "approval_schemes": ["manager", "owner"]},
        {"id": "AP-CRM-SALES", "name": "CRM Sales User", "source": "CRM", "owner": sales_mgr, "enabled": True,
         "requestable": True, "entitlements": ["CRM:EDIT"], "approval_schemes": ["manager"]},
        {"id": "AP-CRM-EXPORT", "name": "CRM Export", "source": "CRM", "owner": sales_mgr, "enabled": True,
         "requestable": False, "entitlements": ["CRM:EXPORT"], "approval_schemes": ["manager"]},
        {"id": "AP-AD-VPN", "name": "VPN", "source": "Active Directory", "owner": it_mgr, "enabled": True,
         "requestable": True, "entitlements": ["AD:VPN"], "approval_schemes": []},
        {"id": "AP-AD-ADMIN", "name": "Server Admins", "source": "Active Directory", "owner": sec, "enabled": True,
         "requestable": True, "entitlements": ["AD:SERVER_ADMINS"], "approval_schemes": ["manager", "owner"]},
        {"id": "AP-OLD", "name": "Legacy Share", "source": "NAS", "owner": it_mgr, "enabled": False,
         "requestable": True, "entitlements": ["NAS:WRITE"], "approval_schemes": ["manager"]},
        {"id": "AP-HR-COMP", "name": "HR Compensation View", "source": "HRIS", "owner": mgr, "enabled": True,
         "requestable": True, "entitlements": ["HR:COMP"], "approval_schemes": ["manager", rng.choice(
             ["hr_business_partner", "department_head", "security_team"])]},
    ]
    roles = [
        {"id": "R-STAFF", "name": f"{dept} Staff", "owner": mgr, "enabled": True, "requestable": False,
         "access_profiles": [f"AP-{p}-ENTRY", "AP-AD-VPN"], "entitlements": [],
         "membership": {"type": "STANDARD", "criteria": {"operation": "AND", "children": [
             {"attribute": "department", "operation": "EQUALS", "value": dept},
             {"attribute": "location", "operation": "EQUALS", "value": loc},
             {"attribute": "cloudLifecycleState", "operation": "EQUALS", "value": "active"}]}}},
        {"id": "R-SALES", "name": "Sales", "owner": sales_mgr, "enabled": True, "requestable": True,
         "access_profiles": ["AP-CRM-SALES"], "entitlements": [], "approval_schemes": ["manager"],
         "membership": {"type": "STANDARD", "criteria": {"operation": "OR", "children": [
             {"attribute": "department", "operation": "EQUALS", "value": "Sales"},
             {"attribute": "title", "operation": "STARTS_WITH", "value": "Account"}]}}},
        {"id": "R-IT", "name": "IT Operations", "owner": it_mgr, "enabled": True, "requestable": False,
         "access_profiles": ["AP-AD-VPN"], "entitlements": [],
         "membership": {"type": "STANDARD", "criteria": {"operation": "AND", "children": [
             {"attribute": "department", "operation": "EQUALS", "value": "IT"},
             {"operation": "OR", "children": [
                 {"attribute": "title", "operation": "CONTAINS", "value": "Engineer"},
                 {"attribute": "title", "operation": "ENDS_WITH", "value": "Administrator"}]}]}}},
        {"id": "R-PAYERS", "name": "Payment Approvers", "owner": exec_, "enabled": True, "requestable": False,
         "access_profiles": [f"AP-{p}-PAY"], "entitlements": [],
         "membership": {"type": "IDENTITY_LIST", "identities": [mgr, ctrl]}},
        {"id": "R-TREASURY", "name": "Treasury", "owner": exec_, "enabled": True, "requestable": True,
         "access_profiles": [f"AP-{p}-PAY"], "entitlements": [], "approval_schemes": ["manager",
                                                                                      "governance_group:Controls"],
         "membership": {"type": "STANDARD", "criteria": {"attribute": "department", "operation": "EQUALS",
                                                         "value": "Treasury"}}},
        {"id": "R-OLD", "name": "Old model", "owner": mgr, "enabled": False, "requestable": False,
         "access_profiles": ["AP-OLD"], "entitlements": [],
         "membership": {"type": "STANDARD", "criteria": {"attribute": "department", "operation": "EQUALS",
                                                         "value": dept}}},
    ]
    pend = rng.randint(3, 6)
    reqs = [
        ("APPROVED", staff, staff, f"AP-{p}-VENDOR", {"manager": "approve", "owner": "approve"}, 0),
        ("SOD_VIOLATION", ctrl, ctrl, f"AP-{p}-VENDOR", {}, 0),
        ("APPROVED", mgr, other, f"AP-{p}-ENTRY", {"manager": "approve", "owner": "approve"}, 0),
        ("PENDING", sales, sales, "AP-AD-ADMIN", {}, rng.randint(1, 2)),
        ("PENDING", it_eng, it_eng, "AP-AD-ADMIN", {"manager": "approve"}, pend),
        ("DENIED", other, other, f"AP-{p}-PAY", {"manager": "deny"}, 0),
        ("DENIED", staff, staff, f"AP-{p}-SUPERUSER", {}, 0),
        ("NOT_REQUESTABLE", sales, sales, "AP-CRM-EXPORT", {}, 0),
        ("NOT_REQUESTABLE", blank, blank, "AP-OLD", {}, 0),
        ("ALREADY_HAS_ACCESS", sales_mgr, sales, "AP-CRM-SALES", {}, 0),
        ("PENDING", other, other, "R-TREASURY", {"manager": "approve"}, rng.randint(0, 2)),
        ("DENIED", leaver, leaver, "AP-AD-VPN", {}, 0),
        ("APPROVED", blank, blank, "AP-AD-VPN", {}, 0),
        ("DENIED", staff, staff, "AP-HR-COMP", {"manager": "approve"}, 0),
        ("DENIED", sales, it_eng, "AP-AD-VPN", {}, 0),
        ("DENIED", blank, blank, f"AP-{p}-PAY", {}, policies["isc_access_requests"]["timeout_days"] +
         rng.randint(0, 5)),
    ]
    order = list(range(len(reqs)))
    rng.shuffle(order)
    requests = [{"id": f"REQ-{n + 1:02d}", "requester": reqs[k][1], "beneficiary": reqs[k][2], "item": reqs[k][3],
                 "decisions": reqs[k][4], "days_pending": reqs[k][5]} for n, k in enumerate(order)]
    return {"_description": f"Generated Identity Security Cloud scenario: {dept} in {loc}, {len(requests)} requests.",
            "identities": identities, "access_profiles": aps, "roles": roles,
            "governance_groups": {"Controls": [ctrl, exec_]}, "requests": requests,
            "_fallback_note": f"fallback approver in the policy is {policies['isc_access_requests']['escalation']['fallback_approver']}; "
                              f"this scenario's governance desk is {desk}"}
