"""
Lab 37 — Okta Administrator Roles: Standard Roles, Custom Roles & Resource Sets
===============================================================================

Okta Professional objectives
----------------------------
* 1.3  Administrator roles, custom roles and resource sets: choosing the
       least-privileged standard admin role, constraining it to groups or
       apps, building a custom admin role (permissions + resource set) when
       no standard role is narrow enough.
* 1.2  Groups and group rules: assigning admin roles to groups instead of
       people, admin groups (only super admins can change their membership),
       group rules (managed by super and org admins).

How it works
------------
You are the Okta administrator at a mid-sized company. Teams ask for admin
rights; you decide what to give, check whether admin actions are allowed, and
audit the assignments that already exist.

Part 1, the delegation planner. Each request lists admin tasks and may name
groups or apps the team should be limited to. Rules, in evaluation order:

1. No tasks, an unknown task, or a named group or app that does not exist →
   ESCALATE (nothing is guessed: deny by default).
2. Collect the permissions the tasks need. Candidate standard roles hold every
   one of them and, when groups or apps are named, can be constrained to them.
3. Pick the candidate that adds the fewest extra write permissions, then the
   fewest extras, then the narrowest by rank.
4. Use a CUSTOM_ROLE instead (exact permissions + a resource set) when every
   needed permission exists for custom roles and either no standard role fits,
   the best fit is a broad role (Super or Organization Administrator), or the
   request is read-only but the best fit can change things.
5. No candidate and a needed permission exists only in standard roles →
   ESCALATE. Otherwise → STANDARD_ROLE with the chosen role and constraint.
   Assign to a group: a request that names one person gets a reason to use a
   group instead.

Part 2, the action evaluator. Each attempt is an admin trying one permission
on one user, group or app. Checks, in order (the most-progressed role decides
the reason when every role fails):

1. Unknown action → DENIED (UNKNOWN_ACTION).
2. The actor holds no admin assignment, directly or through a group →
   DENIED (NOT_ASSIGNED). An unknown role or custom role grants nothing.
3. No assigned role includes the permission → MISSING_PERMISSION.
4. The target is not found, or is outside the role's constraint / resource set
   → OUTSIDE_SCOPE.
5. The target is protected: a super admin (only super admins, except the few
   actions the Help Center marks, such as clearing sessions); another admin
   (only super and org admins in this course's conservative policy); or an
   admin group (only super admins may change its membership) →
   PROTECTED_ADMIN_TARGET.
6. Otherwise → ALLOWED.

Part 3, the assignment audit. Each assignment gets every finding that applies,
most severe first: SUPER_ADMIN_EXCESS (more distinct super admins than the
policy maximum), CUSTOM_ROLE_EMPTY_RESOURCE_SET (missing or empty resource
set), UNSCOPED_ROLE (a constrainable role or an "all ..." resource set applied
org-wide with no recorded reason; an unknown role is treated as privileged and
unscoped), ROLE_ASSIGNED_TO_INDIVIDUAL (prefer a group), else OK.

Run it
------
    python main.py --course okta lab 37
"""

from __future__ import annotations

from dataclasses import dataclass, field

TITLE = "Lab 37 — Okta Administrator Roles: Standard Roles, Custom Roles & Resource Sets"
OBJECTIVES = "Okta Professional 1.3 Admin roles, custom roles and resource sets · 1.2 Groups and group rules"
COURSES = ("okta",)
PLAN_OUTCOMES = ["STANDARD_ROLE", "CUSTOM_ROLE", "ESCALATE"]
EVAL_OUTCOMES = ["ALLOWED", "DENIED"]
DENIALS = ["UNKNOWN_ACTION", "NOT_ASSIGNED", "MISSING_PERMISSION", "OUTSIDE_SCOPE", "PROTECTED_ADMIN_TARGET"]
FINDINGS = ["SUPER_ADMIN_EXCESS", "CUSTOM_ROLE_EMPTY_RESOURCE_SET", "UNSCOPED_ROLE", "ROLE_ASSIGNED_TO_INDIVIDUAL", "OK"]
SUPER = "Super Administrator"
_RS_KEYS = ("users_in_groups", "groups", "apps")
_ALL_KEYS = {"user": "all_users", "group": "all_groups", "app": "all_apps"}
_KIND_OF = {"user": "groups", "group": "groups", "app": "apps"}   # which constraint kind limits each resource


@dataclass
class Plan:
    id: str
    team: str
    outcome: str
    role: str | None
    constraint: dict = field(default_factory=dict)
    permissions: list[str] = field(default_factory=list)
    resource_set: dict = field(default_factory=dict)
    assign_to: str = "-"
    reasons: list[str] = field(default_factory=list)


@dataclass
class Evaluation:
    id: str
    actor: str
    action: str
    target: str
    outcome: str
    rule: str
    via: str = "-"
    reasons: list[str] = field(default_factory=list)


@dataclass
class AuditResult:
    id: str
    assignee: str
    role: str
    finding: str
    findings: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #
def role_perms(role: str | None, cfg: dict) -> set[str]:
    meta = cfg["roles"].get(role or "")
    if meta is None:
        return set()                                   # unknown role grants nothing (deny by default)
    return set(cfg["permissions"]) if "*" in meta["permissions"] else set(meta["permissions"])


def assignment_label(a: dict) -> str:
    return f"Custom: {a['custom_role']}" if a.get("custom_role") else (a.get("role") or "?")


def assignee_label(a: dict) -> str:
    who = a.get("assignee") or {}
    return f"group:{who['group']}" if who.get("group") else f"user:{who.get('user', '?')}"


def holders(a: dict, data: dict) -> list[str]:
    """Users who hold an assignment: the user, or every member of the group."""
    who = a.get("assignee") or {}
    if who.get("group"):
        return list(data.get("groups", {}).get(who["group"], []))
    return [who["user"]] if who.get("user") else []


def admin_index(data: dict) -> tuple[dict[str, list[dict]], set[str], set[str]]:
    """(user -> assignments, super admins, admin groups)."""
    by_user: dict[str, list[dict]] = {}
    supers: set[str] = set()
    admin_groups: set[str] = set()
    for a in data.get("assignments", []):
        if (a.get("assignee") or {}).get("group"):
            admin_groups.add(a["assignee"]["group"])
        for u in holders(a, data):
            by_user.setdefault(u, []).append(a)
            if a.get("role") == SUPER and not a.get("custom_role"):
                supers.add(u)
    return by_user, supers, admin_groups


def _counts(values) -> dict:
    out: dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return out


# --------------------------------------------------------------------------- #
# Part 1 — delegation planner
# --------------------------------------------------------------------------- #
def plan_request(req: dict, data: dict, cfg: dict) -> Plan:
    rid, team = req.get("id", "?"), req.get("team", "?")
    tasks = req.get("tasks") or []
    scope = {k: list(v) for k, v in (req.get("scope") or {}).items() if v}
    who = req.get("assign_to") or {}
    assign_to = f"group:{who['group']}" if who.get("group") else (f"user:{who['user']}" if who.get("user") else "-")
    reasons: list[str] = []

    def done(outcome, role=None, constraint=None, perms=(), rs=None):
        if outcome != "ESCALATE":
            if who.get("group"):
                reasons.append(f"assign to group {who['group']} so access follows group membership")
            else:
                reasons.append(f"assign to a group (for example '{team} Admins') instead of "
                               f"{who.get('user') or 'an individual'}: Okta recommends group assignment")
        return Plan(rid, team, outcome, role, constraint or {}, sorted(perms), rs or {}, assign_to, reasons)

    # Rule 1: missing / unknown input
    if not tasks:
        reasons.append("no tasks listed: no role is guessed (deny by default)")
        return done("ESCALATE")
    unknown = [t for t in tasks if t not in cfg["tasks"]]
    if unknown:
        reasons.append(f"task {', '.join(map(str, unknown))} is not in the delegation catalogue: no role is guessed "
                       "(deny by default)")
        return done("ESCALATE")
    known = {"groups": set(data.get("groups", {})), "apps": set(data.get("apps", []))}
    missing = [f"{k[:-1]} '{n}'" for k in ("groups", "apps") for n in scope.get(k, []) if n not in known[k]]
    if missing:
        reasons.append(f"{', '.join(missing)} does not exist in the org: fix the request first (deny by default)")
        return done("ESCALATE")
    # Rule 2: needed permissions and candidate standard roles
    perms = set()
    for t in tasks:
        perms |= set(cfg["tasks"][t]["permissions"])
    pmeta = cfg["permissions"]
    kinds = set(scope)
    customable = all(pmeta[p]["custom"] for p in perms)
    read_only = not any(pmeta[p]["write"] for p in perms)
    rank = cfg["role_rank"]
    cands = []
    for role in rank:
        have = role_perms(role, cfg)
        if perms <= have and kinds <= set(cfg["roles"][role]["constrain_to"]):
            extra = have - perms
            cands.append((sum(pmeta[p]["write"] for p in extra), len(extra), rank.index(role), role, sorted(extra)))
    rs = {}
    for res, key in (("user", "users_in_groups"), ("group", "groups"), ("app", "apps")):
        if any(pmeta[p]["resource"] == res for p in perms):
            names = scope.get(_KIND_OF[res])
            rs.update({key: names} if names else {_ALL_KEYS[res]: True})
    constraint = dict(scope)
    scope_txt = "; ".join(f"{k}: {', '.join(v)}" for k, v in sorted(scope.items())) or "whole org"
    # Rule 3/4/5
    if not cands:
        if customable:
            reasons.append(f"no standard role holds {len(perms)} needed permissions within {scope_txt}: build a "
                           "custom admin role with exactly these permissions (or assign two standard roles)")
            return done("CUSTOM_ROLE", "Custom admin role", constraint, perms, rs)
        std_only = sorted(p for p in perms if not pmeta[p]["custom"])
        reasons.append(f"no standard role can be limited to {scope_txt} for {', '.join(std_only)}, and custom roles "
                       "cannot grant it: needs identity team approval")
        return done("ESCALATE")
    writes, _, _, best, extra = min(cands)
    if customable and best in cfg["broad_roles"]:
        reasons.append(f"only {best} holds every needed permission; that is far too broad, so build a custom admin "
                       f"role with {len(perms)} permissions on {scope_txt}")
        return done("CUSTOM_ROLE", "Custom admin role", constraint, perms, rs)
    if customable and read_only and writes:
        reasons.append(f"the request is read-only but {best} can also change things "
                       f"({', '.join(p for p in extra if pmeta[p]['write'])}): build a read-only custom admin role "
                       f"on {scope_txt}")
        return done("CUSTOM_ROLE", "Custom admin role", constraint, perms, rs)
    note = f", constrained to {scope_txt}" if scope else ""
    reasons.append(f"least-privileged standard role for {', '.join(cfg['tasks'][t]['description'] for t in tasks)} "
                   f"is {best}{note}" + (f" (also grants {len(extra)} extra permissions)" if extra else ""))
    if best in cfg["broad_roles"]:
        reasons.append(f"{best} is a broad role: needs approval and a named owner, keep the count low")
    return done("STANDARD_ROLE", best, constraint, perms)


def plan_requests(data: dict, cfg: dict) -> list[Plan]:
    return [plan_request(r, data, cfg) for r in data.get("requests", [])]


# --------------------------------------------------------------------------- #
# Part 2 — action evaluator
# --------------------------------------------------------------------------- #
def _check_one(a: dict, action: str, att: dict, data: dict, cfg: dict, supers: set, admins: set,
               admin_groups: set) -> tuple[int, str]:
    """Return (stage reached, reason). Stage 3 = allowed; 0 missing permission, 1 outside scope, 2 protected."""
    meta = cfg["permissions"][action]
    res = meta["resource"]
    label = assignment_label(a)
    if a.get("custom_role"):
        role_meta = None
        defined = data.get("custom_roles", {}).get(a["custom_role"])
        perms = set(defined or [])
        if defined is None:
            return 0, f"custom role '{a['custom_role']}' is not defined: it grants nothing"
    else:
        role_meta = cfg["roles"].get(a.get("role") or "")
        perms = role_perms(a.get("role"), cfg)
        if role_meta is None:
            return 0, f"role '{a.get('role')}' is not a known standard role: it grants nothing"
    if action not in perms:
        return 0, f"{label} does not include {action}"
    # scope
    if res != "org":
        target = att.get("target")
        if res == "user":
            exists = target in data.get("users", {})
            tgroups = {g for g, m in data.get("groups", {}).items() if target in m}
        elif res == "group":
            exists = target in data.get("groups", {})
            tgroups = {target}
        else:
            exists = target in data.get("apps", [])
            tgroups = set()
        if not exists:
            return 1, f"{res} '{target}' is not found in the org (deny by default)"
        if role_meta is not None:
            limit = (a.get("constraints") or {}).get(_KIND_OF[res])
            if limit is not None:
                inside = target in limit if res == "app" else bool(tgroups & set(limit))
                if not inside:
                    return 1, f"{label} is constrained to {', '.join(limit) or 'nothing'}; {target} is outside it"
        else:
            rs = data.get("resource_sets", {}).get(a.get("resource_set") or "")
            if not rs:
                return 1, f"resource set '{a.get('resource_set')}' is missing or empty: the custom role covers nothing"
            key = {"user": "users_in_groups", "group": "groups", "app": "apps"}[res]
            inside = rs.get(_ALL_KEYS[res]) or (target in rs.get(key, []) if res != "user"
                                                 else bool(tgroups & set(rs.get(key, []))))
            if not inside:
                return 1, f"{target} is outside resource set {a.get('resource_set')}"
        # protected targets (writes only)
        if meta["write"]:
            allowed_on_super = (role_meta or {}).get("allowed_on_super_admins", [])
            if res == "user" and target in supers and "*" not in allowed_on_super and action not in allowed_on_super:
                return 2, f"{target} is a super admin: {label} may not {meta['description']} for super admins"
            if res == "user" and target in admins and target not in supers and not (role_meta or {}).get(
                    "manages_other_admins"):
                return 2, f"{target} holds an admin role: {label} may not change other administrators"
            if res == "group" and target in admin_groups and a.get("role") != SUPER:
                return 2, f"{target} has an admin role assigned: only super admins can change an admin group"
    return 3, f"{label} grants {action}" + (f" on {att.get('target')}" if res != "org" else "")


def evaluate_attempt(att: dict, data: dict, cfg: dict) -> Evaluation:
    aid, actor, action = att.get("id", "?"), att.get("actor") or "?", att.get("action") or "-"
    target = att.get("target") or "-"
    if action not in cfg["permissions"]:
        return Evaluation(aid, actor, action, target, "DENIED", "UNKNOWN_ACTION",
                          reasons=[f"action '{action}' is not in the permission catalogue (deny by default)"])
    by_user, supers, admin_groups = admin_index(data)
    mine = by_user.get(actor, [])
    if not mine:
        return Evaluation(aid, actor, action, target, "DENIED", "NOT_ASSIGNED",
                          reasons=[f"{actor} holds no admin role, directly or through a group"])
    results = [(_check_one(a, action, att, data, cfg, supers, set(by_user), admin_groups), a) for a in mine]
    (stage, why), best = max(results, key=lambda r: r[0][0])
    via = f"{assignment_label(best)} via {assignee_label(best)}"
    if stage == 3:
        return Evaluation(aid, actor, action, target, "ALLOWED", "ALLOWED", via, [why])
    rule = ["MISSING_PERMISSION", "OUTSIDE_SCOPE", "PROTECTED_ADMIN_TARGET"][stage]
    return Evaluation(aid, actor, action, target, "DENIED", rule, via, [why])


def evaluate_attempts(data: dict, cfg: dict) -> list[Evaluation]:
    return [evaluate_attempt(a, data, cfg) for a in data.get("attempts", [])]


# --------------------------------------------------------------------------- #
# Part 3 — assignment audit
# --------------------------------------------------------------------------- #
def super_admin_check(data: dict, cfg: dict) -> dict:
    _, supers, _ = admin_index(data)
    over = len(supers) > cfg["max_super_admins"]
    return {"count": len(supers), "super_admins": sorted(supers),
            "outcome": "SUPER_ADMIN_EXCESS" if over else "OK",
            "reasons": [f"{len(supers)} distinct super admins (policy max {cfg['max_super_admins']})"]}


def audit_assignments(data: dict, cfg: dict) -> list[AuditResult]:
    sa = super_admin_check(data, cfg)
    out = []
    for a in data.get("assignments", []):
        found: list[tuple[str, str]] = []
        notes: list[str] = []
        label = assignment_label(a)
        justified = bool((a.get("org_wide_justification") or "").strip())
        if a.get("custom_role"):
            if a["custom_role"] not in data.get("custom_roles", {}):
                found.append(("UNSCOPED_ROLE", f"custom role '{a['custom_role']}' is not defined: treated as "
                              "privileged and unscoped"))
            rs = data.get("resource_sets", {}).get(a.get("resource_set") or "")
            if not rs or not any(rs.get(k) for k in _RS_KEYS + tuple(_ALL_KEYS.values())):
                found.append(("CUSTOM_ROLE_EMPTY_RESOURCE_SET", f"resource set '{a.get('resource_set')}' is missing "
                              "or empty: the role governs nothing, fix or remove it"))
            else:
                alls = [k for k in _ALL_KEYS.values() if rs.get(k)]
                if alls and not justified:
                    found.append(("UNSCOPED_ROLE", f"resource set {a.get('resource_set')} uses "
                                  f"{', '.join(alls)} with no recorded reason: limit it to named groups or apps"))
        else:
            meta = cfg["roles"].get(a.get("role") or "")
            if meta is None:
                found.append(("UNSCOPED_ROLE", f"role '{a.get('role')}' is not in the catalogue: treated as "
                              "privileged and unscoped"))
            else:
                if a.get("role") == SUPER and sa["outcome"] != "OK":
                    found.append(("SUPER_ADMIN_EXCESS", f"{sa['count']} super admins > policy max "
                                  f"{cfg['max_super_admins']}: move this one to a narrower role"))
                limits = [k for k in meta["constrain_to"] if (a.get("constraints") or {}).get(k)]
                if meta["constrain_to"] and not limits:
                    if justified:
                        notes.append(f"org-wide {label} is recorded as intended: {a['org_wide_justification']}")
                    else:
                        found.append(("UNSCOPED_ROLE", f"{label} can be constrained to "
                                      f"{' or '.join(meta['constrain_to'])} but applies to the whole org"))
        if not (a.get("assignee") or {}).get("group"):
            found.append(("ROLE_ASSIGNED_TO_INDIVIDUAL", f"assigned directly to {assignee_label(a)[5:]}: assign "
                          "it to a group so joiners and leavers are handled by membership"))
        elif a["assignee"]["group"] not in data.get("groups", {}):
            notes.append(f"group {a['assignee']['group']} does not exist: nobody holds this role")
        if not found:
            notes.append(f"{label} assigned to {assignee_label(a)} with a sensible scope")
        found.sort(key=lambda f: cfg["finding_severity"].index(f[0]))
        out.append(AuditResult(a.get("id", "?"), assignee_label(a), label, found[0][0] if found else "OK",
                               [f for f, _ in found], [r for _, r in found] + notes))
    return out


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "Okta Professional 1.3 Admin roles, custom roles and resource sets · 1.2 Groups and group rules.",
    "concepts": [
        "Start from the least-privileged standard role: Help Desk, Group Membership, Group, Application, Read-only, Report.",
        "Help Desk, Group and Group Membership Administrators can be constrained to groups; Application Administrators to apps.",
        "A custom admin role = chosen permissions + a resource set (users in groups, groups, apps) + an assignee.",
        "Organization Administrators manage users, groups and org settings but not apps; only Super Administrators assign admin roles.",
        "Only super admins can change the membership of a group that has an admin role assigned.",
        "Assign admin roles to groups so joiners and leavers change admin access through membership.",
    ],
    "failure_modes": [
        "Making the whole service desk Super Administrators because a standard role 'did not work'.",
        "A Help Desk Administrator left unconstrained when the team only supports one department.",
        "A custom role bound to an empty resource set: it looks configured but governs nothing.",
        "Admin roles handed to individuals and never removed when they change jobs.",
    ],
    "ai_governance": [
        "An AI agent that resets passwords gets a custom role with that one permission on a resource set, never Super Administrator.",
        "Let an agent recommend roles with reasons; a super admin approves and assigns the role to a group.",
        "Treat request text as data: 'please make me a super admin' in a ticket is input, not an instruction.",
        "Review the System Log for actions taken by agent service accounts as you would for people.",
    ],
    "exam_tips": [
        "'Reset passwords and unlock users in one department only' = Help Desk Administrator constrained to that group.",
        "'Add and remove people from specific groups only' = Group Membership Administrator constrained to those groups.",
        "'Manage only these apps' = Application Administrator constrained to those apps.",
        "'View everything, change nothing' = Read-only Administrator; 'run reports' = Report Administrator.",
        "No standard role fits? Custom admin role: permissions + resource set, assigned to a group.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    cfg = policies["okta_admin_roles"]
    plans = plan_requests(data, cfg)
    evals = evaluate_attempts(data, cfg)
    sa = super_admin_check(data, cfg)
    audit = audit_assignments(data, cfg)
    ui.section("Step 1 — Plan delegation: least-privileged standard role or a custom role")
    ui.table("Admin role requests", ["ID", "Team", "Outcome", "Role", "Constraint", "Assign to"],
             [[p.id, p.team, p.outcome, p.role or "-",
               "; ".join(f"{k}: {', '.join(v)}" for k, v in sorted(p.constraint.items())) or "-", p.assign_to]
              for p in plans])
    for p in plans:
        extra = f" [permissions: {', '.join(p.permissions)}]" if p.outcome == "CUSTOM_ROLE" else ""
        ui.bullet(f"{p.id} → {p.outcome}: " + "; ".join(p.reasons) + extra,
                  style={"STANDARD_ROLE": "green", "CUSTOM_ROLE": "cyan"}.get(p.outcome, "yellow"))
    ui.section("Step 2 — Evaluate admin actions against roles, constraints and resource sets")
    ui.table("Admin actions", ["ID", "Actor", "Action", "Target", "Outcome", "Rule"],
             [[e.id, e.actor, e.action, e.target, e.outcome, e.rule] for e in evals])
    for e in evals:
        ui.bullet(f"{e.id} → {e.outcome} ({e.rule}): " + "; ".join(e.reasons),
                  style="green" if e.outcome == "ALLOWED" else "red")
    ui.section("Step 3 — Audit existing admin assignments")
    ui.status("Super admin count", "PASS" if sa["outcome"] == "OK" else "FAIL", "; ".join(sa["reasons"]))
    ui.table("Admin assignments", ["ID", "Assignee", "Role", "Finding"],
             [[a.id, a.assignee, a.role, a.finding] for a in audit])
    for a in audit:
        ui.bullet(f"{a.id} → {a.finding}: " + "; ".join(a.reasons), style="green" if a.finding == "OK" else "yellow")
    metrics = {"requests": len(plans), "plan_counts": _counts(p.outcome for p in plans),
               "attempts": len(evals), "eval_counts": _counts(e.outcome for e in evals),
               "denial_counts": _counts(e.rule for e in evals if e.outcome == "DENIED"),
               "assignments": len(audit), "finding_counts": _counts(a.finding for a in audit),
               "super_admins": sa["count"]}
    ui.print(f"{len(plans)} requests planned · {metrics['eval_counts'].get('ALLOWED', 0)} of {len(evals)} actions "
             f"allowed · {sum(a.finding != 'OK' for a in audit)} of {len(audit)} assignments flagged · "
             f"{sa['count']} super admins")
    ui.insight(INSIGHT)
    return {"plans": {p.id: p.outcome for p in plans}, "roles": {p.id: p.role for p in plans},
            "attempts": {e.id: e.outcome for e in evals}, "rules": {e.id: e.rule for e in evals},
            "audit": {a.id: a.finding for a in audit},
            "super_admin_check": {"outcome": sa["outcome"], "count": sa["count"]}, "metrics": metrics}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["okta_admin_roles"]
    plans = plan_requests(data, cfg)
    evals = evaluate_attempts(data, cfg)
    audit = audit_assignments(data, cfg)
    sa = super_admin_check(data, cfg)
    reqs = {r.get("id"): r for r in data.get("requests", [])}
    atts = {a.get("id"): a for a in data.get("attempts", [])}
    asg = {a.get("id"): a for a in data.get("assignments", [])}
    std_roles = sorted(cfg["roles"])
    qs: list = []
    for p in plans:
        src = {k: v for k, v in reqs.get(p.id, {}).items() if k != "id"}
        qs.append(Question(prompt=f"{p.id}: how should this admin access request be handled?", context=f"request={src}",
                           choices=list(PLAN_OUTCOMES), answer=p.outcome, explanation="; ".join(p.reasons),
                           objective="1.3"))
    asked = set()
    for p in plans:
        if p.outcome == "STANDARD_ROLE" and p.role not in asked:
            asked.add(p.role)
            src = reqs.get(p.id, {})
            qs.append(Question(prompt=f"{p.id}: which standard admin role is least privileged for this request?",
                               context=f"tasks={src.get('tasks')} scope={src.get('scope') or 'whole org'}",
                               choices=choices_with(p.role, std_roles, key=p.id), answer=p.role,
                               explanation="; ".join(p.reasons), objective="1.3"))
    for e in evals:
        src = {k: v for k, v in atts.get(e.id, {}).items() if k != "id"}
        qs.append(Question(prompt=f"{e.id}: is this admin action allowed?", context=f"attempt={src}",
                           choices=list(EVAL_OUTCOMES), answer=e.outcome, explanation="; ".join(e.reasons),
                           objective="1.2" if e.target in data.get("groups", {}) else "1.3"))
    seen = set()
    for e in evals:
        if e.outcome == "DENIED" and e.rule not in seen:
            seen.add(e.rule)
            src = {k: v for k, v in atts.get(e.id, {}).items() if k != "id"}
            qs.append(Question(prompt=f"{e.id} is denied. Which check stopped it?", context=f"attempt={src}",
                               choices=list(DENIALS), answer=e.rule, explanation="; ".join(e.reasons),
                               objective="1.3"))
    done = set()
    for a in audit:
        if a.finding in done:
            continue
        done.add(a.finding)
        src = {k: v for k, v in asg.get(a.id, {}).items() if k != "id"}
        qs.append(Question(prompt=f"{a.id}: which audit finding does this admin assignment get (most severe)?",
                           context=f"assignment={src}", answer=a.finding,
                           choices=choices_with(a.finding, FINDINGS, exclude=a.findings, key=a.id),
                           explanation="; ".join(a.reasons),
                           objective="1.2" if a.finding == "ROLE_ASSIGNED_TO_INDIVIDUAL" else "1.3"))
    qs.append(Question(prompt="What is the org-wide super admin check result?",
                       context=f"super admins: {', '.join(sa['super_admins']) or 'none'}; "
                               f"policy max {cfg['max_super_admins']}",
                       choices=["SUPER_ADMIN_EXCESS", "OK"], answer=sa["outcome"], explanation="; ".join(sa["reasons"]),
                       objective="1.3"))
    qs.append(Question(prompt="An Organization Administrator tries to add a user to a group that has the Help Desk "
                              "Administrator role assigned. What happens?",
                       choices=["it is blocked: only super admins can change membership of a group with an admin role",
                                "it succeeds because Organization Administrators manage every group",
                                "it succeeds only if a group rule adds the user",
                                "it succeeds once the user resets their password"],
                       answer="it is blocked: only super admins can change membership of a group with an admin role",
                       explanation=cfg["concepts"]["admin group"], objective="1.2"))
    qs.append(Question(prompt="Why assign admin roles to a group rather than to each person?",
                       choices=["admin access then follows group membership, so movers and leavers lose it in one place",
                                "groups get extra permissions that individuals cannot hold",
                                "individual assignments expire after one day",
                                "group assignment turns every member into a super admin"],
                       answer="admin access then follows group membership, so movers and leavers lose it in one place",
                       explanation="Okta lets you assign admin roles to groups; membership changes then add or "
                                   "remove the role", objective="1.2"))
    qs.append(Question(prompt="Which standard admin roles can manage group rules?",
                       choices=["Super and Organization Administrators", "Group Membership Administrators",
                                "Help Desk Administrators", "Report Administrators"],
                       answer="Super and Organization Administrators",
                       explanation="group rules are an org-level setting; group and group membership admins can only "
                                   "view them", objective="1.2"))
    for term in ("resource set", "custom admin role", "role constraint", "admin group", "group rule"):
        if term in cfg["concepts"]:
            qs.append(Question(prompt=f"Which term is this? \"{cfg['concepts'][term]}\"",
                               choices=sorted(cfg["concepts"]), answer=term, explanation=cfg["concepts"][term],
                               objective="1.2" if term in ("admin group", "group rule") else "1.3"))
    return qs


# --------------------------------------------------------------------------- #
# Seeded scenario generator
# --------------------------------------------------------------------------- #
_FIRST = ["ada", "bo", "cy", "dina", "emil", "fern", "gale", "hal", "isla", "joel", "kira", "leon", "mara", "nils",
          "opal", "pax", "rhea", "soren", "tara", "ugo", "vera", "wade", "xena", "yuri", "zia"]
_LAST = ["ash", "birch", "cove", "dale", "elm", "ford", "glen", "holt", "ivey", "jory", "kemp", "lark", "mead",
         "north", "oak", "pine", "quill", "rowe", "sage", "thorn", "vane", "wick"]


def generate_scenario(rng, policies: dict) -> dict:
    cfg = policies["okta_admin_roles"]
    names = iter(rng.sample([f"{f}.{l}" for f in _FIRST for l in _LAST], 40))
    depts = rng.sample(["Sales", "Finance", "Engineering", "Marketing", "Legal", "Support"], 3)
    d1, d2, d3 = depts
    apps = rng.sample(["Expensely", "Wikiwise", "Payroll Hub", "TicketDesk", "CodeVault", "SignFlow"], 3)
    users: dict = {}

    def person(dept):
        u = next(names)
        users[u] = {"department": dept}
        return u

    groups: dict = {d: [person(d) for _ in range(rng.randint(2, 3))] for d in depts}
    hd = [person("IT") for _ in range(2)]
    supers = [person("IT") for _ in range(cfg["max_super_admins"] + rng.randint(0, 1))]
    solo_super = person("IT")
    org_admin, app_admin, gm_admin, auditor, nobody, odd = (person(x) for x in
                                                            ("IT", "IT", d3, "Audit", d1, "IT"))
    fin_support = groups[d2][0]
    groups.update({"HelpDesk-Admins": hd, "Super-Admins": supers, "Project-Team": [groups[d1][0], groups[d3][0]],
                   "Audit-Team": [auditor], "Dept-Support": [fin_support], "App-Ops": [person("IT")]})
    data_custom = {"Dept Password Reset": ["okta.users.read", "okta.users.credentials.resetPassword"],
                   "App Operator": ["okta.apps.read", "okta.apps.manage"]}
    rsets = {"RS-DEPT": {"users_in_groups": [d2]}, "RS-EMPTY": {"apps": []}}
    asg = [
        {"assignee": {"group": "HelpDesk-Admins"}, "role": "Help Desk Administrator", "constraints": {"groups": [d1, d2]}},
        {"assignee": {"group": "Super-Admins"}, "role": SUPER},
        {"assignee": {"user": solo_super}, "role": SUPER},
        {"assignee": {"user": app_admin}, "role": "Application Administrator"},
        {"assignee": {"group": "Audit-Team"}, "role": "Read-only Administrator"},
        {"assignee": {"user": gm_admin}, "role": "Group Membership Administrator", "constraints": {"groups": ["Project-Team"]}},
        {"assignee": {"group": "App-Ops"}, "custom_role": "App Operator", "resource_set": "RS-EMPTY"},
        {"assignee": {"group": "Dept-Support"}, "custom_role": "Dept Password Reset", "resource_set": "RS-DEPT"},
        {"assignee": {"user": org_admin}, "role": "Organization Administrator"},
        {"assignee": {"user": odd}, "role": rng.choice(["Billing Administrator", "Tenant Operator"])},
    ]
    rng.shuffle(asg)
    for n, a in enumerate(asg, 1):
        a["id"] = f"A{n:02d}"
    t1, t3 = groups[d1][-1], groups[d3][-1]
    attempts = [
        {"actor": hd[0], "action": "okta.users.credentials.resetPassword", "target": t1},
        {"actor": hd[1], "action": "okta.users.credentials.resetPassword", "target": t3},
        {"actor": hd[0], "action": "okta.users.credentials.resetPassword", "target": fin_support},
        {"actor": hd[1], "action": "okta.users.lifecycle.manage", "target": t1},
        {"actor": app_admin, "action": "okta.apps.assignment.manage", "target": rng.choice(apps)},
        {"actor": gm_admin, "action": "okta.groups.members.manage", "target": "Project-Team"},
        {"actor": gm_admin, "action": "okta.groups.members.manage", "target": d1},
        {"actor": org_admin, "action": "okta.groups.members.manage", "target": "HelpDesk-Admins"},
        {"actor": org_admin, "action": "okta.users.credentials.resetPassword", "target": rng.choice(supers)},
        {"actor": org_admin, "action": "okta.users.lifecycle.clearSessions", "target": rng.choice(supers)},
        {"actor": nobody, "action": "okta.users.credentials.resetPassword", "target": t1},
        {"actor": fin_support, "action": "okta.users.credentials.resetPassword", "target": groups[d2][-1]},
        {"actor": fin_support, "action": "okta.users.credentials.resetFactors", "target": groups[d2][-1]},
        {"actor": hd[0], "action": rng.choice(["okta.users.teleport", "okta.everything.manage"]), "target": t1},
    ]
    rng.shuffle(attempts)
    for n, a in enumerate(attempts, 1):
        a["id"] = f"T{n:02d}"
    reqs = [
        {"team": "Service Desk", "tasks": ["reset_passwords", "unlock_users"], "scope": {"groups": [d1]},
         "assign_to": {"group": "HelpDesk-Admins"}},
        {"team": "Project Leads", "tasks": ["manage_group_membership"], "scope": {"groups": ["Project-Team"]},
         "assign_to": {"user": gm_admin}},
        {"team": f"{d3} IT", "tasks": ["create_users", "edit_user_profiles", "manage_group_membership"],
         "scope": {"groups": [d3]}, "assign_to": {"group": f"{d3}-IT"}},
        {"team": "App Team", "tasks": ["manage_apps", "assign_apps"], "scope": {"apps": apps[:2]},
         "assign_to": {"group": "App-Ops"}},
        {"team": "Auditors", "tasks": ["view_directory", "view_apps", "run_reports", "view_system_log"],
         "assign_to": {"group": "Audit-Team"}},
        {"team": "Finance Analysts", "tasks": ["run_reports"], "assign_to": {"user": auditor}},
        {"team": "IT Director", "tasks": ["manage_admins"], "assign_to": {"group": "Super-Admins"}},
        {"team": f"{d2} Support", "tasks": ["reset_passwords", "assign_apps"],
         "scope": {"groups": [d2], "apps": [apps[0]]}, "assign_to": {"group": "Dept-Support"}},
        {"team": f"{d1} Leads", "tasks": ["view_directory"], "scope": {"groups": [d1]}, "assign_to": {"user": t1}},
        {"team": "Branding", "tasks": ["edit_org_settings"], "scope": {"groups": [d1]}, "assign_to": {"user": odd}},
        {"team": "Facilities", "tasks": [rng.choice(["rotate_badges", "order_laptops"])], "assign_to": {"user": odd}},
        {"team": "Identity Team", "tasks": ["manage_group_rules"], "assign_to": {"group": "Super-Admins"}},
    ]
    rng.shuffle(reqs)
    for n, r in enumerate(reqs, 1):
        r["id"] = f"R{n:02d}"
    return {"_description": "Generated Okta admin delegation scenario (fictional).", "org": "Larkspur Example Co",
            "users": users, "groups": groups, "apps": apps, "custom_roles": data_custom, "resource_sets": rsets,
            "assignments": asg, "attempts": attempts, "requests": reqs}
