"""
Lab 35 — Tenant Administration: Roles, Administrative Units & Delegation
========================================================================

SC-300 objectives
-----------------
* 1.1  Configure and manage a Microsoft Entra tenant: built-in and custom
       Microsoft Entra roles, role scope, administrative units (including
       restricted management administrative units), delegation by least
       privilege, emergency access accounts.
* 1.2  Create, configure, and manage Microsoft Entra identities: users and
       guests, groups and dynamic membership rules.

How it works
------------
You are the identity team at a mid-sized company. Help-desk staff and regional
admins ask for admin rights; you decide what to give, then audit what is
already assigned.

Part 1, the delegation planner. Each request names an admin task, and may name
a region or one target object. Rules, in evaluation order:

1. Missing or unknown task → ESCALATE (no role is guessed: deny by default).
2. Unknown requester, or a guest asking for a task whose role is privileged →
   ESCALATE (unknown principals are treated as guests).
3. The task needs only a narrow app permission set → CUSTOM_ROLE with exactly
   those permissions, scoped to the named app if there is one.
4. A target object is named: the least-privileged role can be scoped to that
   object (for example Cloud Application Administrator on one enterprise app)
   → OBJECT, otherwise ESCALATE (a built-in role cannot be limited to it).
5. A region is named: the role can be scoped to an administrative unit and an
   AU exists for that region → ADMINISTRATIVE_UNIT; no AU for the region, or a
   tenant-only role (such as Conditional Access Administrator) → ESCALATE.
   Never silently fall back to tenant scope.
6. Otherwise → TENANT with the least-privileged built-in role for the task.

Part 2, the role assignment audit. Each existing assignment gets every finding
that applies, reported most severe first:

1. PRIVILEGED_ROLE_ON_GUEST: a guest (or an unknown principal) holds a
   privileged role. Unknown roles are treated as privileged.
2. GLOBAL_ADMIN_EXCESS: the tenant has more Global Administrator assignments
   than the policy maximum and this one is not an emergency access account.
   The tenant check also fails if fewer than the minimum emergency accounts exist.
3. RESTRICTED_AU_MEMBER: the admin is expected to manage a member of a restricted
   management AU, but the assignment is not scoped to that AU (tenant-wide
   admins, Global Administrators included, cannot change those members).
4. ASSIGNMENT_TOO_BROAD: tenant scope where an AU was intended and the role is
   AU-scopable, or a broader role than the least-privileged one for the task.
5. OK otherwise.

Part 3, dynamic group checks. Each dynamic membership rule (for example
``(user.department -eq "Sales") -and (user.country -eq "Germany")``) is evaluated
against every user and compared with the documented intent. Any user wrongly
included or excluded, a rule that cannot be parsed, or a group with no documented
intent → DYNAMIC_GROUP_RULE; otherwise OK.

Run it
------
    python main.py --course sc300 lab 35
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

TITLE = "Lab 35 — Tenant Administration: Roles, Administrative Units & Delegation"
OBJECTIVES = "SC-300 1.1 Configure and manage a Microsoft Entra tenant · 1.2 Create, configure, and manage identities"
COURSES = ("sc300",)
PLAN_OUTCOMES = ["TENANT", "ADMINISTRATIVE_UNIT", "OBJECT", "CUSTOM_ROLE", "ESCALATE"]
FINDINGS = ["PRIVILEGED_ROLE_ON_GUEST", "GLOBAL_ADMIN_EXCESS", "RESTRICTED_AU_MEMBER", "ASSIGNMENT_TOO_BROAD",
            "DYNAMIC_GROUP_RULE", "OK"]
GA = "Global Administrator"


@dataclass
class Plan:
    id: str
    requester: str
    task: str
    role: str | None
    scope: str | None
    outcome: str
    reasons: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)


@dataclass
class AuditResult:
    id: str
    principal: str
    role: str
    scope: str
    finding: str
    findings: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


@dataclass
class GroupResult:
    id: str
    name: str
    rule: str
    outcome: str
    members: list[str] = field(default_factory=list)
    wrongly_included: list[str] = field(default_factory=list)
    wrongly_excluded: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #
def role_meta(role: str | None, cfg: dict) -> tuple[dict, bool]:
    """(metadata, known). An unknown role is treated as privileged and unscopable (deny by default)."""
    meta = cfg["roles"].get(role or "")
    if meta is None:
        return {"privileged": True, "au_scopable": False, "object_scopable": False}, False
    return meta, True


def user_type(upn: str | None, principals: dict, cfg: dict) -> tuple[str, bool]:
    """('Member'|'Guest', known). An unknown principal is treated as a guest."""
    p = principals.get(upn or "")
    if p is None:
        return cfg["unknown_principal_user_type"], False
    return p.get("userType") or cfg["unknown_principal_user_type"], True


def au_for_region(region: str, data: dict) -> dict | None:
    for au in data.get("administrative_units", []):
        if str(au.get("region", "")).lower() == str(region).lower():
            return au
    return None


# --------------------------------------------------------------------------- #
# Part 1 — delegation planner
# --------------------------------------------------------------------------- #
def plan_request(req: dict, data: dict, cfg: dict) -> Plan:
    rid, who, task_name = req.get("id", "?"), req.get("requester", "?"), req.get("task")
    principals = data.get("principals", {})
    task = cfg["tasks"].get(task_name or "")
    reasons: list[str] = []

    def done(outcome, role=None, scope=None, perms=()):
        asked = req.get("asked_for")
        if asked and role and asked != role:
            reasons.append(f"asked for {asked}; least privileged is {role}")
        return Plan(rid, who, task_name or "-", role, scope, outcome, reasons, list(perms))

    # Rule 1: unknown task
    if task is None:
        reasons.append(f"task '{task_name}' is not in the delegation catalogue: no role is guessed (deny by default)")
        return done("ESCALATE")
    role = task["role"]
    custom = role == "custom"
    meta, _ = role_meta(None if custom else role, cfg)
    if custom:   # a custom role made of app permissions is treated as privileged for the guest rule
        meta = {"privileged": True, "au_scopable": False, "object_scopable": True}
    # Rule 2: guest / unknown requester and privileged role
    utype, known = user_type(who, principals, cfg)
    if not known:
        reasons.append(f"requester {who} is not in the directory: treated as a guest")
    if utype == "Guest" and meta["privileged"]:
        reasons.append(f"{'a custom app role' if custom else role} is privileged and the requester is a guest "
                       "(B2B user): do not delegate")
        return done("ESCALATE")
    target, region = req.get("target_object"), req.get("region")
    # Rule 3: narrow app permission set → custom role
    if custom:
        scope = target or "tenant"
        reasons.append(f"only {len(task['permissions'])} app permissions needed; no built-in role is that narrow, "
                       f"so build custom role '{task['custom_role']}' scoped to {scope} "
                       "(custom roles need Microsoft Entra ID P1 or P2)")
        return done("CUSTOM_ROLE", f"Custom: {task['custom_role']}", scope, task["permissions"])
    # Rule 4: one target object
    if target:
        if meta["object_scopable"]:
            reasons.append(f"{role} can be assigned at the scope of one application: scoped to {target}")
            return done("OBJECT", role, target)
        reasons.append(f"{role} cannot be scoped to {target}; consider making the requester the object's owner, "
                       "or placing it in an administrative unit")
        return done("ESCALATE")
    # Rule 5: one region
    if region:
        if not meta["au_scopable"]:
            reasons.append(f"{role} can only be assigned tenant-wide, so it cannot be limited to {region}: "
                           "needs identity team approval")
            return done("ESCALATE")
        au = au_for_region(region, data)
        if au is None:
            reasons.append(f"no administrative unit exists for {region}: create one first; never fall back to "
                           "tenant scope")
            return done("ESCALATE")
        note = " (restricted management AU)" if au.get("restricted") else ""
        reasons.append(f"{role} is administrative-unit scopable: scoped to {au['id']}{note}")
        return done("ADMINISTRATIVE_UNIT", role, f"au:{au['id']}")
    # Rule 6: tenant
    reasons.append(f"least-privileged built-in role to {task['description']} is {role}, tenant-wide")
    return done("TENANT", role, "tenant")


def plan_requests(data: dict, cfg: dict) -> list[Plan]:
    return [plan_request(r, data, cfg) for r in data.get("requests", [])]


# --------------------------------------------------------------------------- #
# Part 2 — role assignment audit
# --------------------------------------------------------------------------- #
def global_admin_check(data: dict, cfg: dict) -> dict:
    principals = data.get("principals", {})
    holders = [a.get("principal") for a in data.get("assignments", []) if a.get("role") == GA]
    emergency = sorted({h for h in holders if principals.get(h or "", {}).get("emergency_access")
                        and principals[h].get("userType") == "Member"})
    reasons = [f"{len(holders)} Global Administrator assignments (policy max {cfg['max_global_admins']})",
               f"{len(emergency)} emergency access accounts (policy min {cfg['min_emergency_accounts']})"]
    bad = len(holders) > cfg["max_global_admins"] or len(emergency) < cfg["min_emergency_accounts"]
    return {"count": len(holders), "emergency": emergency, "outcome": "GLOBAL_ADMIN_EXCESS" if bad else "OK",
            "reasons": reasons}


def audit_assignments(data: dict, cfg: dict) -> list[AuditResult]:
    principals = data.get("principals", {})
    restricted = {au["id"]: set(au.get("members", [])) for au in data.get("administrative_units", [])
                  if au.get("restricted")}
    ga = global_admin_check(data, cfg)
    out = []
    for a in data.get("assignments", []):
        upn, role, scope = a.get("principal"), a.get("role"), a.get("scope") or "tenant"
        found: list[tuple[str, str]] = []
        notes: list[str] = []
        meta, known_role = role_meta(role, cfg)
        if not known_role:
            notes.append(f"role '{role}' is not in the catalogue: treated as privileged")
        utype, known = user_type(upn, principals, cfg)
        if not known:
            notes.append(f"{upn} is not in the directory: treated as a guest")
        p = principals.get(upn or "", {})
        if utype == "Guest" and meta["privileged"]:
            found.append(("PRIVILEGED_ROLE_ON_GUEST", f"guest {upn} holds privileged role {role}"))
        if role == GA and ga["count"] > cfg["max_global_admins"] and upn not in ga["emergency"]:
            found.append(("GLOBAL_ADMIN_EXCESS", f"{ga['count']} Global Administrators > policy max "
                          f"{cfg['max_global_admins']}: remove this one or move it to a narrower role"))
        for target in a.get("manages", []):
            for au_id, members in sorted(restricted.items()):
                if target in members and scope != f"au:{au_id}":
                    found.append(("RESTRICTED_AU_MEMBER", f"{target} is in restricted management AU {au_id}; only "
                                  f"admins assigned at that AU's scope can change it, and this assignment is "
                                  f"scoped to {scope}"))
        intended = a.get("intended_scope")
        if scope == "tenant" and intended and intended != "tenant":
            if meta["au_scopable"]:
                found.append(("ASSIGNMENT_TOO_BROAD", f"{role} is tenant-wide but only {intended} is needed: "
                              "re-assign at administrative-unit scope"))
            else:
                notes.append(f"{role} cannot be AU-scoped, so tenant scope is the only option for {intended}")
        need = a.get("needed_for")
        if need:
            task = cfg["tasks"].get(need)
            if task is None:
                found.append(("ASSIGNMENT_TOO_BROAD", f"task '{need}' is unknown, so {role} cannot be justified"))
            elif task["role"] != role and not (task["role"] == "custom" and role.startswith("Custom")):
                least = task.get("custom_role", task["role"]) if task["role"] == "custom" else task["role"]
                found.append(("ASSIGNMENT_TOO_BROAD", f"{role} is broader than needed to {task['description']}: "
                              f"least privileged is {least}"))
        if not found:
            if p.get("emergency_access") and role == GA:
                notes.append("emergency access account: permanent Global Administrator is expected; monitor sign-ins")
            elif utype == "Guest":
                notes.append(f"{role} is not privileged: allowed for a guest, include it in access reviews")
            elif scope.startswith("au:"):
                notes.append(f"scoped to {scope[3:]}: least privilege by administrative unit")
            else:
                notes.append(f"{role} at {scope} scope matches the job")
        found.sort(key=lambda f: cfg["finding_severity"].index(f[0]))
        out.append(AuditResult(a.get("id", "?"), upn or "?", role or "?", scope, found[0][0] if found else "OK",
                               [f for f, _ in found], [r for _, r in found] + notes))
    return out


# --------------------------------------------------------------------------- #
# Part 3 — dynamic membership rules
# --------------------------------------------------------------------------- #
# A deliberately small subset of the Microsoft Entra dynamic membership rule syntax: user.<attribute>
# compared with -eq/-ne/-startsWith/-notStartsWith/-contains/-notContains/-in/-notIn, joined by -and/-or
# (-and binds tighter) with parentheses. Comparisons here are case-insensitive, as Learn describes for
# string values. Exact null handling in the real service is not modelled: a missing attribute matches
# only -ne/-notContains/-notStartsWith/-notIn (kept generic on purpose).
_TOKEN = re.compile(r'\s*(\(|\)|\[|\]|,|"[^"]*"|-[A-Za-z]+|user\.[A-Za-z]+)')
_OPS = {"-eq", "-ne", "-startswith", "-notstartswith", "-contains", "-notcontains", "-in", "-notin"}


class RuleError(ValueError):
    pass


def _tokenize(rule: str) -> list[str]:
    pos, toks = 0, []
    rule = rule.rstrip()
    while pos < len(rule):
        m = _TOKEN.match(rule, pos)
        if not m:
            raise RuleError(f"cannot read the rule near '{rule[pos:pos + 15].strip()}'")
        toks.append(m.group(1))
        pos = m.end()
    return toks


def parse_rule(rule: str):
    """Parse into a nested tuple tree; raises RuleError on anything outside the supported subset."""
    if not rule or not str(rule).strip():
        raise RuleError("rule is empty")
    toks, i = _tokenize(str(rule)), 0

    def peek():
        return toks[i] if i < len(toks) else None

    def take(expected=None):
        nonlocal i
        t = peek()
        if t is None or (expected and t.lower() != expected):
            raise RuleError(f"expected {expected or 'more'} but found {t or 'end of rule'}")
        i += 1
        return t

    def expr():
        node = conj()
        while (peek() or "").lower() == "-or":
            take()
            node = ("or", node, conj())
        return node

    def conj():
        node = unary()
        while (peek() or "").lower() == "-and":
            take()
            node = ("and", node, unary())
        return node

    def unary():
        if peek() == "(":
            take("(")
            node = expr()
            take(")")
            return node
        attr = take()
        if not attr.lower().startswith("user."):
            raise RuleError(f"expected user.<attribute> but found {attr}")
        op = take().lower()
        if op not in _OPS:
            raise RuleError(f"operator {op} is not supported")
        if op in ("-in", "-notin"):
            take("[")
            vals = [take().strip('"')]
            while peek() == ",":
                take(",")
                vals.append(take().strip('"'))
            take("]")
            return ("cmp", attr[5:], op, vals)
        val = take()
        if not val.startswith('"'):
            raise RuleError(f"value {val} must be a quoted string")
        return ("cmp", attr[5:], op, val.strip('"'))

    tree = expr()
    if peek() is not None:
        raise RuleError(f"unexpected {peek()} after the end of the rule")
    return tree


def evaluate_rule(tree, user: dict) -> bool:
    kind = tree[0]
    if kind == "and":
        return evaluate_rule(tree[1], user) and evaluate_rule(tree[2], user)
    if kind == "or":
        return evaluate_rule(tree[1], user) or evaluate_rule(tree[2], user)
    _, attr, op, val = tree
    raw = next((v for k, v in user.items() if k.lower() == attr.lower()), None)
    if raw is None:
        return op in ("-ne", "-notcontains", "-notstartswith", "-notin")
    s = str(raw).lower()
    if op in ("-in", "-notin"):
        hit = s in {v.lower() for v in val}
        return hit if op == "-in" else not hit
    v = val.lower()
    return {"-eq": s == v, "-ne": s != v, "-startswith": s.startswith(v), "-notstartswith": not s.startswith(v),
            "-contains": v in s, "-notcontains": v not in s}[op]


def matches_intent(user: dict, intent: dict) -> bool:
    for attr, allowed in intent.items():
        val = user.get(attr)
        if val is None or str(val).lower() not in {str(a).lower() for a in allowed}:
            return False
    return True


def check_dynamic_groups(data: dict, cfg: dict) -> list[GroupResult]:
    users = {u: p for u, p in sorted(data.get("principals", {}).items())}
    out = []
    for g in data.get("dynamic_groups", []):
        gid, name, rule = g.get("id", "?"), g.get("name", "?"), g.get("rule") or ""
        res = GroupResult(gid, name, rule, "DYNAMIC_GROUP_RULE")
        try:
            tree = parse_rule(rule)
        except RuleError as e:
            res.reasons.append(f"rule cannot be validated ({e}): treat the membership as wrong until fixed")
            out.append(res)
            continue
        intent = g.get("intent")
        res.members = [u for u, p in users.items() if evaluate_rule(tree, p)]
        if not intent:
            res.reasons.append("no documented intent for this group: membership cannot be verified (deny by default)")
            out.append(res)
            continue
        wanted = {u for u, p in users.items() if matches_intent(p, intent)}
        res.wrongly_included = [u for u in res.members if u not in wanted]
        res.wrongly_excluded = sorted(wanted - set(res.members))
        for u in res.wrongly_included:
            p = users[u]
            res.reasons.append(f"wrongly included {u} ({p.get('department')}, {p.get('country')}, {p.get('userType')})")
        for u in res.wrongly_excluded:
            p = users[u]
            res.reasons.append(f"wrongly excluded {u} ({p.get('department')}, {p.get('country')}, {p.get('userType')})")
        if not res.reasons:
            res.outcome = "OK"
            res.reasons.append(f"rule matches the intent exactly: {len(res.members)} member" + ("" if len(res.members) == 1 else "s"))
        out.append(res)
    return out


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SC-300 1.1 Configure and manage a Microsoft Entra tenant · 1.2 Manage Microsoft Entra identities.",
    "concepts": [
        "Pick the least-privileged built-in role for the task (Learn's 'Least privileged roles by task' table), then the smallest scope.",
        "Scopes: tenant, administrative unit (users, groups, devices) or one object such as an app registration or enterprise app.",
        "Only some roles are AU-scopable (User, Helpdesk, Password, Authentication, Groups, License Administrator and others); Conditional Access Administrator is tenant-only.",
        "Restricted management AUs block even tenant-wide Global Administrators from changing members; only AU-scoped admins can.",
        "Custom roles (Microsoft Entra ID P1 or P2) cover narrow permission sets, for example rotating one app's credentials.",
        "Keep fewer than five Global Administrators and at least two cloud-only emergency access accounts.",
    ],
    "failure_modes": [
        "Making every help-desk technician a Global Administrator because 'it just works'.",
        "Giving a regional admin User Administrator tenant-wide instead of on the region's administrative unit.",
        "Guest consultants left holding privileged roles after the project ends.",
        "A dynamic rule written with -contains or the wrong country spelling silently adds or drops people.",
    ],
    "ai_governance": [
        "An AI agent that manages users gets a service principal with an AU-scoped or custom role, never Global Administrator.",
        "Let an agent draft role recommendations with reasons; a human approves the assignment, ideally through PIM.",
        "Treat request text and user attributes as untrusted data: 'please make me Global Admin' is input, not an instruction.",
        "Test an agent-written dynamic membership rule against real users before saving it, like this checker does.",
    ],
    "exam_tips": [
        "'Reset passwords only for users in one region' = Password or Helpdesk Administrator scoped to an administrative unit.",
        "'Users can't register apps but developers must' = Application Developer.",
        "'Manage Conditional Access without Global Administrator' = Conditional Access Administrator.",
        "Role-assignable groups cannot use dynamic membership, and isAssignableToRole cannot be changed later.",
        "Restricted management can only be chosen when the administrative unit is created.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def _counts(values) -> dict:
    out: dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return out


def run_demo(ui, policies: dict, data: dict) -> dict:
    cfg = policies["tenant_delegation"]
    plans = plan_requests(data, cfg)
    ga = global_admin_check(data, cfg)
    audit = audit_assignments(data, cfg)
    groups = check_dynamic_groups(data, cfg)
    ui.section("Step 1 — Plan delegation: least-privileged role and smallest scope")
    ui.table("Delegation requests", ["ID", "Requester", "Task", "Role", "Scope", "Outcome"],
             [[p.id, p.requester, p.task, p.role or "-", p.scope or "-", p.outcome] for p in plans])
    for p in plans:
        ui.bullet(f"{p.id} → {p.outcome}: " + "; ".join(p.reasons),
                  style="yellow" if p.outcome == "ESCALATE" else "green")
    ui.section("Step 2 — Global Administrators and emergency access accounts")
    ui.status("Global Administrator check", "PASS" if ga["outcome"] == "OK" else "FAIL", "; ".join(ga["reasons"]))
    ui.section("Step 3 — Audit existing role assignments")
    ui.table("Role assignments", ["ID", "Principal", "Role", "Scope", "Finding"],
             [[a.id, a.principal, a.role, a.scope, a.finding] for a in audit])
    for a in audit:
        ui.bullet(f"{a.id} → {a.finding}: " + "; ".join(a.reasons), style="green" if a.finding == "OK" else "red")
    ui.section("Step 4 — Check dynamic membership rules")
    ui.table("Dynamic groups", ["ID", "Group", "Members", "Wrongly in", "Wrongly out", "Outcome"],
             [[g.id, g.name, len(g.members), len(g.wrongly_included), len(g.wrongly_excluded), g.outcome]
              for g in groups])
    for g in groups:
        ui.bullet(f"{g.id} {g.name}: {g.rule or '(no rule)'}", style="dim")
        for r in g.reasons:
            ui.bullet(f"  {r}", style="green" if g.outcome == "OK" else "yellow")
    metrics = {"requests": len(plans), "plan_counts": _counts(p.outcome for p in plans),
               "assignments": len(audit), "finding_counts": _counts(a.finding for a in audit),
               "global_admins": ga["count"], "emergency_accounts": len(ga["emergency"]),
               "groups": len(groups), "group_counts": _counts(g.outcome for g in groups)}
    ui.print(f"{len(plans)} requests · {len(audit)} assignments audited · "
             f"{sum(a.finding != 'OK' for a in audit)} with findings · "
             f"{sum(g.outcome != 'OK' for g in groups)} of {len(groups)} dynamic rules need fixing")
    ui.insight(INSIGHT)
    return {"plans": {p.id: p.outcome for p in plans}, "roles": {p.id: p.role for p in plans},
            "global_admin_check": {"outcome": ga["outcome"], "count": ga["count"], "emergency": ga["emergency"]},
            "audit": {a.id: a.finding for a in audit}, "groups": {g.id: g.outcome for g in groups},
            "metrics": metrics}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["tenant_delegation"]
    plans = plan_requests(data, cfg)
    ga = global_admin_check(data, cfg)
    audit = audit_assignments(data, cfg)
    groups = check_dynamic_groups(data, cfg)
    reqs = {r.get("id"): r for r in data.get("requests", [])}
    asg = {a.get("id"): a for a in data.get("assignments", [])}
    builtin = sorted(cfg["roles"])
    qs: list = []
    for p in plans:
        src = {k: v for k, v in reqs.get(p.id, {}).items() if k != "id"}
        qs.append(Question(prompt=f"{p.id}: what should the identity team do with this delegation request?",
                           context=f"request={src}", choices=list(PLAN_OUTCOMES), answer=p.outcome,
                           explanation="; ".join(p.reasons), objective="1.1"))
    asked = set()
    for p in plans:
        if p.outcome in ("TENANT", "ADMINISTRATIVE_UNIT", "OBJECT") and p.role not in asked:
            asked.add(p.role)
            desc = cfg["tasks"][p.task]["description"]
            qs.append(Question(prompt=f"Which built-in role is least privileged to {desc}?",
                               choices=choices_with(p.role, builtin, exclude=[GA], key=p.id), answer=p.role,
                               explanation="; ".join(p.reasons), objective="1.1"))
    done = set()
    for a in audit:
        if a.finding in done:
            continue
        done.add(a.finding)
        src = {k: v for k, v in asg.get(a.id, {}).items() if k != "id"}
        qs.append(Question(prompt=f"{a.id}: which audit finding does this role assignment get (most severe)?",
                           context=f"assignment={src}", answer=a.finding,
                           choices=choices_with(a.finding, FINDINGS[:4] + ["OK"], exclude=a.findings, key=a.id),
                           explanation="; ".join(a.reasons),
                           objective="1.2" if a.finding == "PRIVILEGED_ROLE_ON_GUEST" else "1.1"))
    qs.append(Question(prompt="What is the tenant-wide Global Administrator check result?",
                       context=f"{ga['count']} Global Administrator assignments; emergency accounts: "
                               f"{', '.join(ga['emergency']) or 'none'}",
                       choices=["GLOBAL_ADMIN_EXCESS", "OK", "ASSIGNMENT_TOO_BROAD", "RESTRICTED_AU_MEMBER"],
                       answer=ga["outcome"], explanation="; ".join(ga["reasons"]), objective="1.1"))
    users = sorted(data.get("principals", {}))
    for g in groups:
        qs.append(Question(prompt=f"{g.id} {g.name}: does the dynamic membership rule match the documented intent?",
                           context=f"rule: {g.rule or '(empty)'}\nintent: {next((x.get('intent') for x in data.get('dynamic_groups', []) if x.get('id') == g.id), None)}",
                           choices=["DYNAMIC_GROUP_RULE", "OK"], answer=g.outcome,
                           explanation="; ".join(g.reasons), objective="1.2"))
        for label, lst in (("wrongly include", g.wrongly_included), ("wrongly exclude", g.wrongly_excluded)):
            if lst:
                qs.append(Question(prompt=f"Which user does the {g.name} rule {label}?",
                                   context=f"rule: {g.rule}",
                                   choices=choices_with(lst[0], users, exclude=lst, key=g.id + label),
                                   answer=lst[0], explanation="; ".join(g.reasons), objective="1.2"))
    qs.append(Question(prompt="A Global Administrator, assigned tenant-wide, tries to change a user in a restricted "
                              "management administrative unit. What happens?",
                       choices=["the change is blocked: only admins assigned at that unit's scope can change it",
                                "the change succeeds because Global Administrator bypasses every scope",
                                "the change succeeds only if the user is a guest",
                                "the unit's restriction can be switched off later to allow it"],
                       answer="the change is blocked: only admins assigned at that unit's scope can change it",
                       explanation=cfg["concepts"]["restricted management administrative unit"], objective="1.1"))
    qs.append(Question(prompt="Why can a role-assignable group not be used as a dynamic group?",
                       choices=["role-assignable groups must use assigned membership, so attribute changes cannot "
                                "silently grant admin roles",
                                "dynamic groups cannot contain more than one user",
                                "role-assignable groups only accept guest users",
                                "dynamic membership needs a custom role"],
                       answer="role-assignable groups must use assigned membership, so attribute changes cannot "
                              "silently grant admin roles",
                       explanation=cfg["concepts"]["role-assignable group"], objective="1.2"))
    for term in ("administrative unit", "custom role", "emergency access account", "role scope",
                 "dynamic membership rule"):
        if term in cfg["concepts"]:
            qs.append(Question(prompt=f"Which term is this? \"{cfg['concepts'][term]}\"",
                               choices=sorted(cfg["concepts"]), answer=term, explanation=cfg["concepts"][term],
                               objective="1.2" if term == "dynamic membership rule" else "1.1"))
    return qs


# --------------------------------------------------------------------------- #
# Seeded scenario generator
# --------------------------------------------------------------------------- #
_FIRST = ["ava", "ben", "cara", "dev", "eli", "fay", "gus", "hana", "ivo", "jun", "kai", "lia", "milo", "nora",
          "otto", "pia", "quin", "rosa", "sami", "tess", "uma", "vik", "wren", "yara", "zane"]
_LAST = ["arden", "brook", "cole", "dunn", "ellis", "frost", "grant", "hale", "irwin", "joss", "kerr", "lane",
         "moss", "nash", "orr", "pike", "reed", "stone", "tate", "vale", "west", "york"]


def generate_scenario(rng, policies: dict) -> dict:
    cfg = policies["tenant_delegation"]
    dom = "fernhollow.example"
    names = iter(rng.sample([f"{f}.{l}" for f in _FIRST for l in _LAST], 40))

    def person(dept="IT", country="United States", utype="Member", **kw):
        upn = next(names) + ("@partner.example" if utype == "Guest" else f"@{dom}")
        principals[upn] = {"userType": utype, "department": dept, "country": country, **kw}
        return upn

    principals: dict = {}
    regions = rng.sample(["EMEA", "NA", "LATAM", "APAC"], 3)
    have, missing = regions[:2], regions[2]
    exec1, exec2 = person("Executive"), person("Executive")
    aus = [{"id": f"AU-{r}", "name": f"{r} users", "region": r, "restricted": False, "members": []} for r in have]
    aus.append({"id": "AU-EXEC", "name": "Executives", "region": "EXEC", "restricted": True,
                "members": [exec1, exec2]})
    staff = [person() for _ in range(6)]
    guest = person("Consulting", utype="Guest")
    au_tasks = [t for t, v in cfg["tasks"].items() if v["role"] != "custom" and cfg["roles"][v["role"]]["au_scopable"]]
    tenant_tasks = sorted(cfg["tasks"])
    tenant_tasks.remove("update_app_credentials")
    tenant_only = [t for t, v in cfg["tasks"].items() if v["role"] != "custom" and not cfg["roles"][v["role"]]["au_scopable"]
                   and not cfg["roles"][v["role"]]["object_scopable"]]
    priv = [t for t, v in cfg["tasks"].items() if v["role"] != "custom" and cfg["roles"][v["role"]]["privileged"]]
    reqs = [
        {"requester": rng.choice(staff), "task": rng.choice([t for t in tenant_tasks if t != "configure_enterprise_app"])},
        {"requester": rng.choice(staff), "task": rng.choice(au_tasks), "region": rng.choice(have)},
        {"requester": rng.choice(staff), "task": rng.choice(au_tasks), "region": missing},
        {"requester": rng.choice(staff), "task": rng.choice(tenant_only), "region": rng.choice(have)},
        {"requester": rng.choice(staff), "task": "update_app_credentials", "target_object": "app:" + rng.choice(
            ["Expense-Portal", "HR-Sync", "Field-Survey"])},
        {"requester": rng.choice(staff), "task": "configure_enterprise_app", "target_object": "app:" + rng.choice(
            ["Payroll-SSO", "Travel-Booking", "Wiki"])},
        {"requester": guest, "task": rng.choice(priv)},
        {"requester": rng.choice(staff), "task": rng.choice(["rotate_bitlocker_keys", "approve_invoices", ""])},
        {"requester": rng.choice(staff), "task": "manage_groups", "target_object": "group:Project-Team"},
    ]
    rng.shuffle(reqs)
    for n, r in enumerate(reqs, 1):
        r["id"] = f"R{n:02d}"
    bg = [person("IT", emergency_access=True) for _ in range(cfg["min_emergency_accounts"])]
    extra_ga = [rng.choice(staff) for _ in range(cfg["max_global_admins"] - len(bg) + rng.randint(1, 2))]
    asg = [{"principal": u, "role": GA, "scope": "tenant"} for u in bg + extra_ga]
    asg += [
        {"principal": person("Consulting", utype="Guest"), "role": rng.choice(
            ["Security Administrator", "Application Administrator", "Tenant Super Operator"]), "scope": "tenant"},
        {"principal": person("Audit", utype="Guest"), "role": "License Administrator", "scope": "tenant"},
        {"principal": rng.choice(staff), "role": "User Administrator", "scope": "tenant",
         "intended_scope": f"au:AU-{rng.choice(have)}"},
        {"principal": rng.choice(staff), "role": "Helpdesk Administrator", "scope": "tenant", "manages": [exec1]},
        {"principal": rng.choice(staff), "role": "Helpdesk Administrator", "scope": "au:AU-EXEC", "manages": [exec2]},
        {"principal": rng.choice(staff), "role": "Application Administrator", "scope": "tenant",
         "needed_for": "register_apps"},
    ]
    rng.shuffle(asg)
    for n, a in enumerate(asg, 1):
        a["id"] = f"A{n:02d}"
    country = rng.choice(["Germany", "France", "Spain"])
    code = {"Germany": "DE", "France": "FR", "Spain": "ES"}[country]
    person("Sales", country), person("sales", country), person("Sales", code)
    person("Sales Operations", country)
    person("Sales", country, utype="Guest")
    person("Sales", "Italy")
    groups = [
        {"id": "G01", "name": f"{code}-Sales", "rule": f'(user.department -eq "Sales") -and (user.country -eq "{country}")',
         "intent": {"department": ["Sales"], "country": [country, code], "userType": ["Member"]}},
        {"id": "G02", "name": f"{code}-Sales-Members",
         "rule": f'(user.department -eq "Sales") -and (user.country -in ["{country}","{code}"]) -and (user.userType -eq "Member")',
         "intent": {"department": ["Sales"], "country": [country, code], "userType": ["Member"]}},
    ]
    rng.shuffle(groups)
    for n, g in enumerate(groups, 1):
        g["id"] = f"G{n:02d}"
    return {"_description": "Generated tenant delegation scenario (fictional).", "tenant": "Fernhollow Example Ltd",
            "administrative_units": aus, "principals": principals, "requests": reqs, "assignments": asg,
            "dynamic_groups": groups}
