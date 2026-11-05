"""
Lab 36 — Okta Universal Directory: Users, Custom Attributes, Groups & Group Rules
=================================================================================

Okta Professional objectives
----------------------------
* 1.2  Groups and group rules: Okta groups, Active Directory groups and admin
       groups, group rules written in Okta Expression Language, rule status,
       excluded users, manual membership.
* 1.1  Users, profiles and custom attributes: the Okta user profile, base and
       custom attributes, attribute data types, required attributes.
* 5.2  App access and group assignment troubleshooting: "why is this user
       (not) in this group?".

How it works
------------
You are the Okta administrator at a mid-sized company. HR sends profile
changes, the identity team maintains group rules, and the help desk forwards
"why is this person (not) in that group?" tickets.

Part 1, profile validation. Each request creates a user or partially updates
one (like the Okta Users API partial update: only the attributes sent change,
and ``null`` clears an attribute). The schema is the Okta base profile plus the
company's custom attributes. Rules, in evaluation order (the request is
REJECTED as a whole if any rule fails, else ACCEPTED):

1. Unknown operation, no attributes, update of a user who does not exist, or a
   create for a login that already exists → REJECTED (deny by default).
2. An attribute that is not in the schema → REJECTED. Names are
   case-sensitive: ``Department`` is not ``department``.
3. A value of the wrong type (string, boolean, integer, array of a type) →
   REJECTED. ``"4471"`` is a string, not an integer.
4. After the change, a required attribute is missing or empty → REJECTED.
Accepted requests are applied, in order, before group rules run.

Part 2, group rules. Each rule has a status, an expression, target groups and
excluded users:

1. An expression outside the supported subset, or naming an attribute that is
   not in the schema, is UNPARSEABLE: it matches nobody and is flagged.
2. A rule can populate Okta groups and Active Directory groups, but not admin
   groups: a target group that holds an admin role (``admin_roles``), or that
   does not exist, is skipped and flagged INVALID_TARGET. (Okta also refuses
   to grant admin privileges to a group that is already a rule target.)
3. INACTIVE rules do nothing.
4. Only users in an evaluated status are checked: a deactivated
   (DEPROVISIONED) user, or a user with a missing or unknown status, is not.
   Deactivation removes app assignments, not group memberships: a deactivated
   user keeps the memberships they already have until the user is deleted.
5. A user who matches an active rule and is not on its exclude list is added
   to the rule's valid targets. Manually added members stay in the group
   whatever the rules say: rules never remove them.

Part 3, troubleshooting. Each ticket names a user and a group; the cause is
the first that applies: USER_NOT_ACTIVE (unknown or not evaluated user),
RULE_MATCHED, MANUAL_ASSIGNMENT, USER_EXCLUDED, RULE_INACTIVE (an inactive rule
would match), ATTRIBUTE_MISMATCH (a readable rule targets the group but the
user's attributes do not match, often only by letter case), else NO_RULE (no
readable rule assigns this group, including admin groups and unknown groups).

Run it
------
    python main.py --course okta lab 36
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field

TITLE = "Lab 36 — Okta Universal Directory: Users, Custom Attributes, Groups & Group Rules"
OBJECTIVES = "Okta Professional 1.2 Groups and group rules · 1.1 Users, profiles and custom attributes · " \
             "5.2 Group assignment troubleshooting"
COURSES = ("okta",)
UPDATE_OUTCOMES = ["ACCEPTED", "REJECTED"]
RULE_FLAGS = ["OK", "INACTIVE", "UNPARSEABLE", "INVALID_TARGET"]
CAUSES = ["RULE_MATCHED", "RULE_INACTIVE", "ATTRIBUTE_MISMATCH", "USER_EXCLUDED", "MANUAL_ASSIGNMENT",
          "USER_NOT_ACTIVE", "NO_RULE"]


@dataclass
class UpdateResult:
    id: str
    user: str
    operation: str
    outcome: str
    reasons: list[str] = field(default_factory=list)


@dataclass
class RuleCheck:
    id: str
    name: str
    status: str
    expression: str
    flag: str
    valid_targets: list[str] = field(default_factory=list)
    matched: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    tree: object = None


@dataclass
class TicketResult:
    id: str
    user: str
    group: str
    cause: str
    is_member: bool
    rule: str | None = None
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Part 1 — profile schema validation
# --------------------------------------------------------------------------- #
def build_schema(data: dict, cfg: dict) -> dict:
    """Base profile (from the policy) plus the tenant's custom attributes (from the data)."""
    schema = {k: dict(v) for k, v in cfg["base_attributes"].items()}
    for name, meta in (data.get("custom_attributes") or {}).items():
        schema.setdefault(name, dict(meta))
    return schema


def _type_ok(value, meta: dict) -> tuple[bool, str]:
    t = meta.get("type")
    if t == "string":
        return isinstance(value, str), "a string"
    if t == "boolean":
        return isinstance(value, bool), "a boolean (true or false, not text)"
    if t == "integer":
        return isinstance(value, int) and not isinstance(value, bool), "an integer (a number, not text)"
    if t == "array":
        item = meta.get("items", "string")
        ok = isinstance(value, list) and all(_type_ok(v, {"type": item})[0] for v in value)
        return ok, f"an array of {item} values"
    return False, f"a known type (schema type '{t}' is not supported: deny by default)"


def validate_update(upd: dict, users: dict, schema: dict) -> UpdateResult:
    uid, op, changes = upd.get("id", "?"), upd.get("operation"), upd.get("profile")
    login = upd.get("user") or (changes.get("login") if isinstance(changes, dict) else None)
    res = UpdateResult(uid, login or "?", op or "-", "REJECTED")
    # Rule 1: request shape
    if op not in ("create", "update"):
        res.reasons.append(f"operation '{op}' is not create or update: rejected (deny by default)")
        return res
    if not isinstance(changes, dict) or not changes:
        res.reasons.append("no profile attributes supplied: rejected (deny by default)")
        return res
    if op == "update" and login not in users:
        res.reasons.append(f"user {login} does not exist in Universal Directory: nothing to update")
        return res
    if op == "create" and login in users:
        res.reasons.append(f"a user with login {login} already exists: logins must be unique")
        return res
    errors: list[str] = []
    lower = {k.lower(): k for k in schema}
    for name, value in changes.items():
        meta = schema.get(name)
        # Rule 2: unknown attribute (names are case-sensitive)
        if meta is None:
            hint = f"; did you mean '{lower[name.lower()]}'? attribute names are case-sensitive" \
                if name.lower() in lower else ""
            errors.append(f"attribute '{name}' is not in the profile schema{hint}")
            continue
        if value is None:
            continue   # null clears the attribute; rule 4 catches clearing a required one
        # Rule 3: wrong type
        ok, want = _type_ok(value, meta)
        if not ok:
            errors.append(f"'{name}' must be {want}, got {type(value).__name__} {value!r}")
    # Rule 4: required attributes after the change
    current = {} if op == "create" else dict(users[login].get("profile", {}))
    merged = {**current, **changes}
    for name, meta in schema.items():
        if meta.get("required") and merged.get(name) in (None, "", []):
            errors.append(f"required attribute '{name}' would be missing")
    if errors:
        res.reasons.extend(errors)
        res.reasons.append("Okta rejects the whole request when any attribute fails validation")
        return res
    res.outcome = "ACCEPTED"
    sent = ", ".join(sorted(changes))
    res.reasons.append(f"{op} of {login}: every attribute sent ({sent}) is in the schema with the right type" +
                       (" and every required attribute is present" if op == "create" else ""))
    return res


def apply_updates(data: dict, cfg: dict) -> tuple[list[UpdateResult], dict]:
    """Validate every request in order and apply the accepted ones. Returns (results, users after changes)."""
    schema = build_schema(data, cfg)
    users = copy.deepcopy(data.get("users", {}))
    results = []
    for upd in data.get("profile_updates", []):
        r = validate_update(upd, users, schema)
        results.append(r)
        if r.outcome != "ACCEPTED":
            continue
        changes = upd["profile"]
        if upd["operation"] == "create":
            status = cfg["create_status_active"] if upd.get("activate") else cfg["create_status_default"]
            users[r.user] = {"status": status, "profile": {k: v for k, v in changes.items() if v is not None}}
            r.reasons.append(f"user created with status {status}")
        else:
            prof = users[r.user].setdefault("profile", {})
            for k, v in changes.items():
                if v is None:
                    prof.pop(k, None)
                else:
                    prof[k] = v
    return results, users


# --------------------------------------------------------------------------- #
# Part 2 — Okta Expression Language subset
# --------------------------------------------------------------------------- #
# SIMPLIFIED Okta Expression Language (OEL), enough for typical group rules:
#   * user.<attribute> references (the name must exist in the schema, case-sensitive);
#   * literals: "text" or 'text', integers, true, false, null;
#   * comparisons ==, !=, >, <, >=, <= (string comparison is case-sensitive, as in Okta);
#   * AND / OR (also && and ||; AND binds tighter), NOT or ! and parentheses;
#   * functions: String.startsWith(s, prefix), String.stringContains(s, part), Arrays.contains(array, value)
#     (booleans) and String.toLowerCase(s) / String.toUpperCase(s) (values).
# Not modelled: group functions such as isMemberOfAnyGroup / isMemberOfGroupName (rules reading other groups),
# other String/Arrays/Time/Convert functions, the ternary operator, user.getInternalProperty, and Okta's exact
# rules for comparing mixed types. Here a mismatched type or a null makes ==, >, <, >=, <= false and != true.
_TOKEN = re.compile(r"""\s*("[^"]*"|'[^']*'|==|!=|>=|<=|&&|\|\||[()<>,!=]|-?\d+|[A-Za-z_][A-Za-z0-9_.]*)""")
_BOOL_FUNCS = {"String.startsWith", "String.stringContains", "Arrays.contains"}
_VALUE_FUNCS = {"String.toLowerCase", "String.toUpperCase"}
_CMP = {"==", "!=", ">", "<", ">=", "<="}


class RuleError(ValueError):
    pass


def _tokenize(text: str) -> list[str]:
    pos, toks, text = 0, [], text.rstrip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise RuleError(f"cannot read the expression near '{text[pos:pos + 15].strip()}'")
        toks.append(m.group(1))
        pos = m.end()
    return toks


def parse_expression(text, attributes=None):
    """Parse into a nested tuple tree; raises RuleError outside the subset. ``attributes``: schema names."""
    if not text or not str(text).strip():
        raise RuleError("expression is empty")
    toks, i = _tokenize(str(text)), 0

    def peek():
        return toks[i] if i < len(toks) else None

    def take(expected=None):
        nonlocal i
        t = peek()
        if t is None or (expected is not None and t != expected):
            raise RuleError(f"expected {expected or 'more'} but found {t or 'end of expression'}")
        i += 1
        return t

    def is_kw(t, *words):
        return t is not None and (t.upper() in words or t in words)

    def expr():
        node = conj()
        while is_kw(peek(), "OR", "||"):
            take()
            node = ("or", node, conj())
        return node

    def conj():
        node = unary()
        while is_kw(peek(), "AND", "&&"):
            take()
            node = ("and", node, unary())
        return node

    def unary():
        if is_kw(peek(), "NOT", "!"):
            take()
            return ("not", unary())
        if peek() == "(":
            take("(")
            node = expr()
            take(")")
            return node
        t = peek()
        if t in _BOOL_FUNCS:
            take()
            take("(")
            a = value()
            take(",")
            b = value()
            take(")")
            return ("func", t, a, b)
        left = value()
        if peek() in _CMP:
            op = take()
            return ("cmp", op, left, value())
        if peek() == "=":
            raise RuleError("use == to compare, not =")
        if left[0] == "attr":        # a bare boolean attribute, e.g. user.remoteWorker
            return ("cmp", "==", left, ("lit", True))
        raise RuleError(f"expected a comparison after {show(left)}")

    def value():
        t = take()
        if t[0] in "\"'":
            return ("lit", t[1:-1])
        if re.fullmatch(r"-?\d+", t):
            return ("lit", int(t))
        if t in ("true", "false"):
            return ("lit", t == "true")
        if t == "null":
            return ("lit", None)
        if t in _VALUE_FUNCS:
            take("(")
            arg = value()
            take(")")
            return ("vfunc", t, arg)
        if t.startswith("user."):
            name = t[5:]
            if not name or "." in name:
                raise RuleError(f"{t} is not a user attribute reference")
            if attributes is not None and name not in attributes:
                lower = {a.lower(): a for a in attributes}
                hint = f" (did you mean user.{lower[name.lower()]}?)" if name.lower() in lower else ""
                raise RuleError(f"user.{name} is not in the profile schema{hint}")
            return ("attr", name)
        if ("." in t and t[0].isupper()) or peek() == "(":
            raise RuleError(f"function {t} is outside this simulation's Okta Expression Language subset")
        raise RuleError(f"unexpected '{t}'")

    tree = expr()
    if peek() is not None:
        raise RuleError(f"unexpected '{peek()}' after the end of the expression")
    return tree


def show(node) -> str:
    kind = node[0]
    if kind == "lit":
        v = node[1]
        return f'"{v}"' if isinstance(v, str) else ("null" if v is None else str(v).lower() if isinstance(v, bool) else str(v))
    if kind == "attr":
        return f"user.{node[1]}"
    if kind == "vfunc":
        return f"{node[1]}({show(node[2])})"
    if kind == "func":
        return f"{node[1]}({show(node[2])}, {show(node[3])})"
    if kind == "cmp":
        return f"{show(node[2])} {node[1]} {show(node[3])}"
    if kind == "not":
        return f"NOT {show(node[1])}"
    return f"({show(node[1])} {kind.upper()} {show(node[2])})"


def _value(node, profile: dict):
    kind = node[0]
    if kind == "lit":
        return node[1]
    if kind == "attr":
        return profile.get(node[1])
    arg = _value(node[2], profile)
    if not isinstance(arg, str):
        return None
    return arg.lower() if node[1] == "String.toLowerCase" else arg.upper()


def _num(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def evaluate(tree, profile: dict, leaves: list | None = None) -> bool:
    """True when the profile matches. ``leaves`` collects (text, result, hint) for every test evaluated."""
    kind = tree[0]
    if kind == "and":     # evaluate both sides (no short-circuit) so every failing test can be reported
        a, b = evaluate(tree[1], profile, leaves), evaluate(tree[2], profile, leaves)
        return a and b
    if kind == "or":
        a, b = evaluate(tree[1], profile, leaves), evaluate(tree[2], profile, leaves)
        return a or b
    if kind == "not":
        return not evaluate(tree[1], profile, leaves)
    hint = ""
    if kind == "func":
        a, b = _value(tree[2], profile), _value(tree[3], profile)
        if tree[1] == "Arrays.contains":
            ok = isinstance(a, list) and b in a
            if isinstance(a, list) and isinstance(b, str) and not ok and b.lower() in [str(x).lower() for x in a]:
                hint = f"the array holds a different letter case of \"{b}\""
        elif not isinstance(a, str) or not isinstance(b, str):
            ok = False
        else:
            ok = a.startswith(b) if tree[1] == "String.startsWith" else b in a
            if not ok:
                low = a.lower().startswith(b.lower()) if tree[1] == "String.startsWith" else b.lower() in a.lower()
                if low:
                    hint = f"\"{a}\" differs only by letter case: Okta string functions are case-sensitive"
        got = a
    else:
        op, a, b = tree[1], _value(tree[2], profile), _value(tree[3], profile)
        if op in ("==", "!="):
            same = a == b and type(a) is type(b)
            ok = same if op == "==" else not same
            if isinstance(a, str) and isinstance(b, str) and a != b and a.lower() == b.lower():
                hint = f"\"{a}\" vs \"{b}\": the values differ only by letter case and == is case-sensitive"
            elif a is None and op == "!=":
                hint = "the attribute is empty (null), and null != a value is true"
        elif _num(a) and _num(b):
            ok = {">": a > b, "<": a < b, ">=": a >= b, "<=": a <= b}[op]
        else:
            ok = False     # null or a non-integer value: an ordering comparison is false here
        got = a if tree[2][0] != "lit" else b
    if leaves is not None:
        leaves.append((show(tree), ok, got, hint))
    return ok


# --------------------------------------------------------------------------- #
# Part 2 — rules and memberships
# --------------------------------------------------------------------------- #
def check_rules(data: dict, cfg: dict, users: dict | None = None) -> list[RuleCheck]:
    schema = build_schema(data, cfg)
    groups = data.get("groups", {})
    users = data.get("users", {}) if users is None else users
    out = []
    for r in data.get("group_rules", []):
        status = str(r.get("status") or "INACTIVE").upper()
        rc = RuleCheck(r.get("id", "?"), r.get("name", "?"), status, r.get("expression") or "", "OK")
        flags = []
        try:
            rc.tree = parse_expression(r.get("expression"), set(schema))
        except RuleError as e:
            flags.append("UNPARSEABLE")
            rc.reasons.append(f"expression cannot be used ({e}): it matches nobody until fixed")
        for gid in r.get("assign_to", []):
            g = groups.get(gid)
            if g is None:
                flags.append("INVALID_TARGET")
                rc.reasons.append(f"target group {gid} does not exist: skipped")
            elif g.get("admin_roles"):
                flags.append("INVALID_TARGET")
                rc.reasons.append(f"target {g.get('name', gid)} is an admin group (holds "
                                  f"{', '.join(g['admin_roles'])}): group rules can't assign users to admin groups, "
                                  "skipped")
            else:
                rc.valid_targets.append(gid)
        if not r.get("assign_to"):
            flags.append("INVALID_TARGET")
            rc.reasons.append("the rule has no target group")
        if status != "ACTIVE":
            flags.insert(0, "INACTIVE")
            rc.reasons.append(f"rule status is {status}: inactive rules assign nobody")
        rc.flag = flags[0] if flags else "OK"
        if rc.tree is not None and status == "ACTIVE":
            excl = set(r.get("exclude", []))
            for login, u in sorted(users.items()):
                if evaluated(u, cfg) and login not in excl and evaluate(rc.tree, u.get("profile", {})):
                    rc.matched.append(login)
            if rc.valid_targets:
                rc.reasons.append(f"matches {len(rc.matched)} evaluated user" + ("" if len(rc.matched) == 1 else "s")
                                  + (f" ({len(excl)} excluded by name)" if excl else ""))
        if rc.flag == "OK" and not rc.reasons:
            rc.reasons.append("rule is active and readable")
        out.append(rc)
    return out


def evaluated(user: dict | None, cfg: dict) -> bool:
    """Is this user checked by group rules? Missing or unknown status → no (deny by default)."""
    return bool(user) and str(user.get("status") or "").upper() in cfg["evaluated_statuses"]


def memberships(data: dict, cfg: dict, users: dict, rules: list[RuleCheck]) -> dict[str, list[str]]:
    """Group id → sorted member logins: manual members plus users placed by active, readable rules."""
    out = {}
    for gid, g in data.get("groups", {}).items():
        # Deactivated users keep existing memberships until deleted; rules simply stop evaluating them.
        # Simplification: the data records only manual memberships, so memberships a rule added before a user was
        # deactivated are not modelled (rc.matched holds evaluated users only).
        members = {m for m in g.get("manual_members", []) if m in users}
        for rc in rules:
            if gid in rc.valid_targets:
                members.update(rc.matched)
        out[gid] = sorted(members)
    return out


# --------------------------------------------------------------------------- #
# Part 3 — troubleshooting tickets
# --------------------------------------------------------------------------- #
def diagnose(ticket: dict, data: dict, cfg: dict, users: dict, rules: list[RuleCheck],
             members: dict) -> TicketResult:
    tid, login, gid = ticket.get("id", "?"), ticket.get("user"), ticket.get("group")
    groups = data.get("groups", {})
    g = groups.get(gid or "")
    gname = g.get("name", gid) if g else (gid or "?")
    res = TicketResult(tid, login or "?", gname, "NO_RULE", login in members.get(gid, []))
    u = users.get(login or "")
    if u is None:
        res.cause = "USER_NOT_ACTIVE"
        res.reasons.append(f"{login} is not in Universal Directory: treated as not active (deny by default)")
        return res
    if not evaluated(u, cfg):
        res.cause = "USER_NOT_ACTIVE"
        res.reasons.append(f"{login} has status {u.get('status') or 'missing'}: group rules do not evaluate this "
                           "user, so no rule can add them")
        if res.is_member:
            res.reasons.append(f"the user is still a member of {gname}: deactivation removes app assignments, not "
                               "group memberships, which stay until the user is deleted")
        return res
    if g is None:
        res.reasons.append(f"group {gid} does not exist: no rule can assign it")
        return res
    manual = login in g.get("manual_members", [])
    if g.get("admin_roles") and not manual:
        res.reasons.append(f"{gname} is an admin group (holds {', '.join(g['admin_roles'])}): group rules can't "
                           "assign users to admin groups, so members must be added by an administrator")
        return res
    src = {r.get("id"): r for r in data.get("group_rules", [])}
    targeting = [rc for rc in rules if gid in rc.valid_targets]
    profile = u.get("profile", {})
    readable = [rc for rc in targeting if rc.tree is not None]

    def matches(rc):
        return evaluate(rc.tree, profile)

    hit = [rc for rc in readable if rc.status == "ACTIVE" and login in rc.matched]
    if hit:
        res.cause, res.rule = "RULE_MATCHED", hit[0].id
        res.reasons.append(f"active rule {hit[0].id} '{hit[0].name}' matches: {hit[0].expression}")
        leaves: list = []
        evaluate(hit[0].tree, profile, leaves)
        res.reasons.extend(f"{text}: {hint}" for text, ok, _, hint in leaves if ok and hint)
        if manual:
            res.reasons.append("also added manually, so the user stays even if the rule stops matching")
        return res
    if manual:
        res.cause = "MANUAL_ASSIGNMENT"
        res.reasons.append(f"{login} was added to {gname} manually; rules never remove manually added members"
                           + (" (no rule would add them)" if readable else ""))
        return res
    excl = [rc for rc in readable if rc.status == "ACTIVE" and login in src.get(rc.id, {}).get("exclude", [])
            and matches(rc)]
    if excl:
        res.cause, res.rule = "USER_EXCLUDED", excl[0].id
        res.reasons.append(f"rule {excl[0].id} '{excl[0].name}' matches, but {login} is on its exclude list")
        return res
    idle = [rc for rc in readable if rc.status != "ACTIVE" and login not in src.get(rc.id, {}).get("exclude", [])
            and matches(rc)]
    if idle:
        res.cause, res.rule = "RULE_INACTIVE", idle[0].id
        res.reasons.append(f"rule {idle[0].id} '{idle[0].name}' would match ({idle[0].expression}) but its status is "
                           f"{idle[0].status}: activate it to assign the group")
        return res
    if readable:
        rc = readable[0]
        res.cause, res.rule = "ATTRIBUTE_MISMATCH", rc.id
        leaves: list = []
        evaluate(rc.tree, profile, leaves)
        fails = [lf for lf in leaves if not lf[1]]
        res.reasons.append(f"rule {rc.id} '{rc.name}' targets {gname} but does not match {login}")
        for text, _, got, hint in fails:
            res.reasons.append(f"{text} is false (user value: {got!r})" + (f": {hint}" if hint else ""))
        return res
    broken = [rc.id for rc in targeting]
    res.reasons.append(f"no readable rule assigns {gname}" +
                       (f": rule {', '.join(broken)} cannot be parsed, so it matches nobody" if broken else
                        " and the user was not added manually"))
    return res


def diagnose_all(data: dict, cfg: dict, users: dict, rules: list[RuleCheck], members: dict) -> list[TicketResult]:
    return [diagnose(t, data, cfg, users, rules, members) for t in data.get("tickets", [])]


def run_all(data: dict, cfg: dict) -> dict:
    updates, users = apply_updates(data, cfg)
    rules = check_rules(data, cfg, users)
    members = memberships(data, cfg, users, rules)
    tickets = diagnose_all(data, cfg, users, rules, members)
    return {"updates": updates, "users": users, "rules": rules, "members": members, "tickets": tickets}


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "Okta Professional 1.2 Groups and group rules · 1.1 Users, profiles and custom attributes · "
                 "5.2 App access and group assignment troubleshooting.",
    "concepts": [
        "Universal Directory holds every user profile: the Okta base attributes plus custom attributes you add in "
        "the Profile Editor, each with a data type (string, boolean, integer, number, array).",
        "Group rules use Okta Expression Language, for example user.department == \"Sales\" AND "
        "user.countryCode == \"US\"; string comparisons are case-sensitive.",
        "Rules can populate Okta groups and Active Directory groups from user attributes, but never admin groups "
        "(groups that hold an admin role).",
        "Deactivating a user removes their app assignments but keeps their group memberships until the user is "
        "deleted; group rules stop evaluating them.",
        "A rule can exclude named users; manually added members stay until someone removes them by hand.",
        "Assign apps to groups, not to people: fix the group rule and app access follows.",
    ],
    "failure_modes": [
        "HR sends \"sales\" in lower case and the Sales rule silently skips the user.",
        "A rule written with = instead of ==, or with an attribute name in the wrong case, matches nobody.",
        "user.employeeType != \"Contractor\" also includes everyone whose employeeType is empty.",
        "Leaving a manually added member in a rule-based group after they changed department.",
    ],
    "ai_governance": [
        "An AI agent that drafts group rules should preview who the rule adds and removes before an admin activates it.",
        "Treat HR attribute values as untrusted input: validate type and allowed values before they reach a rule.",
        "Give an automation a custom admin role scoped to specific groups, not Super Administrator.",
        "Log every rule change and every manual membership change in the System Log and review them.",
    ],
    "exam_tips": [
        "Directory > Groups > Rules: a rule must be deactivated before it can be edited, then activated again.",
        "Group rules can't assign users to admin groups, and a group that is already a rule target can't be "
        "granted admin privileges.",
        "Deactivated users keep their group memberships until deleted; deactivation removes app assignments.",
        "Use String.toLowerCase(user.department) == \"sales\" to make a rule case-insensitive.",
        "\"Why is this user not in the group?\": check user status, the rule's status, its expression and the "
        "exclude list, in that order.",
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
    cfg = policies["okta_groups"]
    st = run_all(data, cfg)
    updates, rules, members, tickets = st["updates"], st["rules"], st["members"], st["tickets"]
    groups = data.get("groups", {})
    ui.section("Step 1 — Validate profile changes against the Universal Directory schema")
    ui.table("Profile requests", ["ID", "Operation", "User", "Outcome"],
             [[u.id, u.operation, u.user, u.outcome] for u in updates])
    for u in updates:
        ui.bullet(f"{u.id} → {u.outcome}: " + "; ".join(u.reasons),
                  style="green" if u.outcome == "ACCEPTED" else "red")
    ui.section("Step 2 — Check group rules (status, expression, target groups)")
    ui.table("Group rules", ["ID", "Rule", "Status", "Flag", "Matched"],
             [[r.id, r.name, r.status, r.flag, len(r.matched)] for r in rules])
    for r in rules:
        ui.bullet(f"{r.id} {r.expression or '(empty)'} → {r.flag}: " + "; ".join(r.reasons),
                  style="green" if r.flag == "OK" else "yellow")
    ui.section("Step 3 — Resulting group memberships")
    ui.table("Groups", ["Group", "Type", "Members", "Who"],
             [[g.get("name", gid), g.get("type", "?"), len(members.get(gid, [])),
               ", ".join(m.split("@")[0] for m in members.get(gid, [])) or "-"] for gid, g in groups.items()])
    ui.section("Step 4 — Troubleshoot help-desk tickets")
    ui.table("Tickets", ["ID", "User", "Group", "Member?", "Cause"],
             [[t.id, t.user, t.group, "yes" if t.is_member else "no", t.cause] for t in tickets])
    for t in tickets:
        ui.bullet(f"{t.id} → {t.cause}: " + "; ".join(t.reasons),
                  style="green" if t.cause in ("RULE_MATCHED", "MANUAL_ASSIGNMENT") else "yellow")
    metrics = {"updates": len(updates), "update_counts": _counts(u.outcome for u in updates),
               "rules": len(rules), "rule_flags": _counts(r.flag for r in rules),
               "groups": len(groups), "memberships": sum(len(v) for v in members.values()),
               "tickets": len(tickets), "cause_counts": _counts(t.cause for t in tickets)}
    ui.print(f"{len(updates)} profile requests ({metrics['update_counts'].get('ACCEPTED', 0)} accepted) · "
             f"{sum(r.flag != 'OK' for r in rules)} of {len(rules)} rules need attention · "
             f"{len(tickets)} tickets diagnosed")
    ui.insight(INSIGHT)
    return {"updates": {u.id: u.outcome for u in updates}, "rules": {r.id: r.flag for r in rules},
            "memberships": members, "tickets": {t.id: t.cause for t in tickets}, "metrics": metrics}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["okta_groups"]
    st = run_all(data, cfg)
    updates, rules, members, tickets = st["updates"], st["rules"], st["members"], st["tickets"]
    groups = data.get("groups", {})
    reqs = {u.get("id"): u for u in data.get("profile_updates", [])}
    tk = {t.get("id"): t for t in data.get("tickets", [])}
    rule_names = {rc.id: f"{rc.id} {rc.name}" for rc in rules}
    qs: list = []
    for u in updates:
        src = {k: v for k, v in reqs.get(u.id, {}).items() if k != "id"}
        qs.append(Question(prompt=f"{u.id}: does Okta accept this profile request?", context=f"request={src}",
                           choices=list(UPDATE_OUTCOMES), answer=u.outcome, explanation="; ".join(u.reasons),
                           objective="1.1"))
    for r in rules:
        qs.append(Question(prompt=f"{r.id} '{r.name}': what is the main problem with this group rule, if any?",
                           context=f"status={r.status}; expression: {r.expression or '(empty)'}; targets: "
                                   f"{next((x.get('assign_to') for x in data.get('group_rules', []) if x.get('id') == r.id), [])}",
                           choices=list(RULE_FLAGS), answer=r.flag, explanation="; ".join(r.reasons), objective="1.2"))
    for t in tickets:
        src = tk.get(t.id, {})
        qs.append(Question(prompt=f"{t.id}: what explains {t.user.split('@')[0]}'s membership of {t.group}?",
                           context=f"ticket: {src.get('summary', '')}", choices=list(CAUSES), answer=t.cause,
                           explanation="; ".join(t.reasons), objective="5.2"))
        if t.cause == "RULE_MATCHED" and len(rule_names) >= 2:
            ans = rule_names[t.rule]
            qs.append(Question(prompt=f"Which group rule placed {t.user.split('@')[0]} in {t.group}?",
                               choices=choices_with(ans, sorted(rule_names.values()), key=t.id), answer=ans,
                               explanation="; ".join(t.reasons), objective="1.2"))
    everyone = sorted(st["users"])
    for gid, g in groups.items():
        m = members.get(gid, [])
        others = [x for x in everyone if x not in m]
        if m and len(others) >= 3:
            qs.append(Question(prompt=f"After the profile changes, which user is a member of {g.get('name', gid)}?",
                               choices=choices_with(m[0], others + [m[0]], key=gid), answer=m[0],
                               explanation=f"members of {g.get('name', gid)}: {', '.join(m)}", objective="1.2"))
            break
    qs.append(Question(prompt="An administrator wants a group rule to add users to a group that holds the Help Desk "
                              "Administrator role. What happens?",
                       choices=["the group cannot be a rule target: rules can't assign users to admin groups",
                                "the rule adds the users and they become help desk administrators",
                                "the rule adds the users but the admin role is removed from the group",
                                "the rule works only for users with a Super Administrator approval"],
                       answer="the group cannot be a rule target: rules can't assign users to admin groups",
                       explanation=cfg["concepts"]["admin group"], objective="1.2"))
    qs.append(Question(prompt="Can a group rule populate an Active Directory group?",
                       choices=["yes: rules can populate Active Directory groups based on user attributes",
                                "no: rules only ever assign groups created in Okta",
                                "only if the Active Directory group also holds an admin role",
                                "only for users whose status is deactivated"],
                       answer="yes: rules can populate Active Directory groups based on user attributes",
                       explanation="Okta's group rules page: rules can map Okta groups to AD groups and populate AD "
                                   "groups based on user attributes", objective="1.2"))
    qs.append(Question(prompt="A user who was in three groups is deactivated. What happens to their group memberships?",
                       choices=["they stay until the user is deleted; app assignments are removed and rules stop "
                                "evaluating the user",
                                "they are all removed at once",
                                "only rule-based memberships stay",
                                "they move to the Everyone group only"],
                       answer="they stay until the user is deleted; app assignments are removed and rules stop "
                              "evaluating the user",
                       explanation="deactivation removes app assignments, not group memberships", objective="5.2"))
    qs.append(Question(prompt="A user was added to a group by hand, and later a rule for that group stops matching "
                              "them. What happens to their membership?",
                       choices=["they stay in the group until an administrator removes them",
                                "the rule removes them at its next evaluation",
                                "they are moved to the Everyone group only",
                                "they are suspended until the rule matches again"],
                       answer="they stay in the group until an administrator removes them",
                       explanation=cfg["concepts"]["manual assignment"], objective="5.2"))
    for term in sorted(cfg["concepts"]):
        obj = "1.1" if term in ("custom attribute", "Universal Directory", "profile schema") else "1.2"
        qs.append(Question(prompt=f"Which term is this? \"{cfg['concepts'][term]}\"",
                           choices=choices_with(term, sorted(cfg["concepts"]), key=term), answer=term,
                           explanation=cfg["concepts"][term], objective=obj))
    return qs


# --------------------------------------------------------------------------- #
# Seeded scenario generator
# --------------------------------------------------------------------------- #
_FIRST = ["ada", "bryn", "cole", "dina", "ezra", "fern", "gil", "hedy", "isla", "joel", "kian", "luz", "mae",
          "nils", "odile", "per", "rhea", "sol", "tove", "ugo", "veda", "wim", "xena", "yuri", "zia"]
_LAST = ["abbott", "baird", "corr", "dale", "eames", "faulk", "gorman", "holt", "imber", "jarvis", "kemp",
         "lowe", "marsh", "noble", "ortiz", "price", "quayle", "ross", "shaw", "turner", "upton", "voss"]
CUSTOM = {"businessUnit": {"type": "string", "required": True}, "badgeNumber": {"type": "integer"},
          "remoteWorker": {"type": "boolean"}, "certifications": {"type": "array", "items": "string"}}


def generate_scenario(rng, policies: dict) -> dict:
    dom = "tallowmere.example"
    names = iter(rng.sample([f"{f}.{l}" for f in _FIRST for l in _LAST], 30))
    users: dict = {}
    dept = rng.choice(["Sales", "Marketing", "Finance", "Support"])
    country = rng.choice(["US", "CA", "GB", "DE"])
    other_country = rng.choice([c for c in ("US", "CA", "GB", "DE", "FR") if c != country])
    unit = rng.choice(["Commercial", "Operations", "Corporate"])

    def person(department=dept, cc=country, title="Specialist", etype="Employee", status="ACTIVE", **extra):
        login = f"{next(names)}@{dom}"
        first, last = login.split("@")[0].split(".")
        prof = {"login": login, "email": login, "firstName": first.title(), "lastName": last.title(),
                "department": department, "title": title, "countryCode": cc, "businessUnit": unit,
                "badgeNumber": rng.randint(1000, 9999), "remoteWorker": False, "certifications": []}
        if etype is not None:
            prof["employeeType"] = etype
        prof.update(extra)
        users[login] = {"status": status, "profile": prof}
        return login

    match = person()
    case_bad = person(department=dept.lower())
    excluded = person()
    manual = person(cc=other_country)
    inactive_u = person(status="DEPROVISIONED")
    vp = person(department="Engineering", title=rng.choice(["VP Engineering", "VP Product"]))
    not_vp = person(department="Engineering", title="Vice President, Platform")
    contractor = person(etype="Contractor")
    blank = person(etype=None)
    remote = person()
    pm = person(department="Engineering")
    groups = {
        "G-DEPT": {"name": f"{dept}-{country}", "type": "OKTA_GROUP", "manual_members": [manual]},
        "G-LEAD": {"name": "Leadership", "type": "OKTA_GROUP", "manual_members": []},
        "G-EMP": {"name": "All-Employees", "type": "OKTA_GROUP", "manual_members": []},
        "G-REMOTE": {"name": "Remote-Workers", "type": "OKTA_GROUP", "manual_members": []},
        "G-PMP": {"name": "Project-Managers", "type": "OKTA_GROUP", "manual_members": []},
        "G-AD": {"name": "Finance (AD)", "type": "APP_GROUP", "source": "Active Directory", "manual_members": []},
        "G-OPS": {"name": "Ops-Team", "type": "OKTA_GROUP", "manual_members": [inactive_u]},
        "G-ADM": {"name": "Help-Desk-Admins", "type": "OKTA_GROUP", "admin_roles": ["Help Desk Administrator"],
                  "manual_members": []},
    }
    rules = [
        {"name": f"{dept} {country}", "status": "ACTIVE", "assign_to": ["G-DEPT"], "exclude": [excluded],
         "expression": f'user.department == "{dept}" AND user.countryCode == "{country}"'},
        {"name": "Leadership", "status": "ACTIVE", "assign_to": ["G-LEAD"], "exclude": [],
         "expression": 'String.startsWith(user.title, "VP")'},
        {"name": "Employees", "status": "ACTIVE", "assign_to": ["G-EMP"], "exclude": [],
         "expression": 'user.employeeType != "Contractor"'},
        {"name": "Remote staff", "status": "INACTIVE", "assign_to": ["G-REMOTE"], "exclude": [],
         "expression": "user.remoteWorker == true"},
        {"name": "PMP holders", "status": "ACTIVE", "assign_to": ["G-PMP"], "exclude": [],
         "expression": 'Arrays.contains(user.certifications, "PMP")'},
        {"name": "Finance to AD", "status": "ACTIVE", "assign_to": ["G-AD"], "exclude": [],
         "expression": 'user.department == "Finance"'},
        {"name": "Help desk admins", "status": "ACTIVE", "assign_to": ["G-ADM"], "exclude": [],
         "expression": 'String.startsWith(user.title, "Support")'},
        {"name": "Ops", "status": "ACTIVE", "assign_to": ["G-OPS"], "exclude": [],
         "expression": rng.choice(['user.department = "Operations"', 'user.Department == "Operations"',
                                   'isMemberOfAnyGroup("00g-ops")'])},
    ]
    rng.shuffle(rules)
    for n, r in enumerate(rules, 1):
        r["id"] = f"R{n:02d}"
    new_login = f"{next(names)}@{dom}"
    updates = [
        {"operation": "update", "user": remote, "profile": {"remoteWorker": True}},
        {"operation": "update", "user": pm, "profile": {"certifications": ["PMP", rng.choice(["CISSP", "ITIL"])]}},
        {"operation": "update", "user": match, "profile": {"Department": dept}},
        {"operation": "update", "user": vp, "profile": {"badgeNumber": str(rng.randint(1000, 9999))}},
        {"operation": "update", "user": excluded, "profile": {"lastName": None}},
        {"operation": "create", "user": new_login, "activate": rng.choice([True, False]),
         "profile": {"login": new_login, "email": new_login, "firstName": "New", "lastName": "Hire",
                     "department": dept}},
        {"operation": "update", "user": f"ghost@{dom}", "profile": {"title": "Analyst"}},
        {"operation": "update", "user": case_bad, "profile": {"remoteWorker": rng.choice(["yes", "true"])}},
    ]
    rng.shuffle(updates)
    for n, u in enumerate(updates, 1):
        u["id"] = f"P{n:02d}"
    gname = {k: v["name"] for k, v in groups.items()}
    tickets = [
        (match, "G-DEPT", "is in the group as expected"), (case_bad, "G-DEPT", "is missing from the group"),
        (excluded, "G-DEPT", "is missing from the group"), (manual, "G-DEPT", "is in the group but works abroad"),
        (inactive_u, "G-EMP", "is missing from the group"), (remote, "G-REMOTE", "is missing from the group"),
        (vp, "G-LEAD", "is in the group"), (not_vp, "G-LEAD", "is missing from the group"),
        (blank, "G-EMP", "is in the group with no employee type"), (contractor, "G-EMP", "is missing"),
        (pm, "G-PMP", "is in the group after the update"), (vp, "G-ADM", "needs help desk admin rights"), (inactive_u, "G-OPS", "is deactivated but still listed"),
        (match, "G-OPS", "is missing from the group"),
    ]
    rng.shuffle(tickets)
    tk = [{"id": f"T{n:02d}", "user": u, "group": g, "summary": f"{u.split('@')[0]} {s} ({gname[g]})"}
          for n, (u, g, s) in enumerate(tickets, 1)]
    return {"_description": "Generated Okta Universal Directory scenario (fictional).", "org": "Tallowmere Example Co",
            "custom_attributes": copy.deepcopy(CUSTOM), "users": users, "groups": groups, "group_rules": rules,
            "profile_updates": updates, "tickets": tk}
