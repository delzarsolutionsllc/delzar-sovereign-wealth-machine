"""
Lab 39 — Attribute Mapping, User Lifecycle & Offboarding
========================================================

Okta Professional objectives
----------------------------
* 3.1  Profile Editor and attribute mappings: profile sources (an HR app or a
       directory) mapped into the Okta user profile, Okta-to-app mappings
       pushed to app user profiles, Okta Expression Language, "apply on create
       only" versus "create and update".
* 3.2  Deactivation, user status and offboarding: Staged, Pending user action,
       Active, Suspended, Deactivated and deleted users, what happens to
       sessions, app assignments and app accounts, and how to prove a leaver
       has really lost access.

How it works
------------
You are the Okta administrator at a mid-sized company. HR is the profile
source for employees, Okta pushes profiles to the apps, and every week some
people join, change jobs or leave.

Part 1, mappings. Each user is either created or updated. Rules, in order:

1. Unknown event, unknown profile source, missing HR record or unknown app →
   MAPPING_ERROR (nothing is guessed: deny by default).
2. Admin edits made in Okta are applied first. If the user has a profile
   source, each inbound mapping (app → Okta) then runs: on an update a
   "create only" mapping is skipped, and so is an attribute set to "Inherit
   from Okta"; the rest are evaluated against the HR record.
3. Each assigned app then gets the Okta-to-app mappings, in the same way. On
   a create the app must have Create Users, on an update Update User
   Attributes, or nothing is pushed.
4. An expression whose source attribute is missing, that cannot be parsed, or
   whose result has a different type from the target attribute →
   MAPPING_ERROR (the old value is kept).
5. An edit made below the source (in Okta for a sourced user, or directly in
   the app) to an attribute that the source then writes with a different
   value → OVERWRITTEN_BY_SOURCE.
6. Otherwise OK. The most severe finding wins.

Part 2, lifecycle. A requested status change is ALLOWED only if it is in the
policy's list of Okta transitions, else INVALID_TRANSITION (with the reason,
for example "deactivate first"). For an allowed change the result says whether
the user can sign in, whether Okta sessions are cleared and whether app
assignments are kept. On deactivation each app account is DEACTIVATED when the
app has Deactivate Users provisioning, else LEFT_ACTIVE_ORPHAN (bookmark apps
have no account). Suspension keeps assignments and app accounts unchanged.

Part 3, offboarding checklist. For each leaver and app, in order:

1. Unknown status or unknown app → STILL_HAS_ACCESS (cannot be verified).
2. Not deactivated (Active, Suspended and so on) → STILL_HAS_ACCESS: a
   suspended user keeps every assignment and one unsuspend restores it.
3. Bookmark app, Deactivate Users provisioning, or the app account was
   deactivated by hand → ACCESS_REMOVED.
4. The app account was left active and the app accepts its own password (SWA,
   or local sign-in allowed) → STILL_HAS_ACCESS; SSO-only → ACCESS_REMOVED,
   with a warning to clean up the orphaned account.

Run it
------
    python main.py --course okta lab 39
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

TITLE = "Lab 39 — Attribute Mapping, User Lifecycle & Offboarding"
OBJECTIVES = ("Okta Professional 3.1 Profile Editor and attribute mappings · "
              "3.2 Deactivation, user status and offboarding")
COURSES = ("okta",)
MAP_OUTCOMES = ["MAPPING_ERROR", "OVERWRITTEN_BY_SOURCE", "OK"]
LIFECYCLE_OUTCOMES = ["ALLOWED", "INVALID_TRANSITION"]
ACCOUNT_STATES = ["DEACTIVATED", "LEFT_ACTIVE_ORPHAN", "NO_ACCOUNT", "UNCHANGED"]
OFFBOARD_OUTCOMES = ["ACCESS_REMOVED", "STILL_HAS_ACCESS"]
SECTION = "okta_mapping_offboarding"


@dataclass
class MappingResult:
    id: str
    login: str
    outcome: str
    okta_profile: dict
    app_profiles: dict
    findings: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


@dataclass
class TransitionResult:
    id: str
    user: str
    current: str
    requested: str
    outcome: str
    action: str = "-"
    can_sign_in: bool | None = None
    sessions_cleared: bool | None = None
    assignments: str = "-"
    app_accounts: dict = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)


@dataclass
class OffboardResult:
    id: str
    user: str
    status: str
    app: str
    outcome: str
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Expression evaluation (a small subset of Okta Expression Language)
# --------------------------------------------------------------------------- #
class ExprError(Exception):
    """Raised when an expression cannot produce a value."""


def _split_top(expr: str, sep: str) -> list[str]:
    """Split on ``sep`` outside quotes and parentheses."""
    parts, depth, quote, cur = [], 0, False, ""
    for ch in expr:
        if ch == '"':
            quote = not quote
        elif not quote and ch == "(":
            depth += 1
        elif not quote and ch == ")":
            depth -= 1
        if ch == sep and not quote and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    return parts


def _ref(expr: str, ctx: dict):
    m = re.fullmatch(r"(user|appuser)\.(\w+)", expr)
    if not m:
        return None, False
    prefix, name = m.groups()
    if prefix not in ctx:
        raise ExprError(f"'{prefix}' is not available in this mapping direction")
    return ctx[prefix].get(name), True


def type_name(value) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, str):
        return "string"
    return type(value).__name__


def evaluate(expr, ctx: dict, cfg: dict):
    """Value of ``expr`` for ``ctx`` ({'user': okta profile} or {'appuser': source record}); raises ExprError."""
    if not isinstance(expr, str) or not expr.strip():
        raise ExprError("empty expression")
    expr = expr.strip()
    q = _split_top(expr, "?")
    if len(q) == 2:
        branches = _split_top(q[1], ":")
        cond = re.fullmatch(r"(.+?)\s*(!=|==)\s*null", q[0].strip())
        if len(branches) != 2 or not cond:
            raise ExprError(f"cannot parse expression '{expr}'")
        value, ok = _ref(cond.group(1).strip(), ctx)
        if not ok:
            raise ExprError(f"cannot parse condition '{q[0].strip()}'")
        present = value is not None and value != ""
        return evaluate(branches[0] if present == (cond.group(2) == "!=") else branches[1], ctx, cfg)
    if len(q) > 2:
        raise ExprError(f"cannot parse expression '{expr}'")
    parts = _split_top(expr, "+")
    if len(parts) > 1:
        vals = [evaluate(p, ctx, cfg) for p in parts]
        return "".join(str(v).lower() if isinstance(v, bool) else str(v) for v in vals)
    if len(expr) >= 2 and expr[0] == expr[-1] == '"':
        return expr[1:-1]
    if expr in ("true", "false"):
        return expr == "true"
    m = re.fullmatch(r"(String\.\w+)\((.*)\)", expr)
    if m:
        fn, arg = m.groups()
        if fn not in cfg["functions"]:
            raise ExprError(f"unsupported function {fn}")
        value = evaluate(arg, ctx, cfg)
        if not isinstance(value, str):
            raise ExprError(f"type mismatch: {fn} needs a string, got {type_name(value)} {value!r}")
        return value.lower() if fn.endswith("toLowerCase") else value.upper()
    value, ok = _ref(expr, ctx)
    if not ok:
        raise ExprError(f"cannot parse expression '{expr}'")
    if value is None or value == "":
        raise ExprError(f"source attribute {expr} is missing")
    return value


def _check_type(value, target: str, schema: dict, cfg: dict) -> None:
    ttype = schema.get(target)
    if ttype not in cfg["types"]:
        raise ExprError(f"target attribute '{target}' is not in the profile schema")
    if type_name(value) != ttype:
        raise ExprError(f"type mismatch: '{target}' is {ttype} but the value {value!r} is {type_name(value)}")


def _apply(mappings, ctx, profile, schema, edited, event, owned, source_label, cfg, found, reasons, where):
    for m in mappings:
        t, mode = m.get("target"), m.get("apply")
        if mode not in cfg["apply_modes"]:
            found.append("MAPPING_ERROR")
            reasons.append(f"{where}.{t}: unknown apply mode '{mode}' (deny by default: not applied)")
            continue
        if event == "update" and mode == "create_only":
            reasons.append(f"{where}.{t}: apply on create only, so the existing value {profile.get(t)!r} is kept")
            continue
        if event == "update" and t in owned:
            reasons.append(f"{where}.{t}: set to Inherit from Okta, so the import does not overwrite it")
            continue
        try:
            value = evaluate(m.get("expression"), ctx, cfg)
            _check_type(value, t, schema, cfg)
        except ExprError as e:
            found.append("MAPPING_ERROR")
            reasons.append(f"{where}.{t} = {m.get('expression')}: {e}; value not updated")
            continue
        if t in edited and profile.get(t) != value:
            found.append("OVERWRITTEN_BY_SOURCE")
            reasons.append(f"{where}.{t}: edit {profile.get(t)!r} overwritten by {source_label} value {value!r}")
        profile[t] = value


def map_user(user: dict, data: dict, cfg: dict) -> MappingResult:
    found: list[str] = []
    reasons: list[str] = []
    okta = dict(user.get("okta_profile") or {})
    apps_out: dict = {}
    event = user.get("event")
    uid, login = user.get("id", "?"), user.get("login") or okta.get("login") or "?"
    if event not in ("create", "update"):
        return MappingResult(uid, login, "MAPPING_ERROR", okta, {}, ["MAPPING_ERROR"],
                             [f"unknown event '{event}': no mapping applied (deny by default)"])
    edits = user.get("okta_admin_edits") or {}
    okta.update(edits)
    source = user.get("profile_source")
    if source:
        src = data.get("profile_sources", {}).get(source)
        if src is None:
            found.append("MAPPING_ERROR")
            reasons.append(f"profile source '{source}' is not configured: nothing imported")
        elif user.get("hr_record") is None:
            found.append("MAPPING_ERROR")
            reasons.append(f"no record for this user in profile source {source}")
        else:
            _apply(src.get("mappings", []), {"appuser": user["hr_record"]}, okta, data.get("okta_schema", {}),
                   set(edits), event, set(src.get("okta_owned_attributes", [])), f"profile source {source}", cfg,
                   found, reasons, "okta")
    elif edits:
        reasons.append("Okta is the source for this user, so admin edits in Okta stick")
    for app in user.get("assigned_apps", []):
        meta = data.get("apps", {}).get(app)
        cur = dict((user.get("app_profiles") or {}).get(app) or {})
        app_edits = (user.get("app_edits") or {}).get(app) or {}
        cur.update(app_edits)
        apps_out[app] = cur
        if meta is None:
            found.append("MAPPING_ERROR")
            reasons.append(f"app '{app}' is not in the app catalog: no mapping applied")
            continue
        prov = meta.get("provisioning") or {}
        if event == "create" and not prov.get("create_users"):
            reasons.append(f"{app}: Create Users is off, so no app account or profile is pushed")
            continue
        if event == "update" and not prov.get("update_attributes"):
            reasons.append(f"{app}: Update User Attributes is off, so Okta pushes no changes (app may be stale)")
            continue
        _apply(meta.get("mappings", []), {"user": okta}, cur, meta.get("schema", {}), set(app_edits), event, set(),
               "Okta", cfg, found, reasons, app)
    found.sort(key=cfg["finding_severity"].index)
    outcome = found[0] if found else "OK"
    if not found:
        reasons.append("every mapped attribute produced a valid value and no edit was lost")
    return MappingResult(uid, login, outcome, okta, apps_out, sorted(set(found), key=cfg["finding_severity"].index),
                         reasons)


def run_mappings(data: dict, cfg: dict) -> list[MappingResult]:
    return [map_user(u, data, cfg) for u in data.get("users", [])]


# --------------------------------------------------------------------------- #
# Lifecycle
# --------------------------------------------------------------------------- #
def app_account_state(meta: dict | None, cfg: dict) -> tuple[str, str]:
    """What deactivation does to the user's account in one app."""
    if meta is None:
        return "LEFT_ACTIVE_ORPHAN", "app not in catalog: assume no deprovisioning (deny by default)"
    if meta.get("sso") in cfg["no_account_sso_types"]:
        return "NO_ACCOUNT", "bookmark app: only a link, there is no app account"
    if (meta.get("provisioning") or {}).get("deactivate_users"):
        return "DEACTIVATED", "Deactivate Users provisioning deactivates the app account"
    return "LEFT_ACTIVE_ORPHAN", "no Deactivate Users provisioning: the app account stays active (orphan)"


def transition(req: dict, data: dict, cfg: dict) -> TransitionResult:
    cur, to = req.get("current"), req.get("requested")
    res = TransitionResult(req.get("id", "?"), req.get("user", "?"), str(cur), str(to), "INVALID_TRANSITION")
    if cur not in cfg["statuses"] or to not in cfg["statuses"]:
        res.reasons.append(f"unknown status '{cur if cur not in cfg['statuses'] else to}': not changed (deny by default)")
        return res
    if cur == to:
        res.reasons.append(f"user is already {cfg['statuses'][cur]}")
        return res
    match = next((t for t in cfg["transitions"] if t["from"] == cur and t["to"] == to), None)
    if match is None:
        hint = cfg["invalid_hints"].get(f"{cur}->{to}") or cfg["invalid_hints"].get(f"{cur}->*")
        res.reasons.append(f"{cfg['statuses'][cur]} → {cfg['statuses'][to]} is not an Okta transition"
                           + (f": {hint}" if hint else ""))
        return res
    eff = cfg["status_effects"][to]
    res.outcome, res.action = "ALLOWED", match["action"]
    res.can_sign_in, res.sessions_cleared, res.assignments = eff["can_sign_in"], eff["sessions_cleared"], \
        eff["assignments"]
    res.reasons.append(f"{match['action']}: user {'can' if eff['can_sign_in'] else 'cannot'} sign in, "
                       f"Okta sessions {'cleared' if eff['sessions_cleared'] else 'not affected'}, "
                       f"app assignments {eff['assignments']}")
    for app in req.get("apps", []):
        if to in cfg["deprovision_on"]:
            state, why = app_account_state(data.get("apps", {}).get(app), cfg)
            res.reasons.append(f"{app}: {why}")
        else:
            state = "UNCHANGED"
        res.app_accounts[app] = state
    if to == "SUSPENDED":
        res.reasons.append("suspend keeps group memberships and app assignments; app accounts are not deprovisioned")
    if to == "DEACTIVATED":
        res.reasons.append("group memberships are kept until the user is deleted; open app sessions may last "
                           "until they expire")
    if cur == "DEACTIVATED" and to == "PENDING_USER_ACTION":
        res.reasons.append("app assignments are not restored, except those that come back through groups")
    if to == "DELETED":
        res.reasons.append("permanent: groups, factors and the profile are removed and the username can be reused")
    return res


def run_lifecycle(data: dict, cfg: dict) -> list[TransitionResult]:
    return [transition(r, data, cfg) for r in data.get("lifecycle_requests", [])]


# --------------------------------------------------------------------------- #
# Offboarding verification
# --------------------------------------------------------------------------- #
def verify_offboarding(item: dict, data: dict, cfg: dict) -> OffboardResult:
    status, app = item.get("status"), item.get("app")
    res = OffboardResult(item.get("id", "?"), item.get("user", "?"), str(status), str(app), "STILL_HAS_ACCESS")
    meta = data.get("apps", {}).get(app)
    if status not in cfg["statuses"]:
        res.reasons.append(f"unknown Okta status '{status}': access cannot be verified (deny by default)")
    elif status == "SUSPENDED":
        res.reasons.append("suspended, not deactivated: sign-in is blocked but assignments are kept, no app "
                           "account was deprovisioned, and one unsuspend restores everything")
    elif status not in cfg["deprovisioned_statuses"]:
        res.reasons.append(f"Okta account is still {cfg['statuses'][status]}: deactivate it")
    elif meta is None:
        res.reasons.append(f"app '{app}' is not in the app catalog: access cannot be verified (deny by default)")
    else:
        state, why = app_account_state(meta, cfg)
        if state == "LEFT_ACTIVE_ORPHAN" and item.get("manually_deactivated_in_app"):
            state, why = "DEACTIVATED", "app owner deactivated the account by hand (ticket evidence)"
        res.reasons.append(why)
        if state in ("DEACTIVATED", "NO_ACCOUNT"):
            res.outcome = "ACCESS_REMOVED"
        elif meta.get("sso") in cfg["local_credential_sso_types"] or meta.get("local_login"):
            res.reasons.append(f"{meta.get('sso')} app accepts its own username and password, which the leaver "
                               "may know: they can sign in without Okta")
        else:
            res.outcome = "ACCESS_REMOVED"
            res.reasons.append("sign-in only through Okta SSO, so access is gone, but deactivate the orphaned "
                               "account in the app (licence and audit)")
    return res


def run_offboarding(data: dict, cfg: dict) -> list[OffboardResult]:
    return [verify_offboarding(i, data, cfg) for i in data.get("offboarding", [])]


def metrics(maps, trans, offs) -> dict:
    accounts = [s for t in trans for s in t.app_accounts.values()]
    return {"users": len(maps), "mapping_counts": {o: sum(m.outcome == o for m in maps) for o in MAP_OUTCOMES},
            "requests": len(trans), "allowed": sum(t.outcome == "ALLOWED" for t in trans),
            "invalid": sum(t.outcome == "INVALID_TRANSITION" for t in trans),
            "account_counts": {s: accounts.count(s) for s in ACCOUNT_STATES},
            "checks": len(offs), "still_has_access": sum(o.outcome == "STILL_HAS_ACCESS" for o in offs),
            "access_removed": sum(o.outcome == "ACCESS_REMOVED" for o in offs)}


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "Okta Professional 3.1 Profile Editor and attribute mappings · 3.2 Deactivation, user status "
                 "and offboarding.",
    "concepts": [
        "Data flows one way: profile source (HR) → Okta user profile → app user profiles, through mappings in Profile Editor.",
        "Whatever sits downstream of a source is overwritten on the next import or push, so fix data at the source.",
        "'Apply on create only' sets a value once (for example the login); 'create and update' keeps it in sync.",
        "Suspend is reversible and keeps assignments; deactivate removes app assignments and clears sessions; only "
        "deactivated users can be deleted.",
        "Okta can only deactivate an app account if the app has provisioning with Deactivate Users turned on.",
    ],
    "failure_modes": [
        "A help-desk agent edits a sourced user's department in Okta and it reverts at the next HR import.",
        "A mapping uses an attribute some users do not have, or sends text to a boolean field, and the push fails.",
        "A leaver is suspended 'for now' and still holds every app assignment months later.",
        "An SWA or local-login app has no deprovisioning, so the leaver's own app password still works.",
    ],
    "ai_governance": [
        "An AI agent can draft mapping expressions, but test them on a few users before turning on create and update.",
        "Let an agent run the offboarding checklist, but a human signs off each STILL_HAS_ACCESS before closing the ticket.",
        "Give the agent an Okta admin role scoped to users and groups it needs, not Super Administrator.",
        "Treat HR fields and ticket notes as untrusted data, never as instructions to the agent.",
    ],
    "exam_tips": [
        "Edit lost after an import? The attribute is sourced from the profile source: change it there.",
        "'Cannot sign in but keeps apps and groups' = Suspended; 'apps removed, can be deleted' = Deactivated.",
        "Delete is only offered for Deactivated users, and deletion cannot be undone.",
        "App account still active after deactivation = Deactivate Users provisioning not enabled for that app.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def _yn(v) -> str:
    return "-" if v is None else ("yes" if v else "no")


def run_demo(ui, policies: dict, data: dict) -> dict:
    cfg = policies[SECTION]
    maps, trans, offs = run_mappings(data, cfg), run_lifecycle(data, cfg), run_offboarding(data, cfg)
    m = metrics(maps, trans, offs)
    ui.section("Step 1 — Profile source → Okta → app attribute mappings")
    ui.table("Mapping results", ["ID", "Login", "Event", "Source", "Apps", "Outcome"],
             [[r.id, r.login, u.get("event", "-"), u.get("profile_source") or "Okta",
               ", ".join(u.get("assigned_apps", [])) or "-", r.outcome]
              for r, u in zip(maps, data.get("users", []))])
    for r in maps:
        ui.bullet(f"{r.id} → {r.outcome}: " + "; ".join(r.reasons),
                  style={"OK": "green", "MAPPING_ERROR": "red"}.get(r.outcome, "yellow"))
    ui.section("Step 2 — Lifecycle: validate requested status changes")
    ui.table("Status changes", ["ID", "User", "From", "To", "Outcome", "Sign-in", "Sessions cleared",
                                "Assignments", "App accounts"],
             [[t.id, t.user, t.current, t.requested, t.outcome, _yn(t.can_sign_in), _yn(t.sessions_cleared),
               t.assignments, ", ".join(f"{a}={s}" for a, s in t.app_accounts.items()) or "-"] for t in trans])
    for t in trans:
        ui.bullet(f"{t.id} → {t.outcome}: " + "; ".join(t.reasons),
                  style="green" if t.outcome == "ALLOWED" else "red")
    ui.section("Step 3 — Offboarding checklist: can the leaver still reach each app?")
    ui.table("Offboarding verification", ["ID", "Leaver", "Okta status", "App", "Outcome"],
             [[o.id, o.user, o.status, o.app, o.outcome] for o in offs])
    for o in offs:
        ui.bullet(f"{o.id} {o.app} → {o.outcome}: " + "; ".join(o.reasons),
                  style="green" if o.outcome == "ACCESS_REMOVED" else "red")
    ui.status("Offboarding", "PASS" if m["still_has_access"] == 0 else "FAIL",
              f"{m['still_has_access']} of {m['checks']} checks still have access")
    ui.print(f"Mappings: {m['mapping_counts']} · transitions allowed {m['allowed']}, invalid {m['invalid']} · "
             f"app accounts left active (orphans): {m['account_counts']['LEFT_ACTIVE_ORPHAN']}")
    ui.insight(INSIGHT)
    return {"mappings": {r.id: r.outcome for r in maps}, "lifecycle": {t.id: t.outcome for t in trans},
            "app_accounts": {t.id: dict(t.app_accounts) for t in trans if t.app_accounts},
            "offboarding": {o.id: o.outcome for o in offs}, "metrics": m}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies[SECTION]
    maps, trans, offs = run_mappings(data, cfg), run_lifecycle(data, cfg), run_offboarding(data, cfg)
    users = {u.get("id"): u for u in data.get("users", [])}
    qs: list = []

    def ctx_of(u: dict) -> str:
        keep = ("login", "event", "profile_source", "hr_record", "okta_admin_edits", "assigned_apps", "app_edits")
        return "user=" + str({k: u[k] for k in keep if k in u})

    for r in maps:
        qs.append(Question(prompt=f"{r.id}: after the import and push, which mapping outcome does this user get?",
                           context=ctx_of(users.get(r.id, {})), choices=MAP_OUTCOMES, answer=r.outcome,
                           explanation="; ".join(r.reasons), objective="3.1"))
    for r in maps:
        u = users.get(r.id, {})
        edits = u.get("okta_admin_edits") or {}
        if "OVERWRITTEN_BY_SOURCE" in r.findings and edits:
            attr = next((a for a in edits if r.okta_profile.get(a) != edits[a]), None)
            if attr:
                final, edit = str(r.okta_profile.get(attr)), str(edits[attr])
                qs.append(Question(prompt=f"{r.id}: an admin set {attr} to '{edit}' in Okta. What is it after the "
                                          f"next import from {u.get('profile_source')}?",
                                   context=ctx_of(u), choices=sorted({f"'{final}'", f"'{edit}'", "empty (cleared)"}),
                                   answer=f"'{final}'", explanation="; ".join(x for x in r.reasons if attr in x),
                                   objective="3.1"))
                break
    for t in trans:
        label = cfg["statuses"].get
        qs.append(Question(prompt=f"{t.id}: {t.user} is {label(t.current, t.current)}. Is a change to "
                                  f"{label(t.requested, t.requested)} allowed?",
                           choices=LIFECYCLE_OUTCOMES, answer=t.outcome, explanation="; ".join(t.reasons),
                           objective="3.2"))
    asked = set()
    for t in trans:
        for app, state in t.app_accounts.items():
            if state in ("DEACTIVATED", "LEFT_ACTIVE_ORPHAN") and state not in asked:
                asked.add(state)
                meta = data.get("apps", {}).get(app, {})
                qs.append(Question(prompt=f"{t.id}: {t.user} is deactivated. What happens to the {app} account?",
                                   context=f"{app}: sso={meta.get('sso')}, provisioning={meta.get('provisioning')}",
                                   choices=ACCOUNT_STATES, answer=state,
                                   explanation=app_account_state(meta, cfg)[1], objective="3.2"))
    for o in offs:
        meta = data.get("apps", {}).get(o.app, {})
        qs.append(Question(prompt=f"{o.id}: offboarding check for {o.user} ({o.status}) in {o.app}. Result?",
                           context=f"{o.app}: sso={meta.get('sso')}, provisioning={meta.get('provisioning')}, "
                                   f"local_login={meta.get('local_login', False)}",
                           choices=OFFBOARD_OUTCOMES, answer=o.outcome, explanation="; ".join(o.reasons),
                           objective="3.2"))
    eff = cfg["status_effects"]
    qs.append(Question(prompt="A user is suspended. Which statement is true?",
                       choices=["cannot sign in, but keeps app assignments and group memberships",
                                "app assignments are removed and app accounts are deprovisioned",
                                "the user is permanently deleted after 30 days",
                                "the user can still sign in but not open apps"],
                       answer="cannot sign in, but keeps app assignments and group memberships",
                       explanation=f"Suspended: sign-in {_yn(eff['SUSPENDED']['can_sign_in'])}, assignments "
                                   f"{eff['SUSPENDED']['assignments']}", objective="3.2"))
    qs.append(Question(prompt="Which status must a user have before an admin can delete it?",
                       choices=sorted(cfg["statuses"][s] for s in ("ACTIVE", "SUSPENDED", "DEACTIVATED", "STAGED")),
                       answer=cfg["statuses"]["DEACTIVATED"], explanation=cfg["invalid_hints"]["ACTIVE->DELETED"],
                       objective="3.2"))
    for term in ("profile source", "apply on create only", "Deactivate Users", "orphaned account"):
        if term in cfg["concepts"]:
            qs.append(Question(prompt=f"Which term is this? \"{cfg['concepts'][term]}\"",
                               choices=choices_with(term, cfg["concepts"], key=term), answer=term,
                               explanation=cfg["concepts"][term],
                               objective="3.2" if term in ("Deactivate Users", "orphaned account") else "3.1"))
    return qs


# --------------------------------------------------------------------------- #
# Random scenario
# --------------------------------------------------------------------------- #
_FIRST = ["Avery", "Blake", "Casey", "Devon", "Emery", "Finley", "Harper", "Jordan", "Kendall", "Logan", "Morgan",
          "Noel", "Parker", "Quinn", "Reese", "Rowan", "Sasha", "Taylor"]
_LAST = ["Abara", "Brandt", "Castell", "Dorsey", "Ellison", "Faraday", "Grieve", "Holm", "Ibarra", "Jansen",
         "Kowal", "Lindqvist", "Moreau", "Nakata", "Oduya", "Pryce"]
_DEPTS = ["Finance", "Sales", "Engineering", "Marketing", "Operations", "Legal"]


def base_catalog() -> tuple[dict, dict, dict]:
    """Okta schema, profile sources and app catalog shared by the sample and the generator."""
    okta_schema = {"login": "string", "email": "string", "firstName": "string", "lastName": "string",
                   "department": "string", "title": "string", "employeeNumber": "string", "costCenter": "string",
                   "mobilePhone": "string", "isManager": "boolean", "managerId": "string"}
    sources = {"PeopleHub HR": {
        "okta_owned_attributes": ["mobilePhone"],
        "mappings": [
            {"target": "login", "expression": "String.toLowerCase(appuser.workEmail)", "apply": "create_only"},
            {"target": "email", "expression": "String.toLowerCase(appuser.workEmail)", "apply": "create_and_update"},
            {"target": "firstName", "expression": "appuser.givenName", "apply": "create_and_update"},
            {"target": "lastName", "expression": "appuser.familyName", "apply": "create_and_update"},
            {"target": "department", "expression": 'appuser.dept != null ? appuser.dept : "Unassigned"',
             "apply": "create_and_update"},
            {"target": "title", "expression": "appuser.jobTitle", "apply": "create_and_update"},
            {"target": "employeeNumber", "expression": "appuser.empId", "apply": "create_and_update"},
            {"target": "isManager", "expression": "appuser.isPeopleManager", "apply": "create_and_update"},
            {"target": "mobilePhone", "expression": "appuser.mobile", "apply": "create_and_update"},
        ]}}
    apps = {
        "Expense Portal": {
            "sso": "SAML", "local_login": False,
            "provisioning": {"create_users": True, "update_attributes": True, "deactivate_users": True},
            "schema": {"userName": "string", "email": "string", "displayName": "string", "department": "string",
                       "costCenter": "string", "approver": "boolean"},
            "mappings": [
                {"target": "userName", "expression": "user.login", "apply": "create_and_update"},
                {"target": "email", "expression": "user.email", "apply": "create_and_update"},
                {"target": "displayName", "expression": 'user.firstName + " " + user.lastName',
                 "apply": "create_and_update"},
                {"target": "department", "expression": "user.department", "apply": "create_and_update"},
                {"target": "costCenter", "expression": 'user.costCenter != null ? user.costCenter : "CC-000"',
                 "apply": "create_and_update"},
                {"target": "approver", "expression": "user.isManager", "apply": "create_and_update"},
            ]},
        "Team Chat": {
            "sso": "OIDC", "local_login": False,
            "provisioning": {"create_users": True, "update_attributes": True, "deactivate_users": False},
            "schema": {"handle": "string", "email": "string", "jobTitle": "string", "manager": "string"},
            "mappings": [
                {"target": "handle", "expression": 'String.toLowerCase(user.firstName + "." + user.lastName)',
                 "apply": "create_only"},
                {"target": "email", "expression": "user.email", "apply": "create_and_update"},
                {"target": "jobTitle", "expression": "user.title", "apply": "create_only"},
                {"target": "manager", "expression": "user.managerId", "apply": "create_and_update"},
            ]},
        "Vendor Wiki": {"sso": "SWA", "local_login": True, "provisioning": {}},
        "Legacy CRM": {"sso": "SAML", "local_login": True, "provisioning": {}},
        "Analytics Hub": {"sso": "SAML", "local_login": False, "provisioning": {}},
        "Benefits Link": {"sso": "BOOKMARK", "provisioning": {}},
    }
    return okta_schema, sources, apps


def generate_scenario(rng, policies: dict) -> dict:
    okta_schema, sources, apps = base_catalog()
    dom = "larkspur.example"
    names = iter(rng.sample([(f, l) for f in _FIRST for l in _LAST], 24))

    def hr(first, last, **kw):
        rec = {"workEmail": f"{first}.{last}@{dom}",
               "givenName": first, "familyName": last, "dept": rng.choice(_DEPTS), "jobTitle": "Analyst",
               "empId": f"E{rng.randint(1000, 9999)}", "isPeopleManager": rng.choice([True, False]),
               "mobile": f"+1-555-{rng.randint(1000, 9999)}"}
        rec.update(kw)
        return rec

    def okta_from(rec, **kw):
        prof = {"login": rec["workEmail"].lower(), "email": rec["workEmail"].lower(), "firstName": rec["givenName"],
                "lastName": rec["familyName"], "department": rec.get("dept") or "Unassigned",
                "title": rec.get("jobTitle"), "employeeNumber": rec.get("empId"),
                "isManager": rec.get("isPeopleManager"), "mobilePhone": rec.get("mobile"), "managerId": "E1000",
                "costCenter": f"CC-{rng.randint(100, 999)}"}
        prof.update(kw)
        return prof

    users = []

    def add(event, rec=None, source="PeopleHub HR", **kw):
        u = {"event": event, "profile_source": source, "assigned_apps": ["Expense Portal"]}
        if rec is not None:
            u["hr_record"] = rec
            u["login"] = rec["workEmail"].lower()
        u.update(kw)
        users.append(u)
        return u

    f, l = next(names)
    r = hr(f, l)
    add("create", r, okta_profile={"managerId": "E1000"}, assigned_apps=["Expense Portal", "Team Chat"])
    f, l = next(names)
    r = hr(f, l)
    add("update", r, okta_profile=okta_from(r), okta_admin_edits={"department": rng.choice(
        [d for d in _DEPTS if d != r["dept"]])})
    f, l = next(names)
    r = hr(f, l)
    add("update", r, okta_profile=okta_from(r), assigned_apps=["Team Chat"],
        app_edits={"Team Chat": {"email": f"{f.lower()}@personal.example"}})
    f, l = next(names)
    r = hr(f, l, isPeopleManager=rng.choice(["Yes", "Y", "true"]))
    add("update", r, okta_profile=okta_from(r, isManager=False))
    f, l = next(names)
    r = hr(f, l)
    add("create", r, okta_profile={}, assigned_apps=["Team Chat"])
    f, l = next(names)
    r = hr(f, l, dept=None)
    add("update", r, okta_profile=okta_from(r, costCenter=None), okta_admin_edits={"mobilePhone": "+1-555-0100"})
    f, l = next(names)
    add("update", None, source=None, login=f"{f}.{l}@{dom}".lower(),
        okta_profile={"login": f"{f}.{l}@{dom}".lower(), "email": f"{f}.{l}@{dom}".lower(), "firstName": f,
                      "lastName": l, "department": "IT", "isManager": False, "managerId": "E1000"},
        okta_admin_edits={"title": "Contractor"}, assigned_apps=["Team Chat"],
        app_edits={"Team Chat": {"jobTitle": "Freelancer"}})
    f, l = next(names)
    add("update", None, source="Legacy Directory", login=f"{f}.{l}@{dom}".lower(), okta_profile={})
    rng.shuffle(users)
    for n, u in enumerate(users, 1):
        u["id"] = f"U{n:02d}"

    lifecycle = [("STAGED", "PENDING_USER_ACTION"), ("ACTIVE", "SUSPENDED"), ("SUSPENDED", "ACTIVE"),
                 ("ACTIVE", "DEACTIVATED"), ("DEACTIVATED", "DELETED"), (rng.choice(["ACTIVE", "SUSPENDED"]),
                                                                         "DELETED"),
                 ("STAGED", "SUSPENDED"), ("DEACTIVATED", "ACTIVE"), ("LOCKED_OUT", "ACTIVE")]
    reqs = []
    for cur, to in lifecycle:
        f, l = next(names)
        reqs.append({"user": f"{f}.{l}@{dom}".lower(), "current": cur, "requested": to,
                     "apps": rng.sample(["Expense Portal", "Team Chat", "Vendor Wiki", "Benefits Link"], 3)})
    deact = next(r for r in reqs if r["requested"] == "DEACTIVATED")
    deact["apps"] = ["Expense Portal", "Team Chat", "Benefits Link"]
    rng.shuffle(reqs)
    for n, r in enumerate(reqs, 1):
        r["id"] = f"L{n:02d}"

    f, l = next(names)
    gone = f"{f}.{l}@{dom}".lower()
    f, l = next(names)
    paused = f"{f}.{l}@{dom}".lower()
    off = [{"user": gone, "status": "DEACTIVATED", "app": a} for a in
           ["Expense Portal", "Team Chat", "Vendor Wiki", "Legacy CRM", "Benefits Link"]]
    off.append({"user": gone, "status": "DEACTIVATED", "app": "Analytics Hub",
                "manually_deactivated_in_app": rng.choice([True, False])})
    off.append({"user": paused, "status": "SUSPENDED", "app": rng.choice(["Expense Portal", "Team Chat"])})
    rng.shuffle(off)
    for n, o in enumerate(off, 1):
        o["id"] = f"O{n:02d}"
    return {"_description": "Generated Okta mapping, lifecycle and offboarding scenario (fictional).",
            "company": "Larkspur Example Co", "okta_schema": okta_schema, "profile_sources": sources, "apps": apps,
            "users": users, "lifecycle_requests": reqs, "offboarding": off}
