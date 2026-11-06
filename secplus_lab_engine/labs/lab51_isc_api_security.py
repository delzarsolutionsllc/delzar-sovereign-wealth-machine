"""
Lab 51 — API Access, User Levels & Tenant Sign-In Security
==========================================================

SailPoint ISC objectives
------------------------
* 1.2  REST API, tenant authentication and security administration: how a
       script, a service or a web app gets an API token (personal access
       token, OAuth 2.0 client credentials, authorization code), scopes and
       least privilege, what each user level may do, and how the tenant's
       sign-in is secured (identity profile sign-in methods, pass-through
       authentication, SAML SSO, the emergency bypass, MFA, sessions).

Course mapping: SailPoint Identity Security Administrator objective 1.2
(primary); SailPoint Identity Security Engineer objectives 7.1 (API gateway,
authentication methods and user levels) and 6.2 (microservice architecture
and REST APIs).

How it works
------------
You are the security administrator of a SailPoint Identity Security Cloud
(ISC) tenant. Three parts, each deny by default (missing or unknown input
gives the safest outcome, with a reason saying so):

1. **API access requests**, rules in this order:
   (a) the task is missing or not in the task catalogue → DENY;
   (b) the integration type is missing or unknown → DENY;
   (c) a **web app** acting for the signed-in user → AUTHORIZATION_CODE, but
       only with a redirect URL (no redirect URL → DENY); each call then runs
       with the signed-in user's own user levels;
   (d) an unattended **service** → OAUTH_CLIENT_CREDENTIALS (an API client),
       unless the task needs a user context, or it searches identities while
       Data Segmentation is on: client-credentials tokens have no user, so most
       admin APIs answer 403. Then it needs a named user's PERSONAL_ACCESS_TOKEN
       (no named user → DENY);
   (e) a person's **script** → PERSONAL_ACCESS_TOKEN acting as that person;
   (f) a token that acts as a person is only issued when that person exists,
       is active and their user levels allow the task (part 2) → else DENY.
   Flags on any approved request: OVER_BROAD_SCOPE (sp:scopes:all where a
   narrower scope exists, or a manage scope for a read task), OUTLIVES_OWNER
   (the PAT owner leaves before the token expires), NO_EXPIRY (a PAT with no
   expiry date), STORE_SECRET_SECURELY (the client secret is not going to an
   approved vault). Every token is exchanged at the tenant's API host,
   ``https://{tenant}.api.identitynow.com/oauth/token``.
2. **User level checks**, in this order: unknown or inactive person →
   DENIED; unknown action → DENIED; unknown user levels grant nothing; an
   incompatible combination (e.g. Role Admin + Source Sub-Admin) → DENIED
   until fixed; a full user level listed for the action → ALLOWED; a
   Sub-Admin level → ALLOWED only when every source involved is tied to a
   governance group the person belongs to; granting user levels is Admin
   only unless the tenant lets Role and Source Admins do it; otherwise
   DENIED.
3. **Sign-in security review**, one outcome per item: identity profiles
   (unknown sign-in method → SIGNIN_METHOD_UNKNOWN; pass-through to a source
   that is missing, unhealthy, never aggregated or not a directory type →
   PTA_SOURCE_UNHEALTHY), elevated users (any user level with the Admin
   menu, unknown levels included) without a registered TOTP authenticator →
   ADMIN_WITHOUT_MFA, SAML SSO with fewer than two active, TOTP-registered
   Admins documented for the ``?prompt=true`` bypass → SSO_WITHOUT_BYPASS_PLAN,
   session settings over the company limits → SESSION_TOO_LONG; else OK.

Simplifications: which tasks need a user context and most narrow scope
names are training values that follow SailPoint's idn:<resource>:read|manage
pattern (check each endpoint's API specification); the two-emergency-admin
rule, approved secret stores and session limits are company policy, not
SailPoint numbers. See the policy note.

Run it
------
    python main.py --course spadmin lab 51
    python main.py --course speng lab 51
"""

from __future__ import annotations

from dataclasses import dataclass, field

TITLE = "Lab 51 — API Access, User Levels & Tenant Sign-In Security"
OBJECTIVES = "SailPoint ISC 1.2 REST API, tenant authentication and security administration"
COURSES = ("spadmin", "speng")
SECTION = "isc_api_security"

METHODS = ["PERSONAL_ACCESS_TOKEN", "OAUTH_CLIENT_CREDENTIALS", "AUTHORIZATION_CODE", "DENY"]
FLAGS = ["OVER_BROAD_SCOPE", "OUTLIVES_OWNER", "NO_EXPIRY", "STORE_SECRET_SECURELY"]
LEVEL_OUTCOMES = ["ALLOWED", "DENIED"]
SIGNIN = ["OK", "ADMIN_WITHOUT_MFA", "PTA_SOURCE_UNHEALTHY", "SSO_WITHOUT_BYPASS_PLAN", "SESSION_TOO_LONG",
          "SIGNIN_METHOD_UNKNOWN"]
ACTIVE = ("active", "leaving")


@dataclass
class ApiResult:
    id: str
    task: str
    method: str
    acts_as: str = ""
    scope: str = ""
    token_url: str = ""
    flags: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


@dataclass
class LevelResult:
    id: str
    person: str
    action: str
    outcome: str
    granted_by: str = ""
    reasons: list[str] = field(default_factory=list)


@dataclass
class SignInResult:
    id: str
    kind: str
    outcome: str
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Part 2 — user level checks (used by part 1 too)
# --------------------------------------------------------------------------- #
def _people(data: dict) -> dict:
    return {p.get("id"): p for p in data.get("people", []) if p.get("id")}


def _source_groups(data: dict) -> dict:
    return {s.get("id"): s.get("governance_group") for s in data.get("sources", []) if s.get("id")}


def _role_sources(data: dict) -> dict:
    return {r.get("id"): list(r.get("sources") or []) for r in data.get("roles", []) if r.get("id")}


def check_action(person: dict | None, action: str | None, target: dict, data: dict, cfg: dict,
                 rid: str = "") -> LevelResult:
    """Decide ALLOWED or DENIED for one admin action. ``target`` may hold ``source`` or ``role``."""
    pid = (person or {}).get("id", "?")
    res = LevelResult(id=rid, person=pid, action=action or "?", outcome="DENIED")
    if not person:
        res.reasons.append("person not found: deny by default")
        return res
    if person.get("status") not in ACTIVE:
        res.reasons.append(f"{pid} is not active (status {person.get('status') or 'missing'}): deny by default")
        return res
    spec = cfg["actions"].get(action or "")
    if not spec:
        res.reasons.append(f"action '{action}' is unknown: deny by default")
        return res
    known = cfg["user_levels"]
    levels = list(person.get("user_levels") or [])
    unknown = [lv for lv in levels if lv not in known]
    levels = [lv for lv in levels if lv in known]
    if unknown:
        res.reasons.append(f"unknown user level {', '.join(unknown)} grants nothing")
    for a, b in cfg["incompatible_levels"]:
        if a in levels and b in levels:
            res.reasons.append(f"{known[a]} and {known[b]} cannot be assigned together: fix the assignment "
                               f"before any admin action (deny by default)")
            return res
    allowed = spec["levels"]
    if "ANY_IDENTITY" in allowed:
        res.outcome, res.granted_by = "ALLOWED", "any identity"
        res.reasons.append(f"every identity may {spec['label']}")
        return res
    if action == "grant_user_levels" and data.get("tenant", {}).get("non_org_admins_manage_levels"):
        allowed = allowed + cfg["non_org_admin_level_grantors"]
    full = [lv for lv in levels if lv in allowed and lv not in cfg["sub_admin_levels"]]
    if full:
        res.outcome, res.granted_by = "ALLOWED", full[0]
        res.reasons.append(f"{known[full[0]]} may {spec['label']}")
        return res
    subs = [lv for lv in levels if lv in allowed and lv in cfg["sub_admin_levels"]]
    if subs:
        lv = subs[0]
        scope_kind = cfg["scoped_actions"].get(action)
        groups = set(person.get("governance_groups") or [])
        if scope_kind is None:      # e.g. Search: Sub-Admins search all of the organization's data
            res.outcome, res.granted_by = "ALLOWED", lv
            res.reasons.append(f"{known[lv]} may {spec['label']} (not limited to governance groups)")
            return res
        if scope_kind == "source":
            sources = [target.get("source")] if target.get("source") else []
        else:
            role = target.get("role")
            sources = _role_sources(data).get(role) if role else None
            if role and sources is None:
                res.reasons.append(f"role {role} is unknown: deny by default")
                return res
        if not sources:
            res.reasons.append(f"{known[lv]} needs a known source to check governance groups: deny by default")
            return res
        sg = _source_groups(data)
        outside = [s for s in sources if not sg.get(s) or sg.get(s) not in groups]
        if outside:
            res.reasons.append(f"{known[lv]} is limited to its governance groups ({', '.join(sorted(groups)) or 'none'}); "
                               f"{', '.join(outside)} is not tied to one of them")
            return res
        res.outcome, res.granted_by = "ALLOWED", lv
        res.reasons.append(f"{known[lv]} may {spec['label']} on {', '.join(sources)} through governance group "
                           f"{', '.join(sorted({sg[s] for s in sources}))}")
        return res
    names = ", ".join(known.get(lv, lv) for lv in allowed)
    held = ", ".join(known[lv] for lv in levels) or "no admin user level"
    res.reasons.append(f"{pid} holds {held}; only {names} may {spec['label']}")
    return res


def check_actions(data: dict, cfg: dict) -> list[LevelResult]:
    people = _people(data)
    return [check_action(people.get(a.get("person")), a.get("action"), a, data, cfg, a.get("id", "?"))
            for a in data.get("admin_actions", [])]


# --------------------------------------------------------------------------- #
# Part 1 — API access requests
# --------------------------------------------------------------------------- #
def choose_api_method(req: dict, data: dict, cfg: dict) -> ApiResult:
    tenant = data.get("tenant", {})
    tname = tenant.get("tenant") or "{tenant}"
    res = ApiResult(id=req.get("id", "?"), task=req.get("task") or "?", method="DENY",
                    token_url=cfg["token_url"].format(tenant=tname))
    task = cfg["api_tasks"].get(req.get("task") or "")
    if not task:
        res.reasons.append(f"task '{req.get('task')}' is not in the task catalogue: deny by default")
        return res
    res.scope = task["scope"]
    kind = req.get("integration_type")
    if kind not in cfg["integration_types"]:
        res.reasons.append(f"integration type '{kind}' is unknown: deny by default")
        return res
    if kind == "web_app":
        if not req.get("redirect_url"):
            res.reasons.append("the authorization code flow needs a registered redirect URL: deny until one is given")
            return res
        res.method = "AUTHORIZATION_CODE"
        res.reasons.append("a web app acting for the signed-in user uses the authorization code grant; each call "
                           "runs with that user's own user levels")
        res.reasons.append(f"users sign in at {cfg['authorize_url'].format(tenant=tname)}; the app exchanges the "
                           f"code at {res.token_url}")
    else:
        if kind == "service":
            segmented = task["segmented"] and tenant.get("data_segmentation")
            if not task["user_context"] and not segmented:
                res.method = "OAUTH_CLIENT_CREDENTIALS"
                res.reasons.append("an unattended service without a user uses an API client with the client "
                                   "credentials grant (an Admin creates it under Security Settings > API Management)")
                res.reasons.append(f"the service exchanges its client ID and secret at {res.token_url}")
            else:
                why = ("Data Segmentation is on and API clients have no user to segment by" if segmented else
                       "the task needs a user context and client-credentials tokens have none (403)")
                res.reasons.append(why)
                if not req.get("acts_as"):
                    res.reasons.append("no named user is given for a personal access token: deny by default")
                    return res
        if res.method == "DENY":
            pid = req.get("acts_as") or req.get("requester")
            person = _people(data).get(pid)
            lv = check_action(person, task["action"], req, data, cfg)
            if lv.outcome != "ALLOWED":
                res.acts_as = pid or ""
                res.reasons.append(f"a token acting as {pid} cannot {task['label']}: " + "; ".join(lv.reasons))
                return res
            res.method, res.acts_as = "PERSONAL_ACCESS_TOKEN", pid
            res.reasons.append(f"a personal access token acting as {pid}: {lv.reasons[-1]}")
            res.reasons.append(f"the script exchanges the PAT's client ID and secret at {res.token_url}")
    # Flags on approved requests.
    asked = list(req.get("scopes") or [])
    narrow = task["scope"]
    if cfg["broad_scope"] in asked and narrow != cfg["broad_scope"]:
        res.flags.append("OVER_BROAD_SCOPE")
        res.reasons.append(f"{cfg['broad_scope']} asked where {narrow} is enough (least privilege)")
    elif narrow.endswith(":read") and any(s.endswith(":manage") for s in asked):
        res.flags.append("OVER_BROAD_SCOPE")
        res.reasons.append(f"a manage scope asked for a read-only task; {narrow} is enough")
    if not asked:
        res.reasons.append(f"no scope stated: grant {narrow} (a PAT created through the API with no scope gets "
                           f"{cfg['broad_scope']})")
    if res.method == "PERSONAL_ACCESS_TOKEN":
        owner = _people(data).get(res.acts_as, {})
        expiry = req.get("expiry_days")
        leave = owner.get("leave_in_days")
        if expiry is None:
            res.flags.append("NO_EXPIRY")
            res.reasons.append("the PAT has no expiry date; set one (the default is 6 months)")
        if owner.get("status") == "leaving" and (leave is None or expiry is None or expiry > leave):
            res.flags.append("OUTLIVES_OWNER")
            res.reasons.append(f"the owner {res.acts_as} leaves in {leave if leave is not None else '?'} days but "
                               f"the token would still work: move it to a new owner or an API client")
    public = res.method == "AUTHORIZATION_CODE" and req.get("public_client")
    if not public and req.get("secret_storage") not in cfg["approved_secret_stores"]:
        res.flags.append("STORE_SECRET_SECURELY")
        res.reasons.append(f"the client secret goes to '{req.get('secret_storage') or 'unstated'}'; keep it in an "
                           f"approved vault (it is shown only once)")
    return res


def review_requests(data: dict, cfg: dict) -> list[ApiResult]:
    return [choose_api_method(r, data, cfg) for r in data.get("api_requests", [])]


# --------------------------------------------------------------------------- #
# Part 3 — sign-in security review
# --------------------------------------------------------------------------- #
def review_profile(profile: dict, data: dict, cfg: dict) -> SignInResult:
    res = SignInResult(id=profile.get("id", "?"), kind="identity profile", outcome="OK")
    method = profile.get("sign_in_method")
    if method not in cfg["sign_in_methods"]:
        res.outcome = "SIGNIN_METHOD_UNKNOWN"
        res.reasons.append(f"sign-in method '{method}' is missing or unknown: nobody on this profile can sign in "
                           f"safely (deny by default)")
        return res
    if method == "PASS_THROUGH":
        src = {s.get("id"): s for s in data.get("sources", [])}.get(profile.get("auth_source"))
        problem = None
        if not src:
            problem = f"authentication source '{profile.get('auth_source')}' is missing"
        elif src.get("type") not in cfg["pta_source_types"]:
            problem = f"{src['id']} is a {src.get('type')} source, which cannot do pass-through authentication"
        elif not src.get("aggregated"):
            problem = f"{src['id']} has never been aggregated, so its accounts cannot sign in"
        elif src.get("healthy") is not True:
            problem = f"{src['id']} is not healthy, so pass-through sign-in fails"
        if problem:
            res.outcome = "PTA_SOURCE_UNHEALTHY"
            res.reasons.append(problem)
            return res
        res.reasons.append(f"pass-through sign-in against healthy directory source {src['id']}")
        return res
    res.reasons.append(cfg["sign_in_methods"][method])
    return res


def review_elevated(person: dict, cfg: dict) -> SignInResult:
    res = SignInResult(id=person.get("id", "?"), kind="elevated user", outcome="OK")
    if person.get("totp_registered") is not True:
        res.outcome = "ADMIN_WITHOUT_MFA"
        res.reasons.append("an elevated user (a level with the Admin menu) has no TOTP authenticator registered")
        return res
    res.reasons.append("elevated user with a registered TOTP authenticator")
    return res


def review_sso(sso: dict, data: dict, cfg: dict) -> SignInResult:
    res = SignInResult(id="SSO", kind="SAML SSO", outcome="OK")
    if not sso.get("enabled"):
        res.reasons.append("SSO is not enabled; sign-in follows the identity profiles")
        return res
    people = _people(data)
    ok = [p for p in sso.get("emergency_admins") or []
          if people.get(p, {}).get("status") in ACTIVE and "ORG_ADMIN" in (people[p].get("user_levels") or [])
          and people[p].get("totp_registered") is True]
    need = cfg["min_emergency_admins"]
    if len(ok) < need or not sso.get("bypass_documented"):
        res.outcome = "SSO_WITHOUT_BYPASS_PLAN"
        if len(ok) < need:
            res.reasons.append(f"only {len(ok)} active Admin(s) with TOTP can use the {cfg['bypass_url']} bypass; "
                               f"{need} are needed if the identity provider is down")
        if not sso.get("bypass_documented"):
            res.reasons.append("the ?prompt=true bypass procedure is not documented")
        return res
    res.reasons.append(f"ISC is the SAML service provider; {len(ok)} Admins with TOTP can bypass with ?prompt=true")
    return res


def review_session(session: dict, cfg: dict) -> SignInResult:
    res = SignInResult(id="SESSION", kind="session settings", outcome="OK")
    hours, idle = session.get("max_session_hours"), session.get("idle_minutes")
    bad = []
    if not isinstance(hours, (int, float)) or hours > cfg["max_session_hours"]:
        bad.append(f"maximum session {hours if hours is not None else 'not set'} h is over {cfg['max_session_hours']} h")
    if not isinstance(idle, (int, float)) or idle > cfg["max_idle_minutes"]:
        bad.append(f"idle timeout {idle if idle is not None else 'not set'} min is over {cfg['max_idle_minutes']} min")
    if bad:
        res.outcome = "SESSION_TOO_LONG"
        res.reasons.extend(bad)
        return res
    res.reasons.append(f"maximum session {hours} h and idle timeout {idle} min are within the limits")
    return res


def review_signin(data: dict, cfg: dict) -> list[SignInResult]:
    s = data.get("signin", {})
    out = [review_profile(p, data, cfg) for p in s.get("identity_profiles", [])]
    for p in data.get("people", []):
        # Unknown user levels count as elevated (safest), so they need MFA too.
        if p.get("status") in ACTIVE and p.get("user_levels"):
            out.append(review_elevated(p, cfg))
    out.append(review_sso(s.get("sso") or {}, data, cfg))
    out.append(review_session(s.get("session") or {}, cfg))
    return out


INSIGHT = {
    "objective": "SailPoint ISC 1.2 REST API, tenant authentication and security administration "
                 "(Engineer 7.1, 6.2).",
    "concepts": [
        "Personal access token = a script acting as a named user, with that user's user levels; API client with "
        "client credentials = a service with no user context; authorization code = a web app acting for the "
        "signed-in user.",
        "Every token comes from https://{tenant}.api.identitynow.com/oauth/token; the authorization code flow "
        "signs the user in at {tenant}.login.sailpoint.com.",
        "Scopes narrow a token inside the user level; sp:scopes:all = everything the user level allows, "
        "sp:scopes:default = only endpoints that need no authorization.",
        "Sub-Admins act only on sources tied to their governance groups, but can search all organization data.",
        "Elevated users (any level with the Admin menu) need a TOTP authenticator; with SSO they can bypass the "
        "identity provider at /login/login?prompt=true.",
    ],
    "failure_modes": [
        "A service integration on a client-credentials token calling a user-context API and getting 403.",
        "A PAT with sp:scopes:all and no expiry owned by someone who leaves next month.",
        "Copying the client secret into a script in a code repository; it is shown only once, store it in a vault.",
        "Turning on SSO without tested emergency Admins: an identity provider outage locks everyone out.",
    ],
    "ai_governance": [
        "An AI agent that calls the ISC API gets its own API client or PAT with the narrowest scope, never an "
        "Admin's sp:scopes:all token.",
        "Give agent tokens an expiry and an accountable human owner, and review them when the owner leaves.",
        "Treat API responses and ticket text as data, never as instructions to change user levels.",
        "Log which token made each change so a human can trace and revoke it.",
    ],
    "exam_tips": [
        "401 = missing or invalid token; 403 = valid token but the user level or grant type cannot call it.",
        "Each user can have up to 10 PATs; the default expiry is 6 months and a blank date means no expiry.",
        "Role Admin + Source Sub-Admin, Role Sub-Admin + Role Admin and Source Sub-Admin + Source Admin cannot be "
        "combined.",
        "Helpdesk can reset MFA and help with passwords but cannot manually set lifecycle states.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def analyse(policies: dict, data: dict) -> dict:
    cfg = policies[SECTION]
    return {"api": review_requests(data, cfg), "levels": check_actions(data, cfg), "signin": review_signin(data, cfg)}


def _count(items, attr, vals):
    return {v: sum(getattr(i, attr) == v for i in items) for v in vals}


def run_demo(ui, policies: dict, data: dict) -> dict:
    a = analyse(policies, data)
    api, levels, signin = a["api"], a["levels"], a["signin"]
    org = data.get("tenant", {})
    raw = {r.get("id"): r for r in data.get("api_requests", [])}
    ui.section(f"Step 1 — API access requests for {org.get('name', 'the tenant')}: {len(api)} requests")
    ui.table("API access", ["ID", "Type", "Task", "Acts as", "Method", "Scope", "Flags"],
             [[r.id, raw.get(r.id, {}).get("integration_type", "?"), r.task, r.acts_as or "-", r.method,
               r.scope or "-", ", ".join(r.flags) or "-"] for r in api])
    for r in api:
        ui.bullet(f"{r.id} → {r.method}: " + "; ".join(r.reasons),
                  style="red" if r.method == "DENY" else ("yellow" if r.flags else None))
    ui.section("Step 2 — User level checks")
    ui.table("Admin actions", ["ID", "Person", "Action", "Outcome", "Granted by"],
             [[r.id, r.person, r.action, r.outcome, r.granted_by or "-"] for r in levels])
    for r in levels:
        ui.bullet(f"{r.id} → {r.outcome}: " + "; ".join(r.reasons), style="red" if r.outcome == "DENIED" else None)
    ui.section("Step 3 — Tenant sign-in security review")
    ui.table("Sign-in review", ["Item", "Kind", "Outcome"], [[r.id, r.kind, r.outcome] for r in signin])
    for r in signin:
        if r.outcome != "OK":
            ui.bullet(f"{r.id} → {r.outcome}: " + "; ".join(r.reasons), style="yellow")
    metrics = {"requests": len(api), "methods": _count(api, "method", METHODS),
               "flags": {f: sum(f in r.flags for r in api) for f in FLAGS},
               "actions": _count(levels, "outcome", LEVEL_OUTCOMES), "signin_items": len(signin),
               "signin": _count(signin, "outcome", SIGNIN)}
    m, ac, si = metrics["methods"], metrics["actions"], metrics["signin"]
    ui.print(f"{metrics['requests']} API requests: {m['PERSONAL_ACCESS_TOKEN']} PAT, "
             f"{m['OAUTH_CLIENT_CREDENTIALS']} client credentials, {m['AUTHORIZATION_CODE']} authorization code, "
             f"{m['DENY']} denied · {sum(bool(r.flags) for r in api)} flagged · actions: {ac['ALLOWED']} allowed, "
             f"{ac['DENIED']} denied · sign-in: {si['OK']} OK, {metrics['signin_items'] - si['OK']} findings")
    ui.insight(INSIGHT)
    return {"api": {r.id: r.method for r in api}, "flags": {r.id: list(r.flags) for r in api},
            "actions": {r.id: r.outcome for r in levels}, "signin": {r.id: r.outcome for r in signin},
            "metrics": metrics}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies[SECTION]
    a = analyse(policies, data)
    people = _people(data)
    raw_r = {r.get("id"): r for r in data.get("api_requests", [])}
    raw_a = {r.get("id"): r for r in data.get("admin_actions", [])}
    qs: list = []
    obj = "1.2"

    def who(pid):
        p = people.get(pid) or {}
        return f"{pid} ({', '.join(p.get('user_levels') or []) or 'no user level'}; status {p.get('status', '?')})"

    for r in a["api"]:
        src = {k: v for k, v in raw_r.get(r.id, {}).items() if k not in ("id", "description")}
        qs.append(Question(prompt=f"{r.id}: which way should this caller get its API access?",
                           context=f"{raw_r.get(r.id, {}).get('description', '')} request={src}",
                           choices=METHODS, answer=r.method, explanation="; ".join(r.reasons), objective=obj))
    for r in a["api"]:
        if r.flags:
            ans = r.flags[0]
            src = {k: v for k, v in raw_r.get(r.id, {}).items() if k not in ("id", "description")}
            qs.append(Question(prompt=f"{r.id} is approved as {r.method}. Which issue is flagged first?",
                               context=f"owner={who(r.acts_as) if r.acts_as else 'none'}; request={src}",
                               choices=choices_with(ans, FLAGS + ["NO_ISSUE"], exclude=r.flags[1:], key=r.id),
                               answer=ans, explanation="; ".join(r.reasons), objective=obj))
    for r in a["levels"]:
        src = raw_a.get(r.id, {})
        target = src.get("source") or src.get("role")
        qs.append(Question(prompt=f"{r.id}: may {r.person} {cfg['actions'].get(r.action, {}).get('label', r.action)}"
                                  f"{' on ' + target if target else ''}?",
                           context=f"person={who(r.person)}; governance groups="
                                   f"{(people.get(r.person) or {}).get('governance_groups') or []}",
                           choices=LEVEL_OUTCOMES, answer=r.outcome, explanation="; ".join(r.reasons), objective=obj))
    seen = set()
    for r in a["signin"]:
        key = (r.kind, r.outcome)
        if key in seen:
            continue
        seen.add(key)
        qs.append(Question(prompt=f"Sign-in review, {r.kind} {r.id}: what is the finding?",
                           choices=choices_with(r.outcome, SIGNIN, key=r.id), answer=r.outcome,
                           explanation="; ".join(r.reasons), objective=obj,
                           context=f"{r.kind} {r.id}"))
    tname = data.get("tenant", {}).get("tenant", "acme")
    url = cfg["token_url"].format(tenant=tname)
    qs.append(Question(prompt="Where does a script exchange its client ID and secret for an access token?",
                       choices=sorted([url, f"https://{tname}.identitynow.com/login/login?prompt=true",
                                       f"https://{tname}.login.sailpoint.com/oauth/token",
                                       f"https://{tname}.identitynow.com/api/token"]),
                       answer=url, explanation="the token endpoint is on the tenant's API host", objective=obj))
    qs.append(Question(prompt="A service calls an admin API with a client-credentials token and gets 403 Forbidden. "
                              "Why?",
                       choices=["the token has no user context, and the API expects a user",
                                "the token has expired",
                                "the Authorization header is missing",
                                "client credentials tokens only work from a virtual appliance"],
                       answer="the token has no user context, and the API expects a user",
                       explanation="401 = missing or invalid token; 403 = valid token without the rights or user "
                                   "context the endpoint needs", objective=obj))
    qs.append(Question(prompt="The SAML identity provider is down. How does an Admin sign in to ISC?",
                       choices=sorted([cfg["bypass_url"].format(tenant=tname),
                                       "ask SailPoint Support to disable SSO",
                                       "sign in with a personal access token in the browser",
                                       "use any end user's password at the IdP"]),
                       answer=cfg["bypass_url"].format(tenant=tname),
                       explanation=cfg["concepts"]["emergency bypass"], objective=obj))
    qs.append(Question(prompt="What does sp:scopes:all grant a personal access token?",
                       choices=["every right the owner's user levels allow, and more if levels are added later",
                                "every API in the tenant, whatever the owner's user level",
                                "only endpoints that need no authorization",
                                "read-only access to every endpoint"],
                       answer="every right the owner's user levels allow, and more if levels are added later",
                       explanation="scopes never go beyond the user level; sp:scopes:default is the least-privileged "
                                   "scope", objective=obj))
    qs.append(Question(prompt="A Source Sub-Admin runs Search. Which data can they see?",
                       choices=["all of the organization's data",
                                "only sources tied to their governance groups",
                                "only their own identity",
                                "nothing: Sub-Admins cannot use Search"],
                       answer="all of the organization's data",
                       explanation="Sub-Admins can search all organization data; their edit rights are limited to "
                                   "their governance groups", objective=obj))
    for term in ("personal access token", "client credentials grant", "authorization code grant", "Sub-Admin"):
        qs.append(Question(prompt=f"Which term is this? \"{cfg['concepts'][term]}\"",
                           choices=choices_with(term, cfg["concepts"], key=term), answer=term,
                           explanation=cfg["concepts"][term], objective=obj))
    return qs


# --------------------------------------------------------------------------- #
# Scenario generator
# --------------------------------------------------------------------------- #
COMPANIES = [("Larkspur Example Manufacturing", "larkspur-example"), ("Tidewater Example Bank", "tidewater-example"),
             ("Brightfield Example Health", "brightfield-example"), ("Oakhollow Example Retail", "oakhollow-example")]
FIRST = ["Amara", "Bram", "Chen", "Dana", "Eli", "Farah", "Gus", "Hana", "Ivo", "Jo", "Kai", "Lena", "Mira", "Nils",
         "Omar", "Priya"]
LAST = ["Osei", "Kowalski", "Liu", "Ruiz", "Novak", "Haddad", "Moreno", "Sato", "Petrov", "Whitfield", "Brennan",
        "Fischer", "Lund", "Varga"]


def generate_scenario(rng, policies: dict) -> dict:
    company, tname = rng.choice(COMPANIES)
    names = rng.sample(FIRST, 12)
    ids = [f"P{i:02d}" for i in range(1, 13)]
    g_hr, g_fin, g_it = rng.choice([("GG-HR", "GG-FIN", "GG-IT"), ("GG-PEOPLE", "GG-FINANCE", "GG-INFRA")])

    def person(i, levels, groups=(), totp=True, status="active", leave=None):
        return {"id": ids[i], "name": f"{names[i]} {rng.choice(LAST)}", "user_levels": list(levels),
                "governance_groups": list(groups), "status": status, "leave_in_days": leave,
                "totp_registered": totp}

    leave = rng.randint(5, 40)
    people = [person(0, ["ORG_ADMIN"]), person(1, ["ORG_ADMIN"]), person(2, ["SOURCE_ADMIN"], totp=False),
              person(3, ["SOURCE_SUBADMIN"], [g_hr]), person(4, ["ROLE_SUBADMIN"], [g_fin]),
              person(5, ["HELPDESK"]), person(6, ["CERT_ADMIN", "REPORT_ADMIN"]),
              person(7, ["REPORT_ADMIN"], status="leaving", leave=leave),
              person(8, ["ROLE_ADMIN", "SOURCE_SUBADMIN"], [g_it]),
              person(9, [rng.choice(["SUPER_USER", "TENANT_OWNER", "ROOT"])], totp=None),
              person(10, []), person(11, ["ORG_ADMIN"], status="inactive")]
    sources = [{"id": "SRC-AD", "name": "Corporate Active Directory", "type": rng.choice(["Active Directory",
                                                                                         "Microsoft Entra ID"]),
                "governance_group": g_it, "healthy": True, "aggregated": True},
               {"id": "SRC-LDAP", "name": "Plant directory", "type": "OpenLDAP", "governance_group": g_it,
                "healthy": rng.choice([False, None]), "aggregated": True},
               {"id": "SRC-HR", "name": "HR system", "type": rng.choice(["Workday", "SAP SuccessFactors"]),
                "governance_group": g_hr, "healthy": True, "aggregated": True},
               {"id": "SRC-ERP", "name": "Finance ERP", "type": "SAP", "governance_group": g_fin, "healthy": True,
                "aggregated": True},
               {"id": "SRC-ITSM", "name": "Service desk", "type": "ServiceNow", "governance_group": g_hr,
                "healthy": True, "aggregated": True}]
    roles = [{"id": "ROLE-FIN-AP", "sources": ["SRC-ERP"]}, {"id": "ROLE-FIN-HR", "sources": ["SRC-ERP", "SRC-HR"]}]
    p = ids
    exp = rng.choice([30, 60, 90])
    api = [
        {"id": "R1", "integration_type": "script", "requester": p[0], "task": "read_identities",
         "scopes": ["sp:scopes:all"], "expiry_days": exp, "secret_storage": "vault"},
        {"id": "R2", "integration_type": "service", "requester": p[1], "task": "trigger_aggregation",
         "scopes": ["idn:sources:manage"], "secret_storage": "secrets_manager"},
        {"id": "R3", "integration_type": "service", "requester": p[1], "acts_as": p[5], "task": "read_identities",
         "scopes": ["idn:identity:read"], "expiry_days": exp, "secret_storage": "plaintext_repo"},
        {"id": "R4", "integration_type": "web_app", "requester": p[1], "task": "submit_access_request",
         "redirect_url": f"https://portal.{tname}.example/callback", "scopes": ["idn:access-request:manage"],
         "secret_storage": "vault"},
        {"id": "R5", "integration_type": "script", "requester": p[7], "task": "download_reports",
         "scopes": ["sp:scopes:all"], "expiry_days": None, "secret_storage": "vault"},
        {"id": "R6", "integration_type": "script", "requester": p[10], "task": "read_identities",
         "scopes": ["idn:identity:read"], "expiry_days": exp, "secret_storage": "vault"},
        {"id": "R7", "integration_type": "script", "requester": p[0],
         "task": rng.choice(["export_passwords", "delete_tenant"]), "secret_storage": "vault"},
        {"id": "R8", "integration_type": "script", "requester": p[3], "task": "edit_source", "source": "SRC-ERP",
         "scopes": ["idn:sources:manage"], "expiry_days": exp, "secret_storage": "vault"},
        {"id": "R9", "integration_type": "script", "requester": p[3], "task": "edit_source", "source": "SRC-HR",
         "scopes": ["idn:sources:manage"], "expiry_days": exp, "secret_storage": "vault"},
        {"id": "R10", "integration_type": "web_app", "requester": p[1], "task": "submit_access_request",
         "scopes": ["idn:access-request:manage"], "secret_storage": "vault"},
        {"id": "R11", "integration_type": "service", "requester": p[1], "task": "read_sources",
         "scopes": ["idn:sources:manage"], "secret_storage": "vault"},
        {"id": "R12", "integration_type": rng.choice(["mobile", "desktop"]), "requester": p[0], "task": "read_sources",
         "secret_storage": "vault"},
    ]
    actions = [
        {"id": "A1", "person": p[3], "action": "edit_source", "source": "SRC-HR"},
        {"id": "A2", "person": p[3], "action": "edit_source", "source": "SRC-ERP"},
        {"id": "A3", "person": p[4], "action": "edit_role", "role": "ROLE-FIN-AP"},
        {"id": "A4", "person": p[4], "action": "edit_role", "role": "ROLE-FIN-HR"},
        {"id": "A5", "person": p[4], "action": "role_discovery"},
        {"id": "A6", "person": p[5], "action": "reset_mfa"},
        {"id": "A7", "person": p[5], "action": "set_lifecycle_state"},
        {"id": "A8", "person": p[6], "action": "manage_campaigns"},
        {"id": "A9", "person": p[7], "action": "search"},
        {"id": "A10", "person": p[8], "action": "edit_role", "role": "ROLE-FIN-AP"},
        {"id": "A11", "person": p[9], "action": "security_settings"},
        {"id": "A12", "person": p[2], "action": "grant_user_levels"},
        {"id": "A13", "person": p[3], "action": "search"},
        {"id": "A14", "person": p[1], "action": "manage_virtual_appliances"},
        {"id": "A15", "person": p[0], "action": rng.choice(["delete_tenant", "bypass_audit"])},
    ]
    rng.shuffle(actions)
    profiles = [{"id": "IP-EMP", "name": "Employees", "sign_in_method": "PASS_THROUGH", "auth_source": "SRC-AD"},
                {"id": "IP-PLANT", "name": "Plant workers", "sign_in_method": "PASS_THROUGH",
                 "auth_source": "SRC-LDAP"},
                {"id": "IP-CONTRACT", "name": "Contractors", "sign_in_method": "PASS_THROUGH",
                 "auth_source": "SRC-HR"},
                {"id": "IP-EXEC", "name": "Executives", "sign_in_method": "MFA"},
                {"id": "IP-NE", "name": "Non-employees", "sign_in_method": rng.choice([None, "MAGIC_LINK"])},
                {"id": "IP-SVC", "name": "Service desk", "sign_in_method": "USERNAME_PASSWORD"}]
    return {"_description": f"Generated scenario for {company} (fictional).",
            "tenant": {"name": company, "tenant": tname, "data_segmentation": True,
                       "non_org_admins_manage_levels": False},
            "people": people, "sources": sources, "roles": roles, "api_requests": api, "admin_actions": actions,
            "signin": {"identity_profiles": profiles,
                       "sso": {"enabled": True, "emergency_admins": [p[0], p[11]], "bypass_documented": True},
                       "session": {"max_session_hours": rng.choice([16, 24]),
                                   "idle_minutes": rng.choice([45, 60, 90])}}}
