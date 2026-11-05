"""
Lab 38 — OIN App Integration: SAML SSO, Assignments & Provisioning
==================================================================

Okta Professional objectives
----------------------------
* 2.1  SSO app integrations from the OIN (Okta Integration Network): choosing
       SAML, OIDC (OpenID Connect), SWA (Secure Web Authentication) or a
       Bookmark app, and configuring a SAML 2.0 integration.
* 2.2  Provisioning and app assignments: assigning users directly or through a
       group, and the To App provisioning features.

How it works
------------
You are the Okta administrator at a small company. App owners send requests,
users report failed sign-ins, and HR changes trigger provisioning.

Part 1, the protocol chooser. Each app request lists the sign-on methods the
app supports, its type and whether it has a login form. Rules, in order:

1. Missing or unknown app type → NEEDS_REVIEW (nothing is guessed).
2. The app needs no sign-in at all (a link on the dashboard) → BOOKMARK.
3. SPA, native or mobile app that supports OIDC → OIDC (SAML is a
   browser-redirect protocol and fits these apps poorly).
4. The app supports SAML 2.0 → SAML (federation beats a vaulted password).
5. The app supports OIDC → OIDC.
6. The app has only a login form → SWA (password vaulting).
7. Otherwise → NEEDS_REVIEW. Unknown protocol names are ignored, with a reason.

Part 2, the SAML configuration checker. A sign-in attempt (IdP-initiated from
the End-User Dashboard, or SP-initiated from the app) is checked in this order;
the first check that fails is the outcome, and every problem is listed:

1. APP_INACTIVE: the app integration is missing, inactive, or its status is unknown.
2. NOT_ASSIGNED: the user is unknown, not ACTIVE, or not assigned to the app
   directly or through a group. Unassigned users never get SSO, even when
   every other setting is right.
3. ACS_MISMATCH: the Single sign-on URL is not the SP's Assertion Consumer
   Service (ACS) URL, or (SP-initiated) the request asks for another ACS URL
   that the app is not allowed to request.
4. CERT_MISMATCH: the SP requires a signed assertion and Okta does not sign it
   (a missing setting counts as unsigned), or the SP holds a different Okta
   signing certificate (typical after a certificate rotation).
5. AUDIENCE_MISMATCH: the Audience URI is not the SP entity ID.
6. NAMEID_MISMATCH: unknown or wrong Name ID format, unknown Application
   username setting, or the value sent (for example the Okta username) is not
   an account the SP knows (it stores the email).
7. Otherwise SSO_SUCCESS.

Part 3, provisioning. Each change event gives the expected action (CREATE,
UPDATE, DEACTIVATE or NONE) and a verification status:

1. Unknown or inactive app → NONE, NEEDS_REVIEW.
2. API integration not enabled → NONE, MANUAL_ACTION (an admin must make the
   change in the app by hand).
3. Unknown event, or the To App feature it needs is missing from the settings
   → NONE, NEEDS_REVIEW (unknown settings fail closed: nothing is pushed).
4. assigned: user ACTIVE and assigned → CREATE if Create Users is on, else NONE,
   MANUAL_ACTION; no assignment found → NONE, NEEDS_REVIEW.
5. profile_updated: UPDATE if Update User Attributes is on, else NONE, MANUAL_ACTION.
6. password_changed: UPDATE (password push) if Sync Password is on, else NONE,
   VERIFIED (an SSO user needs no app password).
7. unassigned: still assigned another way → NONE, VERIFIED; else DEACTIVATE if
   Deactivate Users is on, else NONE, ACCESS_REMAINS.
8. okta_deactivated: DEACTIVATE if Deactivate Users is on, else NONE, ACCESS_REMAINS.

Run it
------
    python main.py --course okta lab 38
"""

from __future__ import annotations

from dataclasses import dataclass, field

TITLE = "Lab 38 — OIN App Integration: SAML SSO, Assignments & Provisioning"
OBJECTIVES = ("Okta Professional 2.1 SSO app integrations from the OIN (SAML, OIDC, SWA) · "
              "2.2 Provisioning and app assignments")
COURSES = ("okta",)
PROTOCOLS = ["SAML", "OIDC", "SWA", "BOOKMARK", "NEEDS_REVIEW"]
SSO_OUTCOMES = ["SSO_SUCCESS", "NOT_ASSIGNED", "ACS_MISMATCH", "AUDIENCE_MISMATCH", "NAMEID_MISMATCH",
                "CERT_MISMATCH", "APP_INACTIVE"]
ACTIONS = ["CREATE", "UPDATE", "DEACTIVATE", "NONE"]
VERIFICATIONS = ["VERIFIED", "MANUAL_ACTION", "ACCESS_REMAINS", "NEEDS_REVIEW"]
FLOWS = ("idp_initiated", "sp_initiated")


@dataclass
class ProtocolChoice:
    id: str
    app: str
    outcome: str
    rule: str
    reasons: list[str] = field(default_factory=list)


@dataclass
class SignInResult:
    id: str
    user: str
    app: str
    flow: str
    outcome: str
    problems: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


@dataclass
class ProvisioningResult:
    id: str
    user: str
    app: str
    event: str
    action: str
    verification: str
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Part 1 — protocol chooser
# --------------------------------------------------------------------------- #
def choose_protocol(req: dict, cfg: dict) -> ProtocolChoice:
    rules = {r["name"]: r["outcome"] for r in cfg["protocol_rules"]}
    rid, app = req.get("id", "?"), req.get("app", "?")
    supported = [str(p).lower() for p in req.get("protocols") or []]
    known = [p for p in supported if p in cfg["known_protocols"]]
    notes = [f"'{p}' is not a protocol this policy knows: ignored" for p in supported if p not in known]
    app_type = req.get("app_type")

    def out(rule: str, reason: str) -> ProtocolChoice:
        return ProtocolChoice(rid, app, rules[rule], rule, [reason] + notes)

    if app_type not in cfg["app_types"]:
        return out("unknown app type", f"app type '{app_type or 'not given'}' is missing or unknown: "
                   "review the requirements before creating an integration (deny by default)")
    if req.get("sign_in_required") is False:                     # missing = assume sign-in is needed
        return out("no sign-in needed", "the app needs no sign-in, only a link on the End-User Dashboard")
    if "oidc" in known and app_type in cfg["oidc_first_app_types"]:
        return out("SPA, native or mobile app with OIDC",
                   f"{app_type} app that supports OpenID Connect: use OIDC (SAML fits browser apps)")
    if "saml2" in known:
        extra = "; its login form is not needed, federation beats a vaulted password" if req.get("login_form") else ""
        return out("app supports SAML 2.0", "the app supports SAML 2.0 federation" + extra)
    if "oidc" in known:
        return out("app supports OIDC", "the app supports OpenID Connect")
    if req.get("login_form"):
        return out("login form only", "no federation support, only a login form: Okta vaults and fills "
                   "the credentials (SWA)")
    return out("no supported sign-on method", "no supported protocol and no login form: escalate to the app owner")


# --------------------------------------------------------------------------- #
# Part 2 — assignments and the SAML configuration checker
# --------------------------------------------------------------------------- #
def assignment_paths(login: str, app: dict, users: dict) -> list[str]:
    """How the user is assigned to the app: 'direct' and/or 'group:<name>' (status is not checked here)."""
    a = app.get("assignments", {})
    paths = ["direct"] if login in a.get("users", []) else []
    groups = (users.get(login) or {}).get("groups", [])
    paths += [f"group:{g}" for g in a.get("groups", []) if g in groups]
    return paths


def name_id_value(user: dict, setting: str | None) -> str | None:
    login, email = user.get("login", ""), user.get("email", "")
    return {"okta_username": login, "okta_username_prefix": login.split("@")[0],
            "email": email, "email_prefix": email.split("@")[0]}.get(setting or "")


def check_sign_in(attempt: dict, data: dict, cfg: dict) -> SignInResult:
    users = {u["login"]: u for u in data.get("users", [])}
    apps = data.get("apps", {})
    aid, login, app_id = attempt.get("id", "?"), attempt.get("user", "?"), attempt.get("app", "?")
    flow = attempt.get("flow") if attempt.get("flow") in FLOWS else "unknown"
    app = apps.get(app_id)
    problems: list[tuple[str, str]] = []
    ok: list[str] = []
    if app is None:
        problems.append(("APP_INACTIVE", f"no app integration '{app_id}' exists (fail closed)"))
        return SignInResult(aid, login, app_id, flow, "APP_INACTIVE", ["APP_INACTIVE"], [problems[0][1]])
    saml, sp = app.get("saml", {}), app.get("sp", {})
    if app.get("status") != cfg["active_app_status"]:
        problems.append(("APP_INACTIVE", f"app status is '{app.get('status')}': only ACTIVE integrations sign "
                         "users in (unknown status fails closed)"))
    user = users.get(login)
    paths = assignment_paths(login, app, users)
    if user is None:
        problems.append(("NOT_ASSIGNED", f"user {login} does not exist in Okta"))
    elif user.get("status") not in cfg["sso_user_statuses"]:
        problems.append(("NOT_ASSIGNED", f"user status is '{user.get('status')}', not ACTIVE: no SSO "
                         "(deactivation also removes app assignments)"))
    elif not paths:
        where = ("no tile on the End-User Dashboard; Okta shows 'not assigned to this application'"
                 if flow == "idp_initiated" else "Okta rejects the app's request: the user is not assigned")
        problems.append(("NOT_ASSIGNED", f"{login} is not assigned directly or through a group: {where}"))
    else:
        ok.append("assigned " + " and ".join(paths))
    acs = saml.get("sso_url")
    if not acs or acs != sp.get("acs_url"):
        problems.append(("ACS_MISMATCH", f"Single sign-on URL '{acs}' is not the SP's ACS URL '{sp.get('acs_url')}'"))
    elif flow == "sp_initiated" and attempt.get("request_acs") and attempt["request_acs"] != acs \
            and attempt["request_acs"] not in saml.get("other_requestable_sso_urls", []):
        problems.append(("ACS_MISMATCH", f"the SP's request asks for ACS '{attempt['request_acs']}', which the app "
                         "is not allowed to request"))
    else:
        ok.append("ACS URL matches")
    signed = saml.get("assertion_signed") is True                   # missing = unsigned (fail closed)
    if sp.get("requires_signed_assertion", True) and not signed:
        problems.append(("CERT_MISMATCH", "the SP requires a signed assertion but Assertion Signature is not "
                         "Signed: signature validation fails"))
    elif not saml.get("signing_cert") or saml.get("signing_cert") != sp.get("idp_cert"):
        problems.append(("CERT_MISMATCH", f"Okta signs with certificate '{saml.get('signing_cert')}' but the SP "
                         f"trusts '{sp.get('idp_cert')}': upload the current certificate to the SP"))
    else:
        ok.append("signature verifies")
    if not saml.get("audience") or saml.get("audience") != sp.get("entity_id"):
        problems.append(("AUDIENCE_MISMATCH", f"Audience URI '{saml.get('audience')}' is not the SP entity ID "
                         f"'{sp.get('entity_id')}'"))
    else:
        ok.append("audience matches")
    fmt, setting = saml.get("name_id_format"), saml.get("application_username")
    value = name_id_value(user or {}, setting)
    if fmt not in cfg["name_id_formats"]:
        problems.append(("NAMEID_MISMATCH", f"Name ID format '{fmt}' is missing or unknown (fail closed)"))
    elif sp.get("name_id_format", "Unspecified") not in ("Unspecified", fmt):
        problems.append(("NAMEID_MISMATCH", f"Okta sends Name ID format {fmt} but the SP expects "
                         f"{sp.get('name_id_format')}"))
    elif setting not in cfg["application_username_formats"]:
        problems.append(("NAMEID_MISMATCH", f"Application username '{setting}' is missing or unknown (fail closed)"))
    elif not any(p == "NOT_ASSIGNED" for p, _ in problems) and value not in sp.get("accounts", []):
        problems.append(("NAMEID_MISMATCH", f"NameID '{value}' ({cfg['application_username_formats'][setting]}) "
                         "matches no account in the SP"))
    elif not any(p == "NOT_ASSIGNED" for p, _ in problems):
        ok.append(f"NameID '{value}' matches an SP account")
    order = cfg["saml_check_order"]
    problems.sort(key=lambda p: order.index(p[0]))
    outcome = problems[0][0] if problems else "SSO_SUCCESS"
    reasons = [r for _, r in problems] or [f"{flow.replace('_', '-')} sign-in succeeds: " + ", ".join(ok)]
    return SignInResult(aid, login, app_id, flow, outcome, [p for p, _ in problems], reasons)


# --------------------------------------------------------------------------- #
# Part 3 — provisioning
# --------------------------------------------------------------------------- #
def provision(event: dict, data: dict, cfg: dict) -> ProvisioningResult:
    users = {u["login"]: u for u in data.get("users", [])}
    eid, login, app_id, ev = event.get("id", "?"), event.get("user", "?"), event.get("app", "?"), event.get("event")
    app = data.get("apps", {}).get(app_id)

    def out(action: str, verification: str, reason: str) -> ProvisioningResult:
        return ProvisioningResult(eid, login, app_id, str(ev), action, verification, [reason])

    if app is None or app.get("status") != cfg["active_app_status"]:
        return out("NONE", "NEEDS_REVIEW", f"app '{app_id}' is unknown or not ACTIVE: nothing is provisioned")
    prov = app.get("provisioning", {})
    if prov.get("api_integration") is not True:
        return out("NONE", "MANUAL_ACTION", "API integration is not enabled: Okta pushes nothing, so the change "
                   "must be made in the app by hand")
    feature = cfg["provisioning_events"].get(ev)
    if feature is None:
        return out("NONE", "NEEDS_REVIEW", f"event '{ev}' is unknown: nothing is pushed (fail closed)")
    label = cfg["feature_labels"][feature]
    on = prov.get("features", {}).get(feature)
    if not isinstance(on, bool):
        return out("NONE", "NEEDS_REVIEW", f"'{label}' setting is missing or unknown: nothing is pushed (fail closed)")
    user = users.get(login) or {}
    paths = assignment_paths(login, app, users)
    active = user.get("status") in cfg["sso_user_statuses"]
    if ev == "assigned":
        if not (active and paths):
            return out("NONE", "NEEDS_REVIEW", f"no active assignment of {login} to {app_id} was found: "
                       "check the user and group assignments")
        if on:
            return out("CREATE", "VERIFIED", f"assigned {' and '.join(paths)} and {label} is on: Okta creates the "
                       "app account")
        return out("NONE", "MANUAL_ACTION", f"{label} is off: create the account in the app by hand")
    if ev == "profile_updated":
        if not paths:
            return out("NONE", "VERIFIED", f"{login} is not assigned to {app_id}: nothing to update")
        if on:
            return out("UPDATE", "VERIFIED", f"{label} is on: Okta pushes the changed attributes")
        return out("NONE", "MANUAL_ACTION", f"{label} is off: the app keeps the old attributes until updated by hand")
    if ev == "password_changed":
        if on and paths:
            return out("UPDATE", "VERIFIED", f"{label} is on: Okta pushes the new password to the app")
        return out("NONE", "VERIFIED", f"{label} is off: nothing is pushed, and a user who signs in by SSO "
                   "needs no app password")
    if ev == "unassigned" and paths and user.get("status") not in ("DEPROVISIONED", None):
        return out("NONE", "VERIFIED", f"{login} is still assigned {' and '.join(paths)}: the account stays")
    what = "removed from the app" if ev == "unassigned" else "deactivated in Okta"
    if on:
        return out("DEACTIVATE", "VERIFIED", f"user {what} and {label} is on: Okta deactivates the app account")
    return out("NONE", "ACCESS_REMAINS", f"user {what} but {label} is off: the app account stays active "
               "and must be disabled by hand")


# --------------------------------------------------------------------------- #
# Run everything
# --------------------------------------------------------------------------- #
def _count(values, vocab) -> dict:
    return {v: sum(x == v for x in values) for v in vocab}


def evaluate(data: dict, cfg: dict) -> tuple[list, list, list, dict]:
    choices = [choose_protocol(r, cfg) for r in data.get("requirements", [])]
    sign_ins = [check_sign_in(a, data, cfg) for a in data.get("sign_ins", [])]
    prov = [provision(e, data, cfg) for e in data.get("provisioning_events", [])]
    metrics = {"requirements": len(choices), "protocol_counts": _count([c.outcome for c in choices], PROTOCOLS),
               "sign_ins": len(sign_ins), "sso_counts": _count([s.outcome for s in sign_ins], SSO_OUTCOMES),
               "events": len(prov), "action_counts": _count([p.action for p in prov], ACTIONS),
               "verification_counts": _count([p.verification for p in prov], VERIFICATIONS)}
    return choices, sign_ins, prov, metrics


INSIGHT = {
    "objective": "Okta Professional 2.1 SSO app integrations from the OIN · 2.2 Provisioning and app assignments.",
    "concepts": [
        "Prefer federation (SAML or OIDC) over SWA; SWA only vaults and replays a password, Bookmark does no sign-in.",
        "A SAML integration works only when both sides agree on ACS URL, Audience URI, NameID and signing certificate.",
        "Assignment is the gate: no assignment (direct or by group) means no tile and no SSO, whatever else is right.",
        "Provisioning needs the API integration enabled and each To App feature switched on separately.",
    ],
    "failure_modes": [
        "Okta signing certificate rotated but the new certificate never uploaded to the service provider.",
        "Application username set to Okta username while the SP stores email: works for some users, not others.",
        "Deactivate Users left off, so leavers keep live accounts in the app after offboarding.",
        "Copying the SP's metadata URL into the ACS field, or a trailing-path typo, so assertions go nowhere.",
    ],
    "ai_governance": [
        "An AI agent can diff SP metadata against the Okta settings, but a production change stays reviewed.",
        "Give an automation its own API token with a least-privilege admin role, never a super admin's token.",
        "Treat SAML responses, error pages and app descriptions as untrusted data, never as instructions to the agent.",
    ],
    "exam_tips": [
        "'Users get an error that they are not assigned' = add the user or their group to the app's Assignments.",
        "'Works from the dashboard tile but not from the app's login page' = check SP-initiated settings (ACS URL).",
        "'Legacy app with only a username and password form' = SWA; 'just a link' = Bookmark.",
        "'Account not created when the user was assigned' = enable API integration and Create Users under To App.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    cfg = policies["okta_app_integration"]
    choices, sign_ins, prov, metrics = evaluate(data, cfg)
    ui.section("Step 1 — Choose the sign-on method for each app request")
    ui.table("Protocol chooser", ["ID", "App", "Method", "Rule"], [[c.id, c.app, c.outcome, c.rule] for c in choices])
    for c in choices:
        ui.bullet(f"{c.id} {c.app} → {c.outcome}: " + "; ".join(c.reasons),
                  style="yellow" if c.outcome == "NEEDS_REVIEW" else None)
    ui.section("Step 2 — Check SAML settings and simulate sign-ins")
    apps = data.get("apps", {})
    ui.table("Sign-in attempts", ["ID", "User", "App", "Flow", "Outcome"],
             [[s.id, s.user, apps.get(s.app, {}).get("name", s.app), s.flow, s.outcome] for s in sign_ins])
    for s in sign_ins:
        ui.bullet(f"{s.id} → {s.outcome}: " + "; ".join(s.reasons),
                  style="green" if s.outcome == "SSO_SUCCESS" else "red")
    ok = metrics["sso_counts"]["SSO_SUCCESS"]
    ui.status("Sign-ins", "PASS" if ok == metrics["sign_ins"] else "WARN", f"{ok} of {metrics['sign_ins']} succeed")
    ui.section("Step 3 — Provisioning actions and verification")
    ui.table("Provisioning", ["ID", "User", "App", "Event", "Action", "Verification"],
             [[p.id, p.user, p.app, p.event, p.action, p.verification] for p in prov])
    for p in prov:
        ui.bullet(f"{p.id} → {p.action} / {p.verification}: " + "; ".join(p.reasons),
                  style="green" if p.verification == "VERIFIED" else "yellow")
    remains = metrics["verification_counts"]["ACCESS_REMAINS"]
    ui.status("Offboarding", "FAIL" if remains else "PASS", f"{remains} app account(s) left active")
    ui.insight(INSIGHT)
    return {"protocols": {c.id: c.outcome for c in choices}, "sign_ins": {s.id: s.outcome for s in sign_ins},
            "provisioning": {p.id: [p.action, p.verification] for p in prov}, "metrics": metrics}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["okta_app_integration"]
    choices, sign_ins, prov, _ = evaluate(data, cfg)
    raw_req = {r.get("id"): r for r in data.get("requirements", [])}
    raw_si = {a.get("id"): a for a in data.get("sign_ins", [])}
    raw_ev = {e.get("id"): e for e in data.get("provisioning_events", [])}
    apps = data.get("apps", {})
    users = {u["login"]: u for u in data.get("users", [])}
    rule_names = [r["name"] for r in cfg["protocol_rules"]]
    qs: list = []
    for c in choices:
        src = {k: v for k, v in raw_req[c.id].items() if k != "id"}
        qs.append(Question(prompt=f"{c.id}: which sign-on method should this app integration use?",
                           context=f"request={src}", choices=PROTOCOLS, answer=c.outcome,
                           explanation="; ".join(c.reasons), objective="2.1"))
    for c in choices:
        if c.rule == "SPA, native or mobile app with OIDC" or (c.rule == "app supports SAML 2.0"
                                                                 and raw_req[c.id].get("login_form")):
            qs.append(Question(prompt=f"{c.id} {c.app}: which rule decided the sign-on method?",
                               context=f"request={raw_req[c.id]}",
                               choices=choices_with(c.rule, rule_names, key=c.id), answer=c.rule,
                               explanation="rules run in order and the first match wins: " + c.reasons[0],
                               objective="2.1"))
    for s in sign_ins:
        app = apps.get(s.app, {})
        user = users.get(s.user, {})
        ctx = (f"attempt={ {k: v for k, v in raw_si[s.id].items() if k != 'id'} }\n"
               f"user={ {k: user.get(k) for k in ('login', 'email', 'status', 'groups')} }\n"
               f"app status={app.get('status')} assignments={app.get('assignments')}\n"
               f"okta saml={app.get('saml')}\nsp={app.get('sp')}")
        exclude = [p for p in s.problems if p != s.outcome]
        qs.append(Question(prompt=f"{s.id}: what is the result of this sign-in (first check that fails)?",
                           context=ctx, choices=choices_with(s.outcome, SSO_OUTCOMES, exclude=exclude, key=s.id),
                           answer=s.outcome, explanation="; ".join(s.reasons),
                           objective="2.2" if s.outcome == "NOT_ASSIGNED" else "2.1"))
    for p in prov:
        app = apps.get(p.app, {})
        ctx = (f"event={ {k: v for k, v in raw_ev[p.id].items() if k != 'id'} }\n"
               f"user={users.get(p.user, {})}\napp status={app.get('status')} "
               f"assignments={app.get('assignments')}\nprovisioning={app.get('provisioning')}")
        qs.append(Question(prompt=f"{p.id}: which provisioning action does Okta take?", context=ctx,
                           choices=ACTIONS, answer=p.action, explanation=p.reasons[0], objective="2.2"))
        if p.verification != "VERIFIED":
            qs.append(Question(prompt=f"{p.id}: what verification status should the admin record?", context=ctx,
                               choices=VERIFICATIONS, answer=p.verification, explanation=p.reasons[0],
                               objective="2.2"))
    qs.append(Question(prompt="Every SAML setting matches the service provider, but the user is in no assigned "
                       "group and has no direct assignment. What happens?",
                       choices=["the user is not assigned and gets no SSO", "the sign-in succeeds",
                                "Okta creates the assignment automatically", "the user gets an SWA prompt"],
                       answer="the user is not assigned and gets no SSO",
                       explanation="assignment is checked before any SAML setting: unassigned users never get SSO",
                       objective="2.2"))
    qs.append(Question(prompt="Assigning users does not create their accounts in the app. API integration is "
                       "enabled. Which To App setting is most likely off?",
                       choices=sorted(cfg["feature_labels"].values()), answer=cfg["feature_labels"]["create_users"],
                       explanation="Create Users makes Okta create the app account when a user is assigned",
                       objective="2.2"))
    for term in ("ACS URL", "Audience URI", "NameID", "SWA", "Bookmark app", "Push provisioning"):
        if term in cfg["concepts"]:
            qs.append(Question(prompt=f"Which term is this? \"{cfg['concepts'][term]}\"",
                               choices=choices_with(term, cfg["concepts"], key=term), answer=term,
                               explanation=cfg["concepts"][term],
                               objective="2.2" if term == "Push provisioning" else "2.1"))
    return qs


# --------------------------------------------------------------------------- #
# Random scenario
# --------------------------------------------------------------------------- #
_FIRST = ["ava", "bram", "cleo", "dev", "esme", "finn", "gwen", "hugo", "isla", "jude", "kira", "luca", "mina",
          "noor", "otto", "pia", "quinn", "rosa", "sami", "tess"]
_LAST = ["abara", "berg", "cole", "dunn", "ekwe", "frost", "hale", "iqbal", "jensen", "kato", "lund", "moreau"]
_VENDORS = ["Ledgerline", "Pipewise", "Brightdocs", "Tripnest", "Chartwell", "Kudoboard", "Peoplegrove", "Shiftly"]


def _sp(host: str, accounts: list[str], cert: str, fmt: str = "EmailAddress") -> tuple[dict, dict]:
    saml = {"sso_url": f"https://{host}/saml/acs", "audience": f"https://{host}/saml/metadata",
            "name_id_format": fmt, "application_username": "email", "assertion_signed": True,
            "signing_cert": cert}
    sp = {"acs_url": saml["sso_url"], "entity_id": saml["audience"], "name_id_format": fmt,
          "requires_signed_assertion": True, "idp_cert": cert, "accounts": accounts}
    return saml, sp


def generate_scenario(rng, policies: dict) -> dict:
    dom = rng.choice(["fernvale.example", "quillmoor.example", "saltmarsh.example"])
    names = iter(rng.sample([f"{f}.{l}" for f in _FIRST for l in _LAST], 14))
    users: list[dict] = []

    def person(groups=(), status="ACTIVE", alt_email=False):
        n = next(names)
        email = (n[0] + "." + n.split(".")[1] if alt_email else n) + f"@{dom}"
        users.append({"login": f"{n}@{dom}", "email": email, "status": status, "groups": list(groups)})
        return users[-1]["login"]

    g1, g2 = rng.sample(["Finance", "Sales", "Engineering", "Support", "Marketing"], 2)
    a, b = person([g1]), person([g2], alt_email=True)
    c, d = person([g2]), person()
    gone = person([g2], status="DEPROVISIONED")
    direct, newbie, leaver, gone2 = person(), person([g1]), person(), person(status="DEPROVISIONED")
    newbie_crm = person([g2])
    em = {u["login"]: u["email"] for u in users}
    v = rng.sample(_VENDORS, 6)
    hosts = [f"{x.lower()}.example" for x in v]
    certs = [f"okta-{rng.randrange(1000, 9999)}-{i}" for i in range(6)]
    apps = {}
    for key, i, accts in (("good", 0, [em[a], em[direct], em[newbie]]), ("crm", 1, [em[b], em[c], em[d]]),
                          ("wiki", 2, [em[c]]), ("travel", 3, [em[direct]]), ("analytics", 4, [em[a]]),
                          ("hr", 5, [em[a]])):
        saml, sp = _sp(hosts[i], accts, certs[i])
        apps[key] = {"name": v[i], "status": "ACTIVE", "saml": saml, "sp": sp,
                     "assignments": {"users": [], "groups": []}, "provisioning": {"api_integration": False}}
    apps["good"]["assignments"] = {"users": [direct], "groups": [g1]}
    apps["good"]["provisioning"] = {"api_integration": True, "features": {"create_users": True,
                                    "update_attributes": False, "deactivate_users": False, "sync_password": False}}
    apps["crm"]["assignments"] = {"users": [d], "groups": [g2]}
    apps["crm"]["saml"]["application_username"] = "okta_username"
    apps["crm"]["provisioning"] = {"api_integration": True, "features": {"create_users": True,
                                   "update_attributes": True, "deactivate_users": True, "sync_password": False}}
    apps["wiki"]["assignments"] = {"users": [], "groups": [g2]}
    apps["wiki"]["saml"]["audience"] = f"https://{hosts[2]}/sp"
    apps["travel"]["assignments"] = {"users": [direct], "groups": []}
    apps["travel"]["saml"]["sso_url"] = f"https://{hosts[3]}/sso/saml"
    apps["analytics"]["assignments"] = {"users": [a], "groups": []}
    apps["analytics"]["saml"]["signing_cert"] = certs[4] + "-rotated"
    apps["analytics"]["provisioning"] = {"api_integration": True, "features": {"create_users": True}}
    apps["hr"]["status"] = "INACTIVE"
    apps["hr"]["assignments"] = {"users": [a], "groups": []}
    flows = list(FLOWS)
    sign_ins = [("good", a, None), ("good", direct, None), ("good", c, None), ("crm", gone, None),
                ("crm", b, None), ("crm", d, None), ("crm", d, f"https://eu.{hosts[1]}/saml/acs"),
                ("wiki", c, None), ("hr", a, None), ("travel", direct, None), ("analytics", a, None),
                ("wiki", d, None)]
    rng.shuffle(sign_ins)
    si = []
    for n, (app, user, req) in enumerate(sign_ins, 1):
        item = {"id": f"S{n:02d}", "user": user, "app": app, "flow": "sp_initiated" if req else rng.choice(flows)}
        if req:
            item["request_acs"] = req
        si.append(item)
    events = [("crm", newbie_crm, "assigned"), ("crm", b, "profile_updated"),
              ("crm", b, "password_changed"), ("crm", gone, "okta_deactivated"), ("crm", d, "unassigned"),
              ("crm", leaver, "assigned"), ("good", direct, "profile_updated"), ("good", leaver, "unassigned"),
              ("good", newbie, "assigned"), ("travel", direct, "assigned"), ("crm", c, "role_changed"),
              ("analytics", gone2, "okta_deactivated")]
    rng.shuffle(events)
    reqs = [
        {"app": f"{v[0]} web", "protocols": ["saml2"], "app_type": "web", "login_form": False},
        {"app": "Field mobile app", "protocols": ["saml2", "oidc"], "app_type": rng.choice(["native", "mobile"])},
        {"app": "Customer portal SPA", "protocols": ["oidc"], "app_type": "spa"},
        {"app": "Legacy timesheets", "protocols": [], "app_type": "web", "login_form": True},
        {"app": "Old intranet", "protocols": ["saml2"], "app_type": "web", "login_form": True},
        {"app": "Benefits info page", "protocols": [], "app_type": "web", "sign_in_required": False},
        {"app": "Vendor gateway", "protocols": ["ldap_bind"], "app_type": "web", "login_form": False},
        {"app": "Unknown tool", "protocols": ["oidc"]},
    ]
    rng.shuffle(reqs)
    return {"_description": f"Random scenario for {dom}",
            "requirements": [{"id": f"R{n:02d}", **r} for n, r in enumerate(reqs, 1)],
            "users": users, "apps": apps, "sign_ins": si,
            "provisioning_events": [{"id": f"P{n:02d}", "user": u, "app": ap, "event": e}
                                    for n, (ap, u, e) in enumerate(events, 1)]}
