"""
Lab 40 — Okta Sign-On Policy Evaluator: Global Session, Authentication Policies & Network Zones
==============================================================================================

Okta Professional objectives
----------------------------
* 4.3  Authentication policies and network zones: IP zones, dynamic zones
       (country, autonomous system number (ASN), anonymizers), blocklist
       zones, per-app authentication policy rules, assurance levels,
       possession factor constraints, re-authentication frequency.
* 4.2  Global session policy: policies assigned to groups, rule priority,
       primary factor, MFA for the session, session lifetime.
* 4.1  Authenticators and enrollment policies: factor types (knowledge,
       possession, inherence), required / optional / disabled authenticators.

How it works
------------
In Okta Identity Engine (OIE) a sign-in to an app must pass TWO policies: the
org's global session policy (can this person get an Okta session, and how?)
and the app's authentication policy (can they open THIS app, with what
assurance?). Both must be satisfied. Each sign-in attempt (user, IP, country,
ASN, anonymizer flag, device state, app, authenticators presented) is
evaluated in this order:

1. Unknown user → DENIED_BY_GLOBAL_SESSION_POLICY. Missing or unparsable IP
   → DENIED_BLOCKED_ZONE (Okta cannot prove the request is not from a
   blocklisted zone). Deny by default.
2. Blocklist zones: the IP is in an ACTIVE blocklist zone (IP ranges, or a
   dynamic zone by country, ASN or anonymizer) → DENIED_BLOCKED_ZONE, before
   any authentication. Deactivated zones are ignored.
3. Global session policy: the first ACTIVE policy, by priority, assigned to
   one of the user's groups (everyone is in Everyone) is evaluated. Its rules
   run by priority and the first rule whose conditions match (excluded
   users, network zone in / not in) wins. If none of its rules match, the
   NEXT policy is evaluated (Okta's documented behaviour). The Default
   Policy's catch-all Default Rule matches everything left. A DENY rule, or
   no match at all → DENIED_BY_GLOBAL_SESSION_POLICY. An ALLOW rule sets the
   primary factor ("password", or "any" factor that meets the app's policy),
   whether MFA is required, and the session lifetime.
4. Authentication policy of the app (unknown app → deny): rules run by
   priority, first match wins (conditions: groups, excluded users, network
   zone, device registered, device managed, device assurance policy), the
   catch-all rule last. DENY → DENIED_BY_AUTHENTICATION_POLICY. ALLOW sets
   the number of factor types (1 or 2), possession factor constraints
   (phishing resistant, hardware protected) and re-authentication frequency.
5. Combine: required factor types = the larger of the two policies (global
   session MFA means 2), a password is needed if the global session rule's
   primary factor is "password", and a possession constraint means at least
   one possession authenticator that meets every constraint (others do not
   count as possession). Only presented methods whose authenticator the user
   has ENROLLED count.
6. Satisfied → MFA_REQUIRED_SATISFIED (2 factor types) or ACCESS_GRANTED
   (1); then, if the user's enrollment policy marks an authenticator
   "required" that the user has not enrolled → ENROLLMENT_REQUIRED.
   Not satisfied: the user's enrolled methods could satisfy it →
   INSUFFICIENT_AUTHENTICATORS (wrong or too few factors presented); enrolling
   one authenticator the enrollment policy allows (required or optional)
   would satisfy it → ENROLLMENT_REQUIRED; otherwise →
   INSUFFICIENT_AUTHENTICATORS.

Run it
------
    python main.py --course okta lab 40
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

TITLE = "Lab 40 — Okta Sign-On Policy Evaluator: Global Session, Authentication Policies & Network Zones"
OBJECTIVES = ("Okta Professional 4.3 Authentication policies and network zones · 4.2 Global session policy · "
              "4.1 Authenticators and enrollment policies")
COURSES = ("okta",)
OUTCOMES = ["ACCESS_GRANTED", "MFA_REQUIRED_SATISFIED", "DENIED_BY_GLOBAL_SESSION_POLICY",
            "DENIED_BY_AUTHENTICATION_POLICY", "DENIED_BLOCKED_ZONE", "ENROLLMENT_REQUIRED",
            "INSUFFICIENT_AUTHENTICATORS"]
GRANTED = ("ACCESS_GRANTED", "MFA_REQUIRED_SATISFIED")


@dataclass
class Evaluation:
    id: str
    user: str
    app: str
    outcome: str
    gsp: str | None = None            # global session policy id
    gsp_rule: str | None = None
    auth_policy: str | None = None
    auth_rule: str | None = None
    blocked_by: str | None = None     # blocklist zone id
    zones: list[str] = field(default_factory=list)
    factor_types_required: int = 0
    password_required: bool = False
    constraints: list[str] = field(default_factory=list)
    session_lifetime_minutes: int | None = None
    reauthenticate_minutes: int | None = None
    enroll: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Org configuration and helpers
# --------------------------------------------------------------------------- #
def org(data: dict, cfg: dict) -> dict:
    """The org's configuration: the policy file's 'org', with any key the scenario provides overriding it."""
    return {**cfg["org"], **(data.get("org") or {})}


def _active(obj: dict) -> bool:
    return str(obj.get("status", "ACTIVE")).upper() == "ACTIVE"


def _by_priority(items: list[dict]) -> list[dict]:
    return sorted((i for i in items if _active(i)), key=lambda i: (i.get("priority", 999), i.get("id", "")))


def parse_ip(value):
    try:
        return ipaddress.ip_address(str(value))
    except ValueError:
        return None


def in_zone(zone: dict, req: dict) -> bool:
    """Does the request match the zone? Missing request attributes never match (no guessing)."""
    if zone.get("type") == "IP":
        ip = parse_ip(req.get("ip"))
        if ip is None:
            return False
        for cidr in zone.get("gateways", []):
            try:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False
    # DYNAMIC zone: any listed criterion that matches places the request in the zone.
    # (Okta's dynamic and enhanced dynamic zones combine location, ASN and IP service categories; kept generic here.)
    country = str(req.get("country") or "").upper()
    if country and country in [str(c).upper() for c in zone.get("locations", [])]:
        return True
    if req.get("asn") is not None and req.get("asn") in zone.get("asns", []):
        return True
    return bool(zone.get("anonymizer")) and req.get("anonymizer") is True


def zones_for(req: dict, o: dict) -> list[str]:
    """Ids of the ACTIVE policy-usage zones the request is in."""
    return [z["id"] for z in o["network_zones"] if _active(z) and z.get("usage") != "BLOCKLIST" and in_zone(z, req)]


def zone_condition(cond: dict | None, zones: list[str]) -> tuple[bool, str]:
    """A rule's network zone condition. None = anywhere. Unknown zone ids simply never contain the request."""
    if not cond:
        return True, "anywhere"
    if cond.get("include"):
        hit = sorted(set(cond["include"]) & set(zones))
        return bool(hit), (f"in {', '.join(hit)}" if hit else f"not in {', '.join(cond['include'])}")
    if cond.get("exclude"):
        hit = sorted(set(cond["exclude"]) & set(zones))
        return not hit, (f"in {', '.join(hit)}" if hit else f"outside {', '.join(cond['exclude'])}")
    return True, "anywhere"


def user_groups(user: dict, cfg: dict) -> set[str]:
    return set(user.get("groups", [])) | {cfg["everyone_group"]}


def assigned(policy: dict, groups: set[str]) -> bool:
    return bool(set(policy.get("groups", [])) & groups)


# --------------------------------------------------------------------------- #
# Policy evaluation
# --------------------------------------------------------------------------- #
def blocklisted(req: dict, o: dict) -> tuple[str | None, list[str]]:
    notes = []
    for z in o["network_zones"]:
        if z.get("usage") != "BLOCKLIST":
            continue
        if not _active(z):
            if in_zone(z, req):
                notes.append(f"IP is in {z['id']} but that blocklist zone is deactivated, so it is ignored")
            continue
        if in_zone(z, req):
            return z["id"], notes
    return None, notes


def evaluate_global_session(login: str, groups: set[str], zones: list[str], o: dict) -> tuple[dict | None,
                                                                                             dict | None, list[str]]:
    """(policy, rule, reasons). The first matching rule of the first policy (by priority) with a match wins."""
    reasons = []
    for pol in _by_priority(o["global_session_policies"]):
        if not assigned(pol, groups):
            continue
        for rule in _by_priority(pol.get("rules", [])):
            if login in rule.get("exclude_users", []):
                continue
            ok, why = zone_condition(rule.get("zone"), zones)
            if rule.get("catch_all") or ok:
                return pol, rule, reasons + [f"global session policy {pol['id']} ({pol['name']}) rule "
                                             f"{rule['id']} '{rule['name']}' matched ({why})"]
        reasons.append(f"{pol['id']} applies to the user's groups but none of its rules matched: "
                       "the next policy is evaluated")
    return None, None, reasons + ["no global session policy rule matched (deny by default)"]


def device_condition(cond: dict | None, device: dict) -> tuple[bool, str]:
    """Missing device information is treated as an unregistered, unmanaged device with no assurance."""
    if not cond:
        return True, "any device"
    if cond.get("registered") and not device.get("registered"):
        return False, "device not registered with Okta Verify"
    if cond.get("managed") and not device.get("managed"):
        return False, "device not managed"
    need = cond.get("assurance_any_of")
    if need:
        hit = sorted(set(need) & set(device.get("assurance") or []))
        if not hit:
            return False, f"device meets none of the device assurance policies {', '.join(need)}"
        return True, f"device meets {', '.join(hit)}"
    return True, "device conditions met"


def evaluate_authentication(login: str, groups: set[str], zones: list[str], device: dict, policy: dict
                            ) -> tuple[dict | None, list[str]]:
    for rule in _by_priority(policy.get("rules", [])):
        if rule.get("catch_all"):
            return rule, [f"authentication policy {policy['id']} ({policy['name']}): no earlier rule matched, "
                          f"catch-all {rule['id']} applies"]
        if login in rule.get("exclude_users", []):
            continue
        if rule.get("groups") and not set(rule["groups"]) & groups:
            continue
        zok, zwhy = zone_condition(rule.get("zone"), zones)
        dok, dwhy = device_condition(rule.get("device"), device)
        if zok and dok:
            return rule, [f"authentication policy {policy['id']} ({policy['name']}) rule {rule['id']} "
                          f"'{rule['name']}' matched ({zwhy}; {dwhy})"]
    return None, [f"authentication policy {policy['id']} has no matching rule and no catch-all (deny by default)"]


def satisfies(methods: list[str], need_types: int, need_password: bool, constraints: list[str], cfg: dict
              ) -> tuple[bool, str]:
    """Do these methods meet the combined requirement? Returns (ok, reason)."""
    cat = cfg["authenticator_methods"]
    known = [m for m in methods if m in cat]
    if need_password and "password" not in known:
        return False, "the global session policy establishes the session with a password, and none was given"
    types: set[str] = set()
    good_possession = False
    for m in known:
        meta = cat[m]
        ok_constraints = all(meta.get(c) for c in constraints)
        for t in meta["factor_types"]:
            if t == "possession" and constraints and not ok_constraints:
                continue                       # possession that misses a constraint does not count
            types.add(t)
        if "possession" in meta["factor_types"] and ok_constraints:
            good_possession = True
    if constraints and not good_possession:
        return False, f"no possession authenticator that is {' and '.join(c.replace('_', ' ') for c in constraints)}"
    if len(types) < need_types:
        return False, f"{len(types)} factor type(s) ({', '.join(sorted(types)) or 'none'}) < {need_types} required"
    return True, f"factor types {', '.join(sorted(types))} meet {need_types} required"


def enrollment_policy(groups: set[str], o: dict) -> dict | None:
    return next((p for p in _by_priority(o["enrollment_policies"]) if assigned(p, groups)), None)


def evaluate_attempt(att: dict, data: dict, cfg: dict) -> Evaluation:
    o = org(data, cfg)
    login, app_id = att.get("user"), att.get("app")
    ev = Evaluation(att.get("id", "?"), login or "?", app_id or "?", "DENIED_BY_GLOBAL_SESSION_POLICY")
    user = (data.get("users") or {}).get(login or "")
    if user is None:
        ev.reasons.append(f"user {login} is not in the directory: no session is created (deny by default)")
        return ev
    if parse_ip(att.get("ip")) is None:
        ev.outcome = "DENIED_BLOCKED_ZONE"
        ev.reasons.append("no valid client IP: blocklist zones cannot be checked (deny by default)")
        return ev
    # Rule 2: blocklist zones, before authentication
    blocked, notes = blocklisted(att, o)
    ev.reasons += notes
    if blocked:
        ev.outcome, ev.blocked_by = "DENIED_BLOCKED_ZONE", blocked
        ev.reasons.append(f"request matches blocklist zone {blocked}: rejected before authentication")
        return ev
    groups, zones = user_groups(user, cfg), zones_for(att, o)
    ev.zones = zones
    # Rule 3: global session policy
    gsp, grule, why = evaluate_global_session(login, groups, zones, o)
    ev.reasons += why
    if gsp is None:
        return ev
    ev.gsp, ev.gsp_rule = gsp["id"], grule["id"]
    if grule.get("access") != "ALLOW":
        ev.reasons.append(f"rule {grule['id']} denies the Okta session")
        return ev
    ev.session_lifetime_minutes = grule.get("session_lifetime_minutes")
    # Rule 4: the app's authentication policy
    app = (data.get("apps") or {}).get(app_id or "")
    policy = next((p for p in o["authentication_policies"] if app and p["id"] == app.get("authentication_policy")),
                  None)
    if policy is None:
        ev.outcome = "DENIED_BY_AUTHENTICATION_POLICY"
        ev.reasons.append(f"app {app_id} has no known authentication policy (deny by default)")
        return ev
    ev.auth_policy = policy["id"]
    arule, why = evaluate_authentication(login, groups, zones, att.get("device") or {}, policy)
    ev.reasons += why
    if arule is None or arule.get("access") != "ALLOW":
        ev.outcome = "DENIED_BY_AUTHENTICATION_POLICY"
        if arule:
            ev.auth_rule = arule["id"]
            ev.reasons.append(f"rule {arule['id']} denies access to {app.get('name', app_id)}")
        return ev
    ev.auth_rule, ev.reauthenticate_minutes = arule["id"], arule.get("reauthenticate_minutes")
    # Rule 5: combine both policies
    need = max(2 if grule.get("mfa_required") else 1, int(arule.get("factor_types_required", 2)))
    need_pw = grule.get("primary_factor", "password") == "password"
    cons = list(arule.get("possession_constraints", []))
    ev.factor_types_required, ev.password_required, ev.constraints = need, need_pw, cons
    ev.reasons.append(f"combined requirement: {need} factor type(s)" + (", password" if need_pw else "")
                      + (f", possession {' + '.join(c.replace('_', ' ') for c in cons)}" if cons else ""))
    cat = cfg["authenticator_methods"]
    enrolled = set(user.get("enrolled", []))
    presented = list(att.get("presented") or [])
    usable = [m for m in presented if m in cat and cat[m]["authenticator"] in enrolled]
    for m in presented:
        if m not in usable:
            ev.reasons.append(f"presented '{m}' is ignored: " + ("unknown method" if m not in cat else
                              f"{cat[m]['authenticator']} is not enrolled"))
    ok, why = satisfies(usable, need, need_pw, cons, cfg)
    ev.reasons.append(why)
    ep = enrollment_policy(groups, o)
    settings = (ep or {}).get("authenticators", {})
    # Rule 6: outcome
    if ok:
        ev.outcome = "MFA_REQUIRED_SATISFIED" if need >= 2 else "ACCESS_GRANTED"
        missing = sorted(a for a, s in settings.items() if s == "required" and a not in enrolled)
        if missing:
            ev.outcome, ev.enroll = "ENROLLMENT_REQUIRED", missing
            ev.reasons.append(f"enrollment policy {ep['id']} requires {', '.join(missing)}, not yet enrolled: "
                              "the user must enroll before access completes")
        return ev
    could = [m for m, meta in cat.items() if meta["authenticator"] in enrolled]
    if satisfies(could, need, need_pw, cons, cfg)[0]:
        ev.outcome = "INSUFFICIENT_AUTHENTICATORS"
        better = sorted(m for m in could if m not in usable and satisfies(usable + [m], need, need_pw, cons, cfg)[0])
        ev.reasons.append("the user's enrolled authenticators could satisfy this; the presented ones do not"
                          + (f" (for example {better[0]})" if better else ""))
        return ev
    options = sorted(a for a, s in settings.items() if s in ("required", "optional") and a not in enrolled
                     and satisfies(could + [m for m, meta in cat.items() if meta["authenticator"] == a],
                                   need, need_pw, cons, cfg)[0])
    if options:
        ev.outcome, ev.enroll = "ENROLLMENT_REQUIRED", options
        ev.reasons.append(f"enrollment policy {ep['id']} allows {', '.join(options)}: the user is prompted to enroll")
        return ev
    ev.outcome = "INSUFFICIENT_AUTHENTICATORS"
    ev.reasons.append("no enrolled authenticator meets the requirement and the enrollment policy "
                      f"{ep['id'] if ep else '(none)'} allows none that would")
    return ev


def evaluate_all(data: dict, cfg: dict) -> list[Evaluation]:
    return [evaluate_attempt(a, data, cfg) for a in data.get("attempts", [])]


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "Okta Professional 4.3 Authentication policies and network zones · 4.2 Global session policy · "
                 "4.1 Authenticators and enrollment policies.",
    "concepts": [
        "OIE checks two policies per app sign-in: the global session policy (the Okta session) and the app's "
        "authentication policy (the app). Both must be satisfied.",
        "Blocklist zones reject a request before authentication; policy zones are only conditions inside rules.",
        "Policies and rules run by priority and the first match wins; a policy whose rules all miss passes the "
        "request to the next policy, and catch-all rules sit at the bottom.",
        "'Any 2 factor types' means two of knowledge, possession and inherence: Okta FastPass with biometrics or a "
        "FIDO2 key with user verification can satisfy it alone.",
        "Possession constraints (phishing resistant, hardware protected) stop SMS, email and push from counting.",
        "Enrollment policies decide which authenticators a group may enroll: required, optional or disabled.",
    ],
    "failure_modes": [
        "A broad ALLOW rule placed above a DENY rule, so the deny never fires.",
        "Relaxing the app policy to one factor while the global session policy still asks for a password.",
        "Requiring phishing-resistant MFA while the enrollment policy disables every phishing-resistant authenticator.",
        "Deactivating a blocklist zone during troubleshooting and forgetting to turn it back on.",
    ],
    "ai_governance": [
        "An AI agent that signs in through Okta should use its own app with its own authentication policy, not a "
        "human's session.",
        "Let an agent simulate a policy change against sample sign-ins before an admin saves it, like this "
        "evaluator does.",
        "Treat user-agent strings, IP geolocation and device claims in logs as untrusted data, never as "
        "instructions to the agent.",
    ],
    "exam_tips": [
        "'Block sign-ins from Tor everywhere' = a dynamic (or enhanced dynamic) zone used as a blocklist.",
        "'Allow passwordless only on the office network' = global session policy rule for that zone with "
        "'any factor used to meet the authentication policy', plus an app rule that accepts it.",
        "'Admins must use phishing-resistant MFA for the Admin Console' = Okta Admin Console authentication "
        "policy rule with a phishing-resistant possession constraint.",
        "Check the System Log 'policy evaluation' events to see which policy and rule matched.",
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
    cfg = policies["okta_policy_evaluator"]
    o = org(data, cfg)
    evs = evaluate_all(data, cfg)
    ui.section("Step 1 — Network zones")
    ui.table("Network zones", ["ID", "Type", "Usage", "Status", "Defines"],
             [[z["id"], z.get("type"), z.get("usage"), z.get("status", "ACTIVE"),
               ", ".join(z.get("gateways", [])) or ", ".join(str(x) for x in z.get("locations", []) + z.get("asns", []))
               or ("anonymizers / Tor" if z.get("anonymizer") else "-")] for z in o["network_zones"]])
    ui.section("Step 2 — Global session policy (the Okta session)")
    ui.table("Global session policy", ["ID", "User", "Zones", "Policy", "Rule", "Session"],
             [[e.id, e.user, ", ".join(e.zones) or "-", e.gsp or "-", e.gsp_rule or e.blocked_by or "-",
               f"{e.session_lifetime_minutes} min" if e.session_lifetime_minutes else "-"] for e in evs])
    ui.section("Step 3 — App authentication policy and authenticators")
    ui.table("Sign-in attempts", ["ID", "User", "App", "Auth policy", "Rule", "Needs", "Outcome"],
             [[e.id, e.user, e.app, e.auth_policy or "-", e.auth_rule or "-",
               (f"{e.factor_types_required}FA" + (" +pw" if e.password_required else "")
                + "".join(f" +{c}" for c in e.constraints)) if e.factor_types_required else "-", e.outcome]
              for e in evs])
    for e in evs:
        ui.bullet(f"{e.id} → {e.outcome}: " + "; ".join(e.reasons),
                  style="green" if e.outcome in GRANTED else "yellow" if e.outcome == "ENROLLMENT_REQUIRED" else "red")
    counts = _counts(e.outcome for e in evs)
    granted = sum(e.outcome in GRANTED for e in evs)
    metrics = {"attempts": len(evs), "outcome_counts": counts, "granted": granted,
               "denied": sum(e.outcome.startswith("DENIED") for e in evs),
               "blocked_before_auth": counts.get("DENIED_BLOCKED_ZONE", 0),
               "enrollment_required": counts.get("ENROLLMENT_REQUIRED", 0),
               "insufficient": counts.get("INSUFFICIENT_AUTHENTICATORS", 0)}
    ui.section("Step 4 — Summary")
    ui.print(f"{len(evs)} sign-in attempts · {granted} granted · {metrics['denied']} denied "
             f"({metrics['blocked_before_auth']} by a blocklist zone) · {metrics['enrollment_required']} must enroll "
             f"· {metrics['insufficient']} with insufficient authenticators")
    ui.insight(INSIGHT)
    return {"outcomes": {e.id: e.outcome for e in evs},
            "matched": {e.id: {"global_session": [e.gsp, e.gsp_rule], "authentication": [e.auth_policy, e.auth_rule],
                               "blocked_by": e.blocked_by} for e in evs},
            "metrics": metrics}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["okta_policy_evaluator"]
    o = org(data, cfg)
    evs = evaluate_all(data, cfg)
    raw = {a.get("id"): a for a in data.get("attempts", [])}
    gsp_rules = sorted(r["id"] for p in o["global_session_policies"] for r in p.get("rules", []))
    auth_rules = sorted(r["id"] for p in o["authentication_policies"] for r in p.get("rules", []))
    qs: list = []

    def obj(e: Evaluation) -> str:
        if e.outcome in ("DENIED_BY_GLOBAL_SESSION_POLICY",):
            return "4.2"
        if e.outcome in ("ENROLLMENT_REQUIRED", "INSUFFICIENT_AUTHENTICATORS"):
            return "4.1"
        return "4.3"

    for e in evs:
        src = {k: v for k, v in raw.get(e.id, {}).items() if k != "id"}
        user = (data.get("users") or {}).get(e.user)
        ctx = f"attempt={src}\nuser=" + (f"{user}" if user else "not in the directory")
        qs.append(Question(prompt=f"{e.id}: what is the result of this sign-in attempt?", context=ctx,
                           choices=list(OUTCOMES), answer=e.outcome, explanation="; ".join(e.reasons),
                           objective=obj(e)))
    seen_g, seen_a = set(), set()
    for e in evs:
        ctx = ("attempt=" + str({k: v for k, v in raw.get(e.id, {}).items() if k != "id"})
               + f"\nuser groups: {', '.join(sorted(user_groups((data.get('users') or {}).get(e.user, {}), cfg)))}")
        if e.gsp_rule and e.gsp_rule not in seen_g:
            seen_g.add(e.gsp_rule)
            qs.append(Question(prompt=f"{e.id}: which global session policy rule matched?",
                               context=ctx,
                               choices=choices_with(e.gsp_rule, gsp_rules, key=e.id), answer=e.gsp_rule,
                               explanation="; ".join(r for r in e.reasons if "global session" in r or "next policy"
                                                     in r), objective="4.2"))
        if e.auth_rule and e.auth_rule not in seen_a:
            seen_a.add(e.auth_rule)
            qs.append(Question(prompt=f"{e.id}: which authentication policy rule matched?",
                               context=ctx,
                               choices=choices_with(e.auth_rule, auth_rules, key=e.id), answer=e.auth_rule,
                               explanation="; ".join(r for r in e.reasons if "authentication policy" in r),
                               objective="4.3"))
    qs.append(Question(prompt="A user's sign-in to an app passes the app's authentication policy but the global "
                              "session policy rule that matches denies access. What happens?",
                       choices=["access is denied: both policies must be satisfied",
                                "access is granted because the app policy is more specific",
                                "the user is asked to enroll a new authenticator",
                                "the global session policy is skipped for app sign-ins"],
                       answer="access is denied: both policies must be satisfied",
                       explanation=cfg["concepts"]["global session policy"], objective="4.2"))
    qs.append(Question(prompt="A request comes from an IP in an active blocklist network zone. When is it rejected?",
                       choices=["before any authentication or policy rule is evaluated",
                                "after the password is checked",
                                "only if the app's authentication policy names the zone",
                                "only for users in the Everyone group"],
                       answer="before any authentication or policy rule is evaluated",
                       explanation=cfg["concepts"]["blocklist zone"], objective="4.3"))
    qs.append(Question(prompt="A group's global session policy applies, but none of its rules match the request. "
                              "What does Okta do?",
                       choices=["evaluates the next policy in priority order",
                                "denies the request immediately",
                                "applies the first rule anyway",
                                "grants a session with no MFA"],
                       answer="evaluates the next policy in priority order",
                       explanation="Okta considers rules in order; if none can be met, the next policy is considered",
                       objective="4.2"))
    qs.append(Question(prompt="Which single authenticator can satisfy 'any 2 factor types' on its own?",
                       choices=["Okta FastPass with biometrics", "Phone (SMS code)", "Password",
                                "Email magic link or code"],
                       answer="Okta FastPass with biometrics",
                       explanation="it proves possession of the device and inherence (biometric) at once",
                       objective="4.1"))
    for term in ("dynamic zone", "authenticator enrollment policy", "catch-all rule", "possession factor constraint",
                 "network zone"):
        if term in cfg["concepts"]:
            qs.append(Question(prompt=f"Which term is this? \"{cfg['concepts'][term]}\"",
                               choices=sorted(cfg["concepts"]), answer=term, explanation=cfg["concepts"][term],
                               objective="4.1" if "enrollment" in term else "4.3"))
    return qs


# --------------------------------------------------------------------------- #
# Seeded scenario generator
# --------------------------------------------------------------------------- #
_FIRST = ["ada", "bryn", "cyrus", "dina", "emil", "farah", "gael", "hugo", "isla", "joel", "kira", "luca", "mina",
          "noel", "odin", "pema", "quinn", "rhea", "soren", "tara", "umar", "vera", "wes", "ximena", "yusuf", "zoe"]
_LAST = ["abbott", "baird", "corwin", "dale", "eaton", "flynn", "gale", "hart", "ives", "judd", "keane", "lowe",
         "marsh", "north", "oakes", "price", "quill", "rowe", "shaw", "trent", "upton", "voss", "wilde", "yates"]


def generate_scenario(rng, policies: dict) -> dict:
    """A fictional org's users and sign-in attempts against the policy file's org configuration.
    Every outcome appears (the template guarantees one of each; extra random attempts add variety)."""
    cfg = policies["okta_policy_evaluator"]
    dom = "brambleway.example"
    names = iter(rng.sample([f"{f}.{l}" for f in _FIRST for l in _LAST], 20))

    def user(groups, enrolled):
        login = f"{next(names)}@{dom}"
        users[login] = {"groups": groups, "enrolled": enrolled}
        return login

    def ip(prefix, lo, hi):
        return f"{prefix}.{rng.randint(lo, hi)}"

    users: dict = {}
    admin = user(["Okta Admins"], ["password", "email", "okta_verify", "webauthn"])
    admin_new = user(["Okta Admins"], ["password", "email"])
    fin = user(["Finance"], ["password", "email", "okta_verify"])
    con = user(["Contractors"], ["password", "email", "phone"])
    staff = user(["Sales"], ["password", "email", "okta_verify"])
    staff2 = user(["Support"], ["password", "okta_verify"])          # email (required) never enrolled
    hq, home, wh = lambda: ip("198.51.100", 2, 250), lambda: ip("203.0.113", 140, 250), lambda: ip("203.0.113", 65, 126)
    reg = {"registered": True, "managed": rng.random() < 0.5, "platform": rng.choice(["macOS", "Windows"])}
    managed = {"registered": True, "managed": True, "platform": "Windows", "assurance": ["DA-WINDOWS-BASELINE"]}
    std = rng.choice(["crewboard", "timesheet"])
    atts = [
        {"user": staff, "app": std, "ip": hq(), "country": "US", "presented": [rng.choice(
            ["okta_verify_fastpass", "password"])]},
        {"user": staff, "app": std, "ip": home(), "country": rng.choice(["US", "CA"]),
         "presented": ["password", rng.choice(["okta_verify_push", "email"])]},
        {"user": admin, "app": "okta-admin", "ip": home(), "country": "US", "device": reg,
         "presented": ["password", rng.choice(["webauthn", "okta_verify_fastpass"])]},
        {"user": fin, "app": "ledger-erp", "ip": home(), "country": "US", "device": managed,
         "presented": ["password", "okta_verify_fastpass_biometric"]},
        {"user": rng.choice([staff, fin]), "app": std, "ip": ip("192.0.2", 1, 14), "country": "US",
         "presented": ["password"]},
        {"user": rng.choice([con, staff]), "app": std, "ip": home(), "country": rng.choice(["NL", "DE"]),
         "anonymizer": True, "presented": ["password"]},
        {"user": admin, "app": "okta-admin", "ip": home(), "country": rng.choice(["FR", "BR", "JP"]), "device": reg,
         "presented": ["password", "webauthn"]},
        {"user": con, "app": std, "ip": home(), "country": "US", "asn": rng.choice([64512, 64513]),
         "presented": ["password", "phone_sms"]},
        {"user": f"{next(names)}@{dom}", "app": std, "ip": hq(), "country": "US", "presented": ["password"]},
        {"user": fin, "app": "ledger-erp", "ip": home(), "country": "US",
         "device": rng.choice([{}, {"registered": True, "managed": False}]),
         "presented": ["password", "okta_verify_push"]},
        {"user": con, "app": "ledger-erp", "ip": wh(), "country": "US", "presented": ["password"]},
        {"user": admin_new, "app": "okta-admin", "ip": hq(), "country": "US", "device": reg,
         "presented": ["password", "email"]},
        {"user": staff2, "app": std, "ip": hq(), "country": "US", "presented": ["okta_verify_fastpass"]},
        {"user": staff, "app": std, "ip": home(), "country": "US",
         "presented": [rng.choice(["okta_verify_fastpass_biometric", "password"])]},
        {"user": con, "app": std, "ip": home(), "country": "CA", "presented": ["password", "phone_sms"]},
    ]
    for _ in range(rng.randint(0, 2)):
        atts.append({"user": rng.choice([staff, fin, con]), "app": rng.choice(["crewboard", "timesheet"]),
                     "ip": rng.choice([hq(), home(), wh()]), "country": "US",
                     "presented": rng.sample(["password", "email", "okta_verify_push", "phone_sms"], 2)})
    rng.shuffle(atts)
    for n, a in enumerate(atts, 1):
        a["id"] = f"S{n:02d}"
    return {"_description": "Generated Okta sign-on policy scenario (fictional).", "org_name": "Brambleway Example Co",
            "users": users, "apps": {k: dict(v) for k, v in _APPS.items()}, "attempts": atts}


_APPS = {
    "okta-admin": {"name": "Okta Admin Console", "authentication_policy": "AP-ADMIN-CONSOLE"},
    "ledger-erp": {"name": "Ledger ERP", "authentication_policy": "AP-FINANCE"},
    "crewboard": {"name": "Crewboard chat", "authentication_policy": "AP-STANDARD"},
    "timesheet": {"name": "Timesheet", "authentication_policy": "AP-STANDARD"},
}
