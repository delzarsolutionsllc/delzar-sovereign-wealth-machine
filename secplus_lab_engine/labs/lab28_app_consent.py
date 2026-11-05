"""
Lab 28 — App Consent & Permission Governance
============================================

SC-300 objectives
-----------------
* 3.3  Plan and implement app registrations: delegated vs application
       permissions on Microsoft Graph, granting tenant-wide admin consent.
* 3.2  Integrate enterprise applications: user consent settings, permission
       classifications and the admin consent workflow.
* 3.4  App access with Microsoft Defender for Cloud Apps: OAuth app
       governance, banning risky apps.

When a user signs in to a third-party app for the first time, the app asks
for Microsoft Graph permissions ("read your profile", "read your mail").
Whether the user may say yes alone, must ask an administrator, or is
stopped outright is the tenant's consent policy. This module plays the
identity administrator who owns that policy, then reviews the grants that
were already given.

How it works
------------
Part 1, consent requests (first rule that fires wins):

1. **Invalid request**: no app ID or no permissions listed → BLOCKED
   (deny by default).
2. **Banned app**: the app is banned in Defender for Cloud Apps → BLOCKED.
3. **Unverified critical**: an unverified publisher, multi-tenant app that
   asks for any critical permission → BLOCKED (an organisation rule against
   illicit consent grants; Microsoft Entra on its own would ask for admin
   consent). Unknown permissions count as critical, a missing publisher
   status as unverified, a missing tenancy as multi-tenant.
4. **Application permission**: any application (app-only) permission →
   ADMIN_CONSENT_REQUIRED. Users can never consent to these.
5. **Admin-only delegated permission**: a delegated permission that Graph
   always reserves for admins (e.g. Directory.ReadWrite.All), or an unknown
   one → ADMIN_CONSENT_REQUIRED.
6. **User consent setting** ``do_not_allow`` (or missing / unknown) →
   ADMIN_CONSENT_REQUIRED.
7. **Setting** ``verified_publishers_low_impact``: the publisher must be
   verified or the app registered in this tenant (single-tenant), and every
   permission must be classified low impact → USER_CONSENT_ALLOWED;
   otherwise ADMIN_CONSENT_REQUIRED.
8. **Setting** ``allow_all`` (legacy) → USER_CONSENT_ALLOWED, with a warning.

ADMIN_CONSENT_REQUIRED requests go to the admin consent workflow reviewers
who hold a role that can grant them (application permissions on Microsoft
Graph need Global Administrator or Privileged Role Administrator). With the
workflow off, the user is simply told they need admin approval.

Part 2, review of existing grants (most severe finding wins):

* REVOKE_GRANT: banned app; unverified publisher holding an application
  permission rated high or above; a user (not admin) consented to a high-risk
  delegated permission such as Mail.Read; or unused for longer than the limit
  while holding a critical permission.
* REVIEW: unused for longer than the limit (no usage data counts as unused);
  expired credential (or no credential data for an app-only grant); any
  critical permission (needs an owner to attest); a high-risk grant to a very
  large number of users; no permission data at all.
* OK: none of the above.

Run it
------
    python main.py --course sc300 lab 28
"""

from __future__ import annotations

from dataclasses import dataclass, field

TITLE = "Lab 28 — App Consent & Permission Governance"
OBJECTIVES = ("SC-300 3.3 App registrations: delegated vs application permissions, admin consent · "
              "3.2 Enterprise apps: user consent settings, admin consent workflow · "
              "3.4 Defender for Cloud Apps app governance")
COURSES = ("sc300",)

REQUEST_OUTCOMES = ["USER_CONSENT_ALLOWED", "ADMIN_CONSENT_REQUIRED", "BLOCKED"]
GRANT_OUTCOMES = ["REVOKE_GRANT", "REVIEW", "OK"]
DECISIONS = REQUEST_OUTCOMES + GRANT_OUTCOMES

# rule id -> plain-English label (used in the demo and in "which rule fired" questions)
REQUEST_RULES = {
    "invalid_request": "Invalid request (no app ID or permissions)",
    "banned_app": "App banned in Defender for Cloud Apps",
    "unverified_critical": "Unverified multi-tenant app asking for a critical permission",
    "application_permission": "Application permission requested",
    "admin_only_permission": "Delegated permission reserved for admins",
    "consent_disabled": "User consent is turned off",
    "publisher_not_verified": "Publisher not verified and app not from this tenant",
    "not_low_impact": "Permission not classified as low impact",
    "low_impact_verified": "Verified publisher asking only for low-impact permissions",
    "allow_all": "Legacy setting lets users consent to any app",
}
GRANT_RULES = {
    "banned_app": "App banned in Defender for Cloud Apps",
    "unverified_app_permission": "Unverified publisher holds a high-risk application permission",
    "user_consented_high": "User consented to a high-risk delegated permission",
    "stale_critical": "Unused app still holds a critical permission",
    "no_permission_data": "No permission data to assess",
    "unused": "App not used within the review window",
    "credential_expired": "App credential expired or unknown",
    "privileged_grant": "Critical permission needs owner attestation",
    "wide_high": "High-risk access granted to a very large number of users",
}
SEVERITY = {"REVOKE_GRANT": 2, "REVIEW": 1, "OK": 0}
RISK_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}   # admin queue ordering only


@dataclass
class Perm:
    name: str
    type: str
    risk: str
    admin_only: bool
    known: bool


@dataclass
class RequestResult:
    id: str
    app: str
    outcome: str
    rule: str
    max_risk: str
    routed_to: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


@dataclass
class GrantResult:
    id: str
    app: str
    outcome: str
    rule: str
    max_risk: str
    findings: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Permission classification
# --------------------------------------------------------------------------- #
def _rank(risk: str, cfg: dict) -> int:
    order = cfg["risk_order"]
    return order.index(risk) if risk in order else len(order) - 1


def classify(perm, cfg: dict) -> Perm:
    """Risk of one permission. Unknown name or type → critical; a missing type → application (safer)."""
    if isinstance(perm, str):
        perm = {"name": perm}
    perm = perm if isinstance(perm, dict) else {}
    name = str(perm.get("name") or "?")
    ptype = perm.get("type") if perm.get("type") in ("delegated", "application") else "application"
    entry = cfg["permissions"].get(name, {})
    known = ptype in entry
    risk = entry[ptype] if known else cfg["risk_order"][-1]
    admin_only = ptype == "application" or not known or bool(entry.get("delegated_admin_only"))
    return Perm(name, ptype, risk, admin_only, known)


def classify_all(item: dict, cfg: dict) -> tuple[list[Perm], list[str]]:
    perms = [classify(p, cfg) for p in item.get("permissions") or []]
    notes = []
    for p, raw in zip(perms, item.get("permissions") or []):
        if not (isinstance(raw, dict) and raw.get("type") in ("delegated", "application")):
            notes.append(f"{p.name}: permission type missing/unknown, treated as application")
        if not p.known:
            notes.append(f"{p.name} ({p.type}): not in the permission catalog, treated as critical")
    return perms, notes


def max_risk(perms: list[Perm], cfg: dict) -> str:
    return max((p.risk for p in perms), key=lambda r: _rank(r, cfg), default=cfg["risk_order"][-1])


def _fmt(perms: list[Perm]) -> str:
    return ", ".join(f"{p.name} ({p.type}, {p.risk})" for p in perms)


def _verified(item: dict) -> bool:
    return item.get("publisher_verified") is True


def _tenancy(item: dict) -> str:
    return item.get("tenancy") if item.get("tenancy") in ("single", "multi") else "multi"


# --------------------------------------------------------------------------- #
# Part 1 — consent requests
# --------------------------------------------------------------------------- #
def route(perms: list[Perm], tenant: dict, cfg: dict) -> tuple[list[str], str]:
    """Admin consent workflow reviewers who can grant this request, and a reason."""
    wf = tenant.get("admin_consent_workflow") or {}
    if wf.get("enabled") is not True:
        return [], "admin consent workflow is off: the user is told to contact an admin and cannot submit a request"
    need = "application" if any(p.type == "application" for p in perms) else "delegated"
    roles = cfg["approver_roles"][need]
    reviewers = [r for r in wf.get("reviewers", []) if isinstance(r, dict)]
    ok = [r["name"] for r in reviewers if r.get("role") in roles]
    if not ok:
        return [], (f"no workflow reviewer holds a role that can grant {need} permissions ({', '.join(roles)}): "
                    "the request can only be denied or blocked until one is added")
    others = [r["name"] for r in reviewers if r.get("name") not in ok]
    return ok, (f"routed to admin consent workflow reviewers {', '.join(ok)}"
                + (f" ({', '.join(others)} can review but not grant {need} permissions)" if others else ""))


def evaluate_request(req: dict, tenant: dict, cfg: dict) -> RequestResult:
    req = req if isinstance(req, dict) else {}
    r = RequestResult(str(req.get("id", "?")), str(req.get("app", "?")), "BLOCKED", "invalid_request",
                      cfg["risk_order"][-1])
    if not req.get("app_id") or not req.get("permissions"):
        r.reasons.append("request has no app ID or no permissions listed: blocked by default")
        return r
    perms, notes = classify_all(req, cfg)
    r.max_risk = max_risk(perms, cfg)
    r.reasons += notes
    verified, tenancy = _verified(req), _tenancy(req)
    if req.get("publisher_verified") is None:
        r.reasons.append("publisher verification status missing: treated as unverified")
    if req.get("tenancy") not in ("single", "multi"):
        r.reasons.append("tenancy missing/unknown: treated as multi-tenant")

    def admin(rule: str, why: str) -> RequestResult:
        r.outcome, r.rule = "ADMIN_CONSENT_REQUIRED", rule
        r.reasons.append(why)
        r.routed_to, how = route(perms, tenant, cfg)
        r.reasons.append(how)
        return r

    if req.get("defender_status") == "banned":
        r.rule = "banned_app"
        r.reasons.append("app is banned in Defender for Cloud Apps (app governance): nobody can consent")
        return r
    critical = [p for p in perms if p.risk == cfg["risk_order"][-1]]
    if cfg.get("block_unverified_multitenant_critical", True) and not verified and tenancy == "multi" and critical:
        r.rule = "unverified_critical"
        r.reasons.append(f"unverified publisher, multi-tenant app asking for critical {_fmt(critical)}: "
                         "blocked as a likely illicit consent grant")
        return r
    app_perms = [p for p in perms if p.type == "application"]
    if app_perms:
        return admin("application_permission", f"application permissions {_fmt(app_perms)} always need admin consent")
    reserved = [p for p in perms if p.admin_only]
    if reserved:
        return admin("admin_only_permission", f"delegated {_fmt(reserved)} can only be granted by an administrator")
    setting = tenant.get("user_consent")
    if setting not in cfg["user_consent_settings"] or setting == "do_not_allow":
        if setting not in cfg["user_consent_settings"]:
            r.reasons.append(f"user consent setting '{setting}' missing/unknown: treated as do_not_allow")
        return admin("consent_disabled", "user consent is not allowed in this tenant: an admin must consent")
    if setting == "allow_all":
        r.outcome, r.rule = "USER_CONSENT_ALLOWED", "allow_all"
        r.reasons.append("legacy 'allow user consent for all apps' setting: the user may consent "
                         "(Microsoft recommends restricting this)")
        return r
    if not verified and tenancy != "single":
        return admin("publisher_not_verified", "publisher is not verified and the app is not registered in this tenant")
    not_low = [p for p in perms if p.name not in cfg["low_impact_permissions"]]
    if not_low:
        return admin("not_low_impact", f"{_fmt(not_low)} not classified as low impact")
    r.outcome, r.rule = "USER_CONSENT_ALLOWED", "low_impact_verified"
    who = "verified publisher" if verified else "app registered in this tenant"
    r.reasons.append(f"{who} asking only for low-impact delegated permissions ({_fmt(perms)}): user may consent")
    return r


def matching_rules(req: dict, tenant: dict, cfg: dict) -> list[str]:
    """Every request rule whose condition holds, in evaluation order (the first one decides).
    Used to keep "which rule fired" questions free of a second true answer."""
    req = req if isinstance(req, dict) else {}
    if not req.get("app_id") or not req.get("permissions"):
        return ["invalid_request"]
    perms, _ = classify_all(req, cfg)
    verified, tenancy, setting = _verified(req), _tenancy(req), tenant.get("user_consent")
    crit = cfg["risk_order"][-1]
    checks = [
        ("banned_app", req.get("defender_status") == "banned"),
        ("unverified_critical", cfg.get("block_unverified_multitenant_critical", True) and not verified
         and tenancy == "multi" and any(p.risk == crit for p in perms)),
        ("application_permission", any(p.type == "application" for p in perms)),
        ("admin_only_permission", any(p.admin_only for p in perms)),
        ("consent_disabled", setting not in cfg["user_consent_settings"] or setting == "do_not_allow"),
        ("allow_all", setting == "allow_all"),
        ("publisher_not_verified", setting == "verified_publishers_low_impact" and not verified and tenancy != "single"),
        ("not_low_impact", setting == "verified_publishers_low_impact"
         and any(p.name not in cfg["low_impact_permissions"] for p in perms)),
    ]
    hits = [rule for rule, ok in checks if ok]
    return hits or ["low_impact_verified"]


def evaluate_requests(data: dict, cfg: dict) -> list[RequestResult]:
    tenant = data.get("tenant") or {}
    return [evaluate_request(x, tenant, cfg) for x in data.get("requests", [])]


# --------------------------------------------------------------------------- #
# Part 2 — review existing grants
# --------------------------------------------------------------------------- #
def review_grant(g: dict, cfg: dict) -> GrantResult:
    g = g if isinstance(g, dict) else {}
    rv = cfg["review"]
    res = GrantResult(str(g.get("id", "?")), str(g.get("app", "?")), "OK", "", cfg["risk_order"][-1])
    hits: list[tuple[str, str, str]] = []           # (outcome, rule, reason)
    if g.get("defender_status") == "banned":
        hits.append(("REVOKE_GRANT", "banned_app", "app is banned in Defender for Cloud Apps: revoke its consent"))
    if not g.get("app_id") or not g.get("permissions"):
        hits.append(("REVIEW", "no_permission_data", "no app ID or permission data: cannot be marked OK, investigate"))
        perms, notes = [], []
    else:
        perms, notes = classify_all(g, cfg)
        res.max_risk = max_risk(perms, cfg)
    res.reasons += notes
    rank = lambda p: _rank(p.risk, cfg)
    crit = cfg["risk_order"][-1]
    if not _verified(g):
        bad = [p for p in perms if p.type == "application" and rank(p) >= _rank(rv["revoke_unverified_application_risk"], cfg)]
        if bad:
            hits.append(("REVOKE_GRANT", "unverified_app_permission",
                         f"unverified publisher holds application {_fmt(bad)}"))
    consent = g.get("consent_type") if g.get("consent_type") in ("admin", "user") else "user"
    if g.get("consent_type") not in ("admin", "user"):
        res.reasons.append("consent type missing/unknown: treated as user consent")
    if consent == "user":
        bad = [p for p in perms if p.type == "delegated" and rank(p) >= _rank(rv["revoke_user_consented_delegated_risk"], cfg)]
        if bad:
            hits.append(("REVOKE_GRANT", "user_consented_high",
                         f"a user consented to {_fmt(bad)}: today's consent policy would not allow this "
                         "(illicit consent grant pattern)"))
    days = g.get("last_used_days_ago")
    stale = not isinstance(days, (int, float)) or days > rv["unused_after_days"]
    when = "no usage data (treated as unused)" if not isinstance(days, (int, float)) else f"last used {days} days ago"
    critical = [p for p in perms if p.risk == crit]
    if stale and critical:
        hits.append(("REVOKE_GRANT", "stale_critical", f"{when}, still holding critical {_fmt(critical)}"))
    elif stale and perms:
        hits.append(("REVIEW", "unused", f"{when} (limit {rv['unused_after_days']} days): confirm with the owner or remove"))
    exp = g.get("credential_expires_in_days")
    if isinstance(exp, (int, float)) and exp < 0:
        hits.append(("REVIEW", "credential_expired", f"credential expired {abs(exp)} days ago: rotate it or retire the app"))
    elif exp is None and any(p.type == "application" for p in perms):
        hits.append(("REVIEW", "credential_expired", "no credential data for an app-only grant: check secrets and certificates"))
    if critical and not stale:
        hits.append(("REVIEW", "privileged_grant", f"critical {_fmt(critical)}: owner must attest the need"))
    users = g.get("consented_users")
    wide = [p for p in perms if rank(p) >= _rank(rv["wide_grant_risk"], cfg)]
    if isinstance(users, int) and users >= rv["wide_grant_users"] and wide:
        hits.append(("REVIEW", "wide_high", f"{users} users covered by {_fmt(wide)} (threshold {rv['wide_grant_users']})"))
    if not hits:
        res.rule = "ok"
        res.reasons.append(f"used within {rv['unused_after_days']} days, no risky pattern, highest risk {res.max_risk}: no action")
        return res
    hits.sort(key=lambda h: -SEVERITY[h[0]])           # stable: rule order within a severity is kept
    res.outcome, res.rule = hits[0][0], hits[0][1]
    res.findings = [h[1] for h in hits]
    res.reasons = [h[2] for h in hits] + res.reasons
    return res


def review_grants(data: dict, cfg: dict) -> list[GrantResult]:
    return [review_grant(g, cfg) for g in data.get("grants", [])]


def metrics(reqs: list[RequestResult], grants: list[GrantResult], data: dict) -> dict:
    raw = {x.get("id"): x for x in data.get("requests", []) if isinstance(x, dict)}
    queue = sorted((r for r in reqs if r.outcome == "ADMIN_CONSENT_REQUIRED"),
                   key=lambda r: (-RISK_RANK.get(r.max_risk, 3), -int(raw.get(r.id, {}).get("requesting_users") or 0)))
    return {"requests": {o: sum(r.outcome == o for r in reqs) for o in REQUEST_OUTCOMES},
            "grants": {o: sum(g.outcome == o for g in grants) for o in GRANT_OUTCOMES},
            "admin_queue": [r.id for r in queue],
            "unrouted": [r.id for r in queue if not r.routed_to]}


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SC-300 3.3 App permissions and admin consent · 3.2 User consent settings and admin consent workflow "
                 "· 3.4 Defender for Cloud Apps app governance.",
    "concepts": [
        "Delegated permissions act as the signed-in user; application permissions act as the app itself, tenant-wide.",
        "Users can never consent to application permissions, and some delegated ones (Directory.*.All) are admin-only.",
        "The recommended user consent setting allows only verified publishers (or in-tenant apps) and low-impact permissions.",
        "The admin consent workflow turns 'Need admin approval' into a request that named reviewers can approve, deny or block.",
        "Consent creates a grant that persists after the user forgets the app: review and revoke grants regularly.",
    ],
    "failure_modes": [
        "Leaving 'allow user consent for all apps' on, so a phishing link can win Mail.Read without stealing a password.",
        "Turning user consent off with no admin consent workflow, so users route around IT with shadow apps.",
        "Granting tenant-wide admin consent to a test app and never removing it after the project ends.",
        "Naming workflow reviewers who lack the role to grant application permissions, so requests stall.",
        "Ignoring expired secrets and unused service principals that still hold Directory.ReadWrite.All.",
    ],
    "ai_governance": [
        "An AI agent is an app: register it, give it the fewest Graph permissions, and prefer delegated over application.",
        "Do not let an agent grant consent to itself or to other apps; consent stays a human admin decision.",
        "An agent may triage the consent queue and draft revocations, showing the rule and reasons for each.",
        "Treat app names and descriptions in consent prompts as untrusted text, never as instructions.",
    ],
    "exam_tips": [
        "'Users must request access to apps, and admins approve' = enable the admin consent workflow.",
        "'Let users consent only to low-risk permissions from verified publishers' = user consent settings + permission classifications.",
        "'Daemon or background service with no user' = application permissions + admin consent.",
        "'Detect and ban an OAuth app with excessive permissions' = Defender for Cloud Apps app governance / OAuth app policies.",
        "Granting Microsoft Graph application permissions needs Privileged Role Administrator (or Global Administrator).",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    cfg = policies["app_consent"]
    tenant = data.get("tenant") or {}
    reqs, grants = evaluate_requests(data, cfg), review_grants(data, cfg)
    m = metrics(reqs, grants, data)
    raw = {x.get("id"): x for x in data.get("requests", []) if isinstance(x, dict)}
    ui.section("Step 1 — Tenant consent settings")
    wf = tenant.get("admin_consent_workflow") or {}
    setting = tenant.get("user_consent", "missing")
    ui.table("Settings", ["Setting", "Value"], [
        ["User consent", f"{setting}: {cfg['user_consent_settings'].get(setting, 'unknown, treated as do_not_allow')}"],
        ["Low-impact permissions", ", ".join(cfg["low_impact_permissions"])],
        ["Admin consent workflow", "on" if wf.get("enabled") is True else "off"],
        ["Reviewers", ", ".join(f"{r.get('name')} ({r.get('role')})" for r in wf.get("reviewers", [])) or "none"]])
    ui.section("Step 2 — Consent requests")
    ui.table("Requests", ["ID", "App", "Publisher", "Tenancy", "Users", "Highest risk", "Rule", "Outcome"],
             [[r.id, r.app, "verified" if _verified(raw.get(r.id, {})) else "unverified",
               _tenancy(raw.get(r.id, {})), raw.get(r.id, {}).get("requesting_users", "-"), r.max_risk,
               r.rule, r.outcome] for r in reqs])
    for r in reqs:
        ui.bullet(f"{r.id} {r.app} → {r.outcome}: " + "; ".join(r.reasons),
                  style={"USER_CONSENT_ALLOWED": "green", "BLOCKED": "red"}.get(r.outcome, "yellow"))
    ui.print(f"Admin consent queue (riskiest first, then most requesters): {', '.join(m['admin_queue']) or 'empty'}")
    ui.section("Step 3 — Review of existing grants")
    ui.table("Grants", ["ID", "App", "Highest risk", "Findings", "Outcome"],
             [[g.id, g.app, g.max_risk, ", ".join(g.findings) or "-", g.outcome] for g in grants])
    for g in grants:
        ui.bullet(f"{g.id} {g.app} → {g.outcome}: " + "; ".join(g.reasons),
                  style={"OK": "green", "REVOKE_GRANT": "red"}.get(g.outcome, "yellow"))
    ui.print("Requests: " + ", ".join(f"{k} {v}" for k, v in m["requests"].items())
             + " · Grants: " + ", ".join(f"{k} {v}" for k, v in m["grants"].items()))
    ui.insight(INSIGHT)
    return {"requests": {r.id: r.outcome for r in reqs}, "grants": {g.id: g.outcome for g in grants}, "metrics": m}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def _ctx(item: dict) -> str:
    perms = "; ".join(f"{p.get('name')} ({p.get('type', 'type?')})" if isinstance(p, dict) else str(p)
                      for p in item.get("permissions") or []) or "none"
    keys = ("publisher_verified", "tenancy", "defender_status", "consent_type", "consented_users", "requesting_users",
            "last_used_days_ago", "credential_expires_in_days")
    return f"{item.get('app', '?')}: permissions {perms}; " + ", ".join(f"{k}={item.get(k)}" for k in keys if k in item)


def _concept_objective(term: str) -> str:
    return {"admin consent workflow": "3.2", "permission classification": "3.2", "app governance": "3.4",
            "illicit consent grant": "3.4"}.get(term, "3.3")


def _semantics(cfg: dict) -> list:
    """Concept checks whose answers come from running the engine on small cases."""
    from utils.challenge import Question

    tenant = {"user_consent": "verified_publishers_low_impact",
              "admin_consent_workflow": {"enabled": True, "reviewers": [{"name": "R", "role": "Global Administrator"}]}}
    base = {"id": "Q", "app": "X", "app_id": "x", "publisher_verified": True, "tenancy": "multi",
            "permissions": [{"name": "User.Read", "type": "delegated"}]}
    cases = [
        ("A verified, multi-tenant app asks for User.Read.All as an APPLICATION permission. What happens?",
         {**base, "permissions": [{"name": "User.Read.All", "type": "application"}]}, tenant,
         "application permissions always need admin consent"),
        ("A user consent setting of 'do not allow' meets a verified app asking only for User.Read. What happens?",
         base, {**tenant, "user_consent": "do_not_allow"}, "with user consent off, every app needs an admin"),
        ("An app asks for a permission the catalog has never seen. The publisher is verified. What happens?",
         {**base, "permissions": [{"name": "Unknown.Everything", "type": "delegated"}]}, tenant,
         "unknown permissions are treated as critical and admin-only"),
        ("An unverified app registered in YOUR OWN tenant asks for User.Read and openid. What happens?",
         {**base, "publisher_verified": False, "tenancy": "single",
          "permissions": [{"name": "User.Read", "type": "delegated"}, {"name": "openid", "type": "delegated"}]},
         tenant, "apps registered in this organisation count like verified publishers for low-impact consent"),
    ]
    return [Question(prompt=p, choices=REQUEST_OUTCOMES, answer=(r := evaluate_request(req, t, cfg)).outcome,
                     explanation=f"{why}: " + "; ".join(r.reasons), objective="3.2" if "setting" in p else "3.3")
            for p, req, t, why in cases]


def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["app_consent"]
    tenant = data.get("tenant") or {}
    raw_r = {x.get("id"): x for x in data.get("requests", []) if isinstance(x, dict)}
    raw_g = {x.get("id"): x for x in data.get("grants", []) if isinstance(x, dict)}
    setting = f"tenant user consent setting: {tenant.get('user_consent', 'missing')}"
    qs: list = []
    reqs = evaluate_requests(data, cfg)
    for r in reqs:
        obj = "3.4" if r.rule == "banned_app" else "3.2" if r.rule in ("consent_disabled", "publisher_not_verified",
                                                                        "not_low_impact", "low_impact_verified") else "3.3"
        qs.append(Question(prompt=f"{r.id}: what happens to this consent request?",
                           context=_ctx(raw_r.get(r.id, {})) + "\n" + setting, choices=REQUEST_OUTCOMES,
                           answer=r.outcome, explanation="; ".join(r.reasons), objective=obj))
    seen = set()
    for r in reqs:
        if r.rule in seen or r.rule == "invalid_request":
            continue
        seen.add(r.rule)
        label = REQUEST_RULES[r.rule]
        also = [REQUEST_RULES[x] for x in matching_rules(raw_r.get(r.id, {}), tenant, cfg)]
        qs.append(Question(prompt=f"{r.id}: which rule decided the outcome ({r.outcome})?",
                           context=_ctx(raw_r.get(r.id, {})) + "\n" + setting,
                           choices=choices_with(label, REQUEST_RULES.values(), exclude=also, key=r.id), answer=label,
                           explanation=r.reasons[-1] if r.outcome == "ADMIN_CONSENT_REQUIRED" and len(r.reasons) > 1
                           else "; ".join(r.reasons), objective="3.4" if r.rule == "banned_app" else "3.2"))
    routed = next((r for r in reqs if r.routed_to and any(
        isinstance(p, dict) and p.get("type") == "application" for p in raw_r.get(r.id, {}).get("permissions", []))), None)
    if routed:
        names = [x.get("name") for x in (tenant.get("admin_consent_workflow") or {}).get("reviewers", [])]
        ans = ", ".join(routed.routed_to)
        opts = sorted({ans, *[n for n in names if n not in routed.routed_to], "Any user who requested the app"})
        qs.append(Question(prompt=f"{routed.id} asks for application permissions. Which reviewer(s) can grant it?",
                           context=f"reviewers: {(tenant.get('admin_consent_workflow') or {}).get('reviewers')}",
                           choices=opts, answer=ans, explanation=routed.reasons[-1], objective="3.3"))
    for g in review_grants(data, cfg):
        qs.append(Question(prompt=f"{g.id}: what should happen to this existing grant?",
                           context=_ctx(raw_g.get(g.id, {})), choices=GRANT_OUTCOMES, answer=g.outcome,
                           explanation="; ".join(g.reasons),
                           objective="3.4" if g.rule in ("banned_app", "user_consented_high") else "3.3"))
    for term, definition in sorted(cfg["concepts"].items()):
        qs.append(Question(prompt=f"Which term is this? \"{definition}\"",
                           choices=choices_with(term, cfg["concepts"], k=3, key=term), answer=term,
                           explanation=f"{term}: {definition}", objective=_concept_objective(term)))
    return qs + _semantics(cfg)


# --------------------------------------------------------------------------- #
# Seeded scenario generator
# --------------------------------------------------------------------------- #
_APPS = ["Quillnote", "Brightdesk", "Tallyho Sheets", "Mosswire Chat", "Pebblepoint", "Driftmail", "Lumen Forms",
         "Copperfox Sync", "Harbor Reports", "Juniper Tasks", "Owlpost Mailer", "Cinder Backup", "Maple Planner",
         "Ridge Analytics", "Saltbox Notes"]


def generate_scenario(rng, policies: dict) -> dict:
    """Fresh, reproducible scenario in the shape of data/sample_app_consent.json (uses only ``rng``)."""
    cfg = policies["app_consent"]
    names = rng.sample(_APPS, len(_APPS))
    d = lambda n: {"name": n, "type": "delegated"}
    a = lambda n: {"name": n, "type": "application"}
    low = [p for p in cfg["low_impact_permissions"] if "delegated" in cfg["permissions"].get(p, {})]
    by = lambda t, risks: sorted(n for n, e in cfg["permissions"].items() if e.get(t) in risks)
    high_d = [n for n in by("delegated", ("high",)) if not cfg["permissions"][n].get("delegated_admin_only")]
    crit_d, app_any = by("delegated", ("critical",)), by("application", ("medium", "high", "critical"))
    app_hi, crit_a = by("application", ("high", "critical")), by("application", ("critical",))
    req_templates = [
        dict(publisher_verified=True, tenancy="multi", permissions=[d(p) for p in rng.sample(low, 2)]),
        dict(publisher_verified=False, tenancy="single", permissions=[d(rng.choice(low))]),
        dict(publisher_verified=True, tenancy="multi", permissions=[d(rng.choice(low)), d(rng.choice(high_d))]),
        dict(publisher_verified=False, tenancy="multi", permissions=[d(rng.choice(low))]),
        dict(publisher_verified=True, tenancy="multi", permissions=[a(rng.choice(app_any))]),
        dict(publisher_verified=False, tenancy="multi", permissions=[d(rng.choice(crit_d))]),
        dict(publisher_verified=True, tenancy="multi", permissions=[d(rng.choice(low))], defender_status="banned"),
        dict(publisher_verified=True, tenancy="multi", permissions=[d("Unknown.Scope.All")]),
    ]
    rng.shuffle(req_templates)
    requests = []
    for i, t in enumerate(req_templates, 1):
        requests.append({"id": f"R{i:02d}", "app": names[i - 1], "app_id": f"app-{rng.randrange(16**6):06x}",
                         "requesting_users": rng.randint(1, 40), **t})
    grant_templates = [
        dict(publisher_verified=True, tenancy="multi", consent_type="admin", permissions=[d(rng.choice(low))],
             last_used_days_ago=rng.randint(0, 30), consented_users=rng.randint(10, 200)),
        dict(publisher_verified=False, tenancy="multi", consent_type="user", permissions=[d(rng.choice(high_d))],
             last_used_days_ago=rng.randint(0, 30), consented_users=1),
        dict(publisher_verified=False, tenancy="multi", consent_type="admin", permissions=[a(rng.choice(app_hi))],
             last_used_days_ago=rng.randint(0, 30), credential_expires_in_days=rng.randint(30, 300)),
        dict(publisher_verified=True, tenancy="multi", consent_type="admin", permissions=[d(rng.choice(low))],
             last_used_days_ago=rng.randint(100, 400), consented_users=rng.randint(5, 50)),
        dict(publisher_verified=True, tenancy="single", consent_type="admin", permissions=[a(rng.choice(app_hi))],
             last_used_days_ago=rng.randint(0, 20), credential_expires_in_days=-rng.randint(1, 60)),
        dict(publisher_verified=True, tenancy="single", consent_type="admin", permissions=[a(rng.choice(crit_a))],
             last_used_days_ago=rng.randint(100, 400), credential_expires_in_days=rng.randint(30, 300)),
    ]
    rng.shuffle(grant_templates)
    grants = []
    for i, t in enumerate(grant_templates, 1):
        grants.append({"id": f"G{i:02d}", "app": names[-i], "app_id": f"app-{rng.randrange(16**6):06x}", **t})
    return {"_description": "Generated app consent scenario.",
            "tenant": {"name": "Generated Example Tenant", "user_consent": "verified_publishers_low_impact",
                       "admin_consent_workflow": {"enabled": True, "reviewers": [
                           {"name": "Cloud App Admin", "role": "Cloud Application Administrator"},
                           {"name": "Privileged Role Admin", "role": "Privileged Role Administrator"}]}},
            "requests": requests, "grants": grants}
