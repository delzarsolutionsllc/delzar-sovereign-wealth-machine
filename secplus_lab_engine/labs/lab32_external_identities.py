"""
Lab 32 — External Identities: B2B Collaboration & Cross-Tenant Access
====================================================================

SC-300 objectives
-----------------
* 1.3  Implement identities for external users and tenants: external
       collaboration settings (who can invite, allowed and denied domains),
       inviting guests, cross-tenant access settings for B2B collaboration
       and B2B direct connect, managing guest accounts over their lifetime.
* 2.2  Microsoft Entra Conditional Access: how the resource tenant's
       Conditional Access applies to external users, and how inbound trust
       settings let it accept MFA and device claims from the home tenant.

How it works
------------
You administer the Microsoft Entra tenant of a fictional company (the
*resource tenant*). Partners sign in from their own *home tenants*.

1. **Guest invitations** (external collaboration settings). An invitation
   with no known inviter or no valid email is INVITE_BLOCKED (deny by
   default). The inviter must be allowed by the guest invite level:
   ``anyone`` > ``members_and_admin_roles`` > ``admin_roles_only`` >
   ``no_one``. A guest can invite only under ``anyone`` or when it holds an
   inviter role (such as Guest Inviter). Then the guest's email domain is
   checked against the collaboration restrictions (allow any / deny list /
   allow list, case-insensitive exact domain match). Pass both →
   INVITE_ALLOWED, else INVITE_BLOCKED.
2. **External sign-ins** (cross-tenant access + Conditional Access), in order:
   a. missing home tenant, app or access type → BLOCK;
   b. the settings used are the organisational override for the home tenant
      ID, with every part not overridden inherited from the default. An
      unknown tenant gets the default, whose B2B direct connect is blocked;
   c. inbound access for that access type is blocked, or the app is not in
      the allowed applications → BLOCK. B2B direct connect also needs the
      partner's outbound setting to allow it (mutual consent) → else BLOCK;
   d. the app's Conditional Access grant controls are looked up (``*`` for
      any app not listed). A compliant-device control is met only by a
      device claim from the home tenant that inbound trust accepts
      (compliant, or hybrid joined); the resource tenant cannot check an
      external user's device itself → else BLOCK;
   e. MFA required: home MFA trusted and done → ALLOW_TRUSTED_MFA (no second
      prompt). Trusted but not yet done → REQUIRE_MFA_IN_HOME_TENANT (the user
      is sent home to complete it). Not trusted → REQUIRE_MFA_IN_RESOURCE_TENANT
      for B2B collaboration, but BLOCK for B2B direct connect, whose users have
      no account in the resource tenant to register MFA with;
   f. nothing required → ALLOW.
3. **Guest lifecycle**: an invitation still pending after N days → REMOVE.
   Inactive beyond the remove threshold, or beyond the review threshold
   with no active sponsor → REMOVE. Inactive beyond the review threshold, or
   no active sponsor → REVIEW. Otherwise KEEP. A missing last sign-in is
   treated as inactive beyond the remove threshold (deny by default).

Run it
------
    python main.py --course sc300 lab 32
"""

from __future__ import annotations

from dataclasses import dataclass, field

TITLE = "Lab 32 — External Identities: B2B Collaboration & Cross-Tenant Access"
OBJECTIVES = ("SC-300 1.3 Identities for external users and tenants · "
              "2.2 Microsoft Entra Conditional Access")
COURSES = ("sc300",)

INVITE_OUTCOMES = ["INVITE_ALLOWED", "INVITE_BLOCKED"]
SIGNIN_OUTCOMES = ["ALLOW", "ALLOW_TRUSTED_MFA", "REQUIRE_MFA_IN_HOME_TENANT",
                   "REQUIRE_MFA_IN_RESOURCE_TENANT", "BLOCK"]
LIFECYCLE_OUTCOMES = ["KEEP", "REVIEW", "REMOVE"]
ACCESS_TYPES = ("b2b_collaboration", "b2b_direct_connect")
INVITE_LEVELS = ["anyone", "members_and_admin_roles", "admin_roles_only", "no_one"]
SIGNIN_RULES = ["missing input", "inbound access", "device trust", "MFA trust", "no grant controls"]
RESTRICTION_MODES = ("allow_any", "deny_list", "allow_list")


@dataclass
class InviteResult:
    id: str
    inviter: str
    email: str
    outcome: str
    rule: str
    reasons: list[str] = field(default_factory=list)


@dataclass
class SignInResult:
    id: str
    user: str
    tenant: str
    access_type: str
    app: str
    settings: str
    outcome: str
    rule: str
    reasons: list[str] = field(default_factory=list)


@dataclass
class GuestResult:
    id: str
    upn: str
    sponsor: str
    outcome: str
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Part 1 — guest invitations (external collaboration settings)
# --------------------------------------------------------------------------- #
def domain_of(email) -> str | None:
    if not isinstance(email, str) or email.count("@") != 1:
        return None
    local, dom = email.split("@")
    return dom.strip().lower() if local.strip() and "." in dom else None


def inviter_allowed(member: dict | None, ext: dict) -> tuple[bool, str]:
    level = ext.get("guest_invite_level", "no_one")
    if level not in INVITE_LEVELS:
        return False, f"unknown guest invite level '{level}': treated as no_one (deny by default)"
    if member is None:
        return False, "inviter is not a user in this directory (deny by default)"
    if member.get("account_enabled") is False:
        return False, f"inviter {member['id']} is disabled"
    roles = [r for r in member.get("roles", []) if r in ext.get("inviter_roles", [])]
    is_member = member.get("user_type") == "member"   # missing user type = not proven a member
    if level == "no_one":
        return False, "guest invite level is no_one: nobody, not even admins, may invite"
    if roles and level != "no_one":
        return True, f"inviter holds the {roles[0]} role"
    if level == "anyone":
        return True, "guest invite level is anyone (guests and members may invite)"
    if level == "members_and_admin_roles" and is_member:
        return True, "inviter is a member and members may invite"
    who = "a guest" if member.get("user_type") == "guest" else "not proven to be a member"
    need = "a member or an inviter role" if level == "members_and_admin_roles" else "an inviter role"
    return False, f"inviter {member['id']} is {who} with no inviter role; level {level} needs {need}"


def domain_allowed(domain: str, ext: dict) -> tuple[bool, str]:
    # Exact, case-insensitive domain match. Microsoft Entra also accepts wildcard entries
    # such as *.example.com; this simulation keeps the rule to exact domains.
    cr = ext.get("collaboration_restrictions", {})
    mode = cr.get("mode", "allow_list")             # missing mode = most restrictive list
    listed = domain in {d.lower() for d in cr.get("domains", [])}
    if mode not in RESTRICTION_MODES:
        return False, f"unknown collaboration restriction mode '{mode}' (deny by default)"
    if mode == "allow_any":
        return True, "invitations may go to any domain"
    if mode == "deny_list":
        return (False, f"domain {domain} is on the deny list") if listed else \
            (True, f"domain {domain} is not on the deny list")
    return (True, f"domain {domain} is on the allow list") if listed else \
        (False, f"domain {domain} is not on the allow list")


def evaluate_invitations(data: dict, cfg: dict) -> list[InviteResult]:
    ext = cfg["external_collaboration"]
    members = {m["id"]: m for m in data.get("members", []) if "id" in m}
    out = []
    for inv in data.get("invitations", []):
        inviter, email = inv.get("inviter"), inv.get("guest_email")
        dom = domain_of(email)
        if not inviter or dom is None:
            missing = "inviter" if not inviter else "a valid guest email"
            out.append(InviteResult(inv["id"], inviter or "-", email or "-", "INVITE_BLOCKED", "missing input",
                                    [f"invitation has no {missing} (deny by default)"]))
            continue
        ok, why = inviter_allowed(members.get(inviter), ext)
        if not ok:
            out.append(InviteResult(inv["id"], inviter, email, "INVITE_BLOCKED", "inviter rights", [why]))
            continue
        ok_dom, why_dom = domain_allowed(dom, ext)
        out.append(InviteResult(inv["id"], inviter, email, "INVITE_ALLOWED" if ok_dom else "INVITE_BLOCKED",
                                "domain" if not ok_dom else "allowed", [why, why_dom]))
    return out


# --------------------------------------------------------------------------- #
# Part 2 — external sign-ins (cross-tenant access + Conditional Access)
# --------------------------------------------------------------------------- #
def effective_settings(tenant_id: str, cfg: dict) -> tuple[dict, str]:
    """Organisational override for the tenant, each part not set inherited from the default."""
    cta = cfg["cross_tenant_access"]
    default = cta["default"]
    org = cta.get("organizations", {}).get(tenant_id)
    if org is None:
        return default, "default"
    eff = {}
    for t in ACCESS_TYPES:
        eff[t] = {d: {**default[t][d], **org.get(t, {}).get(d, {})} for d in ("inbound", "outbound")}
    eff["trust"] = {**default["trust"], **org.get("trust", {})}
    return eff, org.get("name", tenant_id)


def app_allowed(direction: dict, app: str) -> bool:
    apps = direction.get("applications", "all")
    return direction.get("access") == "allow" and (apps == "all" or app in apps)


def grant_controls(app: str, cfg: dict) -> list[str]:
    ca = cfg["resource_conditional_access"]
    return list(ca.get(app, ca.get("*", ["mfa"])))


def evaluate_signin(s: dict, cfg: dict) -> SignInResult:
    tenant, app, typ = s.get("home_tenant_id"), s.get("app"), s.get("access_type")

    def res(settings, outcome, rule, reasons):
        return SignInResult(s.get("id", "?"), s.get("user", "?"), tenant or "-", typ or "-", app or "-",
                            settings, outcome, rule, reasons)

    if not tenant or not app or typ not in ACCESS_TYPES:
        what = "home tenant ID" if not tenant else "app" if not app else f"known access type (got {typ!r})"
        return res("-", "BLOCK", "missing input", [f"sign-in has no {what} (deny by default)"])
    eff, label = effective_settings(tenant, cfg)
    reasons = [f"unknown tenant {tenant}: default settings apply" if label == "default"
               else f"organisational settings for {label} (unset parts inherited from default)"]
    kind = typ.replace("b2b_", "B2B ").replace("_", " ")
    inbound = eff[typ]["inbound"]
    if inbound.get("access") != "allow":
        return res(label, "BLOCK", "inbound access", reasons + [f"inbound {kind} is blocked for this tenant"])
    if not app_allowed(inbound, app):
        return res(label, "BLOCK", "inbound access",
                   reasons + [f"app {app} is not in the inbound {kind} allowed applications"])
    if typ == "b2b_direct_connect" and s.get("partner_outbound_allows") is not True:
        return res(label, "BLOCK", "inbound access", reasons + [
            "B2B direct connect needs mutual consent: the partner's outbound setting does not allow it"])
    reasons.append(f"inbound {kind} allows {app}")
    trust = eff["trust"]
    controls = grant_controls(app, cfg)
    if "compliant_device" in controls:
        if trust.get("compliant_device") and s.get("device_compliant") is True:
            reasons.append("compliant-device claim from the home tenant is trusted")
        elif trust.get("hybrid_joined") and s.get("hybrid_joined") is True:
            reasons.append("hybrid-joined device claim from the home tenant is trusted")
        else:
            why = ("home tenant device claims are not trusted" if not (trust.get("compliant_device")
                   or trust.get("hybrid_joined")) else "no trusted device claim was presented")
            return res(label, "BLOCK", "device trust", reasons + [
                f"{app} requires a compliant device and {why}; the resource tenant cannot check an "
                "external user's device itself"])
    if "mfa" in controls:
        if trust.get("mfa") and s.get("home_mfa") is True:
            return res(label, "ALLOW_TRUSTED_MFA", "MFA trust",
                       reasons + ["MFA done in the home tenant is trusted: no second prompt"])
        if trust.get("mfa"):
            return res(label, "REQUIRE_MFA_IN_HOME_TENANT", "MFA trust", reasons + [
                "MFA trust is on but the user has not done MFA yet: sent to the home tenant to complete it"])
        if typ == "b2b_direct_connect":
            return res(label, "BLOCK", "MFA trust", reasons + [
                "MFA is required but home MFA is not trusted, and B2B direct connect users cannot register "
                "MFA in the resource tenant"])
        return res(label, "REQUIRE_MFA_IN_RESOURCE_TENANT", "MFA trust", reasons + [
            "home tenant MFA is not trusted: the guest must register and do MFA in the resource tenant"
            + (" (home MFA ignored)" if s.get("home_mfa") else "")])
    return res(label, "ALLOW", "no grant controls", reasons + [f"no grant controls required for {app}"])


def evaluate_signins(data: dict, cfg: dict) -> list[SignInResult]:
    return [evaluate_signin(s, cfg) for s in data.get("sign_ins", [])]


# --------------------------------------------------------------------------- #
# Part 3 — guest lifecycle
# --------------------------------------------------------------------------- #
def review_guests(data: dict, cfg: dict) -> list[GuestResult]:
    lc = cfg["guest_lifecycle"]
    members = {m["id"]: m for m in data.get("members", []) if "id" in m}
    out = []
    for g in data.get("guests", []):
        sp = members.get(g.get("sponsor") or "")
        sponsor_ok = bool(sp and sp.get("user_type") == "member" and sp.get("account_enabled", False))
        sp_note = (f"sponsor {sp['id']} is active" if sponsor_ok else
                   "no sponsor" if not g.get("sponsor") else f"sponsor {g['sponsor']} is not an active member")
        if g.get("invitation_state") != "Accepted":
            age = g.get("invited_days_ago")
            if age is None or age > lc["pending_invitation_expire_days"]:
                age_txt = "unknown age" if age is None else f"{age} days"
                out.append(GuestResult(g["id"], g.get("upn", "?"), g.get("sponsor") or "-", "REMOVE", [
                    f"invitation not redeemed after {age_txt} > {lc['pending_invitation_expire_days']} days"]))
                continue
            idle, idle_txt = 0, f"invitation pending {age} days (within limit)"
        else:
            idle = g.get("last_sign_in_days_ago")
            if idle is None:
                idle, idle_txt = lc["remove_after_days"] + 1, "no sign-in recorded: treated as inactive (deny by default)"
            else:
                idle_txt = f"last sign-in {idle} days ago"
        if idle > lc["remove_after_days"]:
            outcome, why = "REMOVE", f"{idle_txt} > {lc['remove_after_days']} days"
        elif idle > lc["review_after_days"] and not sponsor_ok:
            outcome, why = "REMOVE", f"{idle_txt} > {lc['review_after_days']} days and {sp_note}"
        elif idle > lc["review_after_days"]:
            outcome, why = "REVIEW", f"{idle_txt} > {lc['review_after_days']} days: ask the sponsor"
        elif not sponsor_ok:
            outcome, why = "REVIEW", f"{sp_note}: assign an accountable sponsor"
        else:
            outcome, why = "KEEP", f"{idle_txt}; {sp_note}"
        out.append(GuestResult(g["id"], g.get("upn", "?"), g.get("sponsor") or "-", outcome, [why]))
    return out


def _counts(results, outcomes) -> dict:
    return {o: sum(r.outcome == o for r in results) for o in outcomes}


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SC-300 1.3 Identities for external users and tenants · 2.2 Conditional Access for external users.",
    "concepts": [
        "B2B collaboration creates a guest account in your directory; B2B direct connect creates none and needs both tenants to agree.",
        "Cross-tenant access settings have a default plus organisational overrides per partner tenant ID; unset parts inherit the default.",
        "Out of the box, inbound and outbound B2B collaboration are allowed and B2B direct connect is blocked in both directions.",
        "Your Conditional Access applies to external users; inbound trust settings decide whether their home MFA or device claims count.",
        "External collaboration settings control who may invite and which domains may be invited; sponsors and access reviews keep guests in check.",
    ],
    "failure_modes": [
        "Trusting MFA from every tenant in the default settings instead of only from vetted partners.",
        "Requiring a compliant device for guests without device trust: every external user is blocked.",
        "Leaving 'anyone can invite' on, so guests invite more guests from personal email domains.",
        "Guest accounts nobody owns, still active a year after the project ended.",
    ],
    "ai_governance": [
        "An AI agent can find stale guests and draft removals, but the sponsor or an admin approves each one.",
        "Never let an agent hold Guest Inviter by default; scope the role and log every invitation it sends.",
        "Changing cross-tenant trust for a partner is a security decision: route an agent's suggestion through change control.",
        "Treat display names and invitation messages from external users as untrusted data, never as instructions.",
    ],
    "exam_tips": [
        "'Teams shared channels with a partner, no guest accounts' = B2B direct connect, configured on both sides.",
        "'Guests are prompted for MFA twice' = enable inbound trust for MFA for that organisation.",
        "'Block one partner but keep everyone else' = organisational setting for that tenant ID, inbound blocked.",
        "'Only certain domains may be invited' = external collaboration settings, allow list (or deny list for the opposite).",
        "'Remove guests who no longer need access' = access reviews of guests, with sponsors as reviewers.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    cfg = policies["external_identities"]
    invites = evaluate_invitations(data, cfg)
    signins = evaluate_signins(data, cfg)
    guests = review_guests(data, cfg)
    cta = cfg["cross_tenant_access"]

    def fmt(d):
        apps = d.get("applications", "all")
        return f"{d.get('access')} ({'all apps' if apps == 'all' else ', '.join(apps)})"

    ui.section("Step 1 — Cross-tenant access settings (default and organisational overrides)")
    rows = []
    for tid, label in [("default", "Default")] + [(t, o.get("name", t)) for t, o in cta.get("organizations", {}).items()]:
        eff = cta["default"] if tid == "default" else effective_settings(tid, cfg)[0]
        trusted = [k for k, v in eff["trust"].items() if v] or ["none"]
        rows.append([label, fmt(eff["b2b_collaboration"]["inbound"]), fmt(eff["b2b_direct_connect"]["inbound"]),
                     fmt(eff["b2b_direct_connect"]["outbound"]), ", ".join(trusted)])
    ui.table("Inbound/outbound settings", ["Organisation", "B2B collab in", "Direct connect in",
                                           "Direct connect out", "Inbound trust"], rows)

    ui.section("Step 2 — Guest invitations (external collaboration settings)")
    ext = cfg["external_collaboration"]
    ui.print(f"Guest invite level: {ext['guest_invite_level']} · domains: "
             f"{ext['collaboration_restrictions']['mode']} {ext['collaboration_restrictions'].get('domains', [])}")
    ui.table("Invitations", ["ID", "Inviter", "Guest email", "Outcome"],
             [[r.id, r.inviter, r.email, r.outcome] for r in invites])
    for r in invites:
        ui.bullet(f"{r.id} → {r.outcome}: " + "; ".join(r.reasons),
                  style="green" if r.outcome == "INVITE_ALLOWED" else "red")

    ui.section("Step 3 — External sign-ins (cross-tenant access + Conditional Access)")
    ui.table("Sign-ins", ["ID", "User", "Settings", "Type", "App", "Outcome"],
             [[r.id, r.user, r.settings, r.access_type, r.app, r.outcome] for r in signins])
    for r in signins:
        ui.bullet(f"{r.id} → {r.outcome} (rule: {r.rule}): " + "; ".join(r.reasons),
                  style={"BLOCK": "red", "ALLOW": "green", "ALLOW_TRUSTED_MFA": "green"}.get(r.outcome, "yellow"))

    ui.section("Step 4 — Guest lifecycle (inactivity and sponsors)")
    lc = cfg["guest_lifecycle"]
    ui.print(f"Review after {lc['review_after_days']} days inactive, remove after {lc['remove_after_days']}; "
             f"pending invitations expire after {lc['pending_invitation_expire_days']} days")
    ui.table("Guests", ["ID", "UPN", "Sponsor", "Outcome"], [[g.id, g.upn, g.sponsor, g.outcome] for g in guests])
    for g in guests:
        ui.bullet(f"{g.id} → {g.outcome}: " + "; ".join(g.reasons),
                  style={"KEEP": "green", "REMOVE": "red"}.get(g.outcome, "yellow"))
    metrics = {"invitations": _counts(invites, INVITE_OUTCOMES), "sign_ins": _counts(signins, SIGNIN_OUTCOMES),
               "guests": _counts(guests, LIFECYCLE_OUTCOMES),
               "default_settings_sign_ins": sum(r.settings == "default" for r in signins)}
    ui.print(f"Invitations {metrics['invitations']} · sign-ins {metrics['sign_ins']} · guests {metrics['guests']}")
    ui.insight(INSIGHT)
    return {"invitations": {r.id: r.outcome for r in invites}, "sign_ins": {r.id: r.outcome for r in signins},
            "guests": {g.id: g.outcome for g in guests}, "metrics": metrics}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["external_identities"]
    invites = evaluate_invitations(data, cfg)
    signins = evaluate_signins(data, cfg)
    guests = review_guests(data, cfg)
    raw_inv = {i["id"]: i for i in data.get("invitations", [])}
    raw_si = {s["id"]: s for s in data.get("sign_ins", []) if "id" in s}
    raw_g = {g["id"]: g for g in data.get("guests", [])}
    members = {m["id"]: m for m in data.get("members", []) if "id" in m}
    qs: list = []

    for r in invites:
        src = {k: v for k, v in raw_inv[r.id].items() if k != "id"}
        inviter = members.get(r.inviter)
        qs.append(Question(prompt=f"{r.id}: can this guest invitation be sent?",
                           context=f"invitation={src}\ninviter={inviter or 'not in directory'}",
                           choices=list(INVITE_OUTCOMES), answer=r.outcome, explanation="; ".join(r.reasons),
                           objective="1.3"))
    for r in signins:
        src = {k: v for k, v in raw_si.get(r.id, {}).items() if k != "id"}
        qs.append(Question(prompt=f"{r.id}: what happens when this external user signs in?",
                           context=f"sign-in={src}\nsettings used: {r.settings}",
                           choices=list(SIGNIN_OUTCOMES), answer=r.outcome, explanation="; ".join(r.reasons),
                           objective="2.2" if r.rule in ("device trust", "MFA trust") else "1.3"))
    done = set()
    for r in signins:
        if r.rule in done or r.rule == "missing input":
            continue
        done.add(r.rule)
        qs.append(Question(prompt=f"{r.id} ended as {r.outcome}. Which evaluation step decided it?",
                           choices=list(SIGNIN_RULES), answer=r.rule, explanation="; ".join(r.reasons),
                           objective="2.2" if r.rule in ("device trust", "MFA trust") else "1.3"))
    for g in guests:
        src = {k: v for k, v in raw_g[g.id].items() if k != "id"}
        qs.append(Question(prompt=f"{g.id}: what should happen to this guest account?", context=f"guest={src}",
                           choices=list(LIFECYCLE_OUTCOMES), answer=g.outcome, explanation="; ".join(g.reasons),
                           objective="1.3"))
    unknown = evaluate_signin({"id": "probe", "home_tenant_id": "00000000-unlisted-tenant",
                               "access_type": "b2b_direct_connect", "app": "teams-shared-channels",
                               "partner_outbound_allows": True, "home_mfa": True}, cfg)
    qs.append(Question(prompt="A user from a tenant with no organisational settings tries B2B direct connect. "
                              "What happens with the default settings?",
                       choices=list(SIGNIN_OUTCOMES), answer=unknown.outcome,
                       explanation="; ".join(unknown.reasons), objective="1.3"))
    qs.append(Question(prompt="Guests complete MFA at home and are then prompted for MFA again by your tenant. "
                              "What fixes the double prompt for a trusted partner?",
                       choices=["enable inbound trust for MFA in that organisation's cross-tenant settings",
                                "turn off Conditional Access for all guest users",
                                "change the guest invite level to anyone",
                                "add the partner's domain to the collaboration deny list"],
                       answer="enable inbound trust for MFA in that organisation's cross-tenant settings",
                       explanation="inbound trust lets your Conditional Access accept the home tenant's MFA claim "
                                   "instead of prompting again", objective="2.2"))
    qs.append(Question(prompt="Which external collaboration model needs both organisations to allow it, "
                              "and creates no guest account?",
                       choices=["B2B direct connect", "B2B collaboration", "Microsoft Entra External ID for customers",
                                "self-service sign-up"],
                       answer="B2B direct connect", explanation=cfg["concepts"]["B2B direct connect"], objective="1.3"))
    for term in ("cross-tenant access settings", "inbound trust settings", "organizational settings", "sponsor",
                 "external collaboration settings"):
        if term in cfg["concepts"]:
            qs.append(Question(prompt=f"Which term is this? \"{cfg['concepts'][term]}\"",
                               choices=choices_with(term, cfg["concepts"], key=term), answer=term,
                               explanation=cfg["concepts"][term],
                               objective="2.2" if term == "inbound trust settings" else "1.3"))
    return qs


# --------------------------------------------------------------------------- #
# Random scenario
# --------------------------------------------------------------------------- #
FIRST = ["Ava", "Ben", "Chloe", "Dev", "Elif", "Finn", "Grace", "Hugo", "Isla", "Jonah", "Keira", "Liam"]
LAST = ["Moss", "Hart", "Quinn", "Pike", "Rowe", "Shaw", "Tate", "Vale", "Wren", "Yates"]
APPS = ["project-hub", "finance-erp", "partner-portal", "teams-shared-channels"]


def generate_scenario(rng, policies: dict) -> dict:
    cfg = policies["external_identities"]
    orgs = list(cfg["cross_tenant_access"].get("organizations", {}))
    denied = [d for d in cfg["external_collaboration"]["collaboration_restrictions"].get("domains", [])] or \
        ["blocked.example"]
    unknown = f"{rng.randrange(16**8):08x}-0000-4000-8000-{rng.randrange(16**12):012x}"

    def person():
        return f"{rng.choice(FIRST)} {rng.choice(LAST)}"

    members = [{"id": f"U{i:03d}", "name": person(), "user_type": "member", "roles": [], "account_enabled": True}
               for i in range(1, 4)]
    members[0]["roles"] = ["User Administrator"]
    members.append({"id": "U900", "name": person(), "user_type": "guest", "roles": [], "account_enabled": True})
    members.append({"id": "U901", "name": person(), "user_type": "guest", "roles": ["Guest Inviter"],
                    "account_enabled": True})
    members.append({"id": "U902", "name": person(), "user_type": "member", "roles": [], "account_enabled": False})
    invitations = []
    for i, (inviter, dom) in enumerate([(rng.choice(["U001", "U002", "U003"]), "partner-one.example"),
                                        ("U900", "partner-two.example"), ("U901", "partner-three.example"),
                                        (rng.choice(["U002", "U003"]), rng.choice(denied)),
                                        (rng.choice(["U404", None]), "partner-one.example")], 1):
        invitations.append({"id": f"I{i:02d}", "inviter": inviter,
                            "guest_email": f"{rng.choice(FIRST).lower()}@{dom}"})
    def candidate():
        typ = rng.choice(ACCESS_TYPES)
        return {"user": f"{rng.choice(FIRST).lower()}@ext.example",
                "home_tenant_id": rng.choice(orgs + [unknown]), "access_type": typ,
                "app": "teams-shared-channels" if typ == "b2b_direct_connect" else rng.choice(APPS[:3]),
                "home_mfa": rng.random() < 0.6, "device_compliant": rng.random() < 0.5,
                "hybrid_joined": rng.random() < 0.3,
                **({"partner_outbound_allows": rng.random() < 0.7} if typ == "b2b_direct_connect" else {})}

    # One seeded candidate per outcome where the policy makes it reachable, then random extras.
    pool, picked = [candidate() for _ in range(80)], []
    for outcome in SIGNIN_OUTCOMES:
        hit = next((c for c in pool if evaluate_signin(c, cfg).outcome == outcome), None)
        if hit is not None:
            picked.append(hit)
    picked += [candidate() for _ in range(rng.randint(3, 6))]
    sign_ins = [{"id": f"S{i:02d}", **c} for i, c in enumerate(picked, 1)]
    sign_ins.append({"id": f"S{len(sign_ins) + 1:02d}", "user": "anon@ext.example", "access_type": "b2b_collaboration",
                     "app": "project-hub"})
    guests = []
    shapes = [(rng.randint(1, 60), "U002", "Accepted"), (rng.randint(91, 179), "U003", "Accepted"),
              (rng.randint(181, 400), "U002", "Accepted"), (rng.randint(1, 60), None, "Accepted"),
              (rng.randint(91, 179), "U902", "Accepted"), (None, "U001", "PendingAcceptance")]
    for i, (idle, sponsor, state) in enumerate(shapes, 1):
        g = {"id": f"G{i:02d}", "upn": f"{rng.choice(FIRST).lower()}_ext#EXT#@harborlane.example",
             "sponsor": sponsor, "invitation_state": state}
        if state == "Accepted":
            g["last_sign_in_days_ago"] = idle
        else:
            g["invited_days_ago"] = rng.randint(31, 90)
        guests.append(g)
    return {"_description": f"Random external identities scenario (seeded), unknown tenant {unknown}",
            "members": members, "invitations": invitations, "sign_ins": sign_ins, "guests": guests}
