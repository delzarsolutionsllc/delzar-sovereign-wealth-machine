"""
Lab 30 — Hybrid Identity Planner: Sync & Authentication Methods
===============================================================

SC-300 objectives
-----------------
* 1.4  Implement and manage hybrid identity: choose and run Microsoft Entra
       Connect Sync or Microsoft Entra Cloud Sync, pick password hash sync,
       pass-through authentication or federation, staged rollout, and keep
       sync healthy.
* 2.1  Plan, implement and manage Microsoft Entra user authentication:
       which sign-in method gives resilience and leaked credential detection,
       and which one enforces on-premises sign-in rules.

How it works
------------
Part 1 plans each organisation. The authentication method is chosen first,
because it can force the sync tool. Rules, in evaluation order:

1. **ADFS_THIRD_PARTY_MFA**: an existing AD FS farm whose third-party MFA (or
   other claims logic) must stay → FEDERATION.
2. **PASSWORDS_STAY_ONPREM**: passwords (even hashes) may never leave
   on-premises → PASS_THROUGH_AUTHENTICATION.
3. **ONPREM_SIGNIN_POLICIES**: on-premises rules such as logon hours or an
   expired password must be enforced at the moment of sign-in →
   PASS_THROUGH_AUTHENTICATION.
4. **DEFAULT_PHS**: otherwise PASSWORD_HASH_SYNC, the simplest and most
   resilient method and the one Microsoft recommends by default.
   Backup: PHS itself needs none (NOT_NEEDED). PTA and federation get PHS
   turned on as a backup (it also feeds leaked credential detection) unless
   rule 2 forbids hashes, which leaves NONE. Needing leaked credential
   detection without PHS is reported as a gap.

The sync tool, in order:

1. **CONNECT_ONLY_REQUIREMENT**: PTA, federation, or any feature that only
   Connect Sync has (device sync for hybrid join, device writeback, merging one
   person across forests, advanced custom rules). An unknown feature is treated
   as Connect-only (deny by default). If disconnected forests are also present,
   Cloud Sync is run side by side for them (a supported coexistence).
2. **DISCONNECTED_FORESTS**: forests that one server cannot reach (often after a
   merger) → MICROSOFT_ENTRA_CLOUD_SYNC, whose agents sit in each forest.
3. **DEFAULT_CLOUD_SYNC**: otherwise MICROSOFT_ENTRA_CLOUD_SYNC.
   A requirement that is not stated is assumed "no" and listed for review.

Part 2 runs sync health checks:

* objects: out of the sync OU scope (or no DN) → OBJECT_FILTERED; a UPN or
  proxy address already used by a cloud object or an earlier object →
  DUPLICATE_ATTRIBUTE; a UPN suffix that is not a verified domain →
  UPN_SUFFIX_NOT_VERIFIED; else OK.
* agents: fewer active pass-through agents than the policy minimum (3) →
  PTA_AGENT_SINGLE; fewer active Cloud Sync provisioning agents than the
  minimum → AGENT_REDUNDANCY_LOW. An agent with no status counts as inactive.
* staged rollout groups: dynamic or nested group, unsupported feature or too
  many groups for one feature → STAGED_ROLLOUT_GROUP_UNSUPPORTED; more members
  than may be added at first (200) → STAGED_ROLLOUT_GROUP_TOO_LARGE.
* sync servers: no successful sync within the policy window (or unknown) →
  SYNC_STALE.

Run it
------
    python main.py --course sc300 lab 30
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

TITLE = "Lab 30 — Hybrid Identity Planner: Sync & Authentication Methods"
OBJECTIVES = "SC-300 1.4 Implement and manage hybrid identity · 2.1 Microsoft Entra user authentication"
COURSES = ("sc300",)

CLOUD_SYNC = "MICROSOFT_ENTRA_CLOUD_SYNC"
CONNECT_SYNC = "MICROSOFT_ENTRA_CONNECT_SYNC"
SYNC_TOOLS = [CLOUD_SYNC, CONNECT_SYNC]
PHS = "PASSWORD_HASH_SYNC"
PTA = "PASS_THROUGH_AUTHENTICATION"
FED = "FEDERATION"
AUTH_METHODS = [PHS, PTA, FED]
BACKUPS = [PHS, "NONE"]
AUTH_RULES = ["ADFS_THIRD_PARTY_MFA", "PASSWORDS_STAY_ONPREM", "ONPREM_SIGNIN_POLICIES", "DEFAULT_PHS"]
SYNC_RULES = ["CONNECT_ONLY_REQUIREMENT", "DISCONNECTED_FORESTS", "DEFAULT_CLOUD_SYNC"]
HEALTH_FINDINGS = ["OK", "OBJECT_FILTERED", "DUPLICATE_ATTRIBUTE", "UPN_SUFFIX_NOT_VERIFIED", "PTA_AGENT_SINGLE",
                   "AGENT_REDUNDANCY_LOW", "STAGED_ROLLOUT_GROUP_TOO_LARGE", "STAGED_ROLLOUT_GROUP_UNSUPPORTED",
                   "SYNC_STALE"]
REQUIREMENT_FIELDS = ["disconnected_forests", "passwords_must_not_leave_onprem", "onprem_signin_policies",
                      "adfs_third_party_mfa", "needs_leaked_credential_detection", "resilience_required"]


@dataclass
class Plan:
    id: str
    name: str
    auth_method: str
    auth_rule: str
    backup: str
    sync_tool: str
    sync_rule: str
    coexistence: bool = False
    leaked_credential_gap: bool = False
    needs_review: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


@dataclass
class HealthResult:
    id: str
    kind: str
    subject: str
    finding: str
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Part 1 — planning
# --------------------------------------------------------------------------- #
def _flag(profile: dict, key: str, review: list[str], reasons: list[str]) -> bool:
    """True only for an explicit True; anything else is 'no', and missing/unclear values are listed for review."""
    v = profile.get(key)
    if v is True:
        return True
    if v is not False:
        review.append(key)
        reasons.append(f"{key} not stated clearly ({v!r}): assumed no; confirm with the customer")
    return False


def choose_auth(profile: dict, cfg: dict) -> tuple[str, str, str, list[str], list[str], bool]:
    """Return (method, rule, backup, reasons, needs_review, leaked_credential_gap)."""
    review: list[str] = []
    reasons: list[str] = []
    adfs_mfa = _flag(profile, "adfs_third_party_mfa", review, reasons)
    stay = _flag(profile, "passwords_must_not_leave_onprem", review, reasons)
    onprem = _flag(profile, "onprem_signin_policies", review, reasons)
    leaked = _flag(profile, "needs_leaked_credential_detection", review, reasons)
    resilience = _flag(profile, "resilience_required", review, reasons)
    if adfs_mfa:
        method, rule = FED, "ADFS_THIRD_PARTY_MFA"
        reasons.append("existing AD FS with third-party MFA must stay, so sign-in stays federated; plan a later move "
                       "to cloud authentication with staged rollout")
        # Unsure: Microsoft Entra external authentication methods may now replace AD FS for third-party MFA;
        # the rule is kept generic (keep federation while the AD FS dependency remains).
    elif stay:
        method, rule = PTA, "PASSWORDS_STAY_ONPREM"
        reasons.append("passwords may not leave on-premises, so password hash sync is ruled out; pass-through agents "
                       "check each password against Active Directory")
    elif onprem:
        method, rule = PTA, "ONPREM_SIGNIN_POLICIES"
        reasons.append("on-premises sign-in rules (logon hours, expired or disabled accounts) must apply at sign-in; "
                       "pass-through authentication asks Active Directory every time")
    else:
        method, rule = cfg.get("default_auth_method", PHS), "DEFAULT_PHS"
        reasons.append("no requirement rules out cloud authentication, so password hash sync is chosen: simplest, "
                       "no extra on-premises sign-in dependency, and it enables leaked credential detection")
        if profile.get("existing_adfs") is True:
            reasons.append("AD FS exists but nothing requires it: move users to password hash sync with staged rollout "
                           "and retire the farm")
    if method == PHS:
        backup = "NOT_NEEDED"  # PHS is already the cloud method; there is nothing to fall back to
    elif stay:
        backup = "NONE"
        reasons.append("no password hash sync backup is allowed: if on-premises sign-in infrastructure is down, cloud "
                       "sign-in stops" + (" (conflicts with the resilience requirement; add agents/servers instead)"
                                         if resilience else ""))
    else:
        backup = PHS
        reasons.append("password hash sync is enabled as a backup, so users can still sign in if on-premises "
                       "sign-in infrastructure fails")
    has_phs = PHS in (method, backup)
    gap = leaked and not has_phs
    if gap:
        reasons.append("leaked credential detection needs password hash sync, which this organisation forbids: gap")
    elif leaked:
        reasons.append("leaked credential detection is available because password hashes are synced")
    return method, rule, backup, reasons, review, gap


def choose_sync(profile: dict, auth_method: str, cfg: dict) -> tuple[str, str, bool, list[str]]:
    """Return (sync tool, rule, coexistence, reasons)."""
    reasons: list[str] = []
    connect_only = set(cfg.get("connect_only_features", []))
    cloud_ok = set(cfg.get("cloud_sync_supported_features", []))
    features = profile.get("features") or []
    forests = profile.get("forests")
    if not isinstance(forests, int) or forests < 1:
        reasons.append(f"forest count not stated ({forests!r}): assumed one forest")
        forests = 1
    disconnected = profile.get("disconnected_forests") is True and forests > 1
    if profile.get("disconnected_forests") is True and forests == 1:
        reasons.append("disconnected forests stated but only one forest given: treated as connected")
    needs: list[str] = []
    if auth_method == PTA:
        needs.append("pass-through authentication is configured with Connect Sync")
    if auth_method == FED:
        needs.append("federation with AD FS is set up and managed through Connect Sync")
    for f in features:
        if f in connect_only:
            needs.append(f"feature '{f}' is only available in Connect Sync")
        elif f not in cloud_ok:
            needs.append(f"feature '{f}' is not on the Cloud Sync supported list: assumed Connect-only")
    # Unsure: Microsoft keeps adding Cloud Sync features (e.g. PTA support was not offered as of the last check);
    # the feature lists live in policy so they can be updated without code changes.
    if needs:
        reasons.extend(needs)
        coexist = disconnected
        if coexist:
            reasons.append("the disconnected forest cannot be reached by one Connect Sync server: run Cloud Sync side "
                           "by side for it (both tools may sync different forests into one tenant)")
        return CONNECT_SYNC, "CONNECT_ONLY_REQUIREMENT", coexist, reasons
    if disconnected:
        reasons.append(f"{forests} disconnected forests: Cloud Sync agents in each forest reach them without one "
                       "central server needing line of sight")
        return CLOUD_SYNC, "DISCONNECTED_FORESTS", False, reasons
    supported = [f for f in features if f in cloud_ok]
    reasons.append("every requirement is met by Cloud Sync, the lighter, cloud-managed option"
                   + (f" (it supports {', '.join(supported)})" if supported else ""))
    return cfg.get("default_sync_tool", CLOUD_SYNC), "DEFAULT_CLOUD_SYNC", False, reasons


def plan_org(profile: dict, cfg: dict) -> Plan:
    if not isinstance(profile, dict):
        profile = {}
    method, arule, backup, areasons, review, gap = choose_auth(profile, cfg)
    tool, srule, coexist, sreasons = choose_sync(profile, method, cfg)
    if "disconnected_forests" not in profile or profile.get("disconnected_forests") not in (True, False):
        review.append("disconnected_forests")
        sreasons.insert(0, "disconnected_forests not stated: assumed no; confirm with the customer")
    return Plan(id=str(profile.get("id", "?")), name=str(profile.get("name", "unnamed organisation")),
                auth_method=method, auth_rule=arule, backup=backup, sync_tool=tool, sync_rule=srule,
                coexistence=coexist, leaked_credential_gap=gap, needs_review=review, reasons=areasons + sreasons)


def plan_all(data: dict, cfg: dict) -> list[Plan]:
    return [plan_org(p, cfg) for p in data.get("organisations", [])]


# --------------------------------------------------------------------------- #
# Part 2 — sync health
# --------------------------------------------------------------------------- #
def _in_scope(dn: str, scope_ous: list[str]) -> bool:
    d = dn.lower().replace(" ", "")
    return any(d.endswith("," + ou.lower().replace(" ", "")) or d == ou.lower().replace(" ", "") for ou in scope_ous)


def check_objects(health: dict, cfg: dict) -> list[HealthResult]:
    scope = health.get("scope_ous") or []
    verified = {d.lower() for d in health.get("verified_domains") or []}
    claimed: dict[str, str] = {}
    for c in health.get("cloud_objects") or []:
        for v in [c.get("upn")] + list(c.get("proxy_addresses") or []):
            if v:
                claimed.setdefault(str(v).lower(), f"cloud object {c.get('id', '?')}")
    out = []
    for o in health.get("objects") or []:
        oid, upn = str(o.get("id", "?")), o.get("upn")
        dn = o.get("dn")
        if not dn:
            out.append(HealthResult(oid, "object", upn or "-", "OBJECT_FILTERED",
                                    ["no distinguished name: scope cannot be confirmed, so the object is not synced"]))
            continue
        if not _in_scope(dn, scope):
            out.append(HealthResult(oid, "object", upn or "-", "OBJECT_FILTERED",
                                    [f"{dn} is outside the sync OU scope; it is not synced (and so cannot clash)"]))
            continue
        # Unsure: UPN and proxyAddresses are compared in one namespace, case-insensitive; Microsoft Entra checks
        # each attribute's uniqueness with its own nuances (e.g. smtp: prefixes).
        clashes = []
        for v in [upn] + list(o.get("proxy_addresses") or []):
            if not v:
                continue
            key = str(v).lower()
            if key in claimed:
                clashes.append(f"'{v}' already used by {claimed[key]}")
            else:
                claimed[key] = f"object {oid}"
        if clashes:
            out.append(HealthResult(oid, "object", upn or "-", "DUPLICATE_ATTRIBUTE", clashes + [
                "duplicate attribute resiliency quarantines the value on this newer object; fix the source in AD"]))
            continue
        suffix = str(upn).rsplit("@", 1)[-1].lower() if upn and "@" in str(upn) else None
        if suffix not in verified:
            out.append(HealthResult(oid, "object", upn or "-", "UPN_SUFFIX_NOT_VERIFIED", [
                (f"UPN suffix '{suffix}' is not a verified domain" if suffix else "no usable UPN")
                + ": the user would get a tenant onmicrosoft.com UPN; add an alternate UPN suffix or verify the domain"]))
            continue
        out.append(HealthResult(oid, "object", upn, "OK", ["in scope, unique UPN and proxy addresses, verified suffix"]))
    return out


def check_agents(health: dict, cfg: dict) -> list[HealthResult]:
    out = []
    for s in health.get("agent_sets") or []:
        sid, kind = str(s.get("id", "?")), s.get("type")
        agents = s.get("agents") or []
        active = sum(1 for a in agents if a.get("status") == "active")
        if kind == "pta":
            need, bad = cfg.get("min_pta_agents", 3), "PTA_AGENT_SINGLE"
            label = "pass-through authentication agents"
        elif kind == "provisioning":
            need, bad = cfg.get("min_provisioning_agents", 3), "AGENT_REDUNDANCY_LOW"
            label = "Cloud Sync provisioning agents"
            # Unsure: Microsoft's high-availability guidance for Cloud Sync agents; 3 is kept as a policy value.
        else:
            out.append(HealthResult(sid, "agents", str(kind), "PTA_AGENT_SINGLE",
                                    [f"unknown agent type {kind!r}: treated as an under-provisioned sign-in path"]))
            continue
        inactive = len(agents) - active
        note = f" ({inactive} installed but not active)" if inactive else ""
        if active < need:
            out.append(HealthResult(sid, "agents", label, bad, [f"{active} active {label}{note}; at least {need} "
                                                                f"are recommended for high availability"]))
        else:
            out.append(HealthResult(sid, "agents", label, "OK", [f"{active} active {label} meets the minimum of {need}"]))
    return out


def check_staged_rollout(health: dict, cfg: dict) -> list[HealthResult]:
    sr = cfg.get("staged_rollout", {})
    per_feature: Counter = Counter()
    out = []
    for g in health.get("staged_rollout_groups") or []:
        gid, feature = str(g.get("id", "?")), g.get("feature")
        per_feature[feature] += 1
        members = g.get("initial_members")
        problems = []
        if feature not in sr.get("supported_features", []):
            problems.append(f"feature {feature!r} cannot be staged")
        gtype = g.get("group_type")
        if gtype in sr.get("unsupported_group_types", []) or gtype is None:
            problems.append(f"group type {gtype!r} is not supported (use an assigned cloud security group)")
        if g.get("nested") is True and not sr.get("nested_groups_supported", False):
            problems.append("nested groups are not supported; members of child groups are not included")
        if per_feature[feature] > sr.get("max_groups_per_feature", 10):
            problems.append(f"more than {sr.get('max_groups_per_feature', 10)} groups for {feature}")
        # Unsure: limits (200 users when first adding a group, 10 groups per feature, no dynamic or nested groups)
        # follow Microsoft Learn's staged rollout notes; keep them in policy.
        if problems:
            out.append(HealthResult(gid, "staged_rollout", str(g.get("group", "?")), "STAGED_ROLLOUT_GROUP_UNSUPPORTED",
                                    problems))
        elif not isinstance(members, int) or members > sr.get("max_initial_group_members", 200):
            out.append(HealthResult(gid, "staged_rollout", str(g.get("group", "?")), "STAGED_ROLLOUT_GROUP_TOO_LARGE", [
                f"{members!r} members when first added; the limit is {sr.get('max_initial_group_members', 200)} "
                "(add the group small, then add members directly)"]))
        else:
            out.append(HealthResult(gid, "staged_rollout", str(g.get("group", "?")), "OK",
                                    [f"assigned group of {members} for {feature}: within limits"]))
    return out


def check_servers(health: dict, cfg: dict) -> list[HealthResult]:
    limit = cfg.get("sync_stale_after_minutes", 180)
    # Unsure: the Connect Sync scheduler runs every 30 minutes by default; the 180-minute alert window is a
    # house threshold, not a Microsoft-published value.
    out = []
    for s in health.get("sync_servers") or []:
        sid, mins = str(s.get("id", "?")), s.get("minutes_since_last_sync")
        host = str(s.get("host", "?"))
        if not isinstance(mins, (int, float)) or isinstance(mins, bool):
            out.append(HealthResult(sid, "sync_server", host, "SYNC_STALE",
                                    ["time of last successful sync unknown: treated as stale"]))
        elif mins > limit:
            out.append(HealthResult(sid, "sync_server", host, "SYNC_STALE",
                                    [f"last successful sync {mins} minutes ago, over the {limit}-minute limit"]))
        else:
            out.append(HealthResult(sid, "sync_server", host, "OK", [f"synced {mins} minutes ago (limit {limit})"]))
    return out


def check_health(data: dict, cfg: dict) -> list[HealthResult]:
    h = data.get("health") or {}
    return check_objects(h, cfg) + check_agents(h, cfg) + check_staged_rollout(h, cfg) + check_servers(h, cfg)


def metrics(plans: list[Plan], health: list[HealthResult]) -> dict:
    return {"organisations": len(plans),
            "auth": dict(Counter(p.auth_method for p in plans)),
            "sync": dict(Counter(p.sync_tool for p in plans)),
            "phs_backup": sum(p.backup == PHS for p in plans),
            "no_backup": sum(p.backup == "NONE" and p.auth_method != PHS for p in plans),
            "coexistence": sum(p.coexistence for p in plans),
            "leaked_credential_gaps": sum(p.leaked_credential_gap for p in plans),
            "needs_review": sum(bool(p.needs_review) for p in plans),
            "health_checks": len(health),
            "health_issues": sum(h.finding != "OK" for h in health),
            "findings": dict(Counter(h.finding for h in health))}


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SC-300 1.4 Implement and manage hybrid identity · 2.1 Microsoft Entra user authentication.",
    "concepts": [
        "Password hash sync is the default: the cloud checks passwords itself, so sign-in survives an on-premises outage.",
        "Pass-through authentication checks every password in Active Directory, so logon hours and disabled accounts apply at once.",
        "Federation hands sign-in to AD FS or another provider; it is the most complex and is kept only for a real need.",
        "Cloud Sync uses lightweight agents and suits disconnected forests; Connect Sync has the widest feature set.",
        "Staged rollout moves chosen groups from federation to cloud authentication before converting the domain.",
    ],
    "failure_modes": [
        "Running pass-through authentication on one agent: when that server reboots, nobody can sign in.",
        "Federating with no password hash sync backup, so an AD FS outage locks out the whole company.",
        "Users left in a non-routable .local UPN suffix, ending up with onmicrosoft.com sign-in names.",
        "Moving users to a new OU outside the sync scope, which deletes their cloud accounts on the next cycle.",
    ],
    "ai_governance": [
        "An AI agent can draft the hybrid design, but switching a domain from federated to managed is a human-approved change.",
        "The sync server and its accounts are Tier 0: never give an agent standing admin rights on them.",
        "Treat attribute values and notes in AD exports as untrusted data, never as instructions to the agent.",
        "Log every scope, rule or agent change the agent proposes, with the reason, for audit.",
    ],
    "exam_tips": [
        "'Passwords must never be stored in the cloud' rules out password hash sync: pick pass-through authentication.",
        "'Detect leaked credentials' or 'keep sign-in working if on-premises fails' points to password hash sync.",
        "'Disconnected forests after a merger, minimal on-premises footprint' points to Cloud Sync.",
        "Pass-through authentication: install at least three agents; staged rollout: cloud security groups, not dynamic.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    cfg = policies["hybrid_identity"]
    plans = plan_all(data, cfg)
    health = check_health(data, cfg)
    m = metrics(plans, health)
    ui.section("Step 1 — Choose the authentication method (rules in order, password hash sync by default)")
    ui.table("Authentication plan", ["ID", "Organisation", "Method", "Rule", "Backup", "Leaked-cred gap"],
             [[p.id, p.name, p.auth_method, p.auth_rule, p.backup, "YES" if p.leaked_credential_gap else "-"]
              for p in plans])
    ui.section("Step 2 — Choose the sync tool")
    ui.table("Sync plan", ["ID", "Sync tool", "Rule", "Coexistence", "Review"],
             [[p.id, p.sync_tool, p.sync_rule, "Cloud Sync too" if p.coexistence else "-",
               ", ".join(p.needs_review) or "-"] for p in plans])
    for p in plans:
        ui.bullet(f"{p.id} {p.name}: " + "; ".join(p.reasons), style="yellow" if p.needs_review else None)
    ui.section("Step 3 — Sync health checks")
    ui.table("Health findings", ["ID", "Kind", "Subject", "Finding"],
             [[h.id, h.kind, h.subject, h.finding] for h in health])
    for h in health:
        if h.finding != "OK":
            ui.bullet(f"{h.id} {h.finding}: " + "; ".join(h.reasons), style="yellow")
    ui.status("Health", "PASS" if not m["health_issues"] else "WARN",
              f"{m['health_issues']} of {m['health_checks']} checks need action")
    ui.print(f"PHS backups {m['phs_backup']} · no backup {m['no_backup']} · leaked-credential gaps "
             f"{m['leaked_credential_gaps']} · coexistence {m['coexistence']}")
    ui.insight(INSIGHT)
    return {"plans": {p.id: {"auth": p.auth_method, "backup": p.backup, "sync": p.sync_tool} for p in plans},
            "health": {h.id: h.finding for h in health}, "metrics": m}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["hybrid_identity"]
    plans = plan_all(data, cfg)
    health = check_health(data, cfg)
    raw = {str(p.get("id", "?")): p for p in data.get("organisations", []) if isinstance(p, dict)}
    qs: list = []

    def ctx(pid):
        return f"profile={ {k: v for k, v in raw.get(pid, {}).items() if k != 'id'} }"

    for p in plans:
        qs.append(Question(prompt=f"{p.id} {p.name}: which sign-in method should it use?", context=ctx(p.id),
                           choices=list(AUTH_METHODS), answer=p.auth_method,
                           explanation="; ".join(p.reasons), objective="1.4"))
        qs.append(Question(prompt=f"{p.id} {p.name}: which sync tool should it deploy?", context=ctx(p.id),
                           choices=list(SYNC_TOOLS), answer=p.sync_tool, explanation="; ".join(p.reasons),
                           objective="1.4"))
    for rule in AUTH_RULES:
        p = next((x for x in plans if x.auth_rule == rule), None)
        if p:
            qs.append(Question(prompt=f"{p.id}: which authentication rule decided the method?", context=ctx(p.id),
                               choices=list(AUTH_RULES), answer=rule, explanation="; ".join(p.reasons),
                               objective="1.4"))
    for p in plans:
        if p.auth_method != PHS:
            qs.append(Question(prompt=f"{p.id} uses {p.auth_method}. What backup sign-in method does it get?",
                               context=ctx(p.id), choices=list(BACKUPS), answer=p.backup,
                               explanation="; ".join(p.reasons), objective="2.1"))
    for p in plans:
        if p.coexistence:
            qs.append(Question(prompt=f"{p.id}: how is its disconnected forest synced?", context=ctx(p.id),
                               choices=["Cloud Sync agents side by side with Connect Sync",
                                        "a second Connect Sync server in active mode for the same tenant",
                                        "the forest is left out of the tenant",
                                        "federation with the forest's domain controllers"],
                               answer="Cloud Sync agents side by side with Connect Sync",
                               explanation="; ".join(p.reasons), objective="1.4"))
            break
    seen = set()
    for h in health:
        if h.finding in seen and h.finding == "OK":
            continue
        seen.add(h.finding)
        qs.append(Question(prompt=f"{h.id} ({h.kind}: {h.subject}): what does the health check report?",
                           choices=choices_with(h.finding, HEALTH_FINDINGS, key=h.id), answer=h.finding,
                           explanation="; ".join(h.reasons), objective="1.4"))
    qs.append(Question(prompt="An organisation needs leaked credential detection. Which method must be enabled?",
                       choices=list(AUTH_METHODS), answer=PHS,
                       explanation=cfg["concepts"]["leaked credential detection"], objective="2.1"))
    qs.append(Question(prompt="Which method enforces on-premises logon hours at the moment of sign-in, without AD FS?",
                       choices=list(AUTH_METHODS), answer=PTA,
                       explanation=cfg["concepts"]["pass-through authentication"], objective="2.1"))
    n = cfg.get("min_pta_agents", 3)
    qs.append(Question(prompt="How many active pass-through authentication agents does the policy require at minimum?",
                       choices=[f"{k} agent" + ("s" if k > 1 else "") for k in sorted({1, 2, n, n + 2})],
                       answer=f"{n} agents", explanation="one agent is a single point of failure; extra agents give "
                       "high availability and load balancing", objective="1.4"))
    sr = cfg["staged_rollout"]
    qs.append(Question(prompt="Which group can be added to a staged rollout feature?",
                       choices=[f"an assigned cloud security group of up to {sr['max_initial_group_members']} users",
                                "a dynamic membership group", "a group with nested child groups",
                                "an on-premises distribution list"],
                       answer=f"an assigned cloud security group of up to {sr['max_initial_group_members']} users",
                       explanation="dynamic and nested groups are not supported, and a group is first added with at "
                       f"most {sr['max_initial_group_members']} members", objective="1.4"))
    for term in ("password hash synchronization", "Microsoft Entra Cloud Sync", "staged rollout",
                 "duplicate attribute resiliency"):
        if term in cfg["concepts"]:
            qs.append(Question(prompt=f"Which term is this? \"{cfg['concepts'][term]}\"",
                               choices=choices_with(term, cfg["concepts"], key=term), answer=term,
                               explanation=cfg["concepts"][term], objective="1.4"))
    return qs


# --------------------------------------------------------------------------- #
# Scenario generator
# --------------------------------------------------------------------------- #
_ORGS = ["Harbourline Foods", "Copperfield Clinics", "Mistral Logistics", "Bramblewood Council", "Orchid Retail",
         "Tidewater Insurance", "Saltmarsh Energy", "Juniper Schools", "Kestrel Aviation", "Quarry Lane Legal"]
_FEATURES = ["password_writeback", "exchange_hybrid_writeback", "device_sync_hybrid_join", "device_writeback",
             "group_provisioning_to_ad", "merge_identities_across_forests"]


def generate_scenario(rng, policies: dict) -> dict:
    """Seeded random scenario in the sample-data shape (uses only ``rng``)."""
    cfg = policies["hybrid_identity"]
    base = {k: False for k in REQUIREMENT_FIELDS}
    templates = [{}, {"adfs_third_party_mfa": True}, {"passwords_must_not_leave_onprem": True},
                 {"onprem_signin_policies": True}, {"disconnected_forests": True, "forests": 2},
                 {"features": ["device_writeback"]}]
    names = rng.sample(_ORGS, k=8)
    orgs = []
    for i, name in enumerate(names):
        prof = dict(base, id=f"P{i + 1:02d}", name=name, forests=rng.randint(1, 3), features=[])
        prof["disconnected_forests"] = prof["forests"] > 1 and rng.random() < 0.3
        prof.update(templates[i] if i < len(templates) else {})
        if i >= len(templates):
            prof["features"] = rng.sample(_FEATURES, k=rng.randint(0, 2))
            for k in ("onprem_signin_policies", "passwords_must_not_leave_onprem"):
                prof[k] = rng.random() < 0.2
        prof["needs_leaked_credential_detection"] = rng.random() < 0.6
        prof["resilience_required"] = rng.random() < 0.5
        orgs.append(prof)
    dom = "corp.example"
    scope = "OU=Staff,DC=corp,DC=example"
    users = rng.sample(["ana", "ben", "cai", "dee", "eli", "fay", "gus", "hal"], k=6)
    objects = [{"id": f"O{i + 1:02d}", "dn": f"CN={u},{scope}", "upn": f"{u}@{dom}",
                "proxy_addresses": [f"SMTP:{u}@{dom}"]} for i, u in enumerate(users)]
    objects[1]["dn"] = f"CN={users[1]},OU=Leavers,DC=corp,DC=example"
    objects[2]["upn"] = f"{users[0]}@{dom}"
    objects[3]["upn"] = f"{users[3]}@corp.local"
    objects[4]["proxy_addresses"] = [f"smtp:{users[5]}@{dom}".upper()]
    pta_n = rng.randint(1, 2)
    sr_max = cfg["staged_rollout"]["max_initial_group_members"]
    return {
        "_description": "Generated hybrid identity scenario.",
        "organisations": orgs,
        "health": {
            "scope_ous": [scope], "verified_domains": [dom], "cloud_objects": [],
            "objects": objects,
            "agent_sets": [{"id": "A01", "type": "pta", "agents": [{"host": f"pta{k}", "status": "active"}
                                                                  for k in range(pta_n)]},
                           {"id": "A02", "type": "pta", "agents": [{"host": f"ptb{k}", "status": "active"}
                                                                  for k in range(cfg["min_pta_agents"])]},
                           {"id": "A03", "type": "provisioning", "agents": [{"host": "cs1", "status": "active"}]}],
            "staged_rollout_groups": [
                {"id": "G01", "group": "SR-Pilot", "feature": "password_hash_sync", "group_type": "assigned",
                 "nested": False, "initial_members": rng.randint(20, sr_max)},
                {"id": "G02", "group": "SR-Wave2", "feature": "password_hash_sync", "group_type": "assigned",
                 "nested": False, "initial_members": rng.randint(sr_max + 1, sr_max * 5)},
                {"id": "G03", "group": "SR-Dynamic", "feature": "password_hash_sync", "group_type": "dynamic",
                 "nested": False, "initial_members": rng.randint(10, 100)}],
            "sync_servers": [{"id": "S01", "host": "sync01", "minutes_since_last_sync": rng.randint(5, 60)},
                             {"id": "S02", "host": "sync02", "minutes_since_last_sync": rng.randint(200, 2000)}],
        },
    }
