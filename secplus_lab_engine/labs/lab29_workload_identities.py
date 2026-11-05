"""
Lab 29 — Workload Identities: Managed Identities, Service Principals & Azure RBAC
================================================================================

SC-300 objectives
-----------------
* 3.1  Identities for applications and Azure workloads: choose between
       managed identities (system-assigned or user-assigned) and service
       principals, assign Azure roles to them, and keep their credentials safe.
* 4.3  Privileged access (PIM) for Azure resource roles: privileged roles
       such as Owner and Contributor at broad scope are standing privilege;
       humans get them as eligible, time-limited assignments, workloads get
       a narrower role instead.

Software needs an identity too. Code that reads a storage account, deploys
from a pipeline or exports payroll must sign in to Microsoft Entra ID, and
the safest identity is the one that has no secret anybody can copy.

How it works
------------
Part 1 — identity-type planner. Each workload is checked against ordered
rules; the first match wins:

1. Hosted on an Azure service that supports managed identities AND used by
   several Azure resources (``resources`` >= policy minimum) or created
   before the resource exists (``pre_provisioned``) → USER_ASSIGNED_MI.
2. Hosted on such an Azure service, one resource → SYSTEM_ASSIGNED_MI
   (the identity lives and dies with that resource).
3. Hosted outside Azure on a platform that issues OpenID Connect (OIDC)
   tokens Entra can trust (``oidc_federation`` true, for example GitHub
   Actions or a Kubernetes cluster) → SERVICE_PRINCIPAL_WITH_FEDERATED_CREDENTIAL.
4. Everything else, including unknown hosting or a missing flag →
   SERVICE_PRINCIPAL_WITH_CERTIFICATE. A client secret is never recommended
   (deny by default: when in doubt, choose the credential that is hardest to leak).

Part 2 — audit of existing service principals and managed identities. Every
check runs and each finding maps to a fix action; the item's headline action
is the most urgent by ``action_priority``:

1. UNUSED → DISABLE_UNUSED: last sign-in older than ``unused_after_days``,
   or no sign-in recorded at all.
2. PRIVILEGED_BROAD_SCOPE → REDUCE_SCOPE: a privileged role (Owner,
   Contributor, User Access Administrator ... or ANY role the policy does not
   list as least-privilege) at subscription, management-group or root scope
   (a missing scope counts as broad).
3. Client secrets (service principals only; Azure manages managed-identity
   credentials): a secret on a workload that could federate →
   REPLACE_SECRET_WITH_FEDERATION; otherwise expired, expiring within
   ``expiring_soon_days``, lifetime over ``max_secret_lifetime_days``, unknown
   expiry or simply present → ROTATE (to a certificate). Expired or expiring
   certificates → ROTATE.
4. NO_OWNER → ASSIGN_OWNER: a service principal with no named owner (an
   unknown principal type is treated as a service principal).
5. No finding → OK.

Run it
------
    python main.py --course sc300 lab 29
"""

from __future__ import annotations

from dataclasses import dataclass, field

TITLE = "Lab 29 — Workload Identities: Managed Identities, Service Principals & Azure RBAC"
OBJECTIVES = ("SC-300 3.1 Identities for applications and Azure workloads · "
              "4.3 Privileged access (PIM) for Azure resource roles")
COURSES = ("sc300",)

IDENTITY_TYPES = ["SYSTEM_ASSIGNED_MI", "USER_ASSIGNED_MI", "SERVICE_PRINCIPAL_WITH_FEDERATED_CREDENTIAL",
                  "SERVICE_PRINCIPAL_WITH_CERTIFICATE"]
ACTIONS = ["REPLACE_SECRET_WITH_FEDERATION", "ROTATE", "ASSIGN_OWNER", "REDUCE_SCOPE", "DISABLE_UNUSED", "OK"]
TYPE_LABELS = {
    "SYSTEM_ASSIGNED_MI": "system-assigned managed identity",
    "USER_ASSIGNED_MI": "user-assigned managed identity",
    "SERVICE_PRINCIPAL_WITH_FEDERATED_CREDENTIAL": "service principal with a federated credential",
    "SERVICE_PRINCIPAL_WITH_CERTIFICATE": "service principal with a certificate",
}


@dataclass
class PlanResult:
    id: str
    name: str
    hosting: str
    rule: str
    outcome: str
    reasons: list[str] = field(default_factory=list)


@dataclass
class AuditResult:
    id: str
    name: str
    type: str
    action: str
    findings: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Part 1 — identity-type planner
# --------------------------------------------------------------------------- #
def _rule_outcome(cfg: dict, name: str) -> str:
    return next(r["outcome"] for r in cfg["planner_rules"] if r["name"] == name)


def plan_identity(w: dict, cfg: dict) -> PlanResult:
    """Recommend an identity type for one workload (first matching rule wins)."""
    hosting = w.get("hosting") or "unknown"
    name = w.get("name", "?")
    reasons: list[str] = []
    in_azure = hosting in cfg["azure_hosting"]
    # A missing managed_identity_supported flag on a listed Azure service means "supported";
    # an explicit False (e.g. the target service does not accept managed-identity tokens) falls through.
    mi_ok = in_azure and w.get("managed_identity_supported", True) is not False
    resources = w.get("resources")
    if not isinstance(resources, int) or resources < 1:
        resources = 1  # unknown count: assume one resource (the tightest lifecycle)
        if in_azure:
            reasons.append("resource count missing: assumed a single resource")
    if mi_ok:
        reasons.append(f"runs on Azure ({hosting}), which supports managed identities: no credential to store")
        if resources >= cfg["user_assigned_min_resources"] or w.get("pre_provisioned"):
            rule = "azure_shared_or_preprovisioned"
            if resources >= cfg["user_assigned_min_resources"]:
                reasons.append(f"shared by {resources} Azure resources (>= {cfg['user_assigned_min_resources']}): "
                               "one user-assigned identity, one set of role assignments")
            if w.get("pre_provisioned"):
                reasons.append("identity and its roles must exist before the resource is (re)created: "
                               "a user-assigned identity is a separate resource with its own lifecycle")
        else:
            rule = "azure_single_resource"
            reasons.append("used by one resource only: a system-assigned identity is deleted with it, "
                           "so nothing is left behind")
    elif in_azure:
        reasons.append(f"runs on Azure ({hosting}) but a managed identity cannot be used here")
        rule = "fallback_certificate"
    elif hosting in cfg["external_hosting"] and w.get("oidc_federation") is True:
        rule = "external_oidc_federation"
        reasons.append(f"runs outside Azure ({hosting}) on a platform that issues OIDC tokens: "
                       "a federated identity credential trusts that token, no secret is stored")
    else:
        rule = "fallback_certificate"
        if hosting not in cfg["external_hosting"]:
            what = "not recorded" if hosting == "unknown" else f"'{hosting}' is not a known platform"
            reasons.append(f"hosting {what}: cannot assume managed identity or federation (deny by default)")
        else:
            reasons.append(f"runs outside Azure ({hosting}) with no OIDC federation available")
    if rule == "fallback_certificate":
        reasons.append("use a certificate credential (private key kept in a vault or HSM), never a client secret")
    return PlanResult(w.get("id", "?"), name, hosting, rule, _rule_outcome(cfg, rule), reasons)


def plan_all(data: dict, cfg: dict) -> list[PlanResult]:
    return [plan_identity(w, cfg) for w in data.get("workloads", [])]


# --------------------------------------------------------------------------- #
# Part 2 — workload identity audit
# --------------------------------------------------------------------------- #
def role_is_privileged(role, cfg: dict) -> bool:
    """Listed privileged roles AND any role the policy does not know are privileged (deny by default)."""
    return role in cfg["privileged_roles"] or role not in cfg["least_privilege_roles"]


def scope_is_broad(scope, cfg: dict) -> bool:
    """Broad scopes, and any unknown or missing scope, count as broad."""
    return scope not in cfg["narrow_scopes"]


def _credential_findings(p: dict, cfg: dict) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    soon = cfg["expiring_soon_days"]
    for c in p.get("credentials", []):
        kind = c.get("type")
        exp = c.get("expires_in_days")
        if kind == "secret":
            before = len(out)
            if p.get("oidc_capable") is True:
                out.append(("SECRET_FEDERATION_POSSIBLE", f"client secret on a workload whose platform supports "
                            f"OIDC federation ({p.get('hosting', '?')}): replace it with a federated credential"))
            elif exp is None:
                out.append(("CREDENTIAL_EXPIRY_UNKNOWN", "client secret with no known expiry: treat as at risk"))
            elif exp < 0:
                out.append(("SECRET_EXPIRED", f"client secret expired {-exp} days ago"))
            elif exp <= soon:
                out.append(("SECRET_EXPIRING", f"client secret expires in {exp} days (<= {soon})"))
            life = c.get("lifetime_days")
            if life is None or life > cfg["max_secret_lifetime_days"]:
                out.append(("SECRET_LONG_LIFETIME", "client secret lifetime unknown" if life is None else
                            f"client secret lifetime {life} days > policy {cfg['max_secret_lifetime_days']} days"))
            if len(out) == before:
                out.append(("SECRET_PRESENT", "client secret present: move to a certificate"))
        elif kind == "certificate":
            if exp is None:
                out.append(("CREDENTIAL_EXPIRY_UNKNOWN", "certificate with no known expiry"))
            elif exp < 0:
                out.append(("CERT_EXPIRED", f"certificate expired {-exp} days ago"))
            elif exp <= soon:
                out.append(("CERT_EXPIRING", f"certificate expires in {exp} days (<= {soon})"))
        # federated credentials hold no secret: nothing to rotate
    return out


def audit_principal(p: dict, cfg: dict) -> AuditResult:
    ptype = p.get("type") if p.get("type") in ("service_principal", "managed_identity") else "service_principal"
    found: list[tuple[str, str]] = []
    notes: list[str] = []
    if p.get("type") not in ("service_principal", "managed_identity"):
        notes.append(f"type '{p.get('type')}' unknown: audited as a service principal (deny by default)")
    last = p.get("last_sign_in_days_ago")
    if last is None or last > cfg["unused_after_days"]:
        found.append(("UNUSED", "no sign-in recorded" if last is None else
                      f"last sign-in {last} days ago > {cfg['unused_after_days']} days"))
    for a in p.get("role_assignments", []):
        role, scope = a.get("role"), a.get("scope")
        if role_is_privileged(role, cfg) and scope_is_broad(scope, cfg):
            why = "" if role in cfg["privileged_roles"] else " (role not in the least-privilege list: treated as privileged)"
            found.append(("PRIVILEGED_BROAD_SCOPE", f"{role or 'unknown role'} at {scope or 'unknown'} scope{why}: "
                          "standing privilege a workload cannot activate just in time, so narrow the role and scope"))
    if ptype == "service_principal":
        found += _credential_findings(p, cfg)
        if not p.get("owners"):
            found.append(("NO_OWNER", "service principal has no owner: nobody is accountable for its credentials"))
    elif p.get("credentials"):
        notes.append("managed identity credentials are created and rotated by Azure: not audited")
    actions = sorted({cfg["finding_actions"][f] for f, _ in found}, key=cfg["action_priority"].index) or ["OK"]
    if not found:
        notes.append("no finding: least-privilege role, recent sign-in" +
                     (", owner named, no risky credential" if ptype == "service_principal" else ""))
    found.sort(key=lambda f: cfg["action_priority"].index(cfg["finding_actions"][f[0]]))
    return AuditResult(p.get("id", "?"), p.get("name", "?"), ptype, actions[0], [f for f, _ in found], actions,
                       [r for _, r in found] + notes)


def audit_all(data: dict, cfg: dict) -> list[AuditResult]:
    return [audit_principal(p, cfg) for p in data.get("principals", [])]


def metrics_of(plans: list[PlanResult], audits: list[AuditResult]) -> dict:
    return {"workloads": len(plans),
            "plan_counts": {t: sum(p.outcome == t for p in plans) for t in IDENTITY_TYPES},
            "principals": len(audits),
            "action_counts": {a: sum(r.action == a for r in audits) for a in ACTIONS},
            "flagged": sum(r.action != "OK" for r in audits),
            "secrets_found": sum(any(f.startswith("SECRET") or f == "CREDENTIAL_EXPIRY_UNKNOWN" for f in r.findings)
                                 for r in audits)}


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SC-300 3.1 Identities for applications and Azure workloads · 4.3 PIM for Azure resource roles.",
    "concepts": [
        "Managed identity: Azure holds and rotates the credential; code asks the local endpoint for a token.",
        "System-assigned lives and dies with one resource; user-assigned is its own resource and can be shared.",
        "An app registration is the global definition; the service principal is the app's identity in one tenant.",
        "Workload identity federation lets GitHub Actions, Kubernetes or another cloud sign in with no stored secret.",
        "Azure RBAC = role + scope; grant the narrowest role at the narrowest scope (resource group or resource).",
    ],
    "failure_modes": [
        "A client secret pasted into a pipeline variable, valid for two years, with nobody owning the app.",
        "Contributor on the whole subscription 'to make the deployment work', never narrowed afterwards.",
        "Using a system-assigned identity for a resource that is rebuilt, losing its role assignments each time.",
        "Old migration service principals left enabled with privileged roles long after the project ended.",
    ],
    "ai_governance": [
        "An AI agent running in Azure should use a managed identity with a narrow data-plane role, not a key in a prompt.",
        "Agents that run outside Azure should federate (OIDC) so there is no secret an attacker can extract from them.",
        "Give every agent identity a named human owner and audit its sign-ins; disable it when it goes quiet.",
        "Agents must never self-assign roles: role assignment rights (Owner, User Access Administrator) stay with humans via PIM.",
    ],
    "exam_tips": [
        "'One resource, no credentials to manage, clean up automatically' = system-assigned managed identity.",
        "'Several resources share the same permissions' or 'create the identity first' = user-assigned managed identity.",
        "'GitHub Actions deploys to Azure without storing a secret' = workload identity federation (federated credential).",
        "'App outside Azure, no federation' = service principal with a certificate rather than a client secret.",
        "Human admins get Azure resource roles as PIM eligible assignments with approval and a maximum duration.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    cfg = policies["workload_identities"]
    plans = plan_all(data, cfg)
    audits = audit_all(data, cfg)
    m = metrics_of(plans, audits)
    ui.section("Step 1 — Choose the identity type for each workload")
    ui.table("Identity planner", ["ID", "Workload", "Hosting", "Rule", "Recommendation"],
             [[p.id, p.name, p.hosting, p.rule, p.outcome] for p in plans])
    for p in plans:
        ui.bullet(f"{p.id} {p.name} → {TYPE_LABELS[p.outcome]}: " + "; ".join(p.reasons))
    ui.section("Step 2 — Audit existing service principals and managed identities")
    ui.table("Workload identity audit", ["ID", "Name", "Type", "Findings", "Fix"],
             [[r.id, r.name, r.type, ", ".join(r.findings) or "-", r.action] for r in audits])
    for r in audits:
        ui.bullet(f"{r.id} {r.name} → {', '.join(r.actions)}: " + "; ".join(r.reasons),
                  style="green" if r.action == "OK" else "red" if r.action in ("DISABLE_UNUSED", "REDUCE_SCOPE")
                  else "yellow")
    ui.section("Step 3 — Remediation plan")
    for r in audits:
        if r.action != "OK":
            ui.bullet(f"{r.name}: {r.action} — {cfg['action_definitions'][r.action]}")
    ui.status("Identities needing a fix", "WARN" if m["flagged"] else "PASS",
              f"{m['flagged']} of {m['principals']} ({m['secrets_found']} with client secrets)")
    ui.print("Recommendations: " + ", ".join(f"{k} {v}" for k, v in m["plan_counts"].items()))
    ui.insight(INSIGHT)
    return {"plans": {p.id: p.outcome for p in plans}, "audit": {r.id: r.action for r in audits}, "metrics": m}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["workload_identities"]
    plans = plan_all(data, cfg)
    audits = audit_all(data, cfg)
    raw_w = {w.get("id", "?"): w for w in data.get("workloads", [])}
    raw_p = {p.get("id", "?"): p for p in data.get("principals", [])}
    qs: list = []
    for p in plans:
        src = {k: v for k, v in raw_w[p.id].items() if k != "id"}
        qs.append(Question(prompt=f"{p.id} {p.name}: which identity should this workload use?", context=f"workload={src}",
                           choices=IDENTITY_TYPES, answer=p.outcome, explanation="; ".join(p.reasons),
                           objective="3.1"))
    for p in plans:
        if p.rule == "azure_shared_or_preprovisioned" and (raw_w[p.id].get("resources") or 1) < 2:
            qs.append(Question(prompt=f"{p.id} {p.name} runs on a single resource. Which planner rule decided it?",
                               context=f"workload={raw_w[p.id]}", choices=[r["name"] for r in cfg["planner_rules"]],
                               answer=p.rule, explanation="; ".join(p.reasons), objective="3.1"))
            break
    for r in audits:
        src = {k: v for k, v in raw_p[r.id].items() if k != "id"}
        qs.append(Question(prompt=f"{r.id} {r.name}: what is the most urgent fix?", context=f"identity={src}",
                           choices=ACTIONS, answer=r.action, explanation="; ".join(r.reasons),
                           objective="4.3" if r.action == "REDUCE_SCOPE" else "3.1"))
    # Unknown roles are privileged: computed by the engine.
    probe = {"id": "X", "type": "managed_identity", "last_sign_in_days_ago": 1,
             "role_assignments": [{"role": "Custom Deployment Operator", "scope": "subscription"}]}
    res = audit_principal(probe, cfg)
    qs.append(Question(prompt="A managed identity holds a custom role the policy does not list, at subscription "
                              "scope, and signed in yesterday. What does the audit recommend?",
                       choices=ACTIONS, answer=res.action, explanation="; ".join(res.reasons), objective="4.3"))
    probe = {"id": "Y", "type": "managed_identity", "last_sign_in_days_ago": 1,
             "role_assignments": [{"role": "Contributor", "scope": "resource_group"}]}
    res = audit_principal(probe, cfg)
    qs.append(Question(prompt="A managed identity has Contributor on one resource group only and is in daily use. "
                              "What does the audit recommend?",
                       choices=ACTIONS, answer=res.action, explanation="; ".join(res.reasons), objective="3.1"))
    qs.append(Question(prompt="An engineer needs Owner on the production subscription for two hours a month. "
                              "What is the best way to grant it?",
                       choices=["an eligible Privileged Identity Management assignment with approval and a time limit",
                                "a permanent active Owner assignment so the engineer is never blocked",
                                "a service principal with a client secret the engineer can use",
                                "Owner on the management group instead, so fewer assignments exist"],
                       answer="an eligible Privileged Identity Management assignment with approval and a time limit",
                       explanation="PIM for Azure resource roles: no standing privilege, activation is time-bound, "
                                   "justified and can need approval", objective="4.3"))
    qs.append(Question(prompt="Why does deleting a resource also remove its system-assigned managed identity?",
                       choices=["its lifecycle is tied to the resource that created it",
                                "Azure deletes every identity that has no client secret",
                                "system-assigned identities expire after 90 days",
                                "a role assignment removal job runs each night"],
                       answer="its lifecycle is tied to the resource that created it",
                       explanation=cfg["concepts"]["system-assigned managed identity"], objective="3.1"))
    terms = sorted(cfg["concepts"])
    for term in ("user-assigned managed identity", "workload identity federation", "service principal",
                 "eligible assignment"):
        if term in cfg["concepts"]:
            qs.append(Question(prompt=f"Which term is this? \"{cfg['concepts'][term]}\"",
                               choices=choices_with(term, terms, key=term), answer=term,
                               explanation=cfg["concepts"][term],
                               objective="4.3" if term == "eligible assignment" else "3.1"))
    return qs


# --------------------------------------------------------------------------- #
# Seeded scenario generator
# --------------------------------------------------------------------------- #
_APPS = ["billing", "orders", "inventory", "reports", "shipping", "payroll", "catalog", "search", "alerts", "ledger"]


def generate_scenario(rng, policies: dict) -> dict:
    """A fresh scenario in the sample-data shape; uses only ``rng`` so a seed always gives the same data."""
    cfg = policies["workload_identities"]
    azure = sorted(cfg["azure_hosting"])
    external = sorted(h for h in cfg["external_hosting"] if h not in ("github_actions", "kubernetes"))
    oidc = ["github_actions", "kubernetes"]
    names = rng.sample(_APPS, len(_APPS))
    workloads = [
        {"name": f"{names[0]}-api", "hosting": rng.choice(azure), "resources": 1},
        {"name": f"{names[1]}-workers", "hosting": rng.choice(azure), "resources": rng.randint(2, 6)},
        {"name": f"{names[2]}-batch", "hosting": rng.choice(azure), "resources": 1, "pre_provisioned": True},
        {"name": f"{names[3]}-deploy", "hosting": rng.choice(oidc), "oidc_federation": True},
        {"name": f"{names[4]}-export", "hosting": rng.choice(external), "oidc_federation": False},
    ]
    for i in range(rng.randint(1, 3)):
        h = rng.choice(azure + external + oidc + ["unknown_vendor"])
        w = {"name": f"{names[5 + i]}-svc", "hosting": h}
        if h in azure:
            w["resources"] = rng.randint(1, 3)
        else:
            w["oidc_federation"] = rng.random() < 0.5
        workloads.append(w)
    rng.shuffle(workloads)
    for i, w in enumerate(workloads, 1):
        w["id"] = f"W{i}"
    narrow = sorted(cfg["least_privilege_roles"])
    life = cfg["max_secret_lifetime_days"]
    soon = cfg["expiring_soon_days"]
    owner = lambda: [rng.choice(["k.ito", "m.reyes", "s.okafor", "l.byrne"])]
    rg = lambda: rng.choice(cfg["narrow_scopes"])
    principals = [
        {"name": "sp-deploy", "type": "service_principal", "hosting": rng.choice(oidc), "oidc_capable": True,
         "credentials": [{"type": "secret", "lifetime_days": rng.randint(life + 1, 730),
                          "expires_in_days": rng.randint(60, 500)}],
         "owners": owner(), "role_assignments": [{"role": "Contributor", "scope": "resource_group"}],
         "last_sign_in_days_ago": rng.randint(0, 5)},
        {"name": "sp-export", "type": "service_principal", "hosting": rng.choice(external), "oidc_capable": False,
         "credentials": [{"type": "secret", "lifetime_days": rng.randint(30, life),
                          "expires_in_days": rng.choice([rng.randint(-40, -1), rng.randint(0, soon)])}],
         "owners": owner(), "role_assignments": [{"role": rng.choice(narrow), "scope": rg()}],
         "last_sign_in_days_ago": rng.randint(0, 20)},
        {"name": "sp-legacy", "type": "service_principal", "hosting": rng.choice(external), "oidc_capable": False,
         "credentials": [{"type": "certificate", "expires_in_days": rng.randint(soon + 1, 700)}],
         "owners": [], "role_assignments": [{"role": rng.choice(narrow), "scope": rg()}],
         "last_sign_in_days_ago": rng.randint(0, 30)},
        {"name": "mi-shared", "type": "managed_identity",
         "role_assignments": [{"role": rng.choice(["Owner", "Contributor", "Custom Platform Operator"]),
                               "scope": rng.choice(cfg["broad_scopes"])}],
         "last_sign_in_days_ago": rng.randint(0, 3)},
        {"name": "sp-migration", "type": "service_principal", "hosting": "on_premises", "oidc_capable": False,
         "credentials": [{"type": "secret", "lifetime_days": 365, "expires_in_days": rng.randint(10, 200)}],
         "owners": owner(), "role_assignments": [{"role": "Contributor", "scope": "subscription"}],
         "last_sign_in_days_ago": rng.randint(cfg["unused_after_days"] + 1, 400)},
        {"name": "mi-app", "type": "managed_identity",
         "role_assignments": [{"role": rng.choice(narrow), "scope": "resource"}],
         "last_sign_in_days_ago": rng.randint(0, 10)},
    ]
    if rng.random() < 0.7:
        principals.append({"name": "sp-monitor", "type": "service_principal", "hosting": rng.choice(oidc),
                           "oidc_capable": True, "credentials": [{"type": "federated"}], "owners": owner(),
                           "role_assignments": [{"role": "Monitoring Reader", "scope": "subscription"}],
                           "last_sign_in_days_ago": rng.randint(0, 5)})
    rng.shuffle(principals)
    for i, p in enumerate(principals, 1):
        p["id"] = f"P{i}"
        p["name"] = f"{p['name']}-{names[i % len(names)]}"
    return {"_description": "Generated workload identity scenario (seeded).", "workloads": workloads,
            "principals": principals}
