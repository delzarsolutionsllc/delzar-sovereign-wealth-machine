"""
Lab 1 — Joiner / Mover / Leaver (JML) & Access Governance
=========================================================

Security+ SY0-701 objectives
----------------------------
* 4.6  Implement and maintain identity and access management
       (provisioning/deprovisioning, RBAC, ABAC, least privilege).
* 5.1  Security governance (separation of duties, policies, procedures).
* 2.4  Indicators of malicious activity (privilege creep, orphaned accounts).

What this lab simulates
-----------------------
An HR feed drives the identity lifecycle:

* **Joiner**  – a new identity is created and birthright access is provisioned
  from its role (RBAC).
* **Mover**   – a role/department change. Correct behaviour: revoke the old
  role's permissions. Leaving them in place causes **privilege creep**.
* **Leaver**  – the account is disabled, every entitlement is revoked and a
  deprovisioning ticket is generated (with an SLA).

Every access decision passes **two** gates:

1. RBAC – does any of the user's roles grant the permission?
2. ABAC – do the *attributes* (employment status, clearance vs. data
   classification, department, time of day) allow it?

Finally a **Separation of Duties** scan flags users who hold two permissions
that should never be combined (e.g. ``po:create`` + ``po:approve``).

Run it
------
    python main.py lab 1
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

TITLE = "Lab 1 — Joiner-Mover-Leaver & Access Governance"
OBJECTIVES = "SY0-701 4.6 IAM · 5.1 Governance (SoD) · 2.4 Privilege creep"


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Identity:
    """A digital identity as tracked by the IGA (Identity Governance) system."""

    user_id: str
    name: str
    department: str
    role: str
    clearance: str
    manager: str | None = None
    status: str = "active"            # active | disabled | terminated
    extra_roles: list[str] = field(default_factory=list)
    permissions: set[str] = field(default_factory=set)
    history: list[str] = field(default_factory=list)

    @property
    def all_roles(self) -> list[str]:
        return [self.role, *self.extra_roles]

    @classmethod
    def from_dict(cls, d: dict) -> "Identity":
        required = ("user_id", "name", "department", "role", "clearance")
        missing = [k for k in required if not d.get(k)]
        if missing:
            raise ValueError(f"Identity record missing required fields: {missing}")
        return cls(
            user_id=d["user_id"],
            name=d["name"],
            department=d["department"],
            role=d["role"],
            clearance=d["clearance"],
            manager=d.get("manager"),
        )


@dataclass
class AccessDecision:
    user_id: str
    action: str
    resource: str
    allowed: bool
    gate: str            # which gate decided: RBAC / ABAC / STATUS / ALLOW
    reasons: list[str]


@dataclass
class SoDConflict:
    user_id: str
    rule_id: str
    perm_a: str
    perm_b: str
    risk: str


@dataclass
class DeprovisionTicket:
    ticket_id: str
    user_id: str
    name: str
    reason: str
    revoked_roles: list[str]
    revoked_permissions: list[str]
    created_at: str
    due_by: str
    priority: str
    steps: list[str]


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #
class IdentityGovernance:
    """A miniature IGA platform: lifecycle, RBAC/ABAC evaluation, SoD scanning."""

    def __init__(self, policy: dict, clock: callable | None = None):
        self.policy = policy
        self.roles: dict[str, list[str]] = policy["roles"]
        self.levels: dict[str, int] = policy["clearance_levels"]
        self.abac: dict = policy["abac_rules"]
        self.sod_rules: list[dict] = policy["sod_conflicts"]
        self.leaver_sla_hours: int = policy.get("leaver_sla_hours", 24)
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.directory: dict[str, Identity] = {}
        self.audit_log: list[dict] = []
        self.tickets: list[DeprovisionTicket] = []

    # ------------------------------------------------------------ helpers
    def _audit(self, event: str, user_id: str, detail: str) -> None:
        self.audit_log.append(
            {"ts": self.clock().isoformat(), "event": event, "user_id": user_id, "detail": detail}
        )

    def _role_perms(self, role: str) -> set[str]:
        if role not in self.roles:
            raise ValueError(f"Unknown role '{role}' (not in RBAC catalog)")
        return set(self.roles[role])

    def get(self, user_id: str) -> Identity:
        if user_id not in self.directory:
            raise KeyError(f"No identity '{user_id}' in directory")
        return self.directory[user_id]

    # ------------------------------------------------------------ lifecycle
    def joiner(self, record: dict) -> Identity:
        """Create an identity and provision birthright access from its role."""
        ident = Identity.from_dict(record)
        if ident.user_id in self.directory:
            raise ValueError(f"Duplicate user_id '{ident.user_id}'")
        if ident.clearance not in self.levels:
            raise ValueError(f"Unknown clearance '{ident.clearance}'")
        ident.permissions = self._role_perms(ident.role)
        ident.history.append(f"JOINER as {ident.role} ({ident.department})")
        self.directory[ident.user_id] = ident
        self._audit("JOINER", ident.user_id, f"role={ident.role} perms={sorted(ident.permissions)}")
        return ident

    def mover(
        self, user_id: str, new_role: str, new_department: str | None = None, revoke_previous: bool = True
    ) -> dict:
        """
        Move a user to a new role.

        ``revoke_previous=True`` is the correct, least-privilege behaviour.
        ``False`` simulates the classic manual mistake that causes privilege creep.
        Returns a dict describing what was added / retained.
        """
        ident = self.get(user_id)
        old_role = ident.role
        new_perms = self._role_perms(new_role)
        if revoke_previous:
            retained: set[str] = set()
            ident.permissions = new_perms | self._extra_perms(ident)
        else:
            retained = self._role_perms(old_role) - new_perms
            ident.permissions |= new_perms
            ident.extra_roles.append(old_role)  # old role is now an un-reviewed extra
        ident.role = new_role
        if new_department:
            ident.department = new_department
        ident.history.append(f"MOVER {old_role} -> {new_role} (revoke_previous={revoke_previous})")
        self._audit("MOVER", user_id, f"{old_role}->{new_role} retained={sorted(retained)}")
        return {"old_role": old_role, "new_role": new_role, "retained_permissions": sorted(retained)}

    def grant_extra_role(self, user_id: str, role: str) -> None:
        """Ad-hoc access grant outside the normal lifecycle (a common creep source)."""
        ident = self.get(user_id)
        ident.permissions |= self._role_perms(role)
        ident.extra_roles.append(role)
        ident.history.append(f"GRANT extra role {role}")
        self._audit("GRANT", user_id, f"extra_role={role}")

    def _extra_perms(self, ident: Identity) -> set[str]:
        perms: set[str] = set()
        for r in ident.extra_roles:
            perms |= self._role_perms(r)
        return perms

    def leaver(self, user_id: str, reason: str = "voluntary_resignation") -> DeprovisionTicket:
        """Disable the account, strip all access and open a deprovisioning ticket."""
        ident = self.get(user_id)
        revoked_roles = ident.all_roles
        revoked_perms = sorted(ident.permissions)
        ident.permissions = set()
        ident.extra_roles = []
        ident.status = "terminated"
        ident.history.append(f"LEAVER ({reason})")

        now = self.clock()
        for_cause = "cause" in reason
        # Terminations for cause are deprovisioned immediately (before the user is told).
        sla = timedelta(hours=1 if for_cause else self.leaver_sla_hours)
        ticket_id = "DEPROV-" + hashlib.sha256(f"{user_id}{now.isoformat()}".encode()).hexdigest()[:8].upper()
        steps = [
            "Disable directory (AD/IdP) account",
            "Revoke all SSO sessions and refresh tokens",
            "Remove from all groups / roles: " + ", ".join(revoked_roles),
            "Disable VPN, MFA tokens and remote-access certificates",
            "Rotate any shared/service credentials the user knew",
            "Transfer mailbox + file ownership to manager",
            "Recover badge, laptop and mobile device",
            "Retain account (disabled) for legal-hold period, then delete",
        ]
        if for_cause:
            steps.insert(0, "IMMEDIATE: coordinate with HR/legal — cut access BEFORE notification")
        ticket = DeprovisionTicket(
            ticket_id=ticket_id,
            user_id=user_id,
            name=ident.name,
            reason=reason,
            revoked_roles=revoked_roles,
            revoked_permissions=revoked_perms,
            created_at=now.isoformat(),
            due_by=(now + sla).isoformat(),
            priority="P1" if for_cause else "P3",
            steps=steps,
        )
        self.tickets.append(ticket)
        self._audit("LEAVER", user_id, f"ticket={ticket_id} revoked={len(revoked_perms)} perms")
        return ticket

    # ------------------------------------------------------------ evaluation
    def check_rbac(self, user_id: str, permission: str) -> bool:
        """RBAC: is the permission granted by any role the user holds?"""
        return permission in self.get(user_id).permissions

    def check_abac(self, user_id: str, resource: dict, hour: int) -> tuple[bool, list[str]]:
        """
        ABAC: evaluate subject + resource + environment attributes.

        ``resource`` = {"name", "classification", "department"}
        """
        ident = self.get(user_id)
        reasons: list[str] = []
        cls = resource.get("classification", "public")

        if self.abac.get("require_clearance_gte_classification", True):
            if self.levels[ident.clearance] < self.levels[cls]:
                reasons.append(f"clearance '{ident.clearance}' < classification '{cls}'")

        if cls in self.abac.get("require_department_match_for", []):
            if resource.get("department") and resource["department"] != ident.department:
                reasons.append(f"department '{ident.department}' != data owner '{resource['department']}'")

        bh = self.abac.get("business_hours", {"start": 0, "end": 24})
        if cls in self.abac.get("restrict_outside_hours_for", []):
            if not (bh["start"] <= hour < bh["end"]):
                reasons.append(f"hour {hour:02d}:00 outside business hours for '{cls}' data")

        return (not reasons, reasons)

    def evaluate_access(self, user_id: str, action: str, resource: dict, hour: int = 12) -> AccessDecision:
        """Full decision: account status -> RBAC -> ABAC. Deny by default."""
        ident = self.get(user_id)
        name = resource.get("name", "?")
        if ident.status not in self.abac.get("allowed_employment_status", ["active"]):
            d = AccessDecision(user_id, action, name, False, "STATUS", [f"account status is '{ident.status}'"])
        elif not self.check_rbac(user_id, action):
            d = AccessDecision(user_id, action, name, False, "RBAC", [f"no role grants '{action}'"])
        else:
            ok, reasons = self.check_abac(user_id, resource, hour)
            d = AccessDecision(user_id, action, name, ok, "ABAC" if not ok else "ALLOW", reasons or ["all gates passed"])
        self._audit("ACCESS_" + ("ALLOW" if d.allowed else "DENY"), user_id, f"{action} on {name}: {d.reasons}")
        return d

    def detect_sod(self, user_id: str | None = None) -> list[SoDConflict]:
        """Scan one user (or the whole directory) for toxic permission combinations."""
        targets = [self.get(user_id)] if user_id else list(self.directory.values())
        out: list[SoDConflict] = []
        for ident in targets:
            for rule in self.sod_rules:
                if rule["a"] in ident.permissions and rule["b"] in ident.permissions:
                    out.append(SoDConflict(ident.user_id, rule["id"], rule["a"], rule["b"], rule["risk"]))
        return out

    def access_review(self) -> list[dict]:
        """Periodic access recertification: flag accounts that need attention."""
        findings = []
        for ident in self.directory.values():
            if ident.status != "active" and ident.permissions:
                findings.append({"user_id": ident.user_id, "finding": "Orphaned access on inactive account"})
            if ident.extra_roles:
                findings.append(
                    {"user_id": ident.user_id, "finding": f"Privilege creep: extra roles {ident.extra_roles}"}
                )
        return findings


# --------------------------------------------------------------------------- #
# Insight panel content
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SY0-701 4.6 (IAM: provisioning, RBAC/ABAC, least privilege) and 5.1 (separation of duties).",
    "concepts": [
        "RBAC grants permissions through job roles; ABAC adds context (clearance, department, time, status).",
        "Least privilege: a Mover must LOSE the old role's rights, not just gain the new ones.",
        "Separation of Duties prevents one person completing a sensitive transaction end-to-end.",
        "Leaver processing: disable first, then revoke, then reclaim assets; keep the account for legal hold.",
    ],
    "failure_modes": [
        "Privilege creep: movers keep old roles; 'temporary' grants never expire.",
        "Orphaned accounts: HR never tells IT, so ex-employees keep VPN/SSO access.",
        "Terminations for cause handled at normal SLA — the user has hours to exfiltrate data.",
        "SoD conflicts invisible because nobody reviews the COMBINED permission set.",
    ],
    "ai_governance": [
        "An AI provisioning agent should only act on events from the authoritative HR source.",
        "Require human approval for any grant that would create an SoD conflict.",
        "Agents must never be able to grant roles to themselves or their own service account.",
        "Log every agent-initiated change with the triggering HR event ID for audit traceability.",
    ],
    "exam_tips": [
        "'Users accumulate permissions over time' => privilege creep => fix with access reviews/recertification.",
        "'Same employee creates and approves payments' => separation of duties.",
        "'Access based on attributes like location or time' => ABAC.",
        "Mandatory vacation and job rotation are detective controls that also expose SoD fraud.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo scenario
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict, clock=None) -> dict:
    """Replay the sample HR feed and render results. Returns a summary dict."""
    iga = IdentityGovernance(policies["identity_governance"], clock=clock)

    ui.section("Step 1 — Replay HR feed (Joiner / Mover / Grant / Leaver)")
    rows = []
    for ev in data["events"]:
        t = ev["type"]
        if t == "joiner":
            ident = iga.joiner(ev["identity"])
            rows.append([t.upper(), ident.user_id, f"{ident.name} as {ident.role}", f"{len(ident.permissions)} perms"])
        elif t == "mover":
            res = iga.mover(ev["user_id"], ev["new_role"], ev.get("new_department"), ev.get("revoke_previous", True))
            flag = f"RETAINED {res['retained_permissions']}" if res["retained_permissions"] else "clean"
            rows.append([t.upper(), ev["user_id"], f"{res['old_role']} -> {res['new_role']}", flag])
        elif t == "grant":
            iga.grant_extra_role(ev["user_id"], ev["extra_role"])
            rows.append([t.upper(), ev["user_id"], f"+{ev['extra_role']}", ev.get("note", "")[:40]])
        # leavers handled after access checks so we can show mid-state too
    ui.table("Lifecycle events", ["Event", "User", "Change", "Result"], rows)

    ui.section("Step 2 — Separation of Duties scan (before leavers)")
    conflicts = iga.detect_sod()
    ui.table(
        "SoD conflicts",
        ["User", "Rule", "Toxic combination", "Risk"],
        [[c.user_id, c.rule_id, f"{c.perm_a} + {c.perm_b}", c.risk] for c in conflicts] or [["-", "-", "none", "-"]],
    )

    ui.section("Step 3 — Process Leavers & generate deprovisioning tickets")
    tickets = []
    for ev in data["events"]:
        if ev["type"] == "leaver":
            tk = iga.leaver(ev["user_id"], ev.get("reason", "voluntary_resignation"))
            tickets.append(tk)
            body = (
                f"[bold]{tk.ticket_id}[/bold]  priority={tk.priority}  user={tk.user_id} ({tk.name})\n"
                f"reason={tk.reason}\ncreated={tk.created_at}\ndue_by={tk.due_by}\n"
                f"revoked {len(tk.revoked_permissions)} permissions from roles {tk.revoked_roles}\n\n"
                + "\n".join(f"  [ ] {s}" for s in tk.steps)
            )
            ui.panel("Deprovisioning Ticket", body, style="red" if tk.priority == "P1" else "yellow")

    ui.section("Step 4 — Access decisions (status -> RBAC -> ABAC)")
    decisions = [
        iga.evaluate_access(c["user_id"], c["action"], c["resource"], c.get("hour", 12)) for c in data["access_checks"]
    ]
    ui.table(
        "Access requests",
        ["User", "Action", "Resource", "Decision", "Gate", "Reason"],
        [
            [d.user_id, d.action, d.resource, "ALLOW" if d.allowed else "DENY", d.gate, "; ".join(d.reasons)]
            for d in decisions
        ],
    )

    ui.section("Step 5 — Periodic access review findings")
    review = iga.access_review()
    for f in review:
        ui.bullet(f"{f['user_id']}: {f['finding']}", style="yellow")
    if not review:
        ui.bullet("No findings", style="green")

    ui.insight(INSIGHT)
    return {
        "identities": len(iga.directory),
        "sod_conflicts": len(conflicts),
        "tickets": len(tickets),
        "denied": sum(1 for d in decisions if not d.allowed),
        "review_findings": len(review),
    }
