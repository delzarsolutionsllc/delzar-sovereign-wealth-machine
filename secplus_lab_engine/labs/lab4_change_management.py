"""
Lab 4 — Change Control & Impact Analyzer (CAB simulator)
========================================================

Security+ SY0-701 objectives
----------------------------
* 1.3  Change management: approval process, ownership, stakeholders, impact
       analysis, test results, backout plan, maintenance window, SOPs;
       technical implications (allow/deny lists, restricted activities,
       downtime, service/application restarts, legacy applications,
       dependencies); documentation & version control.
* 5.1  Governance — separation of duties in approvals.

What this lab does
------------------
Each Request for Change (RFC) is reviewed the way a Change Advisory Board would:

1. **Schedule** — inside an approved maintenance window? on a blackout date?
2. **Approvals** — CAB quorum met? did the requester approve their own change?
3. **Testing** — was it validated in staging?
4. **Impact analysis** — blast radius through the dependency graph, legacy
   systems broken by disabled protocols, services cut off by deny-list rules,
   restarts causing downtime.
5. **Backout validation** — every reversible step has an undo; irreversible
   steps have a backup first and a fail-forward plan; the plan fits the window.
6. **Execution rehearsal** — the change is *executed* against a simulated
   environment, failed on purpose, and the backout is run to prove the system
   returns to its original state.

Run it
------
    python main.py lab 4
    python main.py lab 4 --file my_rfcs.json
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, time

TITLE = "Lab 4 — Change Control & Impact Analyzer (CAB)"
OBJECTIVES = "SY0-701 1.3 Change management · 5.1 Governance"

# How each forward action is reversed. ``None`` = not reversible.
UNDO_MAP: dict[str, str | None] = {
    "apply_patch": "uninstall_patch",
    "config_change": "restore_config",
    "firewall_deny": "firewall_remove_deny",
    "firewall_allow": "firewall_remove_allow",
    "stop_service": "start_service",
    "start_service": "stop_service",
    "restart_service": "restart_service",
    "db_schema_migrate": None,
    "firmware_flash": None,
    "data_purge": None,
}
NON_CHANGING_ACTIONS = {"snapshot", "backup", "verify", "notify", "health_check"}
DOWNTIME_ACTIONS = {"restart_service", "stop_service", "firmware_flash", "db_schema_migrate"}


@dataclass
class ReviewResult:
    rfc_id: str
    title: str
    decision: str = "APPROVE"                 # APPROVE | APPROVE_WITH_CONDITIONS | REJECT
    risk_score: int = 0
    strategy: str = "ROLLBACK"                # ROLLBACK | FAIL_FORWARD | NONE
    blockers: list[str] = field(default_factory=list)
    conditions: list[str] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)
    blast_radius: list[str] = field(default_factory=list)
    generated_backout: list[str] = field(default_factory=list)
    rehearsal: dict | None = None

    def block(self, msg: str, pts: int = 3) -> None:
        self.blockers.append(msg)
        self.risk_score += pts

    def condition(self, msg: str, pts: int = 1) -> None:
        self.conditions.append(msg)
        self.risk_score += pts


class ChangeAdvisoryBoard:
    """Automated CAB pre-review. A human CAB still makes the final call."""

    def __init__(self, policy: dict):
        self.p = policy
        self.systems: dict[str, dict] = policy["systems"]
        self.irreversible = set(policy.get("irreversible_actions", []))

    # ------------------------------------------------------------- graph helpers
    def dependents_of(self, system: str) -> set[str]:
        """All systems that directly or transitively depend ON ``system``."""
        out: set[str] = set()
        frontier = [system]
        while frontier:
            cur = frontier.pop()
            for name, meta in self.systems.items():
                if cur in meta.get("depends_on", []) and name not in out:
                    out.add(name)
                    frontier.append(name)
        return out

    def neighbours(self, system: str) -> set[str]:
        """Direct dependencies and direct dependents (who it talks to)."""
        deps = set(self.systems.get(system, {}).get("depends_on", []))
        users = {n for n, m in self.systems.items() if system in m.get("depends_on", [])}
        return deps | users

    # ------------------------------------------------------------- checks
    def _check_schedule(self, rfc: dict, r: ReviewResult) -> None:
        w = rfc.get("window") or {}
        try:
            start, end = datetime.fromisoformat(w["start"]), datetime.fromisoformat(w["end"])
        except (KeyError, ValueError):
            r.block("No valid maintenance window specified")
            return
        if end <= start:
            r.block("Window end is before start")
            return
        if start.date().isoformat() in self.p.get("blackout_dates", []):
            r.block(f"{start.date()} is a change-freeze blackout date", 4)
        in_window = any(
            mw["day"] == start.strftime("%A")
            and start.date() == end.date()
            and time.fromisoformat(mw["start"]) <= start.time()
            and end.time() <= time.fromisoformat(mw["end"])
            for mw in self.p.get("maintenance_windows", [])
        )
        if not in_window:
            if rfc.get("emergency"):
                r.condition("Outside maintenance window — permitted as EMERGENCY change; requires ECAB review + post-implementation review")
            else:
                r.block(f"{start:%A %Y-%m-%d %H:%M}–{end:%H:%M} is outside approved maintenance windows (uncoordinated downtime)")
        r.observations.append(f"Window {start:%a %Y-%m-%d %H:%M} → {end:%H:%M} ({(end-start).seconds//60} min)")

    def _check_approvals(self, rfc: dict, r: ReviewResult) -> None:
        requester = rfc.get("requested_by")
        approvals = set(rfc.get("approvals", []))
        members = set(self.p.get("cab_members", []))
        if requester in approvals:
            r.block(f"Requester '{requester}' approved their own change (separation of duties violation)")
        valid = (approvals & members) - {requester}
        unknown = approvals - members
        if unknown:
            r.observations.append(f"Ignored approvals from non-CAB members: {sorted(unknown)}")
        quorum = self.p.get("cab_quorum", 2)
        if len(valid) < quorum:
            r.block(f"CAB quorum not met: {len(valid)}/{quorum} independent approvals")
        # Owners of impacted systems should be stakeholders
        owners = {self.systems[s]["owner"] for s in rfc.get("target_systems", []) if s in self.systems}
        missing = owners - approvals - {requester}
        if missing:
            r.condition(f"System owner(s) {sorted(missing)} not among approvers — obtain stakeholder sign-off")

    def _check_testing(self, rfc: dict, r: ReviewResult) -> None:
        if not rfc.get("tested_in_staging"):
            if rfc.get("emergency"):
                r.condition("Not tested in staging (emergency) — monitor closely, test backout first", 2)
            else:
                r.block("No staging test results attached", 2)

    def _check_impact(self, rfc: dict, r: ReviewResult) -> None:
        targets = [t for t in rfc.get("target_systems", [])]
        for t in targets:
            if t not in self.systems:
                r.block(f"Target '{t}' not found in CMDB/asset inventory")
        radius: set[str] = set()
        for t in targets:
            radius |= self.dependents_of(t)
        r.blast_radius = sorted(radius)
        if radius:
            r.risk_score += min(len(radius), 4)
            r.observations.append(f"Blast radius (downstream dependents): {sorted(radius)}")

        # Protocol/feature removals that break legacy peers
        for step in rfc.get("change_steps", []):
            for eff in step.get("effects", []):
                if not eff.startswith("disable:"):
                    continue
                feature = eff.split(":", 1)[1]
                host = step.get("target")
                peers = self.neighbours(host) | {host}
                broken = sorted(p for p in peers if f"requires:{feature}" in self.systems.get(p, {}).get("tags", []))
                for b in broken:
                    legacy = " (LEGACY)" if self.systems[b].get("legacy") else ""
                    if rfc.get("compensating_controls", {}).get(b):
                        r.condition(f"Disabling {feature} on {host} affects {b}{legacy}; compensating control: {rfc['compensating_controls'][b]}")
                    else:
                        r.block(f"Disabling {feature} on {host} BREAKS {b}{legacy}, which requires {feature}", 4)

        # Deny-list changes that cut off dependencies
        for rule in rfc.get("firewall_changes", {}).get("deny", []):
            hit = [n for n, m in self.systems.items() if rule in m.get("tags", [])]
            for h in hit:
                victims = sorted(self.dependents_of(h))
                if victims:
                    r.block(f"Deny-list '{rule}' blocks {h}; dependents lose connectivity: {victims}", 4)
        for rule in rfc.get("firewall_changes", {}).get("allow", []):
            r.condition(f"Allow-list addition '{rule}' widens attack surface — confirm least-privilege source/dest")

        # Restarts = downtime
        down = [s for s in rfc.get("change_steps", []) if s.get("action") in DOWNTIME_ACTIONS]
        if down:
            r.observations.append(f"{len(down)} step(s) cause service interruption: " +
                                  ", ".join(f"{s['action']}@{s.get('target')}" for s in down))

    def generate_backout_plan(self, rfc: dict) -> list[str]:
        """Auto-derive a reverse-order backout runbook from the forward steps."""
        plan = []
        for step in reversed(rfc.get("change_steps", [])):
            act = step.get("action")
            if act in NON_CHANGING_ACTIONS:
                continue
            undo = UNDO_MAP.get(act, "manual_review")
            desc = step.get("patch") or step.get("rule") or step.get("setting") or ""
            if undo is None:
                plan.append(f"RESTORE {step.get('target')} from pre-change backup (step {step.get('step')} '{act}' is irreversible)")
            else:
                plan.append(f"{undo} {step.get('target')} {desc}".strip())
        targets = rfc.get("target_systems", [])
        plan.append("verify: health checks + smoke tests on " + ", ".join(targets))
        plan.append("notify: CAB + service desk that change was backed out")
        return plan

    def _check_backout(self, rfc: dict, r: ReviewResult) -> None:
        steps = rfc.get("change_steps", [])
        backout = rfc.get("backout_plan") or {}
        undo_for = {b.get("undo_of") for b in backout.get("steps", [])}
        r.generated_backout = self.generate_backout_plan(rfc)
        irreversible_steps = [s for s in steps if s.get("action") in self.irreversible]

        if not backout.get("steps"):
            msg = "No backout plan attached (auto-generated draft shown below)"
            (r.condition if rfc.get("emergency") else r.block)(msg, 3)
        else:
            for s in steps:
                act = s.get("action")
                if act in NON_CHANGING_ACTIONS or act in self.irreversible:
                    continue
                if s.get("step") not in undo_for:
                    r.block(f"Backout plan has no undo for step {s.get('step')} ({act} on {s.get('target')})", 2)
            if not backout.get("verification"):
                r.condition("Backout plan lacks post-rollback verification steps")

        for s in irreversible_steps:
            prior = [p for p in steps if p.get("step", 0) < s.get("step", 0)
                     and p.get("action") in {"backup", "snapshot"} and p.get("target") == s.get("target")]
            if not prior:
                r.block(f"Irreversible step {s.get('step')} ({s['action']}) has no prior backup/snapshot of {s.get('target')}", 4)

        if irreversible_steps:
            ff = rfc.get("fail_forward_plan")
            if ff and ff.get("hotfix_steps"):
                r.strategy = "FAIL_FORWARD"
                r.condition("Irreversible change: success depends on fail-forward hotfix readiness — on-call dev must be present")
            else:
                r.strategy = "NONE"
                r.block("Irreversible change with no fail-forward plan: there is no safe recovery path", 4)

        # Time budget: change + backout must fit in the window
        w = rfc.get("window") or {}
        try:
            window_min = (datetime.fromisoformat(w["end"]) - datetime.fromisoformat(w["start"])).seconds // 60
            need = rfc.get("estimated_minutes", 0) + backout.get("estimated_minutes", 0)
            if need > window_min:
                r.block(f"Change ({rfc.get('estimated_minutes', 0)}m) + backout ({backout.get('estimated_minutes', 0)}m) "
                        f"= {need}m exceeds window of {window_min}m", 2)
        except (KeyError, ValueError):
            pass

    # ------------------------------------------------------------- top-level
    def review(self, rfc: dict, rehearse: bool = True) -> ReviewResult:
        r = ReviewResult(rfc.get("id", "?"), rfc.get("title", ""))
        self._check_schedule(rfc, r)
        self._check_approvals(rfc, r)
        self._check_testing(rfc, r)
        self._check_impact(rfc, r)
        self._check_backout(rfc, r)
        if rehearse and r.strategy == "ROLLBACK" and (rfc.get("backout_plan") or {}).get("steps"):
            r.rehearsal = rehearse_change(rfc, self.systems)
            if not r.rehearsal["restored"]:
                r.block("Rehearsal: executing the backout did NOT restore the original state", 3)

        if r.blockers:
            r.decision = "REJECT"
        elif r.risk_score <= self.p.get("max_risk_for_auto_approve", 3) and not r.conditions:
            r.decision = "APPROVE"
        else:
            r.decision = "APPROVE_WITH_CONDITIONS"
        return r


# --------------------------------------------------------------------------- #
# Execution rehearsal (simulated environment)
# --------------------------------------------------------------------------- #
def _initial_state(systems: dict) -> dict:
    return {
        name: {"patches": [], "config_version": 1, "running": True, "fw_deny": [], "fw_allow": [], "schema": 1}
        for name in systems
    }


def _apply(state: dict, action: str, step: dict) -> None:
    s = state.setdefault(step.get("target"), {"patches": [], "config_version": 1, "running": True,
                                              "fw_deny": [], "fw_allow": [], "schema": 1})
    if action == "apply_patch":
        s["patches"].append(step.get("patch"))
    elif action == "uninstall_patch":
        if step.get("patch") in s["patches"]:
            s["patches"].remove(step.get("patch"))
    elif action == "config_change":
        s["config_version"] += 1
    elif action == "restore_config":
        s["config_version"] -= 1
    elif action == "firewall_deny":
        s["fw_deny"].append(step.get("rule"))
    elif action == "firewall_remove_deny":
        if step.get("rule") in s["fw_deny"]:
            s["fw_deny"].remove(step.get("rule"))
    elif action == "firewall_allow":
        s["fw_allow"].append(step.get("rule"))
    elif action == "firewall_remove_allow":
        if step.get("rule") in s["fw_allow"]:
            s["fw_allow"].remove(step.get("rule"))
    elif action == "stop_service":
        s["running"] = False
    elif action == "start_service":
        s["running"] = True
    elif action == "db_schema_migrate":
        s["schema"] += 1
    # restart_service / snapshot / verify / backup do not change modelled state


def rehearse_change(rfc: dict, systems: dict, fail_at_step: int | None = None) -> dict:
    """
    Execute the forward plan in a sandbox, inject a failure at ``fail_at_step``
    (defaults to the last step), then run the RFC's *own* backout plan and
    compare the final state with the original snapshot.
    """
    state = _initial_state(systems)
    original = copy.deepcopy(state)
    steps = rfc.get("change_steps", [])
    by_num = {s.get("step"): s for s in steps}
    fail_at = fail_at_step if fail_at_step is not None else (steps[-1]["step"] if steps else 0)

    executed = []
    for s in steps:
        _apply(state, s["action"], s)
        executed.append(s["step"])
        if s["step"] == fail_at:
            break

    for b in (rfc.get("backout_plan") or {}).get("steps", []):
        fwd = by_num.get(b.get("undo_of"))
        if fwd is None or fwd["step"] not in executed:
            continue
        _apply(state, b["action"], {**fwd, **{k: v for k, v in b.items() if k not in ("action", "undo_of")}})

    diffs = [f"{sysname}: {k} {original[sysname][k]} -> {v}"
             for sysname, attrs in state.items() for k, v in attrs.items()
             if sysname in original and original[sysname][k] != v]
    return {"failed_at_step": fail_at, "executed": executed, "restored": not diffs, "diffs": diffs}


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SY0-701 1.3 Change management processes and their technical implications.",
    "concepts": [
        "Change process: request → impact analysis → test → CAB approval → schedule in window → implement → verify → document.",
        "Impact analysis must follow the DEPENDENCY graph — the patched box is rarely the one that breaks.",
        "Backout (rollback) restores the prior state; fail-forward fixes forward when rollback is impossible.",
        "Allow/deny-list changes, service restarts and legacy applications are the classic technical implications.",
    ],
    "failure_modes": [
        "Hardening a protocol (e.g. disabling TLS 1.0) that an undocumented legacy app still needs.",
        "A backout plan that exists on paper but was never rehearsed — it fails at 3 a.m.",
        "Requester approves their own change, or 'everyone' approves without owner sign-off.",
        "Change + rollback takes longer than the maintenance window → uncoordinated downtime.",
    ],
    "ai_governance": [
        "An AI patching agent must submit RFCs and wait for CAB approval — it must not self-approve.",
        "Require the agent to output an impact analysis and a machine-executable backout plan with every RFC.",
        "Agents may only execute inside an approved window and must auto-trigger backout on failed health checks.",
        "Irreversible actions (schema migrations, data purges, firmware) always need a human at the keyboard.",
    ],
    "exam_tips": [
        "'Plan to restore the system if the change fails' => backout plan.",
        "'Who approves changes' => Change Advisory Board (CAB); emergency changes go through an ECAB.",
        "'Scheduled time to make changes with minimal business impact' => maintenance window.",
        "Legacy applications and dependencies are listed explicitly as technical implications in 1.3.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    cab = ChangeAdvisoryBoard(policies["change_management"])
    results = []
    for rfc in data["rfcs"]:
        r = cab.review(rfc)
        results.append(r)
        ui.section(f"{r.rfc_id} — {r.title}")
        ui.status("CAB pre-review decision", r.decision, f"risk={r.risk_score} strategy={r.strategy}")
        for o in r.observations:
            ui.bullet(o, style="dim")
        for b in r.blockers:
            ui.bullet(f"BLOCKER: {b}", style="red")
        for c in r.conditions:
            ui.bullet(f"CONDITION: {c}", style="yellow")
        if not (rfc.get("backout_plan") or {}).get("steps") or r.strategy != "ROLLBACK":
            ui.panel("Generated backout / recovery runbook", "\n".join(f"{i}. {s}" for i, s in enumerate(r.generated_backout, 1)), style="magenta")
        if r.rehearsal:
            rh = r.rehearsal
            ui.status(f"Rehearsal (fail at step {rh['failed_at_step']}, run backout)",
                      "PASS" if rh["restored"] else "FAIL",
                      "state restored" if rh["restored"] else "; ".join(rh["diffs"]))

    ui.section("CAB summary")
    ui.table("RFC decisions", ["RFC", "Title", "Decision", "Risk", "Strategy", "Blockers"],
             [[r.rfc_id, r.title, r.decision, r.risk_score, r.strategy, len(r.blockers)] for r in results])
    ui.insight(INSIGHT)
    return {r.rfc_id: r.decision for r in results}
