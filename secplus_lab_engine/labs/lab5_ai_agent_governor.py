"""
Lab 5 — AI Agent Supervisor & Guardrail Governor
================================================

Security+ SY0-701 objectives (applied to autonomous agents)
------------------------------------------------------------
* 4.7  Automation & orchestration — guardrails, ticketing, escalation,
       "single point of failure", complexity and technical-debt risks.
* 4.6  Least privilege and privileged access management for NON-HUMAN identities.
* 1.3  Change management — automated changes still require approval.
* 2.4  Indicators of malicious activity — runaway or hijacked automation.
* 5.1  Governance — human-in-the-loop, accountability, audit.

The model
---------
AI agents never touch production directly. Each proposed action is sent to the
**Governor** (a policy decision point for automation) which returns:

* ``ALLOW``                   – inside every boundary; executes automatically.
* ``REQUIRE_HUMAN_APPROVAL``  – plausible but high-impact/uncertain; queued for HITL.
* ``BLOCK``                   – violates a hard boundary; never executes.

Checks performed (in order)
---------------------------
1. Agent identity & quarantine status (kill switch)
2. Least privilege — is this action type in the agent's allow-list?
3. Hallucination detection — non-existent assets, patches, or CAB tickets
4. Hard security boundaries — immutable firewall rule 0, protected controls
   (MFA/EDR/audit logging), audit-log tampering, self-privilege escalation,
   admin grants without an approved CAB ticket
5. Dangerous command patterns (``curl | sh``, ``rm -rf /`` ...)
6. Prompt-injection indicators in the agent's own justification
7. Rate limiting (runaway agent)
8. Confidence threshold & critical-asset escalation → human-in-the-loop

Every decision is written to a **hash-chained ledger** so the audit trail of
what the automation tried to do is itself tamper-evident.

Run it
------
    python main.py lab 5
    python main.py lab 5 --file my_agent_actions.json
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field

from utils.crypto_helpers import build_hash_chain, verify_hash_chain

TITLE = "Lab 5 — AI Agent Supervisor & Guardrail Governor"
OBJECTIVES = "SY0-701 4.7 Automation guardrails · 4.6 Non-human PAM · 5.1 Human-in-the-loop"

ALLOW, HITL, BLOCK = "ALLOW", "REQUIRE_HUMAN_APPROVAL", "BLOCK"
_RANK = {ALLOW: 0, HITL: 1, BLOCK: 2}
CRITICAL_ASSETS = {"auth-service", "ldap", "db-oracle", "api-gateway"}
# Actions whose ``target`` must be a real host in the asset inventory (CMDB).
ASSET_ACTIONS = {"apply_patch", "restart_service", "isolate_host", "run_command"}


@dataclass
class AgentAction:
    id: str
    agent_id: str
    action: str
    target: str
    parameters: dict = field(default_factory=dict)
    justification: str = ""
    cab_ticket: str | None = None
    confidence: float = 1.0
    t: float = 0.0            # seconds since scenario start

    @classmethod
    def from_dict(cls, d: dict) -> "AgentAction":
        return cls(
            id=d["id"], agent_id=d["agent_id"], action=d["action"], target=d.get("target", ""),
            parameters=d.get("parameters", {}), justification=d.get("justification", ""),
            cab_ticket=d.get("cab_ticket"), confidence=float(d.get("confidence", 1.0)), t=float(d.get("t", 0)),
        )


@dataclass
class Violation:
    code: str
    verdict: str
    message: str


@dataclass
class GovernorDecision:
    action_id: str
    agent_id: str
    verdict: str
    violations: list[Violation]
    final: str | None = None          # set after human review: EXECUTED / REJECTED
    reviewer: str | None = None

    @property
    def codes(self) -> list[str]:
        return [v.code for v in self.violations]


class AgentGovernor:
    """Policy decision point that every AI-agent action must pass through."""

    def __init__(self, policy: dict):
        self.p = policy
        self.agents: dict = policy["agents"]
        self.inventory = set(policy["asset_inventory"])
        self.patches = set(policy["patch_catalog"])
        self.tickets = set(policy["approved_cab_tickets"])
        self.dangerous = [re.compile(p, re.I) for p in policy["dangerous_command_patterns"]]
        self.injection = [re.compile(p, re.I) for p in policy["prompt_injection_patterns"]]
        self.history: dict[str, deque] = defaultdict(deque)
        self.block_count: dict[str, int] = defaultdict(int)
        self.quarantined: set[str] = set()
        self.decisions: dict[str, GovernorDecision] = {}
        self.ledger: list[dict] = []

    # ------------------------------------------------------------------ checks
    def _check(self, a: AgentAction) -> list[Violation]:
        v: list[Violation] = []
        add = lambda code, verdict, msg: v.append(Violation(code, verdict, msg))  # noqa: E731

        # 1. identity / kill switch
        if a.agent_id in self.quarantined:
            add("AGENT_QUARANTINED", BLOCK, f"{a.agent_id} is quarantined (kill switch engaged)")
            return v
        agent = self.agents.get(a.agent_id)
        if agent is None:
            add("UNKNOWN_AGENT", BLOCK, f"'{a.agent_id}' is not a registered agent identity")
            return v

        # 2. least privilege
        if a.action not in agent["allowed_actions"]:
            add("OUT_OF_SCOPE_ACTION", BLOCK,
                f"{agent['type']} agent may only {agent['allowed_actions']}; attempted '{a.action}'")

        # 3. hallucination detection
        if a.action in ASSET_ACTIONS and a.target not in self.inventory:
            add("HALLUCINATED_ASSET", BLOCK, f"target '{a.target}' does not exist in the asset inventory")
        patch = a.parameters.get("patch")
        if patch and patch not in self.patches:
            add("HALLUCINATED_PATCH", BLOCK, f"patch '{patch}' is not in the approved patch catalog")
        if a.cab_ticket and a.cab_ticket not in self.tickets:
            add("HALLUCINATED_TICKET", BLOCK, f"CAB ticket '{a.cab_ticket}' does not exist / is not approved")

        # 4. hard boundaries
        if a.action.startswith("firewall_rule") and a.parameters.get("rule_id") in self.p["immutable_firewall_rules"]:
            add("IMMUTABLE_RULE", BLOCK, f"firewall rule {a.parameters['rule_id']} is immutable (root/default-deny rule)")
        if a.action.startswith("firewall_rule"):
            src, port = a.parameters.get("src", ""), str(a.parameters.get("port", ""))
            if src in {"0.0.0.0/0", "any", "*"} and port in {"any", "*", "0-65535"}:
                add("OVERLY_PERMISSIVE_RULE", HITL, "any/any allow rule defeats the firewall — human must confirm")
        if a.action == "grant_privilege":
            role = a.parameters.get("role", "")
            grantee = a.parameters.get("user", a.target)
            if grantee == a.agent_id or grantee in self.agents:
                add("SELF_ESCALATION", BLOCK, f"agent attempted to grant '{role}' to an agent identity ({grantee})")
            if role in self.p["privileged_roles"] and (not a.cab_ticket or a.cab_ticket not in self.tickets):
                add("PRIV_GRANT_NO_CAB", BLOCK, f"granting privileged role '{role}' requires an approved CAB ticket")
        touched = {a.target, a.parameters.get("control", "")} & set(self.p["protected_controls"])
        if touched and a.action not in {"read_logs", "read_inventory"}:
            add("PROTECTED_CONTROL", BLOCK, f"agents may not modify security controls: {sorted(touched)}")
        if a.action in {"delete_logs", "clear_logs", "modify_logs"} or "audit" in str(a.parameters.get("path", "")):
            add("AUDIT_TAMPERING", BLOCK, "agents have no write access to audit logs")

        # 5. dangerous commands
        cmd = a.parameters.get("command", "")
        for pat in self.dangerous:
            if cmd and pat.search(cmd):
                add("DANGEROUS_COMMAND", BLOCK, f"command matches dangerous pattern /{pat.pattern}/")
                break

        # 6. prompt injection in reasoning / justification
        for pat in self.injection:
            if pat.search(a.justification):
                add("PROMPT_INJECTION", BLOCK, f"justification contains injection marker /{pat.pattern}/ — agent may be hijacked")
                break

        # 7. rate limiting
        window = self.p["rate_window_seconds"]
        hist = self.history[a.agent_id]
        while hist and a.t - hist[0] > window:
            hist.popleft()
        if len(hist) >= self.p["max_actions_per_agent_per_window"]:
            add("RATE_LIMIT", BLOCK, f"{len(hist)+1} actions in {window}s exceeds limit "
                                     f"{self.p['max_actions_per_agent_per_window']} (runaway automation)")
        hist.append(a.t)

        # 8. human-in-the-loop triggers
        if a.confidence < self.p["confidence_threshold"]:
            add("LOW_CONFIDENCE", HITL, f"confidence {a.confidence:.2f} < {self.p['confidence_threshold']:.2f}")
        if a.target in CRITICAL_ASSETS and a.action in {"isolate_host", "restart_service", "apply_patch"}:
            add("CRITICAL_ASSET", HITL, f"'{a.target}' is a tier-0 asset — disruptive action needs a human")
        if a.action in self.p.get("always_hitl_actions", []):
            add("HUMAN_REQUIRED_CLASS", HITL, f"'{a.action}' always needs human approval (user-impacting)")
        if not a.justification.strip():
            add("NO_JUSTIFICATION", HITL, "agent supplied no rationale — cannot be audited")
        return v

    # ------------------------------------------------------------------ public API
    def evaluate(self, a: AgentAction) -> GovernorDecision:
        violations = self._check(a)
        verdict = max((x.verdict for x in violations), key=_RANK.get, default=ALLOW)
        d = GovernorDecision(a.id, a.agent_id, verdict, violations,
                             final="EXECUTED" if verdict == ALLOW else None)
        self.decisions[a.id] = d
        if verdict == BLOCK and "AGENT_QUARANTINED" not in d.codes:
            self.block_count[a.agent_id] += 1
            if self.block_count[a.agent_id] >= self.p["quarantine_after_blocks"]:
                self.quarantined.add(a.agent_id)
        self._log({"event": "DECISION", "action": a.id, "agent": a.agent_id, "op": a.action,
                   "target": a.target, "verdict": verdict, "codes": d.codes})
        return d

    def human_review(self, action_id: str, reviewer: str, approve: bool, reason: str = "") -> GovernorDecision:
        """
        Human-in-the-loop override. Only REQUIRE_HUMAN_APPROVAL items can be
        approved, only by an authorised human approver, never by an agent.
        Hard BLOCKs are non-overridable by design.
        """
        d = self.decisions[action_id]
        if reviewer in self.agents:
            raise PermissionError(f"agent '{reviewer}' cannot approve actions (no self-approval)")
        if reviewer not in self.p["human_approvers"]:
            raise PermissionError(f"'{reviewer}' is not an authorised human approver")
        if d.verdict == BLOCK and approve:
            raise PermissionError(f"{action_id} violated a hard boundary {d.codes}; BLOCK cannot be overridden")
        if d.verdict == ALLOW:
            raise ValueError(f"{action_id} was already auto-approved")
        if d.final:
            raise ValueError(f"{action_id} was already reviewed ({d.final} by {d.reviewer})")
        d.final, d.reviewer = ("EXECUTED" if approve else "REJECTED"), reviewer
        self._log({"event": "HUMAN_REVIEW", "action": action_id, "reviewer": reviewer,
                   "approved": approve, "reason": reason})
        return d

    def release_quarantine(self, agent_id: str, reviewer: str) -> None:
        if reviewer not in self.p["human_approvers"]:
            raise PermissionError("only an authorised human can release a quarantined agent")
        self.quarantined.discard(agent_id)
        self.block_count[agent_id] = 0
        self._log({"event": "QUARANTINE_RELEASED", "agent": agent_id, "reviewer": reviewer})

    # ------------------------------------------------------------------ ledger
    def _log(self, entry: dict) -> None:
        self.ledger.append(entry)

    def ledger_chain(self, salt: str = "governor-ledger") -> list[str]:
        return build_hash_chain(self.ledger, salt)

    def verify_ledger(self, chain: list[str], salt: str = "governor-ledger") -> dict:
        return verify_hash_chain(self.ledger, chain, salt)


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SY0-701 4.7 (automation & orchestration guardrails) + 4.6 PAM for non-human identities + 5.1 oversight.",
    "concepts": [
        "Every agent is a non-human identity with its own least-privilege allow-list — never a shared admin account.",
        "Three-tier verdicts: ALLOW (in policy), REQUIRE_HUMAN_APPROVAL (uncertain/high impact), BLOCK (hard boundary).",
        "Hard boundaries are non-overridable: even a human can't approve disabling MFA through the agent pipeline.",
        "A kill switch (quarantine) stops runaway or hijacked automation after repeated violations.",
    ],
    "failure_modes": [
        "Giving the agent a domain-admin service account 'so it can do its job' (no blast-radius limit).",
        "Trusting the agent's own references: it can invent ticket numbers, patch IDs and hostnames.",
        "Indirect prompt injection — data the agent reads (tickets, emails, logs) tells it to break policy.",
        "No rate limit: a looping agent restarts production 400 times before anyone notices.",
    ],
    "ai_governance": [
        "Validate every agent claim against an authoritative source (CMDB, patch catalog, ticketing system).",
        "Route privileged or irreversible actions through the same CAB/approval workflow as humans.",
        "Keep a tamper-evident ledger of every proposed AND executed action for accountability.",
        "Separate duties: the agent that proposes a change must not be the identity that approves it.",
    ],
    "exam_tips": [
        "Automation benefits: enforcing baselines, standard configurations, scaling securely, reaction time.",
        "Automation risks listed in 4.7: complexity, cost, single point of failure, technical debt, ongoing supportability.",
        "'Guard rails' in 4.7 = automated limits that keep scripts/agents inside safe boundaries.",
        "Human-in-the-loop is the governance answer whenever impact is high and confidence is low.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    gov = AgentGovernor(policies["ai_governance"])

    ui.section("Step 1 — Agents propose actions; Governor evaluates each one")
    rows = []
    for raw in data["actions"]:
        a = AgentAction.from_dict(raw)
        d = gov.evaluate(a)
        detail = "; ".join(f"{v.code}" for v in d.violations) or "within policy"
        rows.append([a.id, a.agent_id, f"{a.action} → {a.target}", d.verdict, detail])
    ui.table("Governor decisions", ["ID", "Agent", "Proposed action", "Verdict", "Violations"], rows)

    ui.section("Step 2 — Violation detail")
    for d in gov.decisions.values():
        for v in d.violations:
            if v.verdict != ALLOW:
                ui.bullet(f"{d.action_id} [{v.code}] {v.message}", style="red" if v.verdict == BLOCK else "yellow")

    if gov.quarantined:
        ui.panel("Kill switch", "Quarantined agents: " + ", ".join(sorted(gov.quarantined)) +
                 "\nAll further actions are blocked until a human releases them.", style="red")

    ui.section("Step 3 — Human-in-the-loop review queue")
    review_rows = []
    for rv in data.get("human_reviews", []):
        try:
            d = gov.human_review(rv["action_id"], rv["reviewer"], rv["approve"], rv.get("reason", ""))
            review_rows.append([rv["action_id"], rv["reviewer"], "APPROVE" if rv["approve"] else "REJECT", d.final, rv.get("reason", "")])
        except (PermissionError, ValueError, KeyError) as exc:
            review_rows.append([rv["action_id"], rv["reviewer"], "APPROVE" if rv["approve"] else "REJECT", "DENIED", str(exc)])
    ui.table("Reviews", ["Action", "Reviewer", "Request", "Outcome", "Note"], review_rows)

    ui.section("Step 4 — Tamper-evident decision ledger")
    chain = gov.ledger_chain()
    ui.status("Ledger intact", "VALID" if gov.verify_ledger(chain)["valid"] else "TAMPERED", f"{len(chain)} entries")
    original = dict(gov.ledger[0])
    gov.ledger[0]["verdict"] = ALLOW if gov.ledger[0].get("verdict") != ALLOW else BLOCK
    res = gov.verify_ledger(chain)
    ui.status("Someone rewrites entry #1 after the fact", "VALID" if res["valid"] else "TAMPERED",
              f"chain broken at entry #{res['first_broken_index'] + 1}")
    gov.ledger[0] = original

    ui.insight(INSIGHT)
    verdicts = [d.verdict for d in gov.decisions.values()]
    return {
        "allow": verdicts.count(ALLOW),
        "hitl": verdicts.count(HITL),
        "block": verdicts.count(BLOCK),
        "quarantined": sorted(gov.quarantined),
    }


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    """Predict the Governor's verdict for each proposed action, in sequence."""
    from utils.challenge import Question

    gov = AgentGovernor(policies["ai_governance"])
    qs: list = []
    for raw in data["actions"]:
        a = AgentAction.from_dict(raw)
        prior_blocks = gov.block_count.get(a.agent_id, 0)
        quarantined = a.agent_id in gov.quarantined
        d = gov.evaluate(a)
        agent = gov.agents.get(a.agent_id)
        qs.append(Question(
            prompt=f"{a.id}: {a.agent_id} proposes '{a.action}' on '{a.target}'. Governor verdict?",
            context=(f"params={a.parameters} cab_ticket={a.cab_ticket} confidence={a.confidence} t={a.t:.0f}s\n"
                     f"justification: \"{a.justification}\"\n"
                     f"agent allow-list: {agent['allowed_actions'] if agent else 'NOT REGISTERED'} · "
                     f"prior blocks={prior_blocks} · quarantined={quarantined}"),
            choices=[ALLOW, HITL, BLOCK],
            answer=d.verdict,
            explanation="; ".join(f"{v.code}: {v.message}" for v in d.violations) or "Inside every boundary.",
            objective="4.7",
        ))
    return qs
