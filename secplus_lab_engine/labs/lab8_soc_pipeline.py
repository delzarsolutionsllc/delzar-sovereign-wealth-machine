"""
Lab 8 — End-to-End SOC Pipeline (all labs wired together)
=========================================================

Security+ SY0-701 objectives
----------------------------
* 4.7  Automation & orchestration (SOAR): playbooks, guardrails, escalation.
* 4.8  Incident response · 4.9 Investigation data sources
* 1.3  Change management for emergency changes · 4.6 IAM · 1.2 Zero Trust

The architecture this whole engine builds toward
------------------------------------------------
::

    Lab 3 Detect ──▶ AI SOC agent proposes ──▶ Lab 5 Governor ──▶ human (HITL)
                                                   │
                     ┌─────────────────────────────┼──────────────────────────┐
                     ▼                             ▼                          ▼
          disable_account                     block_ip                   isolate_host
      Lab 1 IGA suspend + Lab 2         Lab 4 emergency RFC → CAB     Lab 7 IR case: capture
      PA revokes every session          review + rehearsed backout    volatile evidence FIRST

The "AI agent" here is a deterministic stand-in that maps findings to
proposed actions, including one overreach that the Governor must stop. Replace
``soc_agent_propose`` with a real model and every guardrail still applies.

Run it
------
    python main.py lab 8
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from labs.lab1_jml_governance import IdentityGovernance
from labs.lab2_zero_trust_evaluator import AccessRequest, PolicyDecision, ZeroTrustGateway
from labs.lab3_log_inspector import Finding, parse_stream, run_detections
from labs.lab4_change_management import ChangeAdvisoryBoard
from labs.lab5_ai_agent_governor import ALLOW, BLOCK, HITL, AgentAction, AgentGovernor
from labs.lab7_incident_response import grade_playbook
from utils.loader import load_data

TITLE = "Lab 8 — End-to-End SOC Pipeline (Detect → Agent → Governor → CAB / IAM / IR)"
OBJECTIVES = "SY0-701 4.7 SOAR · 4.8 IR · 1.3 Emergency change · 4.6 IAM · 1.2 Zero Trust"

DOWNSTREAM = {
    "disable_account": "IAM: suspend account + revoke sessions",
    "block_ip": "Change control: emergency RFC to the CAB",
    "isolate_host": "Incident response: evidence first, then contain",
}


@dataclass
class Proposal:
    finding: Finding
    action: AgentAction


@dataclass
class PipelineRow:
    action_id: str
    finding: str
    proposal: str
    verdict: str
    human: str = "-"
    outcome: str = "-"


@dataclass
class PipelineResult:
    rows: list[PipelineRow] = field(default_factory=list)
    rfc_decision: str | None = None
    suspended: list[str] = field(default_factory=list)
    sessions_revoked: int = 0
    isolated: list[str] = field(default_factory=list)
    custody_records: int = 0


# --------------------------------------------------------------------------- #
# The (simulated) AI SOC agent
# --------------------------------------------------------------------------- #
def soc_agent_propose(findings: list[Finding], events_by_line: dict, agent_id: str) -> list[Proposal]:
    """Map each finding to the response an eager SOC agent would propose."""
    out: list[Proposal] = []
    seen: set[tuple] = set()
    t = 0.0

    def add(f: Finding, action: str, target: str, conf: float, why: str, **params) -> None:
        nonlocal t
        key = (action, target)
        if key in seen:
            return
        seen.add(key)
        t += 15  # an agent pacing its work; Lab 5 shows what a runaway burst triggers
        out.append(Proposal(f, AgentAction(f"P{len(out) + 1:02d}", agent_id, action, target, params, why,
                                           confidence=conf, t=t)))

    for f in findings:
        ev = events_by_line.get(f.evidence_lines[-1]) or events_by_line.get(f.evidence_lines[0])
        if ev is None:
            continue
        if f.rule == "BRUTE_FORCE_SUCCESS":
            add(f, "disable_account", ev.user, 0.93, "Brute force succeeded; account likely compromised.")
            add(f, "block_ip", ev.src_ip, 0.95, "Source of the successful brute force.")
        elif f.rule == "IMPOSSIBLE_TRAVEL":
            add(f, "disable_account", ev.user, 0.71, "Logins from two countries 40 minutes apart.")
        elif f.rule == "TI_MATCH_FILE_HASH":
            add(f, "isolate_host", ev.host.lower(), 0.96, "Known malware hash on endpoint.")
        elif f.rule in {"PASSWORD_SPRAY", "SQL_INJECTION", "PORT_SCAN"} and ev.src_ip:
            add(f, "block_ip", ev.src_ip, 0.90, f"{f.rule.replace('_', ' ').lower()} source.")
        elif f.rule == "AUDIT_LOG_CLEARED":
            # Overreach: the agent "helpfully" tries to lock down the whole network.
            add(f, "firewall_rule_modify", "edge-fw", 0.82,
                "Attacker is covering tracks; contain everything by changing the default rule.",
                rule_id=0, change="default allow -> deny all")
    return out


# --------------------------------------------------------------------------- #
# Pipeline
# --------------------------------------------------------------------------- #
def run_pipeline(policies: dict, data: dict, logs: dict, incident: dict) -> PipelineResult:
    res = PipelineResult()

    # Lab 3 — detect
    events, _ = parse_stream(logs["raw_stream"], logs.get("geoip", {}))
    by_line = {e.line_no: e for e in events}
    findings = run_detections(events, policies["log_inspection"])

    # Lab 1 / Lab 2 — identity + live sessions to act on
    iga = IdentityGovernance(policies["identity_governance"])
    for rec in data.get("directory", []):
        iga.joiner(rec)
    gw = ZeroTrustGateway(policies["zero_trust"], clock=lambda: 1_800_000_000.0)
    for sub in data.get("active_sessions", []):
        req = AccessRequest.from_dict({"id": f"S-{sub}", "subject": sub, "resource": "intranet", "hour": 3, "mfa": True,
                                       "device": {"id": "?", "managed": True, "health_score": 90},
                                       "ip": "0.0.0.0", "geo": "", "usual_geo": ""})
        gw.pa.issue(req, PolicyDecision(req.id, "ALLOW", 100, 50))

    # Lab 5 — govern every proposal
    gov = AgentGovernor(policies["ai_governance"])
    reviews = data.get("human_reviews", {})
    approved: list[AgentAction] = []
    for p in soc_agent_propose(findings, by_line, data.get("agent_id", "soc-triage-03")):
        a = p.action
        d = gov.evaluate(a)
        row = PipelineRow(a.id, f"{p.finding.rule} ({p.finding.severity})", f"{a.action} → {a.target}", d.verdict)
        if d.verdict == ALLOW:
            approved.append(a)
        elif d.verdict == HITL:
            rv = reviews.get(f"{a.action}:{a.target}")
            if rv:
                gov.human_review(a.id, rv["reviewer"], rv["approve"], rv.get("reason", ""))
                row.human = f"{'APPROVE' if rv['approve'] else 'REJECT'} by {rv['reviewer']}"
                row.outcome = rv.get("reason", "")
                if rv["approve"]:
                    approved.append(a)
            else:
                row.human, row.outcome = "PENDING", "waiting in the HITL queue"
        else:
            row.outcome = "; ".join(v.code for v in d.violations)
        res.rows.append(row)

    # Execute approved actions through the owning control
    outcome_for: dict[str, str] = {}
    for a in approved:
        if a.action == "disable_account":
            iga.suspend(a.target, f"IR: {a.id}")
            n = gw.pa.revoke_subject(a.target)
            res.suspended.append(a.target)
            res.sessions_revoked += n
            outcome_for[a.id] = f"suspended in IGA; {n} session token(s) revoked by PA"
        elif a.action == "isolate_host":
            # IR gate: capture volatile evidence before containment
            pb = ["triage_alert", "declare_incident", "capture_netconns", "capture_memory", "isolate_host"]
            g = grade_playbook("pipeline", pb, incident["actions"], incident["incident"]["id"])
            res.isolated.append(a.target)
            res.custody_records += len(g.custody)
            outcome_for[a.id] = (f"IR case opened; {len(g.custody)} volatile evidence items hashed BEFORE isolation")

    ips = [a.target for a in approved if a.action == "block_ip"]
    if ips:
        now = datetime.fromisoformat(data.get("now", "2026-11-03T04:00:00"))
        steps = [{"step": 1, "action": "snapshot", "target": "edge-fw"}]
        steps += [{"step": i + 2, "action": "firewall_deny", "target": "edge-fw", "rule": f"ip:{ip}"} for i, ip in enumerate(ips)]
        rfc = {
            "id": "RFC-AUTO-0001", "title": f"Emergency block of {len(ips)} malicious IP(s)",
            "requested_by": data.get("agent_id", "soc-triage-03"),
            "approvals": data.get("emergency_cab_approvals", []),
            "target_systems": ["edge-fw"],
            "window": {"start": now.isoformat(), "end": (now + timedelta(minutes=30)).isoformat()},
            "estimated_minutes": 10, "tested_in_staging": False, "emergency": True,
            "change_steps": steps,
            "firewall_changes": {"allow": [], "deny": [f"ip:{ip}" for ip in ips]},
            "backout_plan": {"estimated_minutes": 10,
                             "steps": [{"undo_of": s["step"], "action": "firewall_remove_deny"} for s in steps[1:]],
                             "verification": ["confirm legitimate traffic still flows through edge-fw"]},
        }
        r = ChangeAdvisoryBoard(policies["change_management"]).review(rfc)
        res.rfc_decision = r.decision
        for a in approved:
            if a.action == "block_ip":
                outcome_for[a.id] = f"{rfc['id']} → CAB {r.decision}" + (
                    f" (rehearsal {'PASS' if r.rehearsal and r.rehearsal['restored'] else 'FAIL'})" if r.rehearsal else "")

    for row in res.rows:
        if row.action_id in outcome_for:
            row.outcome = outcome_for[row.action_id]
    return res


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SY0-701 4.7 Automation & orchestration (SOAR) tying together 1.2, 1.3, 4.6, 4.8 and 4.9.",
    "concepts": [
        "Detection, decision and execution are separate trust boundaries; no single component (or agent) owns all three.",
        "Every automated action is routed to the control that owns it: IAM for accounts, CAB for network changes, IR for hosts.",
        "Emergency changes still get an RFC, ECAB approval, a rehearsed backout and a post-implementation review.",
        "Human-in-the-loop on user-impacting actions turns false positives into rule-tuning instead of outages.",
    ],
    "failure_modes": [
        "A SOAR playbook that disables accounts automatically locks out the CEO on a false positive.",
        "Automation that blocks IPs directly on the firewall, bypassing change control: no backout, no record.",
        "Isolating or wiping a host before capturing memory destroys the evidence that explains the breach.",
        "An over-privileged agent 'containing' an incident by changing the default firewall rule.",
    ],
    "ai_governance": [
        "Give the SOC agent a narrow allow-list and let it PROPOSE; the Governor and humans DISPOSE.",
        "Make every downstream system (IAM, CAB, IR) enforce its own rules even for approved agent actions: defense in depth.",
        "Feed human rejections back as tuning data, e.g. the travel-VPN egress that triggered impossible travel.",
        "Measure the agent: precision of its proposals, how often humans overturn it, and blocked attempts.",
    ],
    "exam_tips": [
        "SOAR = Security Orchestration, Automation and Response: playbooks that act on SIEM alerts.",
        "Benefits in 4.7: efficiency, enforcing baselines, reaction time, workforce multiplier.",
        "Considerations in 4.7: complexity, cost, single point of failure, technical debt, ongoing supportability.",
        "Containment choices (isolate, segment, disable) must balance evidence preservation against spread.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def _load_inputs(data: dict) -> tuple[dict, dict]:
    return load_data(data.get("logs_file", "sample_logs.json")), load_data(data.get("incident_file", "sample_incident.json"))


def run_demo(ui, policies: dict, data: dict) -> dict:
    logs, incident = _load_inputs(data)
    res = run_pipeline(policies, data, logs, incident)

    ui.section("Detect → Propose → Govern → Human → Execute")
    ui.table("Pipeline trace", ["Finding", "Agent proposal", "Governor", "Human", "Outcome"],
             [[r.finding, r.proposal, r.verdict, r.human, r.outcome] for r in res.rows])

    ui.section("Downstream controls")
    ui.status("IAM: accounts suspended", "OK" if res.suspended else "WARN",
              f"{res.suspended} · {res.sessions_revoked} live session token(s) revoked")
    ui.status("Change control: emergency firewall RFC", res.rfc_decision or "WARN",
              "CAB reviewed the agent's block-list change with a generated backout")
    ui.status("Incident response: hosts isolated", "OK" if res.isolated else "WARN",
              f"{res.isolated} · {res.custody_records} evidence items hashed into custody first")

    ui.insight(INSIGHT)
    verdicts = [r.verdict for r in res.rows]
    return {
        "proposals": len(res.rows),
        "allowed": verdicts.count(ALLOW),
        "hitl": verdicts.count(HITL),
        "blocked": verdicts.count(BLOCK),
        "suspended": res.suspended,
        "sessions_revoked": res.sessions_revoked,
        "rfc_decision": res.rfc_decision,
        "isolated": res.isolated,
    }


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question

    logs, incident = _load_inputs(data)
    res = run_pipeline(policies, data, logs, incident)
    route_choices = sorted(set(DOWNSTREAM.values()) | {"Nothing: the Governor blocks it"})
    qs: list = []
    for r in res.rows:
        action = r.proposal.split(" → ")[0]
        ans = "Nothing: the Governor blocks it" if r.verdict == BLOCK else DOWNSTREAM.get(action)
        if ans is None:
            continue
        qs.append(Question(
            prompt=f"The SOC agent proposes '{r.proposal}' for {r.finding}. Where does it end up?",
            choices=route_choices, answer=ans,
            explanation=f"Governor: {r.verdict}. {r.outcome}",
            objective="4.7"))
    qs.append(Question(
        prompt="Before the agent's isolate_host executes, what must happen first?",
        choices=["Reimage the host", "Capture volatile evidence (RAM, network state) and hash it",
                 "Power the host off", "Notify the attacker's ISP"],
        answer="Capture volatile evidence (RAM, network state) and hash it",
        explanation="Isolation keeps the host powered so memory survives, but the evidence should be captured and "
                    "hashed first. Order of volatility plus chain of custody.",
        objective="4.8"))
    return qs
