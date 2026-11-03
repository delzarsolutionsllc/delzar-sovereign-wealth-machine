"""
Lab 7 — Incident Response Runner & Chain of Custody
===================================================

Security+ SY0-701 objectives
----------------------------
* 4.8  Incident response: process (preparation, detection, analysis,
       containment, eradication, recovery, lessons learned), training,
       testing (tabletop, simulation), root cause analysis, threat hunting,
       digital forensics (legal hold, chain of custody, acquisition,
       reporting, preservation, e-discovery).
* 4.9  Data sources supporting an investigation.

What this lab does
------------------
You give it a *playbook*: an ordered list of response actions picked from a
catalog. The grader then checks it:

* **Lifecycle order** — containment before eradication, eradication before
  recovery, lessons learned at the end, no containment after recovery.
* **Order of volatility** (RFC 3227) — collect CPU/RAM/network state before
  disk, and disk before remote logs and archives.
* **Evidence destruction** — powering off or reimaging before acquisition
  destroys evidence permanently.
* **Prerequisites** — e.g. no reimage without a disk image and a legal hold.
* **Chain of custody** — every evidence item is hashed at acquisition and
  logged to a tamper-evident custody ledger.

The sample compares a rookie response with an expert one.

Run it
------
    python main.py lab 7
    python main.py lab 7 --file my_incident.json   # grade your own playbook
"""

from __future__ import annotations

from dataclasses import dataclass, field

from utils.crypto_helpers import build_hash_chain, sha256_hex, verify_hash_chain

TITLE = "Lab 7 — Incident Response Runner & Chain of Custody"
OBJECTIVES = "SY0-701 4.8 Incident response & digital forensics · 4.9 Data sources"

PHASES = ["preparation", "detection", "analysis", "containment", "eradication", "recovery", "lessons_learned"]
PHASE_IDX = {p: i for i, p in enumerate(PHASES)}
VOLATILITY = {
    1: "CPU registers / cache",
    2: "RAM, process table, network state",
    3: "swap / temp files",
    4: "disk",
    5: "remote logs / monitoring data",
    6: "archival media / backups",
}
PENALTY = {
    "EVIDENCE_DESTROYED": 20, "CHAIN_OF_CUSTODY": 15, "MISSING_PREREQ": 15, "NO_CONTAINMENT": 15,
    "ORDER_OF_VOLATILITY": 10, "PHASE_ORDER": 10, "NO_LESSONS_LEARNED": 10, "ANTI_PATTERN": 10,
    "UNKNOWN_ACTION": 5,
}


@dataclass
class Issue:
    code: str
    step: int
    message: str

    @property
    def penalty(self) -> int:
        return PENALTY[self.code]


@dataclass
class CustodyRecord:
    evidence_id: str
    source: str
    host: str
    step: int
    sha256: str | None
    status: str          # INTACT | BROKEN | DESTROYED


@dataclass
class PlaybookGrade:
    name: str
    score: int
    grade: str
    issues: list[Issue] = field(default_factory=list)
    custody: list[CustodyRecord] = field(default_factory=list)
    ledger_chain: list[str] = field(default_factory=list)
    ledger: list[dict] = field(default_factory=list)


def grade_playbook(name: str, playbook: list[str], catalog: dict, incident_id: str = "IR") -> PlaybookGrade:
    """Walk the playbook step by step and collect issues + the custody ledger."""
    issues: list[Issue] = []
    custody: list[CustodyRecord] = []
    ledger: list[dict] = []
    done: list[str] = []
    destroyed_up_to = 0           # highest volatility rank already destroyed
    max_rank_collected = 0
    seen_phases: list[str] = []

    for step, aid in enumerate(playbook, 1):
        act = catalog.get(aid)
        if act is None:
            issues.append(Issue("UNKNOWN_ACTION", step, f"'{aid}' is not in the action catalog"))
            continue
        phase = act["phase"]

        # lifecycle ordering rules
        if phase in ("eradication", "recovery") and "containment" not in seen_phases:
            issues.append(Issue("PHASE_ORDER", step, f"{phase} ('{aid}') before any containment"))
        if phase == "recovery" and "eradication" not in seen_phases:
            issues.append(Issue("PHASE_ORDER", step, f"recovery ('{aid}') before eradication: threat may still be present"))
        if phase == "containment" and "recovery" in seen_phases:
            issues.append(Issue("PHASE_ORDER", step, f"containment ('{aid}') AFTER recovery: attacker had access the whole time"))
        if "lessons_learned" in seen_phases and phase != "lessons_learned":
            issues.append(Issue("PHASE_ORDER", step, f"'{aid}' after lessons learned: the case was closed too early"))

        for req in act.get("requires", []):
            if req not in done:
                issues.append(Issue("MISSING_PREREQ", step, f"'{aid}' requires '{req}' first"))

        if ap := act.get("anti_pattern"):
            issues.append(Issue("ANTI_PATTERN", step, f"'{aid}': {ap}"))

        if ev := act.get("evidence"):
            rank = ev["volatility_rank"]
            if rank <= destroyed_up_to:
                issues.append(Issue("EVIDENCE_DESTROYED", step,
                                    f"'{aid}' tries to collect {ev['source']}, already destroyed by an earlier step"))
                status, digest = "DESTROYED", None
            else:
                if rank < max_rank_collected:
                    issues.append(Issue("ORDER_OF_VOLATILITY", step,
                                        f"{ev['source']} (rank {rank}) collected after less volatile evidence "
                                        f"(rank {max_rank_collected}); it may have changed or disappeared"))
                max_rank_collected = max(max_rank_collected, rank)
                if ev.get("hashed"):
                    digest = sha256_hex(f"{incident_id}|{ev['host']}|{ev['source']}|step{step}")
                    status = "INTACT"
                else:
                    digest, status = None, "BROKEN"
                    issues.append(Issue("CHAIN_OF_CUSTODY", step, f"{ev['source']} from {ev['host']} acquired without a hash"))
            ev_id = f"EV-{len(custody) + 1:03d}"
            custody.append(CustodyRecord(ev_id, ev["source"], ev["host"], step, digest, status))
            ledger.append({"evidence": ev_id, "action": "ACQUIRED", "by": "ir_analyst", "sha256": digest, "step": step})
            if status == "INTACT":
                ledger.append({"evidence": ev_id, "action": "TRANSFERRED", "to": "evidence_locker", "sha256": digest})

        if destroys := act.get("destroys_up_to_rank"):
            lost = [k for k in range(destroyed_up_to + 1, destroys + 1)]
            uncollected = [VOLATILITY[k] for k in lost if k > max_rank_collected]
            if uncollected:
                issues.append(Issue("EVIDENCE_DESTROYED", step, f"'{aid}' destroys uncollected evidence: {uncollected}"))
            destroyed_up_to = max(destroyed_up_to, destroys)

        done.append(aid)
        seen_phases.append(phase)

    if "containment" not in seen_phases:
        issues.append(Issue("NO_CONTAINMENT", len(playbook), "no containment step: the attacker is never cut off"))
    if "lessons_learned" not in seen_phases:
        issues.append(Issue("NO_LESSONS_LEARNED", len(playbook), "no lessons-learned review: the same incident will recur"))

    score = max(0, 100 - sum(i.penalty for i in issues))
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    return PlaybookGrade(name, score, grade, issues, custody, build_hash_chain(ledger, incident_id), ledger)


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SY0-701 4.8 Incident response process & digital forensics.",
    "concepts": [
        "Lifecycle: preparation → detection → analysis → containment → eradication → recovery → lessons learned.",
        "Order of volatility (RFC 3227): registers/cache → RAM & network state → swap/temp → disk → remote logs → archives.",
        "Chain of custody: who collected what, when, with which hash, and every hand-off since. One gap and the evidence can be thrown out.",
        "A legal hold freezes deletion of relevant data the moment litigation is reasonably anticipated.",
    ],
    "failure_modes": [
        "Pulling the plug 'to stop the malware': RAM-resident malware and network state are gone forever.",
        "Reimaging before imaging the disk: no root cause analysis, no evidence for law enforcement or insurers.",
        "Restoring service before eradication: re-infection from the persistence you never found.",
        "Skipping lessons learned, so the playbook never improves.",
    ],
    "ai_governance": [
        "AI responders should follow the SAME lifecycle; enforce phase gates (no eradication until containment is confirmed).",
        "Agents may collect evidence but must hash it at acquisition and write to an append-only custody ledger.",
        "Destructive actions (power off, reimage, delete) need human sign-off and must check that evidence was acquired first.",
        "Log every agent action into the incident timeline; the agent's own actions are evidence too.",
    ],
    "exam_tips": [
        "'What should be collected first?' → the most volatile source available (usually RAM).",
        "'Stop the spread' = containment; 'remove the malware' = eradication; 'return to normal' = recovery.",
        "'Documents everyone who handled the evidence' = chain of custody.",
        "Tabletop exercise = discussion-based; simulation = hands-on practice of the plan.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    inc, catalog = data["incident"], data["actions"]
    ui.panel(f"Incident {inc['id']}", inc["summary"], style="red")
    grades = {}
    for name, pb in data["playbooks"].items():
        g = grade_playbook(name, pb, catalog, inc["id"])
        grades[name] = g
        ui.section(f"Playbook: {name}  →  score {g.score}/100  (grade {g.grade})")
        ui.table("Timeline", ["#", "Phase", "Action"],
                 [[i, catalog.get(a, {}).get("phase", "?"), catalog.get(a, {}).get("desc", a)] for i, a in enumerate(pb, 1)])
        if g.issues:
            ui.table("Issues", ["Step", "Code", "Penalty", "Detail"],
                     [[i.step, i.code, f"-{i.penalty}", i.message] for i in g.issues])
        else:
            ui.bullet("No issues found.", style="green")
        ui.table("Chain of custody", ["Evidence", "Source", "Host", "Step", "SHA-256", "Status"],
                 [[c.evidence_id, c.source, c.host, c.step, (c.sha256 or "—")[:16] + ("…" if c.sha256 else ""),
                   "VALID" if c.status == "INTACT" else "FAIL"] for c in g.custody] or [["-"] * 5 + ["none collected"]])

    expert = grades.get("expert")
    if expert and expert.ledger:
        ui.section("Custody ledger integrity")
        ok = verify_hash_chain(expert.ledger, expert.ledger_chain, inc["id"])["valid"]
        ui.status("Expert custody ledger", "VALID" if ok else "TAMPERED", f"{len(expert.ledger)} entries")
        tampered = [dict(e) for e in expert.ledger]
        tampered[0]["by"] = "someone_else"
        bad = verify_hash_chain(tampered, expert.ledger_chain, inc["id"])
        ui.status("Ledger after someone rewrites who collected EV-001",
                  "VALID" if bad["valid"] else "TAMPERED", f"breaks at entry #{(bad['first_broken_index'] or 0) + 1}")

    ui.insight(INSIGHT)
    return {name: f"{g.score} ({g.grade})" for name, g in grades.items()}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question

    catalog = data["actions"]
    qs: list = []
    pretty = {p: p.replace("_", " ").title() for p in PHASES}
    for aid in ["triage_alert", "capture_memory", "isolate_host", "block_ioc", "remove_persistence",
                "reset_creds", "restore_service", "lessons", "legal_hold"]:
        if aid not in catalog:
            continue
        a = catalog[aid]
        qs.append(Question(
            prompt=f"Which IR phase does this belong to: '{a['desc']}'?",
            choices=[pretty[p] for p in PHASES], answer=pretty[a["phase"]],
            explanation=f"{pretty[a['phase']]} — " + {
                "detection": "recognising and confirming that an incident is happening.",
                "analysis": "understanding scope and cause while preserving evidence.",
                "containment": "stopping the spread without destroying evidence.",
                "eradication": "removing the threat and the way it got in.",
                "recovery": "safely returning systems to normal operation under watch.",
                "lessons_learned": "improving the plan so this does not recur.",
                "preparation": "being ready before anything happens.",
            }[a["phase"]],
            objective="4.8"))

    pairs = [(2, 4), (4, 5), (3, 4), (2, 6), (5, 6)]
    for a, b in pairs:
        qs.append(Question(
            prompt="Following order of volatility, which do you collect FIRST?",
            choices=sorted([VOLATILITY[a], VOLATILITY[b]]), answer=VOLATILITY[a],
            explanation=f"'{VOLATILITY[a]}' is rank {a} and '{VOLATILITY[b]}' is rank {b} (RFC 3227); "
                        "collect the more volatile data first, before it changes or disappears.",
            objective="4.8"))

    for name, pb in data["playbooks"].items():
        g = grade_playbook(name, pb, catalog)
        steps = "\n".join(f"  {i}. {catalog.get(x, {}).get('desc', x)}" for i, x in enumerate(pb, 1))
        qs.append(Question(
            prompt=f"Grade the '{name}' playbook.",
            context=steps,
            choices=["A", "B", "C", "D", "F"], answer=g.grade,
            explanation=f"Score {g.score}/100. " + ("; ".join(f"{i.code}" for i in g.issues) or "No issues."),
            objective="4.8"))
    return qs
