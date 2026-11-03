"""
Lab 14 — Resilience & Recovery Planner
======================================

Security+ SY0-701 objectives
----------------------------
* 3.4  Resilience and recovery in security architecture: high availability
       (load balancing vs clustering), site considerations (hot, warm, cold,
       geographic dispersion), platform diversity, multi-cloud, continuity of
       operations, capacity planning, testing (tabletop, fail over, simulation,
       parallel processing), backups (onsite/offsite, frequency, encryption,
       snapshots, recovery, replication, journaling), power (generators, UPS).
       RAID is part of the fault-tolerance toolbox.

Model
-----
For each system we compute what the CURRENT design achieves in two events:

* **Host/storage failure**: RTO = cluster failover time, or rebuild +
  restore. RPO = replication lag, or the backup interval.
  Restore time = data TB × hours/TB × multiplier (full 1.0, differential 1.5,
  incremental 2.5: incremental needs the full + every incremental since).
* **Site loss** (only if required): needs an OFFSITE copy (replication or an
  offsite backup) AND a recovery site. RTO = site readiness (+ restore if the
  data isn't already replicated there).

Then disk fault tolerance (RAID), power (UPS + generator runtime) and testing
(restore + DR test within 365 days) are checked. Every gap gets the cheapest
catalog option that closes it.

Run it
------
    python main.py lab 14
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import date

TITLE = "Lab 14 — Resilience & Recovery Planner"
OBJECTIVES = "SY0-701 3.4 Resilience & recovery (sites, replication, backups, RAID, power, testing)"
INF = math.inf


@dataclass
class Plan:
    name: str
    host_rto: float
    host_rpo: float
    site_rto: float | None
    site_rpo: float | None
    restore_hours: float
    verdict: str                          # MEETS_TARGETS | GAPS
    gaps: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def has(self, key: str) -> bool:
        return any(key in g for g in self.gaps)


def fmt(h: float | None) -> str:
    if h is None:
        return "n/a"
    if h == INF:
        return "∞ (cannot recover)"
    return f"{h:g}h" if h >= 1 or h == 0 else f"{h * 60:g}m"


def cheapest(options: dict, ok) -> tuple[str, dict] | None:
    viable = [(k, v) for k, v in options.items() if ok(v)]
    return min(viable, key=lambda kv: (kv[1].get("annual_cost", 0), kv[0])) if viable else None


def raid_for(required: int, raid: dict) -> str | None:
    viable = [(k, v) for k, v in raid.items() if v["tolerates"] >= required]
    return max(viable, key=lambda kv: (kv[1]["efficiency"], -kv[1]["tolerates"]))[0] if viable else None


def plan(system: dict, cfg: dict, as_of: date) -> Plan:
    t, c = system["targets"], system["current"]
    gaps: list[str] = []
    recs: list[str] = []

    backup = c.get("backup") or {}
    mult = cfg["backup_restore_multiplier"].get(backup.get("type"), INF)
    restore = round(c.get("data_tb", 0) * cfg["restore_hours_per_tb"] * mult, 2) if backup else INF
    rep = cfg["replication"].get(c.get("replication") or "")
    clu = cfg["clustering"].get(c.get("clustering") or "")
    site = cfg["site_types"].get(c.get("site") or "")

    # --- host / storage failure ---------------------------------------------------
    host_rto = clu["failover_hours"] if clu else cfg["host_rebuild_hours"] + restore
    host_rpo = min(rep["rpo_hours"] if rep else INF, backup.get("frequency_hours", INF))
    if host_rto > t["rto_hours"]:
        gaps.append(f"RTO: host failure takes {fmt(host_rto)} (rebuild + {backup.get('type')} restore) > target {fmt(t['rto_hours'])}")
        opt = cheapest(cfg["clustering"], lambda v: v["failover_hours"] <= t["rto_hours"])
        if opt:
            recs.append(f"Add {opt[0]} clustering (failover {fmt(opt[1]['failover_hours'])}, ${opt[1]['annual_cost']:,}/yr)")
    if host_rpo > t["rpo_hours"]:
        gaps.append(f"RPO: up to {fmt(host_rpo)} of data lost > target {fmt(t['rpo_hours'])}")
        if t["rpo_hours"] >= 1:
            recs.append(f"Back up at least every {fmt(t['rpo_hours'])} (snapshots/journaling between full backups)")
        else:
            opt = cheapest(cfg["replication"], lambda v: v["rpo_hours"] <= t["rpo_hours"])
            if opt:
                recs.append(f"Add {opt[0]} replication (RPO {fmt(opt[1]['rpo_hours'])}, ${opt[1]['annual_cost']:,}/yr)")

    # --- site loss ----------------------------------------------------------------------
    site_rto = site_rpo = None
    if t.get("survive_site_loss"):
        offsite = bool(rep) or bool(backup.get("offsite"))
        if not offsite:
            site_rto = site_rpo = INF
            gaps.append("SITE: no offsite copy of the data (no replication, backups kept onsite)")
            recs.append("Keep an offsite/cloud backup copy (3-2-1) or replicate to the recovery site")
            if not site:
                gaps.append("SITE: no recovery site, so nowhere to restore to after a site loss")
                opt = cheapest(cfg["site_types"], lambda v: v["rto_hours"] <= t["rto_hours"])
                recs.append(f"Contract a {opt[0]} site" if opt else
                            "Replicate to a hot site or run active-active across regions (geographic dispersion)")
        else:
            site_rpo = rep["rpo_hours"] if rep else backup.get("frequency_hours", INF)
            if not site:
                site_rto = INF
                gaps.append("SITE: no recovery site, so nowhere to restore to after a site loss")
            else:
                site_rto = site["rto_hours"] + (0 if rep else restore)
            if site_rto > t["rto_hours"]:
                if site:
                    gaps.append(f"SITE: {c['site']} site recovery takes {fmt(site_rto)} > target {fmt(t['rto_hours'])}")
                budget = t["rto_hours"] - (0 if rep else restore)
                opt = cheapest(cfg["site_types"], lambda v: v["rto_hours"] <= budget)
                if opt:
                    recs.append(f"Use a {opt[0]} site (ready in {fmt(opt[1]['rto_hours'])}, ${opt[1]['annual_cost']:,}/yr)")
                else:
                    recs.append("Even a hot site is too slow without replicated data: add replication to a hot "
                                "site or run active-active across regions (geographic dispersion)")
            if site_rpo > t["rpo_hours"]:
                gaps.append(f"SITE RPO: after a site loss up to {fmt(site_rpo)} of data is lost > target {fmt(t['rpo_hours'])}")

    # --- disks, power, testing -------------------------------------------------------------
    tol = cfg["raid"].get(c.get("raid") or "", {"tolerates": 0})["tolerates"]
    if tol < t.get("disk_failures", 0):
        gaps.append(f"DISK: {c.get('raid') or 'no RAID'} tolerates {tol} disk failure(s) < required {t['disk_failures']}")
        r = raid_for(t["disk_failures"], cfg["raid"])
        if r:
            recs.append(f"Rebuild storage as {r} (tolerates {cfg['raid'][r]['tolerates']}, "
                        f"{cfg['raid'][r]['efficiency']:.0%} usable capacity)")
    ups_h = c.get("ups_minutes", 0) / 60
    runtime = ups_h + c.get("generator_hours", 0)
    if runtime < t.get("power_outage_hours", 0):
        gaps.append(f"POWER: UPS + generator run {fmt(round(runtime, 2))} < required {fmt(t['power_outage_hours'])}")
        recs.append("Add a generator (a UPS only bridges minutes)" if not c.get("generator_hours")
                    else "Extend generator fuel/runtime contract")
    for key, label, how in (("last_restore_test", "backup restore", "restore test"),
                            ("last_dr_test", "DR failover", "failover test / simulation / parallel processing")):
        when = c.get(key)
        if not when or (as_of - date.fromisoformat(when)).days > cfg["test_max_age_days"]:
            gaps.append(f"TEST: {label} {'never tested' if not when else 'last tested ' + when} (untested plan = no plan)")
            recs.append(f"Schedule a {how} and record the measured RTO/RPO")

    return Plan(system["name"], host_rto, host_rpo, site_rto, site_rpo, restore,
                "GAPS" if gaps else "MEETS_TARGETS", gaps, recs)


def plan_all(data: dict, policies: dict) -> list[Plan]:
    as_of = date.fromisoformat(data["as_of"])
    return [plan(s, policies["resilience"], as_of) for s in data["systems"]]


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SY0-701 3.4 Resilience & recovery: sites, replication, backups, high availability, power, testing.",
    "concepts": [
        "RPO is answered by backup frequency or replication; RTO by failover (clustering) or how fast a site can take over.",
        "Hot = running and synced (expensive); warm = hardware ready, restore data; cold = space and power only.",
        "Incremental backups are fastest to take but slowest to restore; differential is in between; full restores fastest.",
        "RAID is availability, not backup: RAID1/5/10 survive one disk, RAID6 survives two, RAID0 survives none.",
    ],
    "failure_modes": [
        "Nightly backups for a system the business assumed loses at most 4 hours of data.",
        "Backups stored in the same building that floods.",
        "A UPS with no generator, so it buys 10 minutes for a 4-hour outage.",
        "A DR plan never tested; the first failover is during the real disaster.",
    ],
    "ai_governance": [
        "An AI operations agent can trigger failover automatically only for pre-approved, tested runbooks.",
        "Agents must not delete or shorten backup retention; backups are a protected control (Lab 5).",
        "Use agents to run and record restore tests continuously, turning 'untested' into measured RTO/RPO.",
        "Declaring a disaster (moving to the alternate site) stays a human decision.",
    ],
    "exam_tips": [
        "Load balancing spreads load across active nodes; clustering adds failover. Both are high availability.",
        "Geographic dispersion protects against regional disasters; multi-cloud protects against provider failure.",
        "Testing types: tabletop (discussion), simulation, fail over, parallel processing (run both systems).",
        "UPS = short-term power + clean shutdown; generator = long-term power.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    plans = plan_all(data, policies)
    ui.section(f"Step 1 — Achieved vs target (as of {data['as_of']})")
    ui.table("Recovery capability", ["System", "Target RTO/RPO", "Host fail RTO/RPO", "Site loss RTO/RPO", "Restore", "Verdict"],
             [[p.name, f"{fmt(s['targets']['rto_hours'])} / {fmt(s['targets']['rpo_hours'])}",
               f"{fmt(p.host_rto)} / {fmt(p.host_rpo)}",
               "not required" if p.site_rto is None else f"{fmt(p.site_rto)} / {fmt(p.site_rpo)}",
               fmt(p.restore_hours), p.verdict] for p, s in zip(plans, data["systems"])])
    ui.section("Step 2 — Gaps and cheapest fixes")
    for p in plans:
        ui.print(f"[bold]{p.name}[/bold] — {p.verdict}")
        for g in p.gaps:
            ui.bullet(g, style="red")
        for r in p.recommendations:
            ui.bullet(f"→ {r}", style="green")
        if not p.gaps:
            ui.bullet("All targets met and tested.", style="green")
    ui.insight(INSIGHT)
    return {p.name: f"{p.verdict} ({len(p.gaps)} gaps)" for p in plans}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question

    cfg = policies["resilience"]
    qs: list = []
    for s, p in zip(data["systems"], plan_all(data, policies)):
        t, c = s["targets"], s["current"]
        ctx = f"Targets {t}\nCurrent {c}"
        qs.append(Question(prompt=f"{p.name}: does the current design meet its targets?", context=ctx,
                           choices=["MEETS_TARGETS", "GAPS"], answer=p.verdict,
                           explanation="; ".join(p.gaps) or "All targets met and tested.", objective="3.4"))
        qs.append(Question(prompt=f"{p.name}: is the RPO met for a host/storage failure?",
                           context=f"RPO target {fmt(t['rpo_hours'])}; backups every {fmt(c['backup']['frequency_hours'])}; "
                                   f"replication {c.get('replication') or 'none'}",
                           choices=["Yes", "No"], answer="Yes" if p.host_rpo <= t["rpo_hours"] else "No",
                           explanation=f"achieved RPO {fmt(p.host_rpo)} vs target {fmt(t['rpo_hours'])}", objective="3.4"))
    disks = lambda n: f"{n} disk" + ("" if n == 1 else "s")  # noqa: E731  (word labels: digits mean option numbers)
    for name, r in sorted(cfg["raid"].items()):
        qs.append(Question(prompt=f"How many disk failures is {name} GUARANTEED to survive?",
                           choices=[disks(n) for n in range(4)], answer=disks(r["tolerates"]), explanation=f"{name}: tolerates {r['tolerates']}, "
                                                                   f"{r['efficiency']:.0%} usable capacity", objective="3.4"))
    for target in (2, 48, 200):
        opt = cheapest(cfg["site_types"], lambda v: v["rto_hours"] <= target)
        answer = opt[0] if opt else "none"
        qs.append(Question(prompt=f"Data is already replicated. Cheapest site type that meets an RTO of {target} hours?",
                           context="; ".join(f"{k}: ready in {v['rto_hours']}h, ${v['annual_cost']:,}/yr"
                                             for k, v in cfg["site_types"].items()),
                           choices=sorted(cfg["site_types"]), answer=answer,
                           explanation=f"{answer} is the least expensive site with readiness ≤ {target}h", objective="3.4"))
    fastest = min(cfg["backup_restore_multiplier"], key=cfg["backup_restore_multiplier"].get)
    qs.append(Question(prompt="Which backup type restores fastest?", choices=sorted(cfg["backup_restore_multiplier"]),
                       answer=fastest, explanation="A full backup restores in one pass; differential needs full + last "
                                                   "differential; incremental needs full + every incremental since.",
                       objective="3.4"))
    return qs
