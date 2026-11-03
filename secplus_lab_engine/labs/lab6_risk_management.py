"""
Lab 6 — Risk Management Calculator & Business Impact Analysis
=============================================================

Security+ SY0-701 objectives
----------------------------
* 5.2  Risk management: identification, assessment (qualitative/quantitative),
       SLE, ALE, ARO, exposure factor, risk register, risk owner, risk
       appetite/tolerance, risk thresholds, strategies (transfer, accept,
       exemption/exception, avoid, mitigate), business impact analysis
       (RTO, RPO, MTTR, MTBF).

Formulas
--------
    SLE = AV × EF            (single loss expectancy)
    ALE = SLE × ARO          (annualized loss expectancy)
    Control value = ALE_before − ALE_after − annual control cost
    Availability  = MTBF / (MTBF + MTTR)

Treatment logic
---------------
1. ALE within risk appetite → **ACCEPT** (document it; the risk owner signs).
2. Otherwise compute the net annual benefit of every option:
   * **MITIGATE**  = ALE − ALE_after_control − control cost
   * **TRANSFER**  = ALE × insurance coverage − premium
   * **AVOID**     = ALE − cost of stopping the activity (only if the activity is optional)
3. Choose the option with the best positive benefit. If none is positive,
   the risk stays above appetite and needs a formal **EXCEPTION** signed by
   leadership.

Run it
------
    python main.py lab 6
"""

from __future__ import annotations

from dataclasses import dataclass, field

TITLE = "Lab 6 — Risk Management Calculator & BIA"
OBJECTIVES = "SY0-701 5.2 Risk management · SLE/ALE/ARO · BIA (RTO/RPO/MTTR/MTBF)"

# Qualitative bands for the 5×5 heat map
ARO_BANDS = [(0.05, 1), (0.2, 2), (1.0, 3), (5.0, 4)]          # <= threshold → score; above last → 5
SLE_BANDS = [(10_000, 1), (100_000, 2), (500_000, 3), (2_000_000, 4)]


def sle(asset_value: float, exposure_factor: float) -> float:
    """Single loss expectancy: how much one occurrence costs."""
    if not 0 <= exposure_factor <= 1:
        raise ValueError("exposure factor must be between 0 and 1")
    return asset_value * exposure_factor


def ale(single_loss: float, aro: float) -> float:
    """Annualized loss expectancy: expected loss per year."""
    if aro < 0:
        raise ValueError("ARO cannot be negative")
    return single_loss * aro


def band(value: float, bands: list[tuple[float, int]]) -> int:
    for threshold, score in bands:
        if value <= threshold:
            return score
    return 5


def availability(mtbf: float, mttr: float) -> float:
    return mtbf / (mtbf + mttr)


@dataclass
class Option:
    strategy: str
    description: str
    net_benefit: float
    residual_ale: float


@dataclass
class RiskAssessment:
    id: str
    title: str
    owner: str
    sle: float
    ale: float
    likelihood: int
    impact: int
    options: list[Option] = field(default_factory=list)
    treatment: str = "ACCEPT"
    rationale: str = ""
    residual_ale: float = 0.0

    @property
    def inherent_score(self) -> int:
        return self.likelihood * self.impact

    @property
    def rating(self) -> str:
        s = self.inherent_score
        return "CRITICAL" if s >= 15 else "HIGH" if s >= 10 else "MEDIUM" if s >= 5 else "LOW"


def assess(risk: dict, appetite_ale: float) -> RiskAssessment:
    """Compute SLE/ALE, the qualitative rating and the recommended treatment."""
    av, ef, aro = risk["asset_value"], risk["exposure_factor"], risk["aro"]
    s = sle(av, ef)
    a = ale(s, aro)
    ra = RiskAssessment(risk["id"], risk["title"], risk.get("owner", "?"), s, a,
                        likelihood=band(aro, ARO_BANDS), impact=band(s, SLE_BANDS))

    for c in risk.get("controls", []):
        after = ale(sle(av, c.get("new_ef", ef)), c.get("new_aro", aro))
        ra.options.append(Option("MITIGATE", c["name"], a - after - c["annual_cost"], after))
    if ins := risk.get("insurance"):
        covered = a * ins["coverage"]
        ra.options.append(Option("TRANSFER", f"Cyber insurance ({ins['coverage']:.0%} coverage)",
                                 covered - ins["annual_premium"], a - covered))
    if risk.get("activity_optional"):
        av_cfg = risk.get("avoidance", {"description": "Stop the activity", "annual_cost": 0})
        ra.options.append(Option("AVOID", av_cfg["description"], a - av_cfg["annual_cost"], 0.0))

    if a <= appetite_ale:
        ra.treatment, ra.residual_ale = "ACCEPT", a
        ra.rationale = f"ALE ${a:,.0f} is within the risk appetite (${appetite_ale:,.0f}); document it and have the risk owner sign."
        return ra

    viable = [o for o in ra.options if o.net_benefit > 0]
    if not viable:
        ra.treatment, ra.residual_ale = "EXCEPTION", a
        ra.rationale = (f"ALE ${a:,.0f} exceeds appetite but no option is cost-effective. A formal risk "
                        "exception/exemption with an expiry date is needed from leadership.")
        return ra
    best = max(viable, key=lambda o: o.net_benefit)
    ra.treatment, ra.residual_ale = best.strategy, best.residual_ale
    ra.rationale = f"{best.description}: net benefit ${best.net_benefit:,.0f}/yr (best of {len(ra.options)} options)."
    return ra


@dataclass
class BIAResult:
    system: str
    rpo_ok: bool
    rto_ok: bool
    availability: float
    availability_ok: bool
    issues: list[str]


def check_bia(entry: dict) -> BIAResult:
    """Compare recovery capability with the business requirement."""
    issues = []
    rpo_ok = entry["backup_interval_hours"] <= entry["rpo_hours"]
    if not rpo_ok:
        issues.append(f"backups every {entry['backup_interval_hours']}h can lose up to that much data; "
                      f"RPO allows only {entry['rpo_hours']}h")
    rto_ok = entry["restore_time_hours"] <= entry["rto_hours"]
    if not rto_ok:
        issues.append(f"restore takes {entry['restore_time_hours']}h but RTO is {entry['rto_hours']}h")
    avail = availability(entry["mtbf_hours"], entry["mttr_hours"])
    avail_ok = avail >= entry["availability_target"]
    if not avail_ok:
        issues.append(f"availability {avail:.4%} < target {entry['availability_target']:.2%} (MTBF {entry['mtbf_hours']}h, "
                      f"MTTR {entry['mttr_hours']}h). Reduce MTTR or raise MTBF")
    return BIAResult(entry["system"], rpo_ok, rto_ok, avail, avail_ok, issues)


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SY0-701 5.2 Risk management (quantitative & qualitative analysis, strategies, BIA).",
    "concepts": [
        "SLE = AV × EF; ALE = SLE × ARO. A control is worth buying when ALE reduction > its annual cost.",
        "Strategies: mitigate, transfer (insurance), avoid (stop the activity), accept, or exception/exemption.",
        "RPO = how much data you can lose (drives backup frequency); RTO = how long you can be down (drives restore design).",
        "MTBF measures reliability, MTTR measures repairability; availability = MTBF / (MTBF + MTTR).",
    ],
    "failure_modes": [
        "Buying a $500k control to protect against a $30k/yr ALE (security theatre).",
        "Treating low-likelihood/high-impact events as 'won't happen' instead of transferring them.",
        "Backups run nightly while the business assumed an RPO of 4 hours, discovered only after an outage.",
        "Risks accepted informally with no owner, no expiry date and no register entry.",
    ],
    "ai_governance": [
        "An AI risk-analyst agent can compute ALE and draft treatments, but a named human risk OWNER must accept.",
        "Agents must cite the inputs (AV, EF, ARO sources) so assessments can be audited and challenged.",
        "AI agents themselves belong in the risk register: model failure, prompt injection and over-permissioning are risks too.",
        "Any agent with production write access raises the impact (SLE) of a compromise. Price that in.",
    ],
    "exam_tips": [
        "Expect arithmetic: AV $100k, EF 25%, ARO 2 → SLE $25k, ALE $50k.",
        "'Purchasing cyber insurance' = transfer. 'Discontinuing the service' = avoid.",
        "'Maximum tolerable data loss' = RPO. 'Maximum tolerable downtime to restore' = RTO.",
        "Risk appetite = how much risk the org will pursue; risk tolerance = acceptable deviation; threshold = trigger level.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    appetite = data.get("risk_appetite_ale", 10_000)
    results = [assess(r, appetite) for r in data["risks"]]

    ui.section("Step 1 — Quantitative analysis (SLE / ALE)")
    ui.table("Risk register", ["ID", "Risk", "Owner", "SLE", "ARO", "ALE", "L×I", "Rating"],
             [[r.id, r.title, r.owner, f"${r.sle:,.0f}", raw["aro"], f"${r.ale:,.0f}",
               f"{r.likelihood}×{r.impact}={r.inherent_score}", r.rating] for r, raw in zip(results, data["risks"])])

    ui.section("Step 2 — Treatment options (net annual benefit)")
    rows = []
    for r in results:
        for o in r.options:
            rows.append([r.id, o.strategy, o.description, f"${o.net_benefit:,.0f}", f"${o.residual_ale:,.0f}"])
    ui.table("Options", ["Risk", "Strategy", "Option", "Net benefit/yr", "Residual ALE"], rows)

    ui.section("Step 3 — Recommended treatment")
    for r in results:
        ui.status(f"{r.id} {r.title[:40]}", r.treatment, r.rationale)

    ui.section("Step 4 — 5×5 inherent-risk heat map (likelihood ↓, impact →)")
    grid = {(r.likelihood, r.impact): [] for r in results}
    for r in results:
        grid[(r.likelihood, r.impact)].append(r.id)
    ui.table("Heat map", ["L \\ I", "1", "2", "3", "4", "5"],
             [[str(l)] + [",".join(grid.get((l, i), [])) or "·" for i in range(1, 6)] for l in range(5, 0, -1)])

    ui.section("Step 5 — Business impact analysis (RTO / RPO / MTBF / MTTR)")
    bia = [check_bia(b) for b in data.get("bia", [])]
    ui.table("BIA", ["System", "RPO", "RTO", "Availability", "Issues"],
             [[b.system, "PASS" if b.rpo_ok else "FAIL", "PASS" if b.rto_ok else "FAIL",
               f"{b.availability:.4%}" + ("" if b.availability_ok else " ✗"), "; ".join(b.issues) or "-"] for b in bia])

    ui.insight(INSIGHT)
    return {
        "total_ale": round(sum(r.ale for r in results)),
        "residual_ale": round(sum(r.residual_ale for r in results)),
        "treatments": {r.id: r.treatment for r in results},
        "bia_failures": sum(1 for b in bia if b.issues),
    }


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def _money_choices(correct: float, wrong: list[float]) -> tuple[list[str], str]:
    fmt = lambda v: f"${v:,.0f}"  # noqa: E731
    opts = []
    for v in [correct, *wrong]:
        if fmt(v) not in opts:
            opts.append(fmt(v))
    return sorted(opts, key=lambda x: float(x.strip("$").replace(",", ""))), fmt(correct)


def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question

    appetite = data.get("risk_appetite_ale", 10_000)
    qs: list = []
    for raw in data["risks"]:
        r = assess(raw, appetite)
        av, ef, aro = raw["asset_value"], raw["exposure_factor"], raw["aro"]
        ctx = f"{r.title}\nAV=${av:,.0f}  EF={ef:.0%}  ARO={aro}"
        choices, ans = _money_choices(r.ale, [av * aro, r.sle, av * ef * ef, r.sle / aro if aro else av])
        qs.append(Question(prompt=f"{r.id}: what is the ALE?", context=ctx, choices=choices, answer=ans,
                           explanation=f"SLE = ${av:,.0f} × {ef} = ${r.sle:,.0f}; ALE = SLE × {aro} = ${r.ale:,.0f}.",
                           objective="5.2"))
        opts = [f"  MITIGATE: {c['name']} — ${c['annual_cost']:,}/yr, "
                + ", ".join(f"{k.replace('new_', 'new ').upper()}={v}" for k, v in c.items() if k.startswith("new_"))
                for c in raw.get("controls", [])]
        if ins := raw.get("insurance"):
            opts.append(f"  TRANSFER: insurance ${ins['annual_premium']:,}/yr covering {ins['coverage']:.0%}")
        if raw.get("activity_optional"):
            av_cfg = raw.get("avoidance", {"description": "stop the activity", "annual_cost": 0})
            opts.append(f"  AVOID: {av_cfg['description']} — ${av_cfg['annual_cost']:,}/yr")
        qs.append(Question(
            prompt=f"{r.id}: which treatment is most appropriate? (risk appetite ALE ≤ ${appetite:,.0f})",
            context=f"{ctx}  →  ALE ${r.ale:,.0f}\nOptions:\n" + "\n".join(opts),
            choices=["ACCEPT", "AVOID", "EXCEPTION", "MITIGATE", "TRANSFER"],
            answer=r.treatment, explanation=r.rationale, objective="5.2"))
    for b in data.get("bia", []):
        res = check_bia(b)
        verdict = "Meets RPO and RTO" if res.rpo_ok and res.rto_ok else \
            "Fails RPO only" if not res.rpo_ok and res.rto_ok else \
            "Fails RTO only" if res.rpo_ok else "Fails both"
        qs.append(Question(
            prompt=f"{b['system']}: does recovery capability meet the BIA?",
            context=f"RPO {b['rpo_hours']}h, RTO {b['rto_hours']}h; backups every {b['backup_interval_hours']}h; "
                    f"restore takes {b['restore_time_hours']}h",
            choices=["Meets RPO and RTO", "Fails RPO only", "Fails RTO only", "Fails both"],
            answer=verdict, explanation="; ".join(i for i in res.issues if "availability" not in i) or
            "Backup frequency is within RPO and restore time is within RTO.",
            objective="5.2"))
    return qs
