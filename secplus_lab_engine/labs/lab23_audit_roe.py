"""
Lab 23 — Penetration Test Rules-of-Engagement Gate & Audit Planner
==================================================================

Security+ SY0-701 objectives
----------------------------
* 5.5  Types and purposes of audits and assessments: attestation; internal
       (compliance, audit committee, self-assessments); external (regulatory,
       examinations, assessment, independent third-party audit); penetration
       testing (physical, offensive, defensive, integrated, known environment,
       partially known environment, unknown environment, reconnaissance:
       passive and active).
* 4.3  Vulnerability identification methods: penetration testing.
* 5.3  Third-party risk: rules of engagement.

How it works
------------
Part 1 is a rules-of-engagement (RoE) gate, the same guard a governed AI
pentest agent needs. Every planned test action is checked against the
signed engagement record. Any of these gives BLOCK (all reasons are listed):
* the engagement is unsigned, signed by a role that cannot authorise testing,
  lacks an emergency contact or a declared environment type, or the action
  day is outside the authorization validity;
* the target is missing, not inside an in-scope CIDR/domain, or matches an
  out-of-scope CIDR/host (checked with the ipaddress module);
* the technique is unknown to the catalogue, prohibited by the engagement or
  always prohibited by policy;
* the action declares "passive" recon but the technique actually touches the
  target (active), so it cannot claim the passive exemption;
* the hour is outside the testing window. Exception (policy switch): passive
  recon reads only public third-party sources, so it may run outside the
  window, but it still needs valid authorization and an in-scope target.
Otherwise a technique that is not explicitly allowed gives NEEDS_APPROVAL
(deny by default: written approval from the signer first), else ALLOW.

Part 2 is an audit planner: each assessment need is mapped by its driver
(regulator, audit committee, compliance, customer SOC 2, self-check) and
its independence requirement to an assessment type. Unknown driver →
UNCLASSIFIED.

Run it
------
    python main.py lab 23
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

TITLE = "Lab 23 — Penetration Test Rules-of-Engagement Gate & Audit Planner"
OBJECTIVES = ("SY0-701 5.5 Audits and assessments: attestation, internal/external, penetration testing, "
              "reconnaissance · 4.3 Penetration testing · 5.3 Rules of engagement")
DECISIONS = ["ALLOW", "NEEDS_APPROVAL", "BLOCK"]
RULES = {
    "AUTHORIZATION": "authorization (signed, valid, RoE complete)",
    "SCOPE": "scope (in-scope / out-of-scope targets)",
    "TECHNIQUE": "technique (unknown or prohibited)",
    "RECON_TYPE": "recon type (declared passive but active)",
    "WINDOW": "testing window hours",
    "APPROVAL": "technique not explicitly allowed",
}
RECON = {"passive_recon": "passive", "active_recon": "active"}


@dataclass
class GateResult:
    id: str
    technique: str
    target: str
    decision: str
    rules: list[str] = field(default_factory=list)       # RULES codes that fired
    reasons: list[str] = field(default_factory=list)


@dataclass
class AssessmentPlan:
    id: str
    driver: str
    independence_required: bool
    assessment: str
    category: str
    reasons: list[str] = field(default_factory=list)


def _network(entry: str):
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None


def _domain_match(host: str, domain: str) -> bool:
    host, domain = host.lower().rstrip("."), domain.lower().rstrip(".")
    return host == domain or host.endswith("." + domain)


def check_scope(target: str | None, scope: dict) -> list[str]:
    """Return scope violations (empty = in scope)."""
    if not target:
        return ["no target given: cannot prove it is in scope"]
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        ip = None
    for entry in scope.get("out_of_scope", []):
        net = _network(entry)
        if (ip is not None and net is not None and ip in net) or (ip is None and net is None and _domain_match(target, entry)):
            return [f"{target} matches out-of-scope entry {entry}"]
    if ip is not None:
        if any(ip in n for n in map(_network, scope.get("in_scope_cidrs", [])) if n is not None):
            return []
        return [f"{target} is not inside any in-scope CIDR {scope.get('in_scope_cidrs', [])}"]
    if any(_domain_match(target, d) for d in scope.get("in_scope_domains", [])):
        return []
    return [f"{target} is not an in-scope domain {scope.get('in_scope_domains', [])}"]


def in_window(hour, window: dict) -> bool:
    """Window is [start_hour, end_hour); start > end means it wraps past midnight."""
    if hour is None or not window or "start_hour" not in window or "end_hour" not in window:
        return False
    s, e = window["start_hour"], window["end_hour"]
    return s <= hour < e if s <= e else (hour >= s or hour < e)


def engagement_problems(eng: dict, cfg: dict) -> list[str]:
    auth = eng.get("authorization") or {}
    out = []
    if not auth.get("signed") or not auth.get("signed_by"):
        out.append("no signed authorization: testing without written permission is an attack, not a test")
    if auth.get("role") not in cfg["authorized_signer_roles"]:
        out.append(f"signer role '{auth.get('role')}' cannot authorise testing (needs {', '.join(cfg['authorized_signer_roles'])})")
    if not eng.get("emergency_contact"):
        out.append("RoE has no emergency contact to call if testing causes an outage")
    if eng.get("environment") not in cfg["environment_types"]:
        out.append(f"environment type '{eng.get('environment')}' not declared (known / partially_known / unknown)")
    return out


def gate(action: dict, eng: dict, cfg: dict) -> GateResult:
    rules, reasons = [], []

    def hit(rule, msgs):
        if msgs:
            rules.append(rule)
            reasons.extend(msgs)

    auth = eng.get("authorization") or {}
    day = action.get("day")
    probs = engagement_problems(eng, cfg)
    lo, hi = auth.get("valid_from_day"), auth.get("valid_to_day")
    if day is None or lo is None or hi is None or not lo <= day <= hi:
        probs.append(f"day {day} is outside the authorization validity (days {lo}–{hi})")
    hit("AUTHORIZATION", probs)
    hit("SCOPE", check_scope(action.get("target"), eng.get("scope") or {}))

    tech = action.get("technique")
    info = cfg["techniques"].get(tech)
    prohibited = set(eng.get("prohibited", [])) | set(cfg["always_prohibited"])
    if info is None:
        hit("TECHNIQUE", [f"technique '{tech}' is unknown to the catalogue: deny by default"])
    elif tech in prohibited:
        hit("TECHNIQUE", [f"technique '{tech}' ({info['description']}) is prohibited by the RoE"])
    actual = RECON.get(info["category"]) if info else None
    passive = actual == "passive"
    if action.get("recon") == "passive" and info and actual != "passive":
        hit("RECON_TYPE", [f"declared passive recon, but '{tech}' is {actual or info['category']}: it touches the target"])
    if not in_window(action.get("hour"), eng.get("window") or {}):
        if passive and cfg["passive_recon_ignores_window"]:
            reasons.append(f"hour {action.get('hour')} is outside the window, but passive recon sends nothing to the client (policy exemption)")
        else:
            w = eng.get("window") or {}
            hit("WINDOW", [f"hour {action.get('hour')} is outside the testing window {w.get('start_hour')}:00–{w.get('end_hour')}:00"])

    if rules:
        decision = "BLOCK"
    elif tech not in eng.get("allowed_techniques", []):
        decision = "NEEDS_APPROVAL"
        hit("APPROVAL", [f"'{tech}' is not in allowed_techniques: get written approval from "
                         f"{auth.get('signed_by')} ({auth.get('role')}) before running it"])
    else:
        decision = "ALLOW"
        reasons.append(f"signed, in date, in scope, '{tech}' explicitly allowed"
                       + ("" if passive and not in_window(action.get("hour"), eng.get("window") or {}) else ", inside the window"))
    return GateResult(action.get("id", "?"), str(tech), str(action.get("target")), decision, rules, reasons)


def plan_assessment(need: dict, cfg: dict) -> AssessmentPlan:
    driver, indep = need.get("driver"), bool(need.get("independence_required"))
    rule = cfg["assessment_rules"].get(driver)
    if rule is None:
        return AssessmentPlan(need.get("id", "?"), str(driver), indep, "UNCLASSIFIED", "unknown",
                              [f"driver '{driver}' is unknown: cannot choose an assessment type (deny by default)"])
    kind = rule["if_independent" if indep else "default"]
    reasons = [rule["why"]]
    if indep and kind != rule["default"]:
        reasons.append(f"independence required, so {rule['default']} is not enough → {kind}")
    return AssessmentPlan(need["id"], driver, indep, kind, cfg["assessment_types"][kind]["category"], reasons)


def gate_all(data: dict, policies: dict) -> list[GateResult]:
    return [gate(a, data["engagement"], policies["audit"]) for a in data["actions"]]


def plan_all(data: dict, policies: dict) -> list[AssessmentPlan]:
    return [plan_assessment(n, policies["audit"]) for n in data.get("assessment_needs", [])]


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SY0-701 5.5 Audits and assessments: attestation, internal/external audits, penetration testing and reconnaissance.",
    "concepts": [
        "Rules of engagement set scope, timing, allowed and prohibited techniques, and an emergency contact; signed authorization comes first.",
        "Known, partially known and unknown environments describe how much the testers are told beforehand.",
        "Passive recon uses public sources (OSINT, WHOIS, certificate logs); active recon sends traffic to the target (port scans, banner grabs).",
        "Offensive = red team, defensive = blue team, integrated = purple team; physical tests target doors, badges and guards.",
        "Internal audits (compliance, audit committee, self-assessment) differ from external ones (regulatory exam, independent third-party audit, attestation).",
    ],
    "failure_modes": [
        "Scanning an IP that 'looked like ours' but belonged to a neighbour: unauthorised access, whatever the intent.",
        "Running a DoS test in business hours with no emergency contact, causing a real outage.",
        "Treating a team's self-assessment as if it gave an independent opinion.",
        "Calling an active scan 'passive' to slip outside the agreed testing window.",
    ],
    "ai_governance": [
        "An AI pentest agent should call an RoE gate before every action, not once at the start of the engagement.",
        "Deny by default: an unknown technique or an unparseable target is BLOCKED, never guessed.",
        "The agent's own label (e.g. 'passive') is untrusted; the gate reclassifies the technique from its catalogue.",
        "Out-of-scope lists win over in-scope ranges, and every decision is logged with its reasons for the final report.",
    ],
    "exam_tips": [
        "'Testers are given network diagrams and credentials' = known environment; 'given nothing' = unknown environment.",
        "OSINT, WHOIS and social-media research = passive reconnaissance; ping sweeps and port scans = active.",
        "Attestation = an independent party formally vouches for controls (e.g. a SOC 2 report).",
        "Audit committee oversees internal audit; regulators perform examinations; an outside auditor gives independence.",
        "Purple team = integrated testing where red and blue teams share findings.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    cfg, eng = policies["audit"], data["engagement"]
    auth, scope = eng.get("authorization") or {}, eng.get("scope") or {}
    ui.section("Step 1 — The signed rules of engagement")
    ui.panel("Engagement", f"Client: {eng.get('client')}\nSigned by: {auth.get('signed_by')} ({auth.get('role')}), "
             f"days {auth.get('valid_from_day')}–{auth.get('valid_to_day')}\nIn scope: {scope.get('in_scope_cidrs')} "
             f"{scope.get('in_scope_domains')}\nOut of scope: {scope.get('out_of_scope')}\n"
             f"Window: {eng.get('window')} · environment: {eng.get('environment')}\n"
             f"Prohibited: {eng.get('prohibited')}\nPassive recon rule: {cfg['passive_recon_note']}")
    res = gate_all(data, policies)
    ui.section("Step 2 — Gate every planned test action")
    ui.table("Actions", ["ID", "Tester", "Day/Hour", "Target", "Technique", "Decision"],
             [[r.id, a.get("tester"), f"{a.get('day')}/{a.get('hour')}", r.target, r.technique, r.decision]
              for r, a in zip(res, data["actions"])])
    for r in res:
        ui.status(f"{r.id} {r.technique} → {r.target}", r.decision, ", ".join(r.rules))
        for why in r.reasons:
            ui.bullet(why, style="red" if r.decision == "BLOCK" else "yellow" if r.decision == "NEEDS_APPROVAL" else "dim")
    plans = plan_all(data, policies)
    ui.section("Step 3 — Plan the right audit or assessment")
    ui.table("Assessment needs", ["ID", "Driver", "Independent?", "Assessment type", "Internal/external"],
             [[p.id, p.driver, "yes" if p.independence_required else "no", p.assessment, p.category] for p in plans])
    for p in plans:
        ui.bullet(f"{p.id}: " + "; ".join(p.reasons))
    ui.insight(INSIGHT)
    return {**{r.id: r.decision for r in res}, **{p.id: p.assessment for p in plans}}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg, eng = policies["audit"], data["engagement"]
    scope = eng.get("scope") or {}
    qs: list = []
    eng_ctx = (f"In scope: {scope.get('in_scope_cidrs')} {scope.get('in_scope_domains')} · out of scope: "
               f"{scope.get('out_of_scope')}\nwindow={eng.get('window')} allowed={eng.get('allowed_techniques')} "
               f"prohibited={eng.get('prohibited')} authorization days "
               f"{(eng.get('authorization') or {}).get('valid_from_day')}–{(eng.get('authorization') or {}).get('valid_to_day')}")
    for a, r in zip(data["actions"], gate_all(data, policies)):
        ctx = (f"{eng_ctx}\n{r.id}: {a.get('tester')} wants {r.technique} on {r.target}, day {a.get('day')} "
               f"hour {a.get('hour')}, declared recon={a.get('recon')}")
        qs.append(Question(prompt=f"{r.id}: what does the RoE gate decide?", context=ctx, choices=DECISIONS,
                           answer=r.decision, explanation="; ".join(r.reasons), objective="5.5"))
        if r.decision == "BLOCK" and len(r.rules) == 1:
            qs.append(Question(prompt=f"{r.id}: which rule blocks this action?", context=ctx,
                               choices=sorted(RULES[k] for k in RULES if k != "APPROVAL"),
                               answer=RULES[r.rules[0]], explanation=r.reasons[0], objective="5.3"))
    for need, p in zip(data.get("assessment_needs", []), plan_all(data, policies)):
        if p.assessment == "UNCLASSIFIED":
            continue
        qs.append(Question(prompt=f"{p.id}: which type of audit or assessment fits?",
                           context=f"{need.get('description')} (independence required: "
                                   f"{'yes' if p.independence_required else 'no'})",
                           choices=choices_with(p.assessment, cfg["assessment_types"], key=p.id),
                           answer=p.assessment, explanation="; ".join(p.reasons), objective="5.5"))
    env_names = {k: k.replace("_", " ") + " environment" for k in cfg["environment_types"]}
    for k, d in cfg["environment_types"].items():
        qs.append(Question(prompt=f"Which test environment is this? \"{d.split(':', 1)[1].strip()}\"",
                           choices=sorted(env_names.values()), answer=env_names[k], explanation=d, objective="5.5"))
    recon_choices = ["passive reconnaissance", "active reconnaissance", "not reconnaissance"]
    for tech, info in sorted(cfg["techniques"].items()):
        if info["category"] in RECON:
            ans = f"{RECON[info['category']]} reconnaissance"
            qs.append(Question(prompt=f"\"{info['description']}\" is an example of which kind of activity?", choices=recon_choices, answer=ans,
                               explanation=f"{tech}: {ans}; passive never sends traffic to the target, active does.",
                               objective="5.5"))
    for name, d in sorted(cfg["pentest_types"].items()):
        qs.append(Question(prompt=f"Which penetration-testing type is this? \"{d.split(':', 1)[1].strip()}\"",
                           choices=sorted(cfg["pentest_types"]), answer=name, explanation=d, objective="5.5"))
    for name, t in sorted(cfg["assessment_types"].items()):
        qs.append(Question(prompt=f"Is a(n) {name.replace('_', ' ').lower()} an internal or an external assessment?",
                           choices=["internal", "external"], answer=t["category"], explanation=t["definition"],
                           objective="5.5"))
    return qs
