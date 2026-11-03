"""
Lab 13 — Threat Actor & Attack Vector Classifier
================================================

Security+ SY0-701 objectives
----------------------------
* 2.1  Threat actors (nation-state, unskilled attacker, hacktivist, insider
       threat, organized crime, shadow IT), their attributes (internal/external,
       resources/funding, sophistication) and motivations (data exfiltration,
       espionage, service disruption, blackmail, financial gain, philosophical/
       political beliefs, ethical, revenge, disruption/chaos, war).
* 2.2  Threat vectors (message-based, removable device, vulnerable software,
       unsecure networks, default credentials, supply chain, human vectors…).
* 2.5  Mitigation techniques (patching, hardening, least privilege, monitoring…).

How it classifies (deterministic and explainable)
-------------------------------------------------
* **Actor**: each indicator adds weight to the actor profiles that use it.
  Highest total wins, but only if it beats the runner-up by ``min_margin``.
  Otherwise the result is ``Undetermined``: never guess.
* **Motivation**: the first matching rule in an ordered list (more specific
  rules such as blackmail come before generic ones such as financial gain).
* **Vector**: the observed initial-access indicator mapped to a 2.2 vector.
* **Mitigation**: the vector's primary control, plus an actor-specific add-on.

Run it
------
    python main.py lab 13
"""

from __future__ import annotations

from dataclasses import dataclass, field

TITLE = "Lab 13 — Threat Actor & Attack Vector Classifier"
OBJECTIVES = "SY0-701 2.1 Threat actors & motivations · 2.2 Threat vectors · 2.5 Mitigations"
UNDETERMINED = "Undetermined"


@dataclass
class Classification:
    id: str
    actor: str
    actor_scores: dict
    actor_reasons: list[str]
    motivation: str
    motivation_reason: str
    vector: str
    mitigation: str
    addon: str
    unknown_indicators: list[str] = field(default_factory=list)


def score_actors(indicators: list[str], actors: dict) -> dict[str, int]:
    return {a: sum(w.get(i, 0) for i in indicators) for a, w in actors.items()}


def classify(scenario: dict, cfg: dict) -> Classification:
    ind = scenario.get("indicators", [])
    known = {k for w in cfg["actors"].values() for k in w} | {r[0] for r in cfg["motivation_rules"]}
    unknown = [i for i in ind if i not in known]

    scores = score_actors(ind, cfg["actors"])
    ranked = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
    (top, s1), (second, s2) = ranked[0], ranked[1]
    if s1 == 0 or s1 - s2 < cfg["min_margin"]:
        actor = UNDETERMINED
        reasons = [f"top scores too close or empty ({top} {s1} vs {second} {s2}); gather more evidence"]
    else:
        actor = top
        reasons = [f"{i} (+{cfg['actors'][top][i]})" for i in ind if i in cfg["actors"][top]]
        reasons.append(f"score {s1} vs next best {second} {s2}")

    motivation, mreason = UNDETERMINED, "no motivation indicator present"
    for key, label in cfg["motivation_rules"]:
        if key in ind:
            motivation, mreason = label, f"'{key}' → {label}"
            break

    v = cfg["vectors"].get(scenario.get("initial_access", ""))
    vector, mitigation = (v["vector"], v["mitigation"]) if v else (UNDETERMINED, "Investigate the initial access path first")
    addon = cfg["actor_addons"].get(actor, "")
    return Classification(scenario["id"], actor, scores, reasons, motivation, mreason, vector, mitigation, addon, unknown)


def classify_all(data: dict, policies: dict) -> list[Classification]:
    cfg = policies["threat_classification"]
    return [classify(s, cfg) for s in data["scenarios"]]


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SY0-701 2.1 threat actors & motivations, 2.2 threat vectors, 2.5 mitigation techniques.",
    "concepts": [
        "Attributes separate actors: internal vs external, resources/funding, level of sophistication.",
        "Nation-states: well funded, patient (APT), espionage or war. Organized crime: money (ransomware, data sales, extortion).",
        "Hacktivists want attention for a cause; insiders already have access; shadow IT is risk without malice.",
        "Mitigate the VECTOR first (how they got in), then add controls suited to the ACTOR (how they will behave).",
    ],
    "failure_modes": [
        "Attributing every incident to a nation-state: it inflates the response and hides basic hygiene gaps.",
        "Ignoring shadow IT because 'nobody was malicious' when the data exposure is just as real.",
        "Treating insiders like outsiders: perimeter controls do nothing against valid credentials.",
        "Fixing the symptom (malware) but not the vector (USB policy, help-desk reset process).",
    ],
    "ai_governance": [
        "An AI threat-intel agent should output 'Undetermined' rather than guess attribution; attribution errors drive bad decisions.",
        "Require agents to list the indicators behind every classification so analysts can challenge them.",
        "Agents summarising threat reports must treat that content as untrusted input (prompt injection lives in reports too).",
        "Public attribution or law-enforcement referral is always a human decision.",
    ],
    "exam_tips": [
        "'Advanced persistent threat with large budget' = nation-state.",
        "'Defaced site with a political message' = hacktivist. 'Unapproved cloud app' = shadow IT.",
        "'Script kiddie' running public tools = unskilled attacker.",
        "Vishing = voice, smishing = SMS, watering hole = compromise a site the victims trust.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    results = classify_all(data, policies)
    ui.section("Classification")
    ui.table("Threat actor · motivation · vector", ["ID", "Scenario", "Actor", "Motivation", "Initial access vector"],
             [[r.id, s["title"], r.actor, r.motivation, r.vector] for r, s in zip(results, data["scenarios"])])
    ui.section("Why, and what to do")
    for r, s in zip(results, data["scenarios"]):
        ui.print(f"[bold]{r.id} {s['title']}[/bold]")
        ui.bullet(f"Actor evidence: {', '.join(r.actor_reasons)}")
        ui.bullet(f"Motivation: {r.motivation_reason}")
        ui.bullet(f"Mitigate the vector: {r.mitigation}")
        if r.addon:
            ui.bullet(f"For this actor also: {r.addon}")
        if r.unknown_indicators:
            ui.bullet(f"Unrecognised indicators ignored: {r.unknown_indicators}", style="yellow")
    ui.insight(INSIGHT)
    return {r.id: f"{r.actor} / {r.motivation}" for r in results}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["threat_classification"]
    actors = list(cfg["actors"])
    motivations = sorted({m for _, m in cfg["motivation_rules"]})
    vectors = sorted(v["vector"] for v in cfg["vectors"].values())
    mitigations = sorted(v["mitigation"] for v in cfg["vectors"].values())
    qs: list = []
    for s, r in zip(data["scenarios"], classify_all(data, policies)):
        ctx = s["narrative"]
        if r.actor != UNDETERMINED:
            qs.append(Question(prompt=f"{s['id']}: which threat actor is most likely?", context=ctx,
                               choices=choices_with(r.actor, actors, key=s["id"]), answer=r.actor,
                               explanation="; ".join(r.actor_reasons), objective="2.1"))
        if r.motivation != UNDETERMINED:
            qs.append(Question(prompt=f"{s['id']}: what is the primary motivation?", context=ctx,
                               choices=choices_with(r.motivation, motivations, key=s["id"] + "m"), answer=r.motivation,
                               explanation=r.motivation_reason, objective="2.1"))
        if r.vector != UNDETERMINED:
            qs.append(Question(prompt=f"{s['id']}: what was the initial attack vector?", context=ctx,
                               choices=choices_with(r.vector, vectors, key=s["id"] + "v"), answer=r.vector,
                               explanation=f"observed initial access: {s['initial_access']}", objective="2.2"))
            qs.append(Question(prompt=f"{s['id']}: which mitigation best addresses that vector?", context=ctx,
                               choices=choices_with(r.mitigation, mitigations, key=s["id"] + "x"), answer=r.mitigation,
                               explanation=f"{r.vector} → {r.mitigation}" + (f". Also: {r.addon}" if r.addon else ""),
                               objective="2.5"))
    return qs
