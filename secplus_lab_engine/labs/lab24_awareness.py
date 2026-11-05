"""
Lab 24 — Security Awareness Program Analyzer
============================================

Security+ SY0-701 objectives
----------------------------
* 5.6  Implement security awareness practices: phishing (campaigns,
       recognizing a phishing attempt, responding to reported suspicious
       messages), anomalous behavior recognition (risky, unexpected,
       unintentional), user guidance and training (policy/handbooks,
       situational awareness, insider threat, password management, removable
       media and cables, social engineering, operational security,
       hybrid/remote work environments), reporting and monitoring (initial,
       recurring), development, execution.
* 2.2  Threat vectors: phishing, business email compromise, impersonation,
       typosquatting (lookalike domains).

Model
-----
1. **Phishing simulation**: each employee's events give an outcome
   (COMPROMISED > CLICKED > REPORTED > PASSED; no delivery record → NO_DATA).
   The outcome maps to an action through a role-tier table (high-risk roles
   such as finance/exec/it_admin get a stricter table; an unknown role is
   treated as high-risk). Repeat offenders (prior + this failure ≥ the tier
   threshold) → ESCALATE_TO_MANAGER. No training record → untrained,
   training older than the recurring cadence → overdue (deny by default).
   Department rates are checked against thresholds and program KPIs vs targets.
2. **Anomalous behaviour**: ordered policy rules classify observations as
   RISKY / UNINTENTIONAL / UNEXPECTED / NOT_ANOMALOUS; a missing attribute
   gives the default class (RISKY) because intent cannot be ruled out.
3. **Phishing indicators**: weighted indicators (lookalike sender, urgency,
   mismatched link text vs href, credential/payment request, risky
   attachment) → REPORT_AS_PHISHING when the score reaches the threshold.

Run it
------
    python main.py lab 24
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from statistics import median
from urllib.parse import urlparse

TITLE = "Lab 24 — Security Awareness Program Analyzer"
OBJECTIVES = "SY0-701 5.6 Security awareness: phishing campaigns, anomalous behaviour, training, reporting · 2.2 Phishing/BEC vectors"
OUTCOMES = ["REPORTED", "PASSED", "CLICKED", "COMPROMISED", "NO_DATA"]
ACTIONS = ["NONE", "MICRO_TRAINING", "REMEDIAL_TRAINING", "ESCALATE_TO_MANAGER"]
BEHAVIOUR_CLASSES = ["RISKY", "UNEXPECTED", "UNINTENTIONAL", "NOT_ANOMALOUS"]
VERDICTS = ["REPORT_AS_PHISHING", "LIKELY_SAFE"]
DECISIONS = OUTCOMES + ACTIONS + BEHAVIOUR_CLASSES + VERDICTS
RULES = ["outcome mapping", "high-risk role mapping", "repeat-offender threshold", "no training record",
         "recurring training overdue"]
FAILURES = ("CLICKED", "COMPROMISED")
METRICS = {"click_rate": "click rate", "credential_rate": "credential-submission rate", "report_rate": "report rate"}


@dataclass
class EmployeeResult:
    id: str
    dept: str
    role: str
    tier: str
    outcome: str
    action: str
    rule: str
    reasons: list[str] = field(default_factory=list)
    trained: bool = False


@dataclass
class DeptMetrics:
    dept: str
    n: int
    click_rate: float
    credential_rate: float
    report_rate: float
    median_report_minutes: float | None
    flags: list[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        return "FLAGGED" if self.flags else "OK"


@dataclass
class Classification:
    id: str
    cls: str
    response: str
    reasons: list[str] = field(default_factory=list)


@dataclass
class MessageCheck:
    id: str
    verdict: str
    score: int
    indicators: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Part 1 — phishing simulation
# --------------------------------------------------------------------------- #
def outcome_of(events) -> str:
    ev = set(events or [])
    if "delivered" not in ev:
        return "NO_DATA"
    return ("COMPROMISED" if "submitted_credentials" in ev else "CLICKED" if "clicked" in ev
            else "REPORTED" if "reported" in ev else "PASSED")


def evaluate_employee(emp: dict, campaign_day: int, cfg: dict) -> EmployeeResult:
    role = emp.get("role") or "unknown"
    tier = "high_risk" if role in cfg["high_risk_roles"] or role not in cfg["known_roles"] else "standard"
    outcome = outcome_of(emp.get("events"))
    reasons = [f"outcome {outcome} from events {emp.get('events') or 'none recorded'}"]
    if role not in cfg["known_roles"]:
        reasons.append(f"unknown role '{role}': treated as high-risk (deny by default)")
    if outcome == "NO_DATA":
        reasons.append("no delivery record: participation cannot be shown, assume training is needed")
    if outcome == "COMPROMISED":
        reasons.append("credentials submitted: force a password reset and revoke active sessions")
    if outcome == "CLICKED" and "reported" in emp.get("events", []):
        reasons.append("reported after clicking: good recovery, still counts as a click")
    action = cfg["outcome_action"][tier][outcome]
    rule = "high-risk role mapping" if action != cfg["outcome_action"]["standard"][outcome] else "outcome mapping"
    if rule == "high-risk role mapping":
        reasons.append(f"high-risk tier uses the stricter table: {outcome} → {action}")
    candidates = []
    if outcome in FAILURES:
        prior = emp.get("prior_failures")
        if prior is None:
            reasons.append("no failure history on record: counted as 0 prior failures")
        total, need = (prior or 0) + 1, cfg["escalate_after_failures"][tier]
        if total >= need:
            candidates.append(("ESCALATE_TO_MANAGER", "repeat-offender threshold",
                               f"{total} failures ≥ {need} ({tier}): repeat offender"))
    day = emp.get("training_completed_day")
    trained = isinstance(day, int) and campaign_day - day <= cfg["recurring_training_days"]
    if not isinstance(day, int):
        candidates.append((cfg["untrained_action"], "no training record",
                           "no training record: treated as untrained, complete initial training"))
    elif not trained:
        candidates.append((cfg["overdue_action"], "recurring training overdue",
                           f"training {campaign_day - day} days old > {cfg['recurring_training_days']}-day recurring cadence"))
    for act, r, why in candidates:
        reasons.append(why)
        if ACTIONS.index(act) > ACTIONS.index(action):
            action, rule = act, r
    return EmployeeResult(emp["id"], emp.get("dept", "unknown"), role, tier, outcome, action, rule, reasons, trained)


def _rate(k: int, n: int) -> float:
    return round(100 * k / n, 1) if n else 0.0


def _stats(emps: list[dict], results: list[EmployeeResult]) -> dict:
    n = len(results)
    mins = [e["report_minutes"] for e in emps if "reported" in (e.get("events") or [])
            and isinstance(e.get("report_minutes"), (int, float))]
    return {"n": n, "click_rate": _rate(sum(r.outcome in FAILURES for r in results), n),
            "credential_rate": _rate(sum(r.outcome == "COMPROMISED" for r in results), n),
            "report_rate": _rate(sum("reported" in (e.get("events") or []) for e in emps), n),
            "median_report_minutes": median(mins) if mins else None,
            "training_completion": _rate(sum(r.trained for r in results), n)}


def department_metrics(data: dict, results: list[EmployeeResult], cfg: dict) -> list[DeptMetrics]:
    t, out = cfg["department_thresholds"], []
    for dept in sorted({r.dept for r in results}):
        pairs = [(e, r) for e, r in zip(data["employees"], results) if r.dept == dept]
        s = _stats([e for e, _ in pairs], [r for _, r in pairs])
        flags = []
        if s["click_rate"] > t["max_click_rate"]:
            flags.append(f"click rate {s['click_rate']}% > {t['max_click_rate']}%")
        if s["credential_rate"] > t["max_credential_rate"]:
            flags.append(f"credential-submission rate {s['credential_rate']}% > {t['max_credential_rate']}%")
        if s["report_rate"] < t["min_report_rate"]:
            flags.append(f"report rate {s['report_rate']}% < {t['min_report_rate']}%")
        out.append(DeptMetrics(dept, s["n"], s["click_rate"], s["credential_rate"], s["report_rate"],
                               s["median_report_minutes"], flags))
    return out


def program_kpis(data: dict, results: list[EmployeeResult], cfg: dict) -> dict:
    s, t = _stats(data["employees"], results), cfg["program_targets"]
    med = s["median_report_minutes"]
    checks = {"report_rate": (s["report_rate"], f"≥ {t['report_rate_min']}%", s["report_rate"] >= t["report_rate_min"]),
              "click_rate": (s["click_rate"], f"≤ {t['click_rate_max']}%", s["click_rate"] <= t["click_rate_max"]),
              "credential_rate": (s["credential_rate"], f"≤ {t['credential_rate_max']}%",
                                  s["credential_rate"] <= t["credential_rate_max"]),
              "median_report_minutes": (med, f"≤ {t['median_report_minutes_max']} min",
                                        med is not None and med <= t["median_report_minutes_max"]),
              "training_completion": (s["training_completion"], f"≥ {t['training_completion_min']}%",
                                      s["training_completion"] >= t["training_completion_min"])}
    return {k: {"value": v, "target": tg, "status": "MET" if ok else "MISSED"} for k, (v, tg, ok) in checks.items()}


# --------------------------------------------------------------------------- #
# Part 2 — anomalous behaviour and phishing indicators
# --------------------------------------------------------------------------- #
def classify_behaviour(obs: dict, cfg: dict) -> Classification:
    missing = [a for a in cfg["behaviour_required_attributes"] if not isinstance(obs.get(a), bool)]
    cls, reasons = None, []
    if missing:
        reasons.append(f"missing {', '.join(missing)}: intent cannot be ruled out (deny by default)")
    else:
        for rule in cfg["behaviour_rules"]:
            if all(obs[k] == v for k, v in rule["match"].items()):
                cls = rule["class"]
                reasons.append(f"matched rule {rule['match']}")
                break
    cls = cls or cfg["behaviour_default_class"]
    if not reasons:
        reasons.append("no rule matched: default class")
    response = cfg["behaviour_responses"][cls]
    ctl = cfg["technical_controls"].get(obs.get("category"))
    if ctl and cls != "NOT_ANOMALOUS":
        response += f"; technical control: {ctl}"
    return Classification(obs["id"], cls, response, reasons)


def _distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _trusted(domain: str, cfg: dict) -> bool:
    return any(domain == t or domain.endswith("." + t) for t in cfg["trusted_domains"])


def is_lookalike(domain: str, cfg: dict) -> bool:
    if _trusted(domain, cfg):
        return False
    norm = domain
    for k, v in cfg["homoglyphs"].items():
        norm = norm.replace(k, v)
    return any(norm == t or _distance(domain, t) <= cfg["lookalike_max_distance"] for t in cfg["trusted_domains"])


def check_message(msg: dict, cfg: dict) -> MessageCheck:
    found = []
    sender = (msg.get("from") or "").lower()
    domain = sender.rsplit("@", 1)[1] if "@" in sender else ""
    if not domain:
        found.append(("missing_sender", "sender missing or unparseable (deny by default)"))
    elif is_lookalike(domain, cfg):
        found.append(("lookalike_sender_domain", f"sender domain {domain} imitates a trusted domain (typosquatting)"))
    elif not _trusted(domain, cfg):
        found.append(("external_sender", f"external sender {domain}"))
    text = f"{msg.get('subject', '')} {msg.get('body', '')}".lower()
    hits = [k for k in cfg["urgency_keywords"] if k in text]
    if hits:
        found.append(("urgency_language", f"urgency language: {hits}"))
    for link in msg.get("links", []):
        shown = re.search(r"[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}", link.get("text", "").lower())
        real = (urlparse(link.get("href", "")).hostname or "").lower()
        if shown and urlparse("//" + shown.group(0)).hostname != real:
            found.append(("mismatched_link", f"link text '{link['text']}' really goes to {real or 'nowhere'}"))
            break
    asks = [k for k in cfg["request_keywords"] if k in text]
    if asks:
        found.append(("credential_or_payment_request", f"asks for credentials/payment: {asks}"))
    bad = [a for a in msg.get("attachments", []) if a.lower().endswith(tuple(cfg["risky_attachment_extensions"]))]
    if bad:
        found.append(("unexpected_attachment_type", f"risky attachment type: {bad}"))
    score = sum(cfg["indicator_weights"][k] for k, _ in found)
    verdict = "REPORT_AS_PHISHING" if score >= cfg["report_threshold"] else "LIKELY_SAFE"
    return MessageCheck(msg["id"], verdict, score, [f"{k}: {why}" for k, why in found])


def analyze(data: dict, policies: dict) -> dict:
    cfg = policies["awareness"]
    emps = [evaluate_employee(e, data["campaign"]["day"], cfg) for e in data["employees"]]
    return {"employees": emps, "departments": department_metrics(data, emps, cfg),
            "kpis": program_kpis(data, emps, cfg),
            "behaviours": [classify_behaviour(o, cfg) for o in data.get("behaviours", [])],
            "messages": [check_message(m, cfg) for m in data.get("messages", [])]}


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SY0-701 5.6 Security awareness practices: phishing campaigns, anomalous behaviour, training, reporting.",
    "concepts": [
        "Phishing campaigns (simulations) measure click, credential-submission and report rates; the report rate matters most.",
        "Anomalous behaviour is risky (deliberate rule-bending), unexpected (out of pattern) or unintentional (honest mistake).",
        "Training topics: policy/handbooks, situational awareness, insider threat, passwords, removable media and cables, social engineering, OPSEC, hybrid/remote work.",
        "Initial training happens at onboarding; recurring training keeps it current. Reporting and monitoring track both.",
        "A program is developed (goals, audience, content), executed (delivery, simulations) and measured against KPIs.",
    ],
    "failure_modes": [
        "Punishing every click: people stop reporting, and the report rate is your early-warning sensor.",
        "One annual video and no simulations: no data on who actually recognises a phish.",
        "Same thresholds for the finance clerk and the payroll admin, although BEC targets high-risk roles.",
        "Treating a missing training record as 'probably done' instead of untrained.",
        "Sending insider-threat suspicions to the user's manager first, so evidence disappears.",
    ],
    "ai_governance": [
        "An AI mail triage agent should score indicators and explain each one, not just say 'safe'.",
        "Message bodies are untrusted input: the agent must never follow instructions found inside an email.",
        "An agent may assign micro-training automatically, but escalation and insider-threat referral need a human.",
        "Log every classification with the policy version so behaviour verdicts can be audited and contested.",
    ],
    "exam_tips": [
        "Suspected phish: report it (Report Phishing button / SOC), do not click, reply or forward it to colleagues.",
        "Lookalike domain (examp1e.com) = typosquatting; wire-transfer request from a 'CEO' = BEC / impersonation.",
        "'Employee plugs in a USB drive found in the car park' = removable media training (baiting).",
        "Risky = intentional, unexpected = deviates from baseline, unintentional = accident: know the three words.",
        "Initial vs recurring is about training cadence; computer-based training (CBT) and gamification are delivery methods.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    a = analyze(data, policies)
    ui.section(f"Step 1 — Phishing campaign {data['campaign']['id']} results")
    ui.table("Employees", ["ID", "Dept", "Role (tier)", "Outcome", "Action", "Rule"],
             [[r.id, r.dept, f"{r.role} ({r.tier})", r.outcome, r.action, r.rule] for r in a["employees"]])
    for r in a["employees"]:
        if r.action != "NONE" or len(r.reasons) > 1:
            ui.bullet(f"{r.id} → {r.action}: " + "; ".join(r.reasons[1:] or r.reasons), style="yellow")
    ui.section("Step 2 — Department metrics and program KPIs")
    ui.table("Departments", ["Dept", "N", "Click %", "Creds %", "Report %", "Median report", "Status"],
             [[d.dept, d.n, d.click_rate, d.credential_rate, d.report_rate,
               "-" if d.median_report_minutes is None else f"{d.median_report_minutes} min", d.status]
              for d in a["departments"]])
    for d in a["departments"]:
        for f in d.flags:
            ui.bullet(f"{d.dept}: {f}", style="red")
    ui.table("Program KPIs", ["KPI", "Value", "Target", "Status"],
             [[k, v["value"], v["target"], v["status"]] for k, v in a["kpis"].items()])
    ui.section("Step 3 — Anomalous behaviour")
    ui.table("Observations", ["ID", "Class", "Response"], [[c.id, c.cls, c.response] for c in a["behaviours"]])
    ui.section("Step 4 — Phishing indicator checker")
    for m in a["messages"]:
        ui.status(m.id, m.verdict, f"score {m.score} (threshold {policies['awareness']['report_threshold']})")
        for i in m.indicators:
            ui.bullet(i, style="dim")
    ui.insight(INSIGHT)
    return {"employees": {r.id: [r.outcome, r.action] for r in a["employees"]},
            "departments": {d.dept: d.status for d in a["departments"]},
            "kpis": {k: v["status"] for k, v in a["kpis"].items()},
            "behaviours": {c.id: c.cls for c in a["behaviours"]},
            "messages": {m.id: m.verdict for m in a["messages"]}}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg, a = policies["awareness"], analyze(data, policies)
    qs: list = []
    for e, r in zip(data["employees"], a["employees"]):
        ctx = (f"{r.id} · dept={r.dept} role={r.role} events={e.get('events')} prior_failures={e.get('prior_failures')} "
               f"training_day={e.get('training_completed_day')} campaign_day={data['campaign']['day']}")
        qs.append(Question(f"{r.id}: what is the simulation outcome?", OUTCOMES, r.outcome, r.reasons[0], "5.6", ctx))
        qs.append(Question(f"{r.id}: what action does the policy require?", ACTIONS, r.action,
                           "; ".join(r.reasons), "5.6", ctx))
        if r.rule != "outcome mapping":
            qs.append(Question(f"{r.id}: which rule set the action to {r.action}?", RULES, r.rule,
                               "; ".join(r.reasons), "5.6", ctx))
    for d in a["departments"]:
        if len(d.flags) == 1:
            ans = next(v for k, v in METRICS.items() if d.flags[0].startswith(v))
            qs.append(Question(f"{d.dept} is FLAGGED. Which threshold does it breach?", sorted(METRICS.values()), ans,
                               d.flags[0], "5.6", f"{d.dept}: click {d.click_rate}%, creds {d.credential_rate}%, "
                               f"report {d.report_rate}%; thresholds {cfg['department_thresholds']}"))
    for k, v in a["kpis"].items():
        qs.append(Question(f"Program KPI {k} (target {v['target']}): met or missed?", ["MET", "MISSED"], v["status"],
                           f"value {v['value']} vs target {v['target']}", "5.6"))
    for o, c in zip(data.get("behaviours", []), a["behaviours"]):
        qs.append(Question(f"{c.id}: how is this behaviour classified?", BEHAVIOUR_CLASSES, c.cls,
                           f"{'; '.join(c.reasons)} → {c.response}", "5.6",
                           f"{o.get('description')} · " + ", ".join(f"{k}={o.get(k)}" for k in cfg["behaviour_required_attributes"])))
    for msg, m in zip(data.get("messages", []), a["messages"]):
        ctx = (f"From: {msg.get('from')}\nSubject: {msg.get('subject')}\n{msg.get('body')}\nlinks={msg.get('links', [])} "
               f"attachments={msg.get('attachments', [])}")
        qs.append(Question(f"{m.id}: what should the user do?", VERDICTS, m.verdict,
                           f"score {m.score}: " + ("; ".join(m.indicators) or "no indicators"), "5.6", ctx))
        present = [i.split(":")[0] for i in m.indicators]
        if present:
            qs.append(Question(f"{m.id}: which phishing indicator is present?",
                               choices_with(present[0], cfg["indicator_weights"], exclude=present, key=m.id), present[0],
                               m.indicators[0], "2.2", ctx))
    rp = cfg["report_procedure"]
    qs.append(Question("A user receives a suspected phishing email. What is the correct response?",
                       sorted([rp["do"], *rp["dont"][:3]]), rp["do"],
                       "Reporting lets the SOC pull the message from every mailbox; clicking, replying or forwarding spreads risk.",
                       "5.6"))
    for kind, text in sorted(cfg["training_types"].items()):
        qs.append(Question(f"Which training cadence is this? \"{text}\"", sorted(cfg["training_types"]), kind, text, "5.6"))
    for topic, text in sorted(cfg["guidance_topics"].items()):
        qs.append(Question(f"Which user guidance topic covers: \"{text}\"?",
                           choices_with(topic, cfg["guidance_topics"], key=topic), topic, f"{topic}: {text}", "5.6"))
    return qs
