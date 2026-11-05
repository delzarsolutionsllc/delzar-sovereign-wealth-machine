"""
Lab 19 — SIEM Correlation & Alert Tuning
========================================

Security+ SY0-701 objectives
----------------------------
* 4.4  Alerting and monitoring: monitoring computing resources (systems,
       applications, infrastructure); activities (log aggregation, alerting,
       scanning, reporting, archiving, alert response and remediation /
       validation, quarantine, alert tuning); tools (SIEM, SCAP, benchmarks,
       agents/agentless, SNMP traps, NetFlow, antivirus, DLP, vulnerability
       scanners).
* 4.9  Data sources to support an investigation: firewall, application,
       endpoint, OS-specific security and network (DNS) logs.

Model
-----
1. Normalise: every event needs ``id``, ``ts`` (ISO-8601 UTC string or integer
   epoch seconds) and a known ``source``. An event that fails is not dropped:
   it raises SIEM-000 (an unparsed event is invisible to every other rule).
2. Correlate: each rule in ``policies["siem"]["rules"]`` has a logic type —
   ``threshold`` (N events, or N distinct values, per group within W seconds;
   brute force escalates to critical if a success follows), ``impossible_travel``,
   ``after_hours``, ``source_silence`` (blind spot), ``threat_intel``, ``match``.
3. Tune: a suppression applies only if it matches the rule and entities, has an
   owner, and has not expired at the alert's time; critical alerts are never
   suppressed. Anything else leaves the alert standing (deny by default).
4. Score: each event carries a ground-truth scenario label, so the lab counts
   true / false positives, false negatives and precision before and after tuning.

Run it
------
    python main.py lab 19
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone

TITLE = "Lab 19 — SIEM Correlation & Alert Tuning"
OBJECTIVES = "SY0-701 4.4 Alerting and monitoring: SIEM, correlation, alert tuning, response · 4.9 Log data sources"
DECISIONS = ["ALERT", "SUPPRESSED"]


@dataclass
class Alert:
    id: str
    rule_id: str
    rule_name: str
    severity: str
    ts: int
    entities: dict
    evidence: list[str]
    reasons: list[str]
    response: str
    disposition: str = "ALERT"
    tuning: list[str] = field(default_factory=list)
    scenario: str = ""


@dataclass
class Metrics:
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float
    missed: list[str] = field(default_factory=list)
    unlabeled: int = 0


def parse_ts(value) -> int | None:
    """Integer epoch seconds or an ISO-8601 string (Z or offset); anything else = None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if dt.tzinfo is None:
            return None                     # no timezone = ambiguous: do not guess
        return int(dt.timestamp())
    return None


def iso(t: int) -> str:
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def _match(e: dict, flt: dict) -> bool:
    return all(e.get(k) == v for k, v in flt.items())


def normalize(events: list[dict], cfg: dict, start: int = 0) -> tuple[list[dict], list[tuple[dict, str, int]]]:
    """Split events into parsed ones (with '_t') and failures (event, why, ingest time of the previous good event)."""
    norm = next((r for r in cfg["rules"] if r.get("logic") == "normalization"), {})
    required = norm.get("params", {}).get("required", ["id", "ts", "source"])
    good, bad, seen = [], [], start
    for e in events:
        missing = [k for k in required if e.get(k) in (None, "")]
        t = parse_ts(e.get("ts"))
        if missing:
            bad.append((e, f"missing field(s): {', '.join(missing)}", seen))
        elif t is None:
            bad.append((e, f"unparseable timestamp {e['ts']!r}", seen))
        elif e.get("source") not in cfg["sources"]:
            bad.append((e, f"unknown log source {e.get('source')!r}", t))
        else:
            good.append({**e, "_t": t})
            seen = max(seen, t)
    return sorted(good, key=lambda e: (e["_t"], e["id"])), bad


def _first_window(evs: list[dict], count: int, window: int, distinct: str | None) -> list[dict] | None:
    for j, last in enumerate(evs):
        win = [e for e in evs[: j + 1] if last["_t"] - e["_t"] <= window]
        if len({e.get(distinct) if distinct else e["id"] for e in win}) >= count:
            return win
    return None


def _haversine(a, b) -> float:
    la1, lo1, la2, lo2 = map(math.radians, (*a, *b))
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 2 * 6371 * math.asin(math.sqrt(h))


def run_rule(rule: dict, evs: list[dict], bad: list, data: dict, cfg: dict) -> list[dict]:
    """Return raw alert dicts {ts, entities, evidence, reasons, severity?, response?} for one rule."""
    p, logic, out = rule.get("params", {}), rule.get("logic"), []
    if logic == "normalization":
        for e, why, seen in bad:
            out.append({"ts": seen, "entities": {"host": str(e.get("host", "?"))},
                        "evidence": [str(e.get("id", "?"))], "reasons": [f"event {e.get('id', '?')}: {why}"]})
    elif logic == "threshold":
        groups: dict = {}
        for e in evs:
            if _match(e, p["filter"]):
                groups.setdefault(tuple(e.get(k) for k in p["group_by"]), []).append(e)
        for key, g in sorted(groups.items(), key=lambda kv: kv[1][0]["_t"]):
            win = _first_window(g, p["count"], p["window_seconds"], p.get("distinct"))
            if not win:
                continue
            what = f"{len({e.get(p['distinct']) for e in win})} distinct {p['distinct']} values" if p.get("distinct") \
                else f"{len(win)} events matching {p['filter']}"
            a = {"ts": win[-1]["_t"], "entities": {k: str(v) for k, v in zip(p["group_by"], key)},
                 "evidence": [e["id"] for e in win],
                 "reasons": [f"{what} within {win[-1]['_t'] - win[0]['_t']}s "
                             f"(threshold {p['count']} in {p['window_seconds']}s)"]}
            esc = p.get("escalate")
            if esc:
                hit = next((e for e in evs if _match(e, esc["filter"]) and 0 <= e["_t"] - a["ts"] <= esc["within_seconds"]
                            and all(e.get(k) == v for k, v in zip(p["group_by"], key))), None)
                if hit:
                    a.update(severity=esc["severity"], response=esc["response"])
                    a["evidence"].append(hit["id"])
                    a["reasons"].append(f"followed by a successful login ({hit['id']}) {hit['_t'] - a['ts']}s later: "
                                        "possible account compromise")
            out.append(a)
    elif logic == "impossible_travel":
        last: dict = {}
        for e in (x for x in evs if _match(x, p["filter"])):
            prev, last[e.get("user")] = last.get(e.get("user")), e
            if not prev or prev.get("geo") == e.get("geo"):
                continue
            ent = {"user": str(e.get("user"))}
            if prev.get("geo") not in cfg["geo"] or e.get("geo") not in cfg["geo"]:
                out.append({"ts": e["_t"], "entities": ent, "evidence": [prev["id"], e["id"]],
                            "reasons": [f"location {prev.get('geo')!r} → {e.get('geo')!r} not in the geolocation "
                                        "table: travel cannot be verified"]})
                continue
            km = _haversine(cfg["geo"][prev["geo"]], cfg["geo"][e["geo"]])
            hours = max(e["_t"] - prev["_t"], 1) / 3600
            if km / hours > p["max_speed_kmh"]:
                out.append({"ts": e["_t"], "entities": ent, "evidence": [prev["id"], e["id"]],
                            "reasons": [f"{prev['geo']} → {e['geo']}: {km:.0f} km in {hours * 60:.0f} min = "
                                        f"{km / hours:.0f} km/h (max {p['max_speed_kmh']} km/h)"]})
    elif logic == "after_hours":
        start, end = p["business_hours"]
        for e in evs:
            if e.get("action") not in p["actions"]:
                continue
            dt = datetime.fromtimestamp(e["_t"], timezone.utc)
            weekend = p.get("weekdays_only") and dt.weekday() >= 5
            if weekend or not start <= dt.hour < end:
                out.append({"ts": e["_t"], "entities": {"user": str(e.get("user")), "host": str(e.get("host"))},
                            "evidence": [e["id"]],
                            "reasons": [f"privileged action '{e['action']}' at {dt:%a %H:%M} UTC, outside business "
                                        f"hours {start:02d}:00-{end:02d}:00{' Mon-Fri' if p.get('weekdays_only') else ''}"]})
    elif logic == "source_silence":
        win = data.get("window", {})
        ws, we = parse_ts(win.get("start")), parse_ts(win.get("end"))
        note = "" if ws is not None and we is not None else " (no valid window in data: using the event span)"
        ws = ws if ws is not None else min((e["_t"] for e in evs), default=0)
        we = we if we is not None else max((e["_t"] for e in evs), default=0)
        for src, gap in p["max_gap_seconds"].items():
            ts = [e for e in evs if e["source"] == src]
            marks = [(ws, None)] + [(e["_t"], e) for e in ts] + [(we, None)]
            for (t0, e0), (t1, e1) in zip(marks, marks[1:]):
                if t1 - t0 > gap:
                    ev = [x["id"] for x in (e0, e1) if x][:1]
                    out.append({"ts": t1, "entities": {"source": src}, "evidence": ev,
                                "reasons": [f"no '{src}' events from {iso(t0)} to {iso(t1)} ({t1 - t0}s > {gap}s "
                                            f"allowed): monitoring blind spot{note}"]})
                    break
    elif logic == "threat_intel":
        ti, seen = cfg["threat_intel"], set()
        bad_set = set(ti["ips"]) | set(ti["domains"])
        for e in evs:
            for f in ti["fields"]:
                ind = e.get(f)
                who = e.get("src_ip") or e.get("host")
                if ind in bad_set and (ind, who) not in seen:
                    seen.add((ind, who))
                    out.append({"ts": e["_t"], "entities": {"indicator": str(ind), "source_host": str(who)},
                                "evidence": [e["id"]],
                                "reasons": [f"{e['source']} event {e['id']}: {f}={ind} is on the threat-intel list"]})
    elif logic == "match":
        for e in evs:
            if _match(e, p["filter"]):
                out.append({"ts": e["_t"], "entities": {k: str(e[k]) for k in ("host", "user") if e.get(k)},
                            "evidence": [e["id"]],
                            "reasons": [f"event {e['id']} matches {p['filter']}"]})
    else:
        out.append({"ts": 0, "entities": {"rule": str(rule.get("id"))}, "evidence": [],
                    "reasons": [f"unknown logic type {logic!r}: rule cannot run, treat the detection as broken"]})
    return out


def tune(alert: Alert, cfg: dict) -> None:
    """Apply suppressions. Only a matching, owned, unexpired suppression on a non-critical alert applies."""
    for s in cfg.get("suppressions", []):
        if s.get("rule") != alert.rule_id or not all(alert.entities.get(k) == v for k, v in s.get("match", {}).items()):
            continue
        exp = parse_ts(s.get("expires"))
        if not s.get("match"):
            alert.tuning.append(f"{s['id']} has no entity match, so it would hide every {alert.rule_id} alert: ignored")
        elif not s.get("owner"):
            alert.tuning.append(f"{s['id']} matches but has no owner: ignored (deny by default)")
        elif exp is None:
            alert.tuning.append(f"{s['id']} matches but has no valid expiry: ignored (deny by default)")
        elif alert.ts >= exp:
            alert.tuning.append(f"{s['id']} ({s.get('reason')}) expired {iso(exp)}: ignored, alert stands")
        elif alert.severity in cfg["never_suppress_severities"]:
            alert.tuning.append(f"{s['id']} matches but {alert.severity} alerts are never suppressed")
        else:
            alert.disposition = "SUPPRESSED"
            alert.tuning.append(f"{s['id']}: {s.get('reason')} (owner {s['owner']}, expires {iso(exp)})")
            return


def evaluate(data: dict, policies: dict) -> list[Alert]:
    cfg = policies["siem"]
    evs, bad = normalize(data.get("events", []), cfg, parse_ts(data.get("window", {}).get("start")) or 0)
    by_id = {str(e.get("id")): e for e in data.get("events", [])}
    raw = []
    for rule in cfg["rules"]:
        for a in run_rule(rule, evs, bad, data, cfg):
            raw.append((a["ts"], rule["id"], rule, a))
    alerts = []
    for n, (_, _, rule, a) in enumerate(sorted(raw, key=lambda r: (r[0], r[1])), 1):
        scen = next((by_id[i]["scenario"] for i in a["evidence"] if by_id.get(i, {}).get("scenario")), "")
        al = Alert(f"AL-{n:02d}", rule["id"], rule.get("name", rule["id"]), a.get("severity", rule.get("severity", "high")),
                   a["ts"], a["entities"], a["evidence"], a["reasons"], a.get("response", rule.get("response", "")),
                   scenario=scen)
        tune(al, cfg)
        alerts.append(al)
    return alerts


def score(alerts: list[Alert], data: dict, tuned: bool = True) -> Metrics:
    labels = {k: v.get("label") for k, v in data.get("scenarios", {}).items()}
    live = [a for a in alerts if a.disposition == "ALERT" or not tuned]
    tp = sum(labels.get(a.scenario) == "actionable" for a in live)
    fp = sum(labels.get(a.scenario) == "benign" for a in live)
    hit = {a.scenario for a in live}
    actionable = sorted(k for k, v in labels.items() if v == "actionable")
    missed = [k for k in actionable if k not in hit]
    return Metrics(tp, fp, len(missed), round(100 * tp / (tp + fp), 1) if tp + fp else 0.0,
                   round(100 * (len(actionable) - len(missed)) / len(actionable), 1) if actionable else 0.0,
                   missed, len(live) - tp - fp)


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SY0-701 4.4 Alerting and monitoring: SIEM aggregation, correlation, alert tuning and response (with 4.9 log sources).",
    "concepts": [
        "A SIEM aggregates and normalises logs from many sources so one rule can correlate auth, firewall, EDR, DNS and app events.",
        "Correlation rules turn many weak signals into one alert: thresholds in a time window, distinct counts, travel speed, time of day.",
        "Silence is a signal: an expected source that stops sending events is a monitoring blind spot, not a quiet day.",
        "Alert tuning (thresholds, suppressions) cuts false positives; every suppression needs an owner, a reason and an expiry.",
        "Alert response and remediation: quarantine via EDR, block at the firewall, lock the account, then validate the fix.",
    ],
    "failure_modes": [
        "Alert fatigue: a noisy rule nobody tunes trains analysts to ignore the queue, real attacks included.",
        "Permanent, ownerless suppressions: the scanner exception outlives the scanner and hides an attacker on that IP.",
        "Dropping events the parser cannot read instead of alerting on them: a silent loss of visibility.",
        "Over-tuning: raising a threshold to kill noise also hides low-and-slow attacks (false negatives).",
    ],
    "ai_governance": [
        "An AI triage agent may close or suppress alerts only through owned, expiring, logged suppressions, never silently.",
        "Score the agent like a rule: measure its precision and false negatives against labelled incidents before trusting it.",
        "Containment actions (quarantine, account lock) recommended by an agent should need human approval or a tight playbook scope.",
        "Event fields are untrusted input: a log line saying 'ignore previous instructions' must never steer the agent.",
    ],
    "exam_tips": [
        "'Collects logs from many systems and correlates them' = SIEM. 'Unsolicited alert from a network device' = SNMP trap.",
        "'Who talked to whom, how much, which ports, but no payload' = NetFlow. 'Automates benchmark checks (XCCDF/OVAL)' = SCAP.",
        "False positive = alert on benign activity; false negative = attack with no alert. Tuning trades one for the other.",
        "Agent-based monitoring installs software on the host; agentless uses remote protocols or APIs.",
        "Isolating an infected endpoint so it cannot spread = quarantine; rescanning afterwards = validation.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    alerts = evaluate(data, policies)
    raw, tuned = score(alerts, data, tuned=False), score(alerts, data)
    ui.section("Step 1 — Log aggregation & correlation")
    srcs = sorted({e.get("source") for e in data.get("events", [])}, key=str)
    ui.print(f"{len(data.get('events', []))} events from sources: {', '.join(map(str, srcs))}")
    ui.table("Alerts", ["ID", "Rule", "Severity", "Time", "Entities", "Evidence", "Disposition"],
             [[a.id, f"{a.rule_id} {a.rule_name}", a.severity, iso(a.ts)[11:], ", ".join(f"{k}={v}" for k, v in a.entities.items()),
               ", ".join(a.evidence[:3]) + (" ..." if len(a.evidence) > 3 else ""), a.disposition] for a in alerts])
    ui.section("Step 2 — Reasons, tuning and response")
    for a in alerts:
        ui.print(f"[bold]{a.id} {a.rule_id} {a.rule_name}[/bold] → {a.disposition} ({a.severity})")
        for r in a.reasons:
            ui.bullet(r)
        for t in a.tuning:
            ui.bullet(f"TUNING: {t}", style="green" if a.disposition == "SUPPRESSED" else "yellow")
        if a.disposition == "ALERT":
            ui.bullet(f"RESPONSE: {a.response}", style="red")
    ui.section("Step 3 — Alert quality against ground truth")
    ui.table("Before vs after tuning", ["Stage", "TP", "FP", "FN", "Precision", "Recall"],
             [[n, m.tp, m.fp, m.fn, f"{m.precision}%", f"{m.recall}%"] for n, m in (("raw", raw), ("tuned", tuned))])
    for a in alerts:
        if a.disposition == "SUPPRESSED":
            ui.bullet(f"{a.id} suppressed: scenario {a.scenario} is "
                      f"{data.get('scenarios', {}).get(a.scenario, {}).get('label', 'unlabeled')}, so FP {raw.fp} → {tuned.fp} "
                      f"and precision {raw.precision}% → {tuned.precision}%", style="green")
    for s in tuned.missed:
        ui.bullet(f"FALSE NEGATIVE {s}: {data['scenarios'][s]['description']} (no rule fired)", style="red")
    ui.insight(INSIGHT)
    return {a.id: a.disposition for a in alerts}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["siem"]
    alerts = evaluate(data, policies)
    raw, tuned = score(alerts, data, tuned=False), score(alerts, data)
    names = sorted({r["name"] for r in cfg["rules"]})
    responses = sorted({r["response"] for r in cfg["rules"]} | {a.response for a in alerts})
    labels = {k: v.get("label") for k, v in data.get("scenarios", {}).items()}
    by_id = {str(e.get("id")): e for e in data.get("events", [])}
    qs: list = []
    for a in alerts:
        ctx = f"Evidence {', '.join(a.evidence)} · entities {a.entities}"
        raw_ev = "\n".join(str({k: v for k, v in by_id[i].items() if k != "scenario"})
                           for i in a.evidence[:6] if i in by_id) or "(no events: the source was silent)"
        qs.append(Question(prompt=f"{a.id}: which correlation rule raised this alert?", context=raw_ev,
                           choices=choices_with(a.rule_name, names, key=a.id), answer=a.rule_name,
                           explanation=next(r["description"] for r in cfg["rules"] if r["id"] == a.rule_id),
                           objective="4.4"))
        sups = [s for s in cfg.get("suppressions", []) if s.get("rule") == a.rule_id]
        if sups:
            qs.append(Question(prompt=f"{a.id} ({a.rule_name}, {a.entities}): final disposition after tuning?",
                               context="Suppressions: " + "; ".join(f"{s['id']} {s.get('match')} owner={s.get('owner')!r} "
                                                                    f"expires={s.get('expires')}" for s in sups)
                                       + f"\nAlert time {iso(a.ts)}",
                               choices=DECISIONS, answer=a.disposition,
                               explanation="; ".join(a.tuning or ["no suppression matches: the alert stands"]), objective="4.4"))
        if a.disposition == "ALERT" and labels.get(a.scenario) in ("actionable", "benign"):
            verdict = "true positive" if labels[a.scenario] == "actionable" else "false positive"
            qs.append(Question(prompt=f"{a.id}: ground truth for scenario {a.scenario} is "
                                      f"'{data['scenarios'][a.scenario]['description']}'. This alert is a...",
                               choices=["false negative", "false positive", "true negative", "true positive"],
                               context="; ".join(a.reasons), answer=verdict, explanation=f"an alert fired and the activity is {labels[a.scenario]}",
                               objective="4.4"))
        if a.disposition == "ALERT" and a.severity == "critical":
            qs.append(Question(prompt=f"{a.id} escalated to critical. What is the recommended response?", context=ctx,
                               choices=choices_with(a.response, responses, key=a.id), answer=a.response,
                               explanation="; ".join(a.reasons), objective="4.4"))
    if raw.tp + raw.fp and tuned.tp + tuned.fp:
        ans = f"{tuned.precision}%"
        qs.append(Question(prompt="What is alert precision AFTER tuning?",
                           context=f"after tuning: TP={tuned.tp} FP={tuned.fp} (raw TP={raw.tp} FP={raw.fp})",
                           choices=sorted({ans, f"{raw.precision}%", f"{tuned.recall}%", "50.0%", "100.0%"}), answer=ans, explanation=f"precision = TP / (TP + FP) = {tuned.tp}/{tuned.tp + tuned.fp}",
                           objective="4.4"))
    for name, text in sorted({**cfg["tools"], **cfg["activities"]}.items()):
        qs.append(Question(prompt=f"Which monitoring tool or activity is this? \"{text}\"",
                           choices=choices_with(name, sorted({**cfg["tools"], **cfg["activities"]}), key=name),
                           answer=name, explanation=f"{name}: {text}", objective="4.4"))
    for src, text in sorted(cfg["sources"].items()):
        qs.append(Question(prompt=f"Which log source records this? \"{text.split('(')[1].rstrip(')')}\"",
                           choices=sorted(cfg["sources"]), answer=src, explanation=text, objective="4.9"))
    return qs
