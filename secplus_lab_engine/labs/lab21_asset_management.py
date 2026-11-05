"""
Lab 21 — Asset Inventory & Secure Disposal
==========================================

Security+ SY0-701 objectives
----------------------------
* 4.2  Security implications of proper hardware, software and data asset
       management: acquisition/procurement process; assignment/accounting
       (ownership, classification); monitoring/asset tracking (inventory,
       enumeration); disposal/decommissioning (sanitization, destruction,
       certification, data retention).
* 3.3  Data classification drives the required protection (and disposal) level.
* 4.5  Network access control (NAC) to quarantine unmanaged devices.

How it works
------------
Part 1 — inventory reconciliation. The CMDB (what we think we own) is compared
with a discovery scan (what is actually on the network), matching by MAC:

    UNMANAGED     on the network but not in the CMDB (shadow IT)
    MISSING       tracked as active but not seen for > missing_after_days
    NO_OWNER      no accountable owner recorded
    UNCLASSIFIED  no (or an unknown) data classification
    OK            none of the above

Part 2 — disposal requests, NIST SP 800-88 style. Levels are ordered
Clear < Purge < Destroy. The minimum level depends on classification and on
whether the media is reused inside the organisation or leaves it. Each method
maps to a level and to the media it works on. A request is REJECTED when the
media/method/classification is unknown (deny by default), the method does not
work on that media, the level is too low, a third party gives no certificate
of destruction, a legal hold applies or the retention period has not expired.

Run it
------
    python main.py lab 21
"""

from __future__ import annotations

from dataclasses import dataclass, field

TITLE = "Lab 21 — Asset Inventory & Secure Disposal"
OBJECTIVES = ("SY0-701 4.2 Asset management: procurement, ownership, classification, inventory, "
              "enumeration, sanitization, destruction, certification, retention · 3.3 Data classification · 4.5 NAC")
DECISIONS = ["APPROVE", "REJECT"]
FINDINGS = ["UNMANAGED", "MISSING", "NO_OWNER", "UNCLASSIFIED", "OK"]
RULES = {
    "unknown_input": "unknown or missing media, method or request field",
    "method_media": "method does not work on this media type",
    "level_too_low": "sanitization level below the required minimum",
    "certificate": "no certificate of destruction from the third party",
    "legal_hold": "asset is under legal hold",
    "retention": "retention period has not expired",
}


@dataclass
class InventoryResult:
    key: str                     # asset_id, or "scan:<ip>" for unmanaged hosts
    hostname: str
    findings: list[str]
    primary: str
    reasons: list[str] = field(default_factory=list)
    action: str = ""


@dataclass
class DisposalDecision:
    id: str
    decision: str
    required_level: str | None
    method_level: str | None
    rules: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


def _mac(m) -> str:
    return str(m or "").strip().lower().replace("-", ":")


# --------------------------------------------------------------------------- #
# Part 1 — inventory reconciliation
# --------------------------------------------------------------------------- #
def reconcile(data: dict, cfg: dict) -> list[InventoryResult]:
    today, limit = data["today"], cfg["missing_after_days"]
    scan = {_mac(h.get("mac")): h for h in data.get("scan", []) if _mac(h.get("mac"))}
    known = {_mac(a.get("mac")) for a in data.get("cmdb", [])}
    out = []
    for a in data.get("cmdb", []):
        findings, reasons = [], []
        seen_now = _mac(a.get("mac")) in scan
        if a.get("status") in cfg["tracked_statuses"] and not seen_now:
            last = a.get("last_seen")
            if last is None:
                findings.append("MISSING")
                reasons.append("never seen on the network (no last_seen recorded)")
            elif today - last > limit:
                findings.append("MISSING")
                reasons.append(f"active but last seen day {last}: {today - last} days ago > {limit}")
        if not str(a.get("owner") or "").strip():
            findings.append("NO_OWNER")
            reasons.append("no owner recorded")
        if a.get("classification") not in cfg["classifications"]:
            findings.append("UNCLASSIFIED")
            reasons.append(f"classification '{a.get('classification') or ''}' is not one of {cfg['classifications']}")
        if not findings:
            findings = ["OK"]
            reasons.append("seen in today's scan" if seen_now else
                           f"status '{a.get('status')}', last seen day {a.get('last_seen')}: within policy")
        primary = next(f for f in cfg["finding_priority"] if f in findings)
        out.append(InventoryResult(a.get("asset_id", "?"), a.get("hostname", "?"), findings, primary, reasons,
                                   cfg["finding_actions"][primary]))
    for h in data.get("scan", []):
        if _mac(h.get("mac")) not in known:
            out.append(InventoryResult(f"scan:{h.get('ip')}", h.get("hostname", "?"), ["UNMANAGED"], "UNMANAGED",
                                       [f"MAC {h.get('mac')} at {h.get('ip')} is not in the CMDB"],
                                       cfg["finding_actions"]["UNMANAGED"]))
    return out


# --------------------------------------------------------------------------- #
# Part 2 — disposal requests
# --------------------------------------------------------------------------- #
def evaluate_disposal(req: dict, cfg: dict, today: int) -> DisposalDecision:
    levels = cfg["sanitization_levels"]
    rules, reasons = [], []

    def deny(rule, text):
        if rule not in rules:
            rules.append(rule)
        reasons.append(text)

    media, method_name = req.get("media"), req.get("method")
    method = cfg["methods"].get(method_name)
    cls, dest = req.get("classification"), req.get("destination")
    if media not in cfg["media_types"]:
        deny("unknown_input", f"unknown media type '{media}': cannot choose a sanitization method")
    if method is None:
        deny("unknown_input", f"unknown method '{method_name}': not an approved sanitization technique")
    if cls not in cfg["min_level"]:
        deny("unknown_input", f"unknown classification '{cls}': cannot set the required level")
    elif dest not in cfg["min_level"][cls]:
        deny("unknown_input", f"unknown destination '{dest}': must be one of {sorted(cfg['min_level'][cls])}")
    if req.get("performed_by") not in ("internal", *cfg["certificate_required"]["performed_by"]):
        deny("unknown_input", f"unknown performed_by '{req.get('performed_by')}'")

    required = cfg["min_level"].get(cls, {}).get(dest)
    mlevel = method["level"] if method else None
    if method and media in cfg["media_types"] and media not in method["media"]:
        note = cfg["incompatibility_notes"].get(f"{method_name}:{media}", "not a valid technique for this media")
        deny("method_media", f"{method_name} on {media}: {note}")
    if required and mlevel and levels.index(mlevel) < levels.index(required):
        deny("level_too_low", f"{method_name} is {mlevel.upper()} but {cls} media going {dest} needs at least "
                              f"{required.upper()}")
    cert = cfg["certificate_required"]
    if (req.get("performed_by") in cert["performed_by"] and mlevel in cert["levels"]
            and req.get("certificate_of_destruction") is not True):
        deny("certificate", "third-party sanitization/destruction with no certificate of destruction: "
                            "no proof the media was actually destroyed")
    if req.get("legal_hold") is not False:
        deny("legal_hold", "under legal hold: disposal is suspended" if req.get("legal_hold")
             else "legal hold status not confirmed (missing)")
    ru = req.get("retention_until")
    if not isinstance(ru, int):
        deny("retention", "retention end date not recorded")
    elif ru > today:
        deny("retention", f"retention runs until day {ru} (today is day {today})")

    if not rules:
        reasons.append(f"{method_name} = {mlevel.upper()} on {media} meets the {required.upper()} minimum for "
                       f"{cls} media going {dest}")
    return DisposalDecision(req.get("id", "?"), "REJECT" if rules else "APPROVE", required, mlevel, rules, reasons)


def evaluate_all(data: dict, policies: dict) -> tuple[list[InventoryResult], list[DisposalDecision]]:
    cfg = policies["asset_mgmt"]
    return reconcile(data, cfg), [evaluate_disposal(r, cfg, data["today"]) for r in data.get("disposals", [])]


def methods_for(media: str, level: str, cfg: dict) -> list[str]:
    """Specific methods (not the generic level names) at exactly ``level`` that work on ``media``."""
    return sorted(m for m, v in cfg["methods"].items()
                  if v["level"] == level and media in v["media"] and m not in cfg["sanitization_levels"])


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SY0-701 4.2 Asset management: procurement, assignment/accounting, tracking and disposal.",
    "concepts": [
        "Procurement is the first control: buy through an approved process so every asset enters the inventory with an owner.",
        "Assignment/accounting gives every asset an accountable owner and a data classification.",
        "Monitoring/tracking compares the inventory with enumeration (discovery scans) to find unmanaged and missing assets.",
        "NIST SP 800-88 levels: Clear (logical overwrite) < Purge (crypto-erase, secure erase, degauss) < Destroy (shred, pulverize, incinerate).",
        "Disposal needs certification (certificate of destruction) and must respect data retention and legal holds.",
    ],
    "failure_modes": [
        "Shadow IT devices nobody owns never get patched, monitored or wiped.",
        "Degaussing an SSD: flash storage is not magnetic, so the data survives.",
        "Overwriting an SSD: wear levelling leaves old blocks behind; use crypto-erase or destroy.",
        "Paying a shredding vendor without getting a certificate of destruction: no proof, no accountability.",
        "Destroying records still under retention or legal hold (spoliation of evidence).",
    ],
    "ai_governance": [
        "Agents, models and API keys are assets: inventory them with an owner and a classification.",
        "An unregistered AI agent or tool found in traffic is shadow IT: onboard it or block it.",
        "When decommissioning an AI system, sanitize its training data, vector stores, logs and backups too.",
        "An AI asset agent may reconcile and recommend, but disposal approval stays with a human owner.",
    ],
    "exam_tips": [
        "'Device on the network not in the inventory' = unmanaged asset / shadow IT; NAC can quarantine it.",
        "'SSD leaving the organisation' = crypto-erase/secure erase (purge) or physical destruction, never degauss.",
        "Certificate of destruction = documented proof that media was destroyed, usually from a third party.",
        "Legal hold overrides the retention schedule: nothing under hold may be deleted or destroyed.",
        "Clear protects against simple recovery tools; Purge against laboratory recovery; Destroy makes reuse impossible.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    cfg = policies["asset_mgmt"]
    inv, disp = evaluate_all(data, policies)
    ui.section(f"Step 1 — Reconcile the CMDB with the discovery scan (today = day {data['today']}, "
               f"MISSING after {cfg['missing_after_days']} days)")
    ui.table("Inventory", ["Asset", "Hostname", "Findings", "Action"],
             [[r.key, r.hostname, ", ".join(r.findings), r.action] for r in inv])
    for r in inv:
        if r.primary != "OK":
            ui.bullet(f"{r.key} {r.hostname}: {'; '.join(r.reasons)}", style="yellow")
    ui.section("Step 2 — Disposal requests (Clear < Purge < Destroy)")
    reqs = {r.get("id"): r for r in data.get("disposals", [])}
    ui.table("Disposals", ["ID", "Media", "Class", "Destination", "Method", "Level / needed", "Decision"],
             [[d.id, reqs[d.id].get("media"), reqs[d.id].get("classification"), reqs[d.id].get("destination"),
               reqs[d.id].get("method"), f"{d.method_level or '?'} / {d.required_level or '?'}", d.decision]
              for d in disp])
    for d in disp:
        ui.print(f"[bold]{d.id}[/bold] → {d.decision}")
        for r in d.reasons:
            ui.bullet(r, style="red" if d.decision == "REJECT" else "green")
    ui.insight(INSIGHT)
    return {**{r.key: r.primary for r in inv}, **{d.id: d.decision for d in disp}}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["asset_mgmt"]
    inv, disp = evaluate_all(data, policies)
    qs: list = []
    cmdb = {a.get("asset_id"): a for a in data.get("cmdb", [])}
    scan_macs = {_mac(h.get("mac")) for h in data.get("scan", [])}
    for r in inv:
        a = cmdb.get(r.key)
        ctx = (f"today=day {data['today']}, MISSING after {cfg['missing_after_days']} days\n"
               + (f"CMDB: {a}\nin today's scan: {'yes' if _mac(a.get('mac')) in scan_macs else 'no'}" if a
                  else f"scan host {r.hostname} at {r.key[5:]} (no CMDB record with its MAC)"))
        if len(r.findings) == 1:
            qs.append(Question(prompt=f"{r.key} ({r.hostname}): what is the inventory finding?", context=ctx,
                               choices=FINDINGS, answer=r.primary, explanation="; ".join(r.reasons), objective="4.2"))
    for d, req in zip(disp, data.get("disposals", [])):
        ctx = ", ".join(f"{k}={v}" for k, v in req.items() if k != "id") + f"\ntoday=day {data['today']}"
        qs.append(Question(prompt=f"{d.id}: approve or reject this disposal request?", context=ctx,
                           choices=DECISIONS, answer=d.decision, explanation="; ".join(d.reasons), objective="4.2"))
        if len(d.rules) == 1:
            qs.append(Question(prompt=f"{d.id}: which rule rejects it?", context=ctx,
                               choices=sorted(RULES.values()), answer=RULES[d.rules[0]],
                               explanation=d.reasons[0], objective="4.2"))
        if d.required_level:
            qs.append(Question(prompt=f"{d.id}: what is the MINIMUM sanitization level required?",
                               context=f"classification={req.get('classification')}, destination={req.get('destination')}",
                               choices=list(cfg["sanitization_levels"]), answer=d.required_level,
                               explanation=f"min_level[{req.get('classification')}][{req.get('destination')}] = "
                                           f"{d.required_level}", objective="4.2"))
    specific = sorted(m for m in cfg["methods"] if m not in cfg["sanitization_levels"])
    for media in ("ssd", "hdd", "mobile"):
        ok = methods_for(media, "purge", cfg)
        if ok:
            qs.append(Question(prompt=f"Which of these is a PURGE-level (not Clear, not Destroy) "
                                      f"method for {media.upper()} media?",
                               choices=choices_with(ok[0], specific, exclude=ok, key=media), answer=ok[0],
                               explanation=f"purge-level methods valid on {media}: {', '.join(ok)}", objective="4.2"))
    terms = sorted(cfg["glossary"])
    for term in terms:
        qs.append(Question(prompt=f"Which term is this? \"{cfg['glossary'][term]}\"",
                           choices=choices_with(term, terms, k=3, key=term), answer=term,
                           explanation=f"{term}: {cfg['glossary'][term]}",
                           objective="2.1" if term == "shadow IT" else "4.2"))
    return qs
