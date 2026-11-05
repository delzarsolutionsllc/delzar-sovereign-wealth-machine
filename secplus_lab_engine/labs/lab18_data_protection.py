"""
Lab 18 — Data Protection & DLP Gate
===================================

Security+ SY0-701 objectives
----------------------------
* 3.3  Protect data: data types (regulated, trade secret, intellectual
       property, legal, financial, human/non-human readable), classifications
       (public, private, sensitive, confidential, restricted, critical), states
       of data (at rest, in transit, in use), data sovereignty, geolocation,
       methods (geographic restrictions, encryption, hashing, masking,
       tokenization, obfuscation, segmentation, permission restrictions).
* 4.5  Data loss prevention (DLP) as an enterprise security capability.
* 5.4  Privacy: data subject, data sovereignty and local/regional rules.

How it works
------------
1. **Detect**: policy regexes scan each sample record for SSNs, payment card
   numbers (PAN, kept only if the Luhn check passes, so a random 16-digit
   order number is NOT flagged), health record IDs, emails, phones, passwords,
   API keys and trade-secret / IP / legal markings. Each detector maps to a
   data type and a classification. Records are the data BEFORE the flow's
   stated protection is applied.
2. **Classify**: effective classification = the highest of the declared label
   and every detected classification. An unknown declared label → BLOCK.
3. **Gate** each outbound flow, deny by default:
   * destination missing/unapproved, destination type not allowed for the
     classification, or region not allowed (geographic restriction) → BLOCK;
   * regulated personal data whose origin region has a sovereignty rule may
     only be processed in that rule's regions → BLOCK;
   * per data type × state, the applied protection must be an accepted method
     (an encrypted channel counts as encryption in transit). A miss is either
     a required fix (ALLOW_WITH_PROTECTION) or a hard BLOCK (e.g. passwords
     stored with reversible encryption instead of a salted hash).

Run it
------
    python main.py lab 18
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

TITLE = "Lab 18 — Data Protection & DLP Gate"
OBJECTIVES = ("SY0-701 3.3 Data types, classifications, states, sovereignty, protection methods"
              " · 4.5 DLP · 5.4 Data sovereignty / privacy")
DECISIONS = ["ALLOW", "ALLOW_WITH_PROTECTION", "BLOCK"]
STATES = ["at_rest", "in_transit", "in_use"]
BLOCK_RULES = {
    "classification": "unknown classification label",
    "destination": "destination missing or not approved",
    "dest_type": "destination type not allowed for the classification",
    "region": "region not allowed (geographic restriction)",
    "sovereignty": "data sovereignty rule for the data subjects' region",
    "state": "unknown state of data",
    "protection": "protection method not acceptable for this data type and state",
}


@dataclass
class Finding:
    detector: str
    label: str
    data_type: str
    classification: str
    match: str


@dataclass
class FlowDecision:
    id: str
    decision: str
    classification: str
    findings: list[Finding] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    required: list[str] = field(default_factory=list)     # protection still needed (ALLOW_WITH_PROTECTION)
    block_rules: list[str] = field(default_factory=list)  # BLOCK_RULES keys that fired
    unmet: list[str] = field(default_factory=list)        # data types whose protection rule is not met

    @property
    def data_types(self) -> list[str]:
        return sorted({f.data_type for f in self.findings})


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def detect(text: str, detectors: dict) -> list[Finding]:
    out = []
    for name, d in detectors.items():
        for m in re.finditer(d["pattern"], text):
            value = m.group(0)
            if d.get("validator") == "luhn":
                digits = re.sub(r"\D", "", value)
                if not (13 <= len(digits) <= 19 and luhn_ok(digits)):
                    continue                                  # random number, not a card: not flagged
            out.append(Finding(name, d["label"], d["data_type"], d["classification"], value))
    return out


def mask(value: str, keep: int = 4) -> str:
    return "*" * max(len(value) - keep, 0) + value[-keep:]


def evaluate(flow: dict, cfg: dict) -> FlowDecision:
    rank = cfg["classification_rank"]
    findings = [f for rec in flow.get("records", []) for f in detect(rec, cfg["detectors"])]
    reasons, required, rules, unmet = [], [], [], []
    declared = flow.get("declared_classification")
    if declared not in rank:
        rules.append("classification")
        reasons.append(f"declared classification '{declared}' is unknown: unlabelled data is blocked by default")
    labels = [c for c in [declared, *(f.classification for f in findings)] if c in rank]
    cls = max(labels, key=rank.get) if labels else "unknown"
    if declared in rank and rank.get(cls, 0) > rank[declared]:
        top = max(findings, key=lambda f: rank[f.classification])
        reasons.append(f"content found ({top.label}) raises the label from {declared} to {cls}")

    dest = flow.get("destination") or {}
    dtype, region = dest.get("type"), dest.get("region")
    if not dest.get("approved"):
        rules.append("destination")
        reasons.append(f"destination {dtype or '(missing)'} is not an approved destination")
    if cls in rank:
        if dtype not in cfg["allowed_destinations"][cls]:
            rules.append("dest_type")
            reasons.append(f"{cls} data may not go to a '{dtype}' destination")
        regions = cfg["allowed_regions"][cls]
        if "*" not in regions and region not in regions:
            rules.append("region")
            reasons.append(f"{cls} data may only be in {'/'.join(regions)}, not region '{region}'")
    origin = flow.get("data_origin")
    allowed_here = cfg["sovereignty"].get(origin) if origin else None
    if allowed_here and "regulated" in {f.data_type for f in findings} and region not in allowed_here:
        rules.append("sovereignty")
        reasons.append(f"personal data of {origin} data subjects must stay in {'/'.join(allowed_here)} "
                       f"(data sovereignty), not '{region}'")

    state = flow.get("state")
    applied = set(flow.get("protection") or [])
    if state == "in_transit" and flow.get("encrypted_channel"):
        applied.add("encryption")
    if state not in STATES:
        rules.append("state")
        reasons.append(f"state of data '{state}' is unknown (expected at_rest/in_transit/in_use)")
    else:
        for dt in sorted({f.data_type for f in findings}):
            rule = cfg["protection_rules"].get(dt, {}).get(state)
            if rule is None:
                rules.append("protection")
                reasons.append(f"no protection rule for {dt} data {state}: blocked by default")
            elif not applied & set(rule["accept"]):
                unmet.append(dt)
                have = ", ".join(sorted(applied)) or "none"
                text = f"{dt} data {state} has protection ({have}); needs {' or '.join(rule['accept'])}: {rule['method']}"
                if rule["action"] == "BLOCK":
                    rules.append("protection")
                    reasons.append(text)
                else:
                    required.append(rule["method"])
                    reasons.append(text)
    rules = list(dict.fromkeys(rules))
    decision = "BLOCK" if rules else "ALLOW_WITH_PROTECTION" if required else "ALLOW"
    if decision == "ALLOW":
        reasons.append(f"{cls} data to an approved {dtype} in {region}; protection meets policy")
    return FlowDecision(flow.get("id", "?"), decision, cls, findings, reasons, required, rules, unmet)


def evaluate_all(data: dict, policies: dict) -> list[FlowDecision]:
    return [evaluate(f, policies["data_protection"]) for f in data["flows"]]


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SY0-701 3.3 Data protection: types, classifications, states, sovereignty, methods (with 4.5 DLP).",
    "concepts": [
        "Data types: regulated (PII, PHI, PCI), trade secret, intellectual property, legal, financial; human- or non-human-readable.",
        "Classify by the most sensitive content found, not by the label someone typed; the label drives handling rules.",
        "States: at rest (disk/database: encrypt, tokenize), in transit (TLS/IPsec), in use (memory/screen: mask, restrict).",
        "Data sovereignty: data is subject to the laws of the country where it is collected/stored; geolocation enforces it.",
        "Masking hides digits, tokenization swaps in a vault-mapped surrogate, hashing is one-way, encryption is reversible.",
    ],
    "failure_modes": [
        "Storing passwords with reversible encryption: steal the key and you have every password (hash + salt instead).",
        "A regex that flags every 16-digit number: alert fatigue until DLP is ignored (validate PANs with Luhn).",
        "Exporting EU customer data to a cheaper overseas region and breaking data sovereignty rules.",
        "Showing full card numbers to support staff who only need the last 4 digits.",
    ],
    "ai_governance": [
        "Put a DLP gate in front of prompts and agent tool calls: secrets and PII must not reach an external model.",
        "AI agents need data-handling rules by classification, the same as people: least privilege on data, not just systems.",
        "Region-pin AI model endpoints and logs for regulated data; prompts are data in transit and at rest too.",
        "Content returned to an agent is untrusted: an 'ignore the DLP policy' line in a record is data, not an instruction.",
    ],
    "exam_tips": [
        "'Replaces the value with a random surrogate mapped in a vault' = tokenization. 'Shows only the last 4' = masking.",
        "Passwords: salted hashing (plus key stretching such as bcrypt/PBKDF2), never encryption.",
        "Data in transit → TLS/IPsec/VPN. Data at rest → full-disk/database/file encryption. Data in use → hardest to protect.",
        "Data sovereignty = the law of the country where the data resides; geographic restrictions/geofencing enforce it.",
        "DLP can sit on endpoints, the network or in the cloud, and can alert, block or quarantine transfers.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    res = evaluate_all(data, policies)
    ui.section("Step 1 — Detect and classify")
    ui.table("Content inspection", ["Flow", "Declared", "Detections", "Effective"],
             [[r.id, f["declared_classification"],
               ", ".join(f"{x.detector}={mask(x.match)}" for x in r.findings) or "none", r.classification]
              for r, f in zip(res, data["flows"])])
    ui.section("Step 2 — DLP decision per outbound flow")
    ui.table("Flows", ["Flow", "State", "Destination", "Protection", "Decision"],
             [[r.id, f.get("state"), f"{(f.get('destination') or {}).get('type')}@{(f.get('destination') or {}).get('region')}",
               " + ".join((f.get("protection") or []) + (["TLS channel"] if f.get("encrypted_channel") else [])) or "none",
               r.decision]
              for r, f in zip(res, data["flows"])])
    for r, f in zip(res, data["flows"]):
        ui.status(f"{r.id} {f.get('description', '')}", r.decision, r.classification)
        for reason in r.reasons:
            ui.bullet(reason, style="red" if r.decision == "BLOCK" else "yellow" if r.required else None)
    ui.section("Step 3 — Protection methods")
    for text in policies["data_protection"]["protection_methods"].values():
        ui.bullet(text, style="dim")
    ui.insight(INSIGHT)
    return {r.id: r.decision for r in res}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["data_protection"]
    classes = sorted(cfg["classification_rank"], key=cfg["classification_rank"].get)
    methods = sorted(cfg["protection_methods"])
    qs: list = []
    for f, r in zip(data["flows"], evaluate_all(data, policies)):
        d = f.get("destination") or {}
        ctx = (f"{r.id}: {f.get('description', '')}\nrecords={f.get('records')}\n"
               f"declared={f.get('declared_classification')} state={f.get('state')} "
               f"destination={d.get('type')}@{d.get('region')} approved={d.get('approved')} "
               f"origin={f.get('data_origin')} encrypted_channel={f.get('encrypted_channel')} "
               f"protection={f.get('protection') or 'none'}")
        qs.append(Question(f"{r.id}: what does the DLP gate decide?", DECISIONS, r.decision,
                           "; ".join(r.reasons), "3.3", ctx))
        if r.classification in classes:
            qs.append(Question(f"{r.id}: what is the effective classification?", classes, r.classification,
                               f"highest of declared '{f.get('declared_classification')}' and detections "
                               f"{[x.classification for x in r.findings] or 'none'}", "3.3", ctx))
        if r.block_rules:
            ans = BLOCK_RULES[r.block_rules[0]]
            others = [BLOCK_RULES[k] for k in r.block_rules[1:]]
            qs.append(Question(f"{r.id}: which rule blocks this flow?",
                               choices_with(ans, BLOCK_RULES.values(), exclude=others, key=r.id), ans,
                               "; ".join(r.reasons), "5.4" if ans == BLOCK_RULES["sovereignty"] else "3.3", ctx))
        if r.unmet:
            dt = r.unmet[0]
            rule = cfg["protection_rules"][dt][f["state"]]
            ans = rule["accept"][0]
            qs.append(Question(f"{r.id}: which protection method would satisfy policy for the {dt} data?",
                               choices_with(ans, methods, exclude=rule["accept"][1:], key=r.id + dt), ans,
                               f"{dt} {f['state']}: accepted {rule['accept']} — {rule['method']}", "3.3", ctx))
        pans = [x for x in re.findall(cfg["detectors"]["payment_card"]["pattern"], " ".join(f.get("records", [])))
                if 13 <= len(re.sub(r"\D", "", x)) <= 19]
        if pans:
            flagged = any(x.match == pans[0] for x in r.findings)
            ans = "Yes, it passes the Luhn check" if flagged else "No, it fails the Luhn check"
            qs.append(Question(f"{r.id}: is '{pans[0]}' flagged as a payment card number?",
                               ["Yes, it passes the Luhn check", "No, it fails the Luhn check",
                                "Yes, any 16-digit number is a PAN", "No, card numbers are never inspected"],
                               ans, "the detector keeps a 13-19 digit match only when its Luhn checksum is valid",
                               "4.5", ctx))
    for name, definition in sorted(cfg["protection_methods"].items()):
        qs.append(Question(f"Which protection method is this? \"{definition.split(':', 1)[1].strip()}\"",
                           methods, name, definition, "3.3"))
    return qs
