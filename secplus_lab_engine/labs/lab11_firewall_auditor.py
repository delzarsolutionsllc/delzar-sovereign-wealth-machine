"""
Lab 11 — Firewall Rule & Network Segmentation Auditor
=====================================================

Security+ SY0-701 objectives
----------------------------
* 3.2  Secure enterprise infrastructure: security zones, attack surface,
       device placement (DMZ/screened subnet), firewalls, ACLs, fail-closed.
* 4.5  Modify enterprise capabilities: firewall rules, access lists,
       ports/protocols, screened subnets, implicit deny.

How rules are modelled
----------------------
A rule ``{id, action, src, dst, proto, ports, log, comment}`` matches a set of
traffic. ``src``/``dst`` are a zone name, a CIDR or ``any``; zones (and their
CIDRs) come from the ruleset. Because each rule is a *set*, the auditor
can prove relationships between rules:

* **SHADOWED**: an earlier rule with the OPPOSITE action fully covers this
  one, so it can never take effect (e.g. a deny after a broader allow).
* **REDUNDANT**: an earlier rule with the SAME action fully covers it.
* **ANY_ANY**: allow any source → any destination on any port.
* **ANY_SERVICE**: allow on every port (not least privilege).
* **SEGMENTATION_VIOLATION**: allowed zone-to-zone flow not in the policy
  (e.g. internet → internal, guest → internal).
* **INSECURE_PROTOCOL**: cleartext protocols anywhere; remote-admin ports
  from untrusted zones.
* **OVERLY_BROAD**: huge CIDR (e.g. /8) spanning several zones.
* **MISSING_DEFAULT_DENY**: no explicit, logged ``deny any any`` at the end.
* **NO_LOGGING / UNDOCUMENTED**: deny without logging; rule without a comment.

Score = 100 − Σ penalties, then grade A–F, with a fix for every finding.

Run it
------
    python main.py lab 11
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

TITLE = "Lab 11 — Firewall Rule & Network Segmentation Auditor"
OBJECTIVES = "SY0-701 3.2 Secure infrastructure (zones, screened subnet) · 4.5 Firewall rules & ACLs"

ANY = "*"
FIXES = {
    "ANY_ANY": "Delete it. Replace with specific source, destination and service rules.",
    "ANY_SERVICE": "Restrict to the exact ports the business flow needs (least privilege).",
    "SEGMENTATION_VIOLATION": "Remove the flow, or route it through an approved path (jump host, proxy, DMZ service).",
    "SHADOWED": "Move it ABOVE the broader rule that hides it, or delete it if it is no longer needed.",
    "REDUNDANT": "Delete the duplicate. Fewer rules = smaller attack surface and easier audits.",
    "INSECURE_PROTOCOL": "Replace with an encrypted equivalent (SSH, SFTP, SNMPv3) or a VPN/jump host with MFA.",
    "OVERLY_BROAD": "Narrow the CIDR to the actual hosts or subnet that need access.",
    "MISSING_DEFAULT_DENY": "Add a final 'deny any any any' rule with logging (explicit implicit-deny).",
    "NO_LOGGING": "Enable logging so blocked attempts reach the SIEM.",
    "UNDOCUMENTED": "Add a comment/owner/ticket reference so the rule can be reviewed and recertified.",
}


@dataclass
class Finding:
    rule_id: int | None
    code: str
    penalty: int
    detail: str
    fix: str


@dataclass
class Audit:
    name: str
    score: int
    grade: str
    findings: list[Finding] = field(default_factory=list)

    def codes_for(self, rule_id: int) -> set[str]:
        return {f.code for f in self.findings if f.rule_id == rule_id}


# --------------------------------------------------------------------------- #
# Set algebra over rules
# --------------------------------------------------------------------------- #
def parse_ports(spec) -> list[tuple[int, int]]:
    """'any' | 443 | '80,443' | '1000-2000' → list of (lo, hi)."""
    s = str(spec).strip().lower()
    if s in ("any", "*", ""):
        return [(0, 65535)]
    out = []
    for part in s.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-")
            out.append((int(lo), int(hi)))
        else:
            out.append((int(part), int(part)))
    return out


def resolve(spec: str, zones: dict) -> list[tuple[str, ipaddress.IPv4Network]]:
    """Endpoint spec → list of (zone, network). 'internet' covers only public space."""
    if str(spec).lower() in ("any", "*"):
        return [(ANY, ipaddress.ip_network("0.0.0.0/0"))]
    if spec in zones:
        return [(spec, ipaddress.ip_network(c)) for c in zones[spec]] if zones[spec] else \
               [(spec, ipaddress.ip_network("0.0.0.0/0"))]
    net = ipaddress.ip_network(spec, strict=False)
    hits = []
    for z, cidrs in zones.items():
        for c in cidrs:
            zn = ipaddress.ip_network(c)
            if net.subnet_of(zn):
                return [(z, net)]                 # inside one zone
            if zn.subnet_of(net):
                hits.append((z, zn))              # CIDR spans this zone
    return hits or [("internet", net)]


def zones_of(spec: str, zones: dict) -> set[str]:
    return set(zones) if str(spec).lower() in ("any", "*") else {z for z, _ in resolve(spec, zones)}


def endpoint_covers(a: str, b: str, zones: dict) -> bool:
    ra, rb = resolve(a, zones), resolve(b, zones)
    if ra[0][0] == ANY:
        return True
    if rb[0][0] == ANY:
        return False
    return all(any(bz == az and bn.subnet_of(an) for az, an in ra) for bz, bn in rb)


def ports_cover(a, b) -> bool:
    return all(any(alo <= blo and bhi <= ahi for alo, ahi in parse_ports(a)) for blo, bhi in parse_ports(b))


def proto_covers(a: str, b: str) -> bool:
    return a == "any" or a == b


def rule_covers(a: dict, b: dict, zones: dict) -> bool:
    return (proto_covers(a.get("proto", "any"), b.get("proto", "any")) and ports_cover(a["ports"], b["ports"])
            and endpoint_covers(a["src"], b["src"], zones) and endpoint_covers(a["dst"], b["dst"], zones))


def is_default_deny(r: dict) -> bool:
    return (r["action"] == "deny" and str(r["src"]).lower() == "any" and str(r["dst"]).lower() == "any"
            and parse_ports(r["ports"]) == [(0, 65535)] and r.get("proto", "any") == "any")


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #
def flow_allowed(src_z: str, dst_z: str, ports, policy: dict) -> tuple[bool, str]:
    if src_z == dst_z:
        return True, "intra-zone"
    for f in policy["never_allowed"]:
        if f["from"] == src_z and f["to"] == dst_z:
            return False, f"{src_z} → {dst_z} is never allowed ({f['why']})"
    for f in policy["allowed_flows"]:
        if f["from"] == src_z and f["to"] in (dst_z, ANY) and ports_cover(f["ports"], ports):
            return True, "policy flow"
    return False, f"{src_z} → {dst_z} on ports {ports} is not an approved flow"


def audit(ruleset: dict, cfg: dict) -> Audit:
    zones, rules, w = ruleset["zones"], ruleset["rules"], cfg["weights"]
    findings: list[Finding] = []

    def add(rid, code, detail):
        findings.append(Finding(rid, code, w[code], detail, FIXES[code]))

    untrusted = set(cfg["untrusted_zones"])
    for i, r in enumerate(rules):
        rid = r["id"]
        if is_default_deny(r):
            if not r.get("log"):
                add(rid, "NO_LOGGING", "default deny does not log")
            continue
        # shadowed / redundant: first earlier rule that fully covers this one
        for prev in rules[:i]:
            if rule_covers(prev, r, zones):
                code = "REDUNDANT" if prev["action"] == r["action"] else "SHADOWED"
                add(rid, code, f"fully covered by earlier rule {prev['id']} ({prev['action']}) — "
                               + ("never takes effect" if code == "SHADOWED" else "adds nothing"))
                break
        if r["action"] == "allow":
            any_ports = parse_ports(r["ports"]) == [(0, 65535)]
            if str(r["src"]).lower() == "any" and str(r["dst"]).lower() == "any" and any_ports:
                add(rid, "ANY_ANY", "allows any source to any destination on any port")
            elif any_ports:
                add(rid, "ANY_SERVICE", f"allows every port from {r['src']} to {r['dst']}")
            src_z, dst_z = zones_of(r["src"], zones), zones_of(r["dst"], zones)
            # "never allowed" flows first: they are the dangerous ones (e.g. internet → internal)
            bad = sorted({why for s in src_z for d in dst_z
                          for ok, why in [flow_allowed(s, d, r["ports"], cfg["segmentation_policy"])] if not ok},
                         key=lambda why: ("never allowed" not in why, why))
            if bad:
                add(rid, "SEGMENTATION_VIOLATION", "; ".join(bad[:3]) + (f" (+{len(bad) - 3} more)" if len(bad) > 3 else ""))
            for lo, hi in parse_ports(r["ports"]):
                if (lo, hi) == (0, 65535):
                    continue
                for p in range(lo, min(hi, lo + 1024) + 1):
                    name = cfg["cleartext_ports"].get(str(p))
                    if name:
                        add(rid, "INSECURE_PROTOCOL", f"permits {name} (port {p}), which sends credentials in cleartext")
                    name = cfg["remote_admin_ports"].get(str(p))
                    if name and src_z & untrusted:
                        add(rid, "INSECURE_PROTOCOL", f"exposes {name} (port {p}) to untrusted zone(s) {sorted(src_z & untrusted)}")
            for spec in (r["src"], r["dst"]):
                if str(spec).lower() not in ("any", "*") and spec not in zones:
                    net = ipaddress.ip_network(spec, strict=False)
                    if net.prefixlen <= cfg["broad_prefix_max"]:
                        add(rid, "OVERLY_BROAD", f"{spec} (/{net.prefixlen}) spans {sorted(zones_of(spec, zones))}")
        elif not r.get("log"):
            add(rid, "NO_LOGGING", "deny rule does not log, so blocked attempts are invisible")
        if not str(r.get("comment", "")).strip():
            add(rid, "UNDOCUMENTED", "no comment/owner/ticket")

    if not rules or not is_default_deny(rules[-1]):
        add(None, "MISSING_DEFAULT_DENY", "the rule set does not end with an explicit 'deny any any any'")

    score = max(0, 100 - sum(f.penalty for f in findings))
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    return Audit(ruleset["name"], score, grade, findings)


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SY0-701 3.2 secure infrastructure (zones, screened subnets) and 4.5 firewall rules / ACLs.",
    "concepts": [
        "Rules are evaluated top-down, first match wins, so ORDER is part of the security policy.",
        "Implicit deny: anything not explicitly allowed is blocked. Make it explicit and logged.",
        "Screened subnet (DMZ): internet → DMZ on published ports only; DMZ → internal only to specific back-end services.",
        "Least privilege for networks: specific source, destination, protocol and port, never 'any' for convenience.",
    ],
    "failure_modes": [
        "A 'temporary' any/any rule added during troubleshooting and never removed.",
        "A new deny rule appended to the bottom, below an allow that already matches the traffic (shadowed).",
        "RDP or SMB opened to the internet 'for a vendor'.",
        "Rule sets nobody can explain because rules carry no owner, ticket or comment.",
    ],
    "ai_governance": [
        "An AI firewall agent should submit proposed rules to this audit + change control (Lab 4) before deployment.",
        "Block agents from creating any/any or segmentation-violating rules (Lab 5 OVERLY_PERMISSIVE_RULE).",
        "Agents must never edit the default-deny or other immutable rules (Lab 5 rule 0).",
        "Require every agent-created rule to carry a ticket reference and an expiry for temporary access.",
    ],
    "exam_tips": [
        "'Rule never matches because an earlier rule catches the traffic' = shadowed rule.",
        "'Last rule of an ACL that blocks everything else' = implicit deny.",
        "Screened subnet = DMZ; place public-facing servers there, not on the internal network.",
        "Fail-closed (secure) vs fail-open (available): know which a firewall/IPS should use for the scenario.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    cfg = policies["firewall_audit"]
    out = {}
    for rs in data["rulesets"]:
        a = audit(rs, cfg)
        out[a.name] = f"{a.score} ({a.grade})"
        ui.section(f"{a.name}  →  score {a.score}/100  (grade {a.grade})")
        ui.table("Rules (top-down, first match wins)", ["#", "Action", "Src", "Dst", "Proto", "Ports", "Log", "Comment"],
                 [[r["id"], r["action"].upper(), r["src"], r["dst"], r.get("proto", "any"), r["ports"],
                   "yes" if r.get("log") else "no", r.get("comment", "")] for r in rs["rules"]])
        if a.findings:
            ui.table("Findings", ["Rule", "Code", "Penalty", "Detail", "Fix"],
                     [[f.rule_id if f.rule_id is not None else "-", f.code, f"-{f.penalty}", f.detail, f.fix]
                      for f in a.findings])
        else:
            ui.bullet("No findings: least-privilege, segmented, explicit default deny.", style="green")
    ui.insight(INSIGHT)
    return out


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["firewall_audit"]
    codes = sorted(FIXES)
    qs: list = []
    for rs in data["rulesets"]:
        a = audit(rs, cfg)
        zones = ", ".join(f"{z}={v or ['public']}" for z, v in rs["zones"].items())
        for i, r in enumerate(rs["rules"]):
            present = a.codes_for(r["id"])
            if is_default_deny(r) and not present:
                continue
            # answer: the most severe issue on this rule (or none)
            answer = max(present, key=lambda c: (cfg["weights"][c], c)) if present else "No issue"
            pool = codes + ["No issue"]
            ctx_rules = "\n".join(f"  {x['id']}: {x['action']} {x['src']} → {x['dst']} {x.get('proto', 'any')}/{x['ports']}"
                                  f"{' log' if x.get('log') else ''} \"{x.get('comment', '')}\"" for x in rs["rules"][: i + 1])
            qs.append(Question(
                prompt=f"{rs['name']} rule {r['id']}: what is its MOST severe problem?",
                context=f"Zones: {zones}\nRules so far:\n{ctx_rules}",
                choices=choices_with(answer, pool, exclude=present | ({"No issue"} if present else set()),
                                     key=f"{rs['name']}{r['id']}"),
                answer=answer,
                explanation="; ".join(f"{f.code}: {f.detail}" for f in a.findings if f.rule_id == r["id"])
                            or "Specific, approved, documented flow.",
                objective="4.5" if answer in ("SHADOWED", "REDUNDANT", "NO_LOGGING", "UNDOCUMENTED", "No issue") else "3.2"))
        qs.append(Question(prompt=f"{rs['name']}: does it end with an explicit default deny?",
                           choices=["Yes", "No"],
                           answer="No" if any(f.code == "MISSING_DEFAULT_DENY" for f in a.findings) else "Yes",
                           explanation="An explicit, logged 'deny any any any' makes implicit deny visible and auditable.",
                           objective="4.5"))
    return qs
