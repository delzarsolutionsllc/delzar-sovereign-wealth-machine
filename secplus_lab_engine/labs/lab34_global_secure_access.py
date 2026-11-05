"""
Lab 34 — Global Secure Access: Traffic Forwarding & Private Access
==================================================================

SC-300 objectives
-----------------
* 2.4  Implement Global Secure Access: traffic forwarding profiles
       (Microsoft traffic, Internet Access, Private Access), the Global Secure
       Access client, Microsoft Entra Private Access (Quick Access and per-app
       enterprise applications, application segments, connector groups) and
       Microsoft Entra Internet Access (web content filtering, security profiles).
* 2.2  Microsoft Entra Conditional Access: security profiles reach users
       through a Conditional Access session control on policies that target
       "All internet resources with Global Secure Access".

How it works
------------
Global Secure Access is Microsoft's Security Service Edge (SSE). The client on
the device acquires traffic, the forwarding profiles decide which traffic goes
into the tunnel, and the cloud service then enforces Private Access or
Internet Access rules. This engine evaluates one traffic flow (user, device,
destination, port, protocol) at a time, in this order:

1. **Identity and client**: an unknown user, an unknown device, or a device
   without the Global Secure Access client (a missing flag counts as "not
   installed") → BYPASSED_NOT_FORWARDED. Traffic that is not acquired is not
   protected, and private resources are unreachable from outside.
2. **Classify the destination**: Microsoft traffic (policy list of Microsoft
   365 / Entra endpoints) first; then private (covered by any application
   segment, an RFC 1918 address or a private DNS suffix); else internet. A
   flow with no destination gets BLOCKED_NO_SEGMENT (deny by default).
3. **Forwarding profile**: the profile for that traffic type must be enabled
   and assigned to the user (directly, through a group, or "All users"),
   otherwise BYPASSED_NOT_FORWARDED.
4. **Microsoft traffic** → TUNNELED_MICROSOFT.
5. **Private traffic**: find an application segment that matches destination
   (FQDN, wildcard FQDN, IP or CIDR) AND port AND protocol, checking per-app
   enterprise applications before Quick Access. No segment anywhere (or a
   missing port/protocol) → BLOCKED_NO_SEGMENT. A segment exists only in apps
   the user is not assigned to → BLOCKED_NO_SEGMENT. The app's connector group
   is missing or has no healthy connector → BLOCKED_CONNECTOR_UNAVAILABLE.
   Otherwise TUNNELED_PRIVATE_ACCESS (with a warning below the redundancy
   minimum).
6. **Internet traffic**: security profiles linked by *enabled* Conditional
   Access policies that include the user and target "All internet resources
   with Global Secure Access" are evaluated in priority order (lowest number
   first), then the baseline profile. Inside a profile, linked web content
   filtering policies run in link-priority order and the first rule that
   matches (FQDN or web category) decides allow or block. Report-only policies
   are logged, never enforced. A missing security profile → block. No rule
   matched: an uncategorised destination gets the policy's
   ``unknown_category_action`` (block, deny by default), anything else the
   default action (allow) → TUNNELED_INTERNET_ALLOWED or BLOCKED_BY_WEB_FILTER.

A **health check** then flags connector groups with fewer than the minimum
healthy connectors, overlapping application segments, and forwarding or
security profiles that reach nobody.

Run it
------
    python main.py --course sc300 lab 34
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

TITLE = "Lab 34 — Global Secure Access: Traffic Forwarding & Private Access"
OBJECTIVES = "SC-300 2.4 Implement Global Secure Access · 2.2 Conditional Access"
COURSES = ("sc300",)

FLOW_OUTCOMES = ["TUNNELED_MICROSOFT", "TUNNELED_INTERNET_ALLOWED", "BLOCKED_BY_WEB_FILTER",
                 "TUNNELED_PRIVATE_ACCESS", "BLOCKED_NO_SEGMENT", "BLOCKED_CONNECTOR_UNAVAILABLE",
                 "BYPASSED_NOT_FORWARDED"]
RULES = ["identity", "client", "destination", "profile_disabled", "profile_assignment", "microsoft_profile",
         "segment_match", "app_assignment", "connector_health", "missing_security_profile", "web_filter_rule",
         "unknown_category", "default_action"]
HEALTH_TYPES = ["CONNECTOR_GROUP_UNHEALTHY", "SEGMENT_OVERLAP", "PROFILE_UNASSIGNED"]
TRAFFIC_TYPES = ["microsoft", "private", "internet"]
PROFILE_NAMES = {"microsoft": "Microsoft traffic profile", "internet": "Internet Access profile",
                 "private": "Private Access profile"}


@dataclass
class FlowResult:
    id: str
    user: str
    destination: str
    traffic: str
    outcome: str
    rule: str
    app: str | None = None
    reasons: list[str] = field(default_factory=list)


@dataclass
class HealthFinding:
    type: str
    target: str
    severity: str
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Matching helpers (pure)
# --------------------------------------------------------------------------- #
def _ip(value):
    try:
        return ipaddress.ip_address(str(value))
    except ValueError:
        return None


def _net(value):
    try:
        return ipaddress.ip_network(str(value), strict=False)
    except ValueError:
        return None


def fqdn_match(pattern: str, host: str) -> bool:
    """Case-insensitive. '*.corp.example' matches any subdomain but not the apex 'corp.example'
    (generic wildcard behaviour; check Microsoft Learn for the exact product rule)."""
    p, h = str(pattern).lower().rstrip("."), str(host).lower().rstrip(".")
    if p.startswith("*."):
        return h.endswith(p[1:]) and h != p[2:]
    return p == h


def dest_matches(seg_dest: str, host: str) -> bool:
    """A segment destination is an IP/CIDR (matches IP flows only) or an FQDN/wildcard (matches names only)."""
    net, addr = _net(seg_dest), _ip(host)
    if net is not None:
        return addr is not None and addr.version == net.version and addr in net
    return addr is None and fqdn_match(seg_dest, host)


def parse_ports(ports) -> list[tuple[int, int]]:
    out = []
    for p in ports or []:
        s = str(p).strip()
        try:
            lo, _, hi = s.partition("-")
            lo_i, hi_i = int(lo), int(hi or lo)
        except ValueError:
            continue  # malformed port entry matches nothing (deny by default)
        out.append((min(lo_i, hi_i), max(lo_i, hi_i)))
    return out


def port_in(port, ports) -> bool:
    try:
        n = int(port)
    except (TypeError, ValueError):
        return False
    return any(lo <= n <= hi for lo, hi in parse_ports(ports))


def protocols_of(seg: dict) -> set[str]:
    raw = seg.get("protocol", "")
    items = raw if isinstance(raw, list) else str(raw).split(",")
    return {str(x).strip().lower() for x in items if str(x).strip()}


def segment_label(seg: dict) -> str:
    return f"{seg.get('destination')}:{','.join(str(p) for p in seg.get('ports', []))}/" \
           f"{'+'.join(sorted(protocols_of(seg))) or '?'}"


def destinations_overlap(a: str, b: str) -> bool:
    na, nb = _net(a), _net(b)
    if na is not None and nb is not None:
        return na.version == nb.version and na.overlaps(nb)
    if na is not None or nb is not None:
        return False  # IP vs name: cannot tell without DNS, so not reported (generic simplification)
    a, b = a.lower(), b.lower()
    if a == b:
        return True
    if a.startswith("*.") and b.startswith("*."):
        return a[1:].endswith(b[1:]) or b[1:].endswith(a[1:])
    return (a.startswith("*.") and fqdn_match(a, b)) or (b.startswith("*.") and fqdn_match(b, a))


def segments_overlap(a: dict, b: dict) -> bool:
    if not destinations_overlap(str(a.get("destination", "")), str(b.get("destination", ""))):
        return False
    if not protocols_of(a) & protocols_of(b):
        return False
    return any(alo <= bhi and blo <= ahi for alo, ahi in parse_ports(a.get("ports"))
               for blo, bhi in parse_ports(b.get("ports")))


# --------------------------------------------------------------------------- #
# Directory helpers
# --------------------------------------------------------------------------- #
def _users(data: dict) -> set[str]:
    return {str(u.get("upn", "")).lower() for u in data.get("users", []) if u.get("upn")}


def groups_of(upn: str, data: dict) -> set[str]:
    upn = upn.lower()
    return {g for g, members in data.get("groups", {}).items() if upn in {m.lower() for m in members}}


def targets(entries, upn: str, data: dict, cfg: dict) -> bool:
    """Is the user in an assignment list (UPNs, group names, or the 'All users' keyword)?"""
    if not upn or upn.lower() not in _users(data):
        return False
    entries = list(entries or [])
    if cfg["all_users_keyword"] in entries:
        return True
    return upn.lower() in {str(e).lower() for e in entries} or bool(groups_of(upn, data) & set(entries))


def members(entries, data: dict, cfg: dict) -> set[str]:
    return {u for u in _users(data) if targets(entries, u, data, cfg)}


def healthy_connectors(group: dict | None, cfg: dict) -> int:
    if not group:
        return 0
    return sum(c.get("status") in cfg["healthy_connector_statuses"] for c in group.get("connectors", []))


def ordered_apps(data: dict, cfg: dict) -> list[dict]:
    order = cfg["app_evaluation_order"]
    apps = data.get("private_apps", [])
    # Unknown app types sort last. Precedence between per-app and Quick Access is kept generic here:
    # enterprise apps are checked before Quick Access, which is how Microsoft describes the intent.
    return sorted(apps, key=lambda a: order.index(a.get("type")) if a.get("type") in order else len(order))


def classify(dest: str, data: dict, cfg: dict) -> str:
    if any(fqdn_match(p, dest) for p in cfg["microsoft_destinations"] if _ip(dest) is None):
        return "microsoft"
    if any(dest_matches(s.get("destination", ""), dest) for a in data.get("private_apps", [])
           for s in a.get("segments", [])):
        return "private"
    addr = _ip(dest)
    if addr is not None and any(addr in ipaddress.ip_network(n) for n in cfg["private_ip_ranges"]
                                if ipaddress.ip_network(n).version == addr.version):
        return "private"
    if addr is None and any(dest.lower().endswith("." + s.lower().lstrip(".")) or dest.lower() == s.lower()
                            for s in data.get("private_dns_suffixes", [])):
        return "private"
    return "internet"


def category_of(dest: str, data: dict) -> str | None:
    for pattern, cat in data.get("web_categories", {}).items():
        if fqdn_match(pattern, dest):
            return cat
    return None


def linked_security_profiles(upn: str, data: dict, cfg: dict) -> tuple[list[str], list[str]]:
    """(profile names linked by enforced CA policies for this user, report-only notes)."""
    names, notes = [], []
    for p in data.get("conditional_access_policies", []):
        if p.get("target_resources") != cfg["ca_internet_target"] or not p.get("security_profile"):
            continue
        if not targets(p.get("include", []), upn, data, cfg) or targets(p.get("exclude", []), upn, data, cfg):
            continue
        if p.get("state") in cfg["enforced_ca_states"]:
            names.append(p["security_profile"])
        elif p.get("state") in cfg["report_only_ca_states"]:
            notes.append(f"report-only policy '{p.get('name')}' would link '{p['security_profile']}' (not enforced)")
    return list(dict.fromkeys(names)), notes


# --------------------------------------------------------------------------- #
# Flow evaluation
# --------------------------------------------------------------------------- #
def _result(flow, traffic, outcome, rule, reasons, app=None) -> FlowResult:
    return FlowResult(flow.get("id", "?"), flow.get("user") or "?", str(flow.get("destination") or "-"), traffic,
                      outcome, rule, app, reasons)


def _evaluate_private(flow, upn, dest, data, cfg, reasons) -> FlowResult:
    port, proto = flow.get("port"), str(flow.get("protocol") or "").lower()
    if port is None or not proto:
        return _result(flow, "private", "BLOCKED_NO_SEGMENT", "segment_match", reasons + [
            "port or protocol missing: no segment can be matched (deny by default)"])
    candidates = [(a, s) for a in ordered_apps(data, cfg) for s in a.get("segments", [])
                  if dest_matches(s.get("destination", ""), dest) and port_in(port, s.get("ports"))
                  and proto in protocols_of(s)]
    if not candidates:
        return _result(flow, "private", "BLOCKED_NO_SEGMENT", "segment_match", reasons + [
            f"no application segment covers {dest}:{port}/{proto}"])
    mine = [(a, s) for a, s in candidates if targets(a.get("assigned_to", []), upn, data, cfg)]
    if not mine:
        names = ", ".join(sorted({a.get("name", a.get("id", "?")) for a, _ in candidates}))
        return _result(flow, "private", "BLOCKED_NO_SEGMENT", "app_assignment", reasons + [
            f"segment exists in {names} but {upn} is not assigned to that app, so no segment is available to them"])
    app, seg = mine[0]
    label = app.get("name", app.get("id", "?"))
    reasons = reasons + [f"matched segment {segment_label(seg)} in {app.get('type', '?')} app '{label}'"]
    groups = {g.get("name"): g for g in data.get("connector_groups", [])}
    cg_name = app.get("connector_group")
    if cg_name not in groups:
        return _result(flow, "private", "BLOCKED_CONNECTOR_UNAVAILABLE", "connector_health", reasons + [
            f"connector group '{cg_name}' is not defined (deny by default)"], label)
    healthy = healthy_connectors(groups[cg_name], cfg)
    if healthy == 0:
        return _result(flow, "private", "BLOCKED_CONNECTOR_UNAVAILABLE", "connector_health", reasons + [
            f"connector group '{cg_name}' has no healthy connector"], label)
    reasons.append(f"connector group '{cg_name}' has {healthy} healthy connector(s)")
    if healthy < cfg["min_healthy_connectors"]:
        reasons.append(f"warning: below the {cfg['min_healthy_connectors']}-connector redundancy minimum")
    return _result(flow, "private", "TUNNELED_PRIVATE_ACCESS", "segment_match", reasons, label)


def _evaluate_internet(flow, upn, dest, data, cfg, reasons) -> FlowResult:
    profiles = {p.get("name"): p for p in data.get("security_profiles", [])}
    policies = {p.get("name"): p for p in data.get("web_filtering_policies", [])}
    linked, notes = linked_security_profiles(upn, data, cfg)
    reasons = reasons + notes
    for name in linked:
        if name not in profiles:
            return _result(flow, "internet", "BLOCKED_BY_WEB_FILTER", "missing_security_profile", reasons + [
                f"Conditional Access links security profile '{name}' which does not exist: "
                f"{cfg['missing_security_profile_action']} (deny by default)"])
    chain = sorted((profiles[n] for n in linked if not profiles[n].get("baseline")),
                   key=lambda p: p.get("priority", 10 ** 9))
    chain += [p for p in profiles.values() if p.get("baseline")]
    category = category_of(dest, data)
    reasons.append(f"web category: {category or 'uncategorised'}; profiles evaluated: "
                   + (" → ".join(p.get("name", "?") for p in chain) or "none"))
    for prof in chain:
        for link in sorted(prof.get("links", []), key=lambda l: l.get("priority", 10 ** 9)):
            pol = policies.get(link.get("policy"))
            if pol is None:
                reasons.append(f"'{prof.get('name')}' links missing policy '{link.get('policy')}' (ignored)")
                continue
            for rule in pol.get("rules", []):
                hit = (rule.get("type") == "fqdn" and fqdn_match(rule.get("value", ""), dest)) or \
                      (rule.get("type") == "webCategory" and category is not None
                       and str(rule.get("value", "")).lower() == category.lower())
                if hit:
                    action = pol.get("action") if pol.get("action") in ("allow", "block") else "block"
                    why = (f"{rule.get('type')} rule '{rule.get('value')}' in policy '{pol.get('name')}' "
                           f"({action}) via security profile '{prof.get('name')}'")
                    out = "TUNNELED_INTERNET_ALLOWED" if action == "allow" else "BLOCKED_BY_WEB_FILTER"
                    return _result(flow, "internet", out, "web_filter_rule", reasons + [why])
    if category is None:
        action, rule, why = cfg["unknown_category_action"], "unknown_category", \
            "no rule matched and the destination is uncategorised"
    else:
        action, rule, why = cfg["default_internet_action"], "default_action", "no filtering rule matched"
    out = "TUNNELED_INTERNET_ALLOWED" if action == "allow" else "BLOCKED_BY_WEB_FILTER"
    return _result(flow, "internet", out, rule, reasons + [f"{why}: default action is {action}"])


def evaluate_flow(flow: dict, data: dict, cfg: dict) -> FlowResult:
    upn = str(flow.get("user") or "").lower()
    if upn not in _users(data):
        return _result(flow, "-", "BYPASSED_NOT_FORWARDED", "identity", [
            f"user '{flow.get('user')}' is not in the directory: no profile can apply, traffic is not acquired "
            "(not protected and cannot reach private apps)"])
    device = {d.get("id"): d for d in data.get("devices", [])}.get(flow.get("device"))
    if device is None:
        return _result(flow, "-", "BYPASSED_NOT_FORWARDED", "client", [
            f"device '{flow.get('device')}' is unknown: treated as having no Global Secure Access client"])
    if device.get("gsa_client_installed") is not True:
        state = "not recorded (treated as not installed)" if "gsa_client_installed" not in device else "not installed"
        return _result(flow, "-", "BYPASSED_NOT_FORWARDED", "client", [
            f"Global Secure Access client {state} on {device.get('id')}: traffic goes direct, unprotected"])
    dest = str(flow.get("destination") or "").strip()
    if not dest:
        return _result(flow, "-", "BLOCKED_NO_SEGMENT", "destination", [
            "no destination recorded: cannot be matched to any segment or rule (deny by default)"])
    traffic = classify(dest, data, cfg)
    pname = PROFILE_NAMES[traffic]
    reasons = [f"client installed on {device.get('id')}; {dest} classified as {traffic} traffic"]
    profile = data.get("forwarding_profiles", {}).get(traffic)
    if not profile or profile.get("enabled") is not True:
        return _result(flow, traffic, "BYPASSED_NOT_FORWARDED", "profile_disabled", reasons + [
            f"{pname} is disabled or not configured: the client does not acquire this traffic"])
    if not targets(profile.get("assigned_to", []), upn, data, cfg):
        return _result(flow, traffic, "BYPASSED_NOT_FORWARDED", "profile_assignment", reasons + [
            f"{pname} is not assigned to {upn} (directly, by group or All users)"])
    reasons.append(f"{pname} is enabled and assigned to {upn}")
    if traffic == "microsoft":
        return _result(flow, traffic, "TUNNELED_MICROSOFT", "microsoft_profile",
                       reasons + ["Microsoft 365 / Entra endpoint: tunneled by the Microsoft traffic profile"])
    if traffic == "private":
        return _evaluate_private(flow, upn, dest, data, cfg, reasons)
    return _evaluate_internet(flow, upn, dest, data, cfg, reasons)


def evaluate_flows(data: dict, cfg: dict) -> list[FlowResult]:
    return [evaluate_flow(f, data, cfg) for f in data.get("flows", [])]


# --------------------------------------------------------------------------- #
# Health check
# --------------------------------------------------------------------------- #
def health_check(data: dict, cfg: dict) -> list[HealthFinding]:
    out: list[HealthFinding] = []
    minimum = cfg["min_healthy_connectors"]
    groups = {g.get("name"): g for g in data.get("connector_groups", [])}
    for name, g in groups.items():
        n = healthy_connectors(g, cfg)
        if n < minimum:
            total = len(g.get("connectors", []))
            out.append(HealthFinding("CONNECTOR_GROUP_UNHEALTHY", name, "high" if n == 0 else "medium", [
                f"{n} of {total} connector(s) healthy, below the minimum of {minimum}"
                + (": every app on it is unreachable" if n == 0 else ": one failure takes its apps offline")]))
    for app in data.get("private_apps", []):
        cg = app.get("connector_group")
        if cg not in groups:
            out.append(HealthFinding("CONNECTOR_GROUP_UNHEALTHY", str(cg), "high", [
                f"app '{app.get('name')}' uses connector group '{cg}' which does not exist"]))
    segs = [(a, s) for a in ordered_apps(data, cfg) for s in a.get("segments", [])]
    for i, (a1, s1) in enumerate(segs):
        for a2, s2 in segs[i + 1:]:
            if segments_overlap(s1, s2):
                out.append(HealthFinding("SEGMENT_OVERLAP", f"{a1.get('name')} / {a2.get('name')}", "medium", [
                    f"{segment_label(s1)} ({a1.get('name')}) overlaps {segment_label(s2)} ({a2.get('name')}): "
                    "traffic may land on the wrong app and connector group"]))
    for kind in TRAFFIC_TYPES:
        prof = data.get("forwarding_profiles", {}).get(kind)
        if prof is not None and not members(prof.get("assigned_to", []), data, cfg):
            out.append(HealthFinding("PROFILE_UNASSIGNED", PROFILE_NAMES[kind],
                                     "high" if prof.get("enabled") else "low",
                                     [f"{PROFILE_NAMES[kind]} reaches no user"]))
    for prof in data.get("security_profiles", []):
        if prof.get("baseline"):
            continue
        reach = set()
        for p in data.get("conditional_access_policies", []):
            if (p.get("security_profile") == prof.get("name") and p.get("state") in cfg["enforced_ca_states"]
                    and p.get("target_resources") == cfg["ca_internet_target"]):
                reach |= members(p.get("include", []), data, cfg) - members(p.get("exclude", []), data, cfg)
        if not reach:
            out.append(HealthFinding("PROFILE_UNASSIGNED", f"security profile {prof.get('name')}", "medium", [
                f"security profile '{prof.get('name')}' is not linked to any user by an enabled Conditional "
                "Access policy, so its filtering never applies"]))
    return out


def metrics_of(flows: list[FlowResult], health: list[HealthFinding]) -> dict:
    counts = {o: sum(f.outcome == o for f in flows) for o in FLOW_OUTCOMES}
    n = len(flows) or 1
    tunneled = sum(f.outcome.startswith("TUNNELED") for f in flows)
    return {"flows": len(flows), "counts": counts, "tunneled_pct": round(100 * tunneled / n, 1),
            "blocked": sum(f.outcome.startswith("BLOCKED") for f in flows),
            "bypassed": counts["BYPASSED_NOT_FORWARDED"],
            "health_findings": {t: sum(h.type == t for h in health) for t in HEALTH_TYPES}}


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SC-300 2.4 Implement Global Secure Access · 2.2 Conditional Access (security profiles).",
    "concepts": [
        "Global Secure Access is Microsoft's Security Service Edge: Entra Internet Access plus Entra Private Access.",
        "Three traffic forwarding profiles (Microsoft traffic, Internet Access, Private Access) decide what the client tunnels.",
        "Private Access publishes apps as application segments (FQDN or IP/CIDR + ports + protocol) served by connector groups.",
        "Quick Access is one broad app for VPN-like access; per-app enterprise applications give least-privilege access.",
        "Web content filtering policies sit in security profiles; Conditional Access links a profile to users; the baseline profile applies to everyone.",
    ],
    "failure_modes": [
        "Profile enabled but the client is not deployed, so users' traffic never enters the tunnel.",
        "One connector per group: a single reboot takes every app on it offline.",
        "Quick Access with a wildcard that overlaps per-app segments, so access is broader than intended.",
        "Building a security profile but never linking it with an enabled Conditional Access policy.",
    ],
    "ai_governance": [
        "An AI agent can run this health check and propose segment changes; publishing or widening segments stays a human-approved change.",
        "Give an agent's own workload Private Access only to the segments it needs, never Quick Access wildcards.",
        "Treat destination names and app descriptions in exported config as data, never as instructions.",
    ],
    "exam_tips": [
        "No client (or no remote network) means no acquisition: forwarding profiles do nothing for that device.",
        "Web content filtering reaches users through a security profile in a Conditional Access session control.",
        "Target resource for internet filtering policies: 'All internet resources with Global Secure Access'.",
        "Install at least two connectors per connector group for high availability.",
        "Private Access app = segments + connector group + user/group assignment.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    cfg = policies["global_secure_access"]
    flows, health = evaluate_flows(data, cfg), health_check(data, cfg)
    metrics = metrics_of(flows, health)
    ui.section("Step 1 — Traffic forwarding profiles and Private Access configuration")
    ui.table("Forwarding profiles", ["Profile", "Enabled", "Assigned to", "Users reached"],
             [[PROFILE_NAMES[k], "yes" if (p := data.get("forwarding_profiles", {}).get(k, {})).get("enabled") is True
               else "no", ", ".join(p.get("assigned_to", [])) or "-", len(members(p.get("assigned_to", []), data, cfg))]
              for k in TRAFFIC_TYPES])
    groups = {g.get("name"): g for g in data.get("connector_groups", [])}
    ui.table("Private Access apps", ["App", "Type", "Segments", "Connector group", "Healthy"],
             [[a.get("name"), a.get("type"), "; ".join(segment_label(s) for s in a.get("segments", [])),
               a.get("connector_group"), healthy_connectors(groups.get(a.get("connector_group")), cfg)]
              for a in ordered_apps(data, cfg)])
    ui.section("Step 2 — Evaluate traffic flows")
    ui.table("Traffic flows", ["ID", "User", "Destination", "Traffic", "Outcome", "Rule"],
             [[f.id, f.user, f.destination, f.traffic, f.outcome, f.rule] for f in flows])
    for f in flows:
        style = "green" if f.outcome.startswith("TUNNELED") else "red" if f.outcome.startswith("BLOCKED") else "yellow"
        ui.bullet(f"{f.id} → {f.outcome}: " + "; ".join(f.reasons), style=style)
    ui.section("Step 3 — Health check")
    ui.table("Health findings", ["Type", "Target", "Severity"], [[h.type, h.target, h.severity] for h in health])
    for h in health:
        ui.bullet(f"{h.type} {h.target}: " + "; ".join(h.reasons), style="red" if h.severity == "high" else "yellow")
    ui.status("Health check", "PASS" if not health else "WARN", f"{len(health)} finding(s)")
    ui.print(f"{metrics['flows']} flows: tunneled {metrics['tunneled_pct']}% · blocked {metrics['blocked']} · "
             f"bypassed {metrics['bypassed']}")
    ui.insight(INSIGHT)
    return {"flows": {f.id: f.outcome for f in flows}, "rules": {f.id: f.rule for f in flows},
            "health": [{"type": h.type, "target": h.target, "severity": h.severity} for h in health],
            "metrics": metrics}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
RULE_LABELS = {
    "identity": "user not found in the directory", "client": "Global Secure Access client check",
    "destination": "missing destination", "profile_disabled": "forwarding profile disabled",
    "profile_assignment": "forwarding profile not assigned to the user", "microsoft_profile": "Microsoft traffic profile",
    "segment_match": "application segment match", "app_assignment": "user not assigned to the Private Access app",
    "connector_health": "connector group health", "missing_security_profile": "missing security profile",
    "web_filter_rule": "web content filtering rule", "unknown_category": "uncategorised destination default",
    "default_action": "default internet action",
}


def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["global_secure_access"]
    flows, health = evaluate_flows(data, cfg), health_check(data, cfg)
    raw = {f.get("id"): f for f in data.get("flows", [])}
    qs: list = []
    for f in flows:
        src = {k: v for k, v in raw.get(f.id, {}).items() if k != "id"}
        obj = "2.2" if f.rule in ("web_filter_rule", "missing_security_profile") else "2.4"
        qs.append(Question(prompt=f"{f.id}: what happens to this traffic flow?", context=f"flow={src}",
                           choices=choices_with(f.outcome, FLOW_OUTCOMES, key=f.id), answer=f.outcome,
                           explanation="; ".join(f.reasons), objective=obj))
    labels = sorted(set(RULE_LABELS.values()))
    seen = set()
    for f in flows:
        if f.rule in seen or f.rule not in RULE_LABELS:
            continue
        seen.add(f.rule)
        ans = RULE_LABELS[f.rule]
        qs.append(Question(prompt=f"{f.id} ended as {f.outcome}. Which check decided it?",
                           context=f"flow={ {k: v for k, v in raw.get(f.id, {}).items() if k != 'id'} }",
                           choices=choices_with(ans, labels, key=f.id + "r"), answer=ans,
                           explanation="; ".join(f.reasons),
                           objective="2.2" if f.rule == "web_filter_rule" else "2.4"))
    weak = [h for h in health if h.type == "CONNECTOR_GROUP_UNHEALTHY"]
    names = sorted(g.get("name") for g in data.get("connector_groups", []) if g.get("name"))
    if weak and weak[0].target in names:
        bad = {h.target for h in weak}
        qs.append(Question(prompt=f"Which connector group is below the {cfg['min_healthy_connectors']}-healthy-"
                                  "connector minimum?",
                           choices=choices_with(weak[0].target, names, exclude=bad), answer=weak[0].target,
                           explanation="; ".join(weak[0].reasons), objective="2.4"))
    for h in health[:1] + [x for x in health if x.type == "SEGMENT_OVERLAP"][:1]:
        qs.append(Question(prompt=f"The health check flags '{h.target}'. What kind of finding is it?",
                           context="; ".join(h.reasons) if h.type != "SEGMENT_OVERLAP" else "",
                           choices=HEALTH_TYPES, answer=h.type, explanation="; ".join(h.reasons), objective="2.4"))
    qs.append(Question(prompt="A device has no Global Secure Access client. What happens to its Microsoft 365 traffic?",
                       choices=["it is not forwarded: it goes direct and the profiles do not apply",
                                "it is tunneled anyway because the Microsoft traffic profile is enabled",
                                "it is blocked by the web content filter",
                                "it is sent through the Private Access connector group"],
                       answer="it is not forwarded: it goes direct and the profiles do not apply",
                       explanation="the client (or a remote network) acquires traffic; without it nothing enters the "
                                   "tunnel", objective="2.4"))
    qs.append(Question(prompt="How does a web content filtering policy reach a group of users (other than the "
                              "baseline profile)?",
                       choices=["link it to a security profile and select that profile in a Conditional Access "
                                "session control",
                                "assign the filtering policy directly to the group in the forwarding profile",
                                "add the group to a connector group",
                                "publish it as an application segment"],
                       answer="link it to a security profile and select that profile in a Conditional Access "
                              "session control",
                       explanation=f"the Conditional Access policy targets '{cfg['ca_internet_target']}' and uses "
                                   "the security profile session control", objective="2.2"))
    qs.append(Question(prompt="Conditional Access policies that link a security profile in report-only mode do what?",
                       choices=["log what they would do, without enforcing the profile",
                                "enforce the profile for every user", "block all internet traffic",
                                "disable the Internet Access profile"],
                       answer="log what they would do, without enforcing the profile",
                       explanation="only enabled policies are enforced", objective="2.2"))
    for term in cfg["concepts"]:
        qs.append(Question(prompt=f"Which term is this? \"{cfg['concepts'][term]}\"",
                           choices=choices_with(term, list(cfg["concepts"]), key=term), answer=term,
                           explanation=cfg["concepts"][term],
                           objective="2.2" if term in ("security profile",) else "2.4"))
    return qs


# --------------------------------------------------------------------------- #
# Seeded scenario generator
# --------------------------------------------------------------------------- #
_FIRST = ["amira", "bruno", "carla", "dmitri", "esme", "farid", "greta", "hugo", "isla", "jonas", "kemi", "leo"]
_COMPANIES = [("Thornbury Example Logistics", "thornbury"), ("Quillon Example Health", "quillon"),
              ("Marrow Example Energy", "marrow"), ("Vellum Example Insurance", "vellum")]


def generate_scenario(rng, policies: dict) -> dict:
    """Seeded random scenario in the sample's shape, with at least one flow per outcome."""
    company, key = rng.choice(_COMPANIES)
    dom, internal = f"{key}.example", f"{key}.internal"
    names = rng.sample(_FIRST, 7)
    upn = [f"{n}@{dom}" for n in names]
    fin, eng, ops, con, nocl, unknown_dev, extra = upn
    octet = rng.randint(20, 90)
    build_cidr, qa_cidr = f"10.{octet}.0.0/16", f"10.{octet}.{rng.randint(1, 200)}.0/24"
    build_ip = f"10.{octet}.{rng.randint(201, 250)}.{rng.randint(2, 250)}"
    ssh_port, app_port = rng.choice([22, 2222]), rng.choice([443, 8443])
    wrong_port = rng.choice([8080, 9443, 5000])
    social, gamble = rng.choice(["chirp.example", "friendhub.example"]), rng.choice(["bet", "wager", "spin"])
    data = {
        "_description": f"Generated Global Secure Access scenario for {company} (fictional).",
        "tenant": company,
        "private_dns_suffixes": [internal],
        "users": [{"upn": u, "name": u.split("@")[0].title()} for u in upn],
        "groups": {"Finance": [fin], "Engineering": [eng, extra], "Ops": [ops, nocl], "Contractors": [con],
                   "GSA-Pilot": []},
        "devices": [{"id": f"DEV-{i:02d}", "user": u, "gsa_client_installed": True} for i, u in enumerate(upn, 1)],
        "forwarding_profiles": {
            "microsoft": {"enabled": True, "assigned_to": [policies["global_secure_access"]["all_users_keyword"]]},
            "internet": {"enabled": True, "assigned_to": ["Finance", "Engineering", "Ops"]},
            "private": {"enabled": True, "assigned_to": ["Finance", "Engineering", "Ops", "Contractors"]},
        },
        "connector_groups": [
            {"name": "CG-Main", "connectors": [{"name": f"main-{i}", "status": "active"} for i in range(1, 3)]},
            {"name": "CG-Build", "connectors": [{"name": "build-1", "status": "active"},
                                                {"name": "build-2", "status": rng.choice(["inactive", "unknown"])}]},
            {"name": "CG-Old", "connectors": [{"name": "old-1", "status": "inactive"}]},
        ],
        "private_apps": [
            {"id": "PA-ERP", "name": "ERP", "type": "enterprise", "connector_group": "CG-Main",
             "assigned_to": ["Finance"],
             "segments": [{"destination": f"erp.{internal}", "ports": [str(app_port)], "protocol": "tcp"}]},
            {"id": "PA-BUILD", "name": "Build Servers", "type": "enterprise", "connector_group": "CG-Build",
             "assigned_to": ["Engineering"],
             "segments": [{"destination": build_cidr, "ports": [str(ssh_port)], "protocol": "tcp"}]},
            {"id": "PA-OLD", "name": "Legacy Files", "type": "enterprise", "connector_group": "CG-Old",
             "assigned_to": ["Ops"], "segments": [{"destination": f"files.{internal}", "ports": ["445"],
                                                   "protocol": "tcp"}]},
            {"id": "QA", "name": "Quick Access", "type": "quick_access", "connector_group": "CG-Main",
             "assigned_to": ["Engineering", "Ops"],
             "segments": [{"destination": f"*.{internal}", "ports": ["443", str(app_port)], "protocol": "tcp"},
                          {"destination": qa_cidr, "ports": ["443"], "protocol": "tcp"}]},
        ],
        "web_categories": {f"*.{gamble}-example.test": "Gambling", social: "Social networking",
                           "news.example": "News"},
        "web_filtering_policies": [
            {"name": "Block-HighRisk", "action": "block", "rules": [{"type": "webCategory", "value": "Gambling"}]},
            {"name": "Block-Social", "action": "block",
             "rules": [{"type": "webCategory", "value": "Social networking"}]},
            {"name": "Allow-Social-Ops", "action": "allow", "rules": [{"type": "fqdn", "value": social}]},
        ],
        "security_profiles": [
            {"name": "Baseline", "baseline": True, "links": [{"policy": "Block-HighRisk", "priority": 100}]},
            {"name": "Standard", "priority": 200, "links": [{"policy": "Block-Social", "priority": 100}]},
            {"name": "Ops", "priority": 100, "links": [{"policy": "Allow-Social-Ops", "priority": 100},
                                                        {"policy": "Block-Social", "priority": 200}]},
            {"name": "Contractor-Strict", "priority": 300, "links": [{"policy": "Block-Social", "priority": 100}]},
        ],
        "conditional_access_policies": [
            {"name": "GSA Standard", "state": "enabled", "include": ["Finance", "Engineering"], "exclude": [],
             "target_resources": policies["global_secure_access"]["ca_internet_target"], "security_profile": "Standard"},
            {"name": "GSA Ops", "state": "enabled", "include": ["Ops"], "exclude": [],
             "target_resources": policies["global_secure_access"]["ca_internet_target"], "security_profile": "Ops"},
            {"name": "GSA Contractors", "state": "reportOnly", "include": ["Contractors"], "exclude": [],
             "target_resources": policies["global_secure_access"]["ca_internet_target"],
             "security_profile": "Contractor-Strict"},
        ],
    }
    data["devices"][4]["gsa_client_installed"] = False
    del data["devices"][5]["gsa_client_installed"]
    flows = [
        (fin, 1, f"{key}.sharepoint.com", 443),                       # TUNNELED_MICROSOFT
        (fin, 1, "news.example", 443),                                # TUNNELED_INTERNET_ALLOWED
        (eng, 2, social, 443),                                        # BLOCKED_BY_WEB_FILTER (Standard)
        (ops, 3, social, 443),                                        # allowed by Ops profile
        (eng, 2, f"www.{gamble}-example.test", 443),                  # blocked by baseline
        (fin, 1, f"erp.{internal}", app_port),                        # TUNNELED_PRIVATE_ACCESS
        (fin, 1, f"erp.{internal}", wrong_port),                      # BLOCKED_NO_SEGMENT
        (fin, 1, build_ip, ssh_port),                                 # BLOCKED_NO_SEGMENT (app assignment)
        (eng, 2, build_ip, ssh_port),                                 # TUNNELED_PRIVATE_ACCESS (1 healthy)
        (ops, 3, f"files.{internal}", 445),                           # BLOCKED_CONNECTOR_UNAVAILABLE
        (con, 4, "news.example", 443),                                # BYPASSED (profile not assigned)
        (nocl, 5, f"{key}.sharepoint.com", 443),                      # BYPASSED (no client)
        (unknown_dev, 6, f"erp.{internal}", app_port),                # BYPASSED (flag missing)
    ]
    for _ in range(rng.randint(0, 3)):
        u = rng.randrange(len(upn))
        flows.append((upn[u], u + 1, rng.choice([f"wiki.{internal}", "news.example", social,
                                                 f"{key}.sharepoint.com", f"tools-{rng.randint(1, 99)}.example"]),
                      rng.choice([443, 80, app_port])))
    data["flows"] = [{"id": f"F{i:02d}", "user": u, "device": f"DEV-{d:02d}", "destination": dst, "port": p,
                      "protocol": "tcp"} for i, (u, d, dst, p) in enumerate(flows, 1)]
    return data
