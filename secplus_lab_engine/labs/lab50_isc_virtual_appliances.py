"""
Lab 50 — Virtual Appliance Clusters: Health, Networking & Troubleshooting
=========================================================================

SailPoint ISC objectives
------------------------
* 2.1  Virtual appliance purpose and health: what a virtual appliance (VA)
       does, why a cluster needs two or more VAs, the status and health
       warnings shown on the Virtual Appliances page, and where VAs go.
* 2.2  Virtual appliance troubleshooting: the usual causes of a failed
       source test connection, a disconnected VA or an aggregation timeout,
       the VA logs and commands, and which changes on a VA are supported.

Course mapping: SailPoint Identity Security Administrator objectives 2.1
(primary) and 2.2; SailPoint Identity Security Engineer objectives 4.1 (VA
deployment, networking and HA/DR), 4.2 (VA setup, keys and valid
configurations) and 4.3 (VA logs, commands and troubleshooting).

How it works
------------
You look after the virtual appliances of a SailPoint Identity Security
Cloud (ISC) tenant. A VA is a SailPoint-managed virtual machine on your
network. It talks to the tenant with OUTBOUND HTTPS 443 only and runs the
connectors (the CCG service) that reach your on-premises sources. VAs are
grouped in clusters; SailPoint requires at least two VAs per cluster
because it updates and reboots them one at a time. Four parts, each deny
by default (a value that is missing or not reported counts as failing):

1. **Health per VA**, checks in this order. UNHEALTHY when any of these
   fail: (a) heartbeat missing or older than the stale limit, (b) charon
   (VA management service) not running, (c) ccg not running, (d) proxy
   settings that do not match the network (a proxy required but no
   proxy.yaml, or a proxy.yaml where none is used), (e) DNS not resolving,
   (f) any required SailPoint/AWS endpoint not reachable on 443, (g) NTP not
   synchronised or clock skew over the limit, (h) disk or (i) memory at or
   over 90%, (j) config.yaml missing or a keyPassphrase that differs from
   the cluster's. DEGRADED when it only has warnings: disk or memory at or
   over 80%, ccg restarted more than 10 times in 30 minutes, a certificate
   in /home/sailpoint/ca-certificates expired or expiring within 30 days, a
   release older than the current one (VA did not update), or an OS reboot
   pending. Otherwise HEALTHY.
2. **Cluster status**: a VA that is HEALTHY or DEGRADED is working. No
   working VA → DOWN. Two or more working VAs on at least two different
   hosts → REDUNDANT. Otherwise (one working VA, or all of them on one
   host, or a host not recorded) → SINGLE_POINT_OF_FAILURE. Any inactive VA
   is also noted, because SailPoint pauses updates for the whole cluster
   while one VA is not connected.
3. **Troubleshooting tickets** (source test connection fails, VA shows
   disconnected, aggregation timeouts, after a network change). The engine
   checks the named VA, or every VA in the cluster, for causes in the
   policy's order, first hit wins: PROXY_MISCONFIGURED, DNS_FAILURE,
   OUTBOUND_443_BLOCKED, NTP_TIME_SKEW, CCG_SERVICE_DOWN,
   RESOURCE_EXHAUSTION, CERTIFICATE_TRUST (a PKIX / certificate error in
   the ticket, or an expired certificate), SOURCE_CONNECTIVITY (the VA is
   fine but a source-side symptom remains). An unknown VA, cluster or
   symptom, or no evidence at all → NEEDS_EVIDENCE (run STUNT, collect
   logs, open a support case). Every answer carries the next step, a
   command and a log file from the knowledge table in the policy.
   Network-level causes come first because one of them (for example a
   broken DNS server) also makes every endpoint look unreachable.
4. **Deployment checks**: per cluster, at least two VAs, one VA per
   hypervisor host, production VAs spread over at least two datacenters
   (HA/DR) and no DMZ placement → COMPLIANT, else NON_COMPLIANT; the
   tenant also needs a sandbox cluster with two or more VAs. Each requested
   change on a VA is VALID when it is a documented, supported action (proxy.yaml,
   local NTP, a CA certificate, hosts.yaml, restarting ccg, adding a VA,
   more VM resources...) and NOT_SUPPORTED otherwise: installing antivirus,
   packages or monitoring agents, migrating a VA, skipping updates,
   deploying in the DMZ, any unknown action, or an unknown target.

Simplifications: the tenant computes the real status badges itself; the
heartbeat and time-skew limits here are training values. File paths and
service names follow SailPoint documentation where it gives them; the
charon journal and STUNT output names are generic (see the policy notes).

Run it
------
    python main.py --course spadmin lab 50
    python main.py --course speng lab 50
"""

from __future__ import annotations

from dataclasses import dataclass, field

TITLE = "Lab 50 — Virtual Appliance Clusters: Health, Networking & Troubleshooting"
OBJECTIVES = ("SailPoint ISC 2.1 Virtual appliance purpose and health · 2.2 Virtual appliance troubleshooting")
COURSES = ("spadmin", "speng")
SECTION = "isc_virtual_appliances"

HEALTH = ["HEALTHY", "DEGRADED", "UNHEALTHY"]
CLUSTER = ["REDUNDANT", "SINGLE_POINT_OF_FAILURE", "DOWN"]
CAUSES = ["PROXY_MISCONFIGURED", "DNS_FAILURE", "OUTBOUND_443_BLOCKED", "NTP_TIME_SKEW", "CCG_SERVICE_DOWN",
          "RESOURCE_EXHAUSTION", "CERTIFICATE_TRUST", "SOURCE_CONNECTIVITY", "NEEDS_EVIDENCE"]
PLACEMENT = ["COMPLIANT", "NON_COMPLIANT"]
CHANGES = ["VALID", "NOT_SUPPORTED"]
DECISIONS = HEALTH + CLUSTER + CAUSES + PLACEMENT + CHANGES

CHECK_LABELS = {
    "heartbeat": "heartbeat to the tenant", "charon": "charon service", "ccg": "ccg service",
    "proxy": "proxy settings", "dns": "DNS resolution", "outbound_443": "outbound HTTPS 443",
    "ntp": "NTP time sync", "disk_error": "disk over 90%", "memory_error": "memory over 90%",
    "keys": "config.yaml and keyPassphrase", "disk_warning": "disk over 80%", "memory_warning": "memory over 80%",
    "ccg_restarts": "ccg restart count", "certificate": "certificate expiry", "release": "VA release",
    "reboot_pending": "OS reboot pending",
}


@dataclass
class VAResult:
    id: str
    cluster: str
    host: str
    health: str
    failed: list[str] = field(default_factory=list)       # check names, in evaluation order
    reasons: list[str] = field(default_factory=list)


@dataclass
class ClusterResult:
    id: str
    status: str
    working: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


@dataclass
class TicketResult:
    id: str
    symptom: str
    cause: str
    checked: list[str] = field(default_factory=list)
    next_step: str = ""
    command: str = ""
    log: str = ""
    reasons: list[str] = field(default_factory=list)


@dataclass
class PlacementResult:
    id: str
    outcome: str
    vas: int
    hosts: int
    datacenters: int
    reasons: list[str] = field(default_factory=list)


@dataclass
class ChangeResult:
    id: str
    action: str
    target: str
    outcome: str
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Part 1 — VA health
# --------------------------------------------------------------------------- #
def _num(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def check_va(va: dict, cluster: dict | None, cfg: dict) -> dict[str, str]:
    """Return {check_name: reason} for every failed check (unhealthy and degraded), deny by default."""
    out: dict[str, str] = {}
    hb = _num(va.get("last_heartbeat_minutes_ago"))
    if hb is None:
        out["heartbeat"] = "no heartbeat reported (treated as disconnected)"
    elif hb > cfg["heartbeat_stale_minutes"]:
        out["heartbeat"] = f"last heartbeat {hb} min ago > {cfg['heartbeat_stale_minutes']} min"
    services = va.get("services") or {}
    for svc in ("charon", "ccg"):
        state = services.get(svc)
        if state != "running":
            out[svc] = f"{svc} service is '{state or 'not reported'}', not running"
    proxy = va.get("proxy") or {}
    req, conf = proxy.get("required"), proxy.get("configured")
    if not isinstance(req, bool) or not isinstance(conf, bool):
        out["proxy"] = "proxy settings not reported (treated as wrong)"
    elif req and not conf:
        out["proxy"] = "network requires a proxy but /home/sailpoint/proxy.yaml is not configured"
    elif conf and not req:
        out["proxy"] = "proxy.yaml points at a proxy, but this network has none"
    dns = va.get("dns")
    if dns != "ok":
        out["dns"] = f"DNS is '{dns or 'not reported'}': names do not resolve"
    reach = va.get("outbound_443") or {}
    blocked = [e for e in cfg["required_endpoints"] if reach.get(e) is not True]
    if blocked:
        out["outbound_443"] = "outbound 443 not reachable to: " + ", ".join(blocked)
    ntp = va.get("ntp") or {}
    skew = _num(ntp.get("skew_seconds"))
    if ntp.get("synced") is not True:
        out["ntp"] = "NTP not synchronised" + (f" (clock off by {skew}s)" if skew is not None else "")
    elif skew is None or abs(skew) > cfg["max_time_skew_seconds"]:
        out["ntp"] = (f"clock skew {skew}s > {cfg['max_time_skew_seconds']}s" if skew is not None
                      else "clock skew not reported")
    for res in ("disk", "memory"):
        pct = _num(va.get(f"{res}_used_pct"))
        if pct is None:
            out[f"{res}_error"] = f"{res} usage not reported (treated as full)"
        elif pct >= cfg[f"{res}_error_pct"]:
            out[f"{res}_error"] = f"{res} {pct}% >= {cfg[f'{res}_error_pct']}%"
        elif pct >= cfg[f"{res}_warning_pct"]:
            out[f"{res}_warning"] = f"{res} {pct}% >= {cfg[f'{res}_warning_pct']}%"
    keys = va.get("keys") or {}
    expected = (cluster or {}).get("key_passphrase_fingerprint")
    if keys.get("config_yaml") is not True:
        out["keys"] = "config.yaml missing or not reported"
    elif not expected:
        out["keys"] = f"cluster '{va.get('cluster')}' is unknown or has no keyPassphrase on record"
    elif keys.get("key_passphrase_fingerprint") != expected:
        out["keys"] = "keyPassphrase differs from the rest of the cluster (it must be identical on every VA)"
    restarts = _num(va.get("ccg_restarts_30min"))
    if restarts is None:
        out["ccg_restarts"] = "ccg restart count not reported"
    elif restarts > cfg["ccg_restart_limit_30min"]:
        out["ccg_restarts"] = f"ccg restarted {restarts} times in 30 min (> {cfg['ccg_restart_limit_30min']})"
    if "cert_min_days_left" not in va:
        out["certificate"] = "certificate expiry not reported"
    else:
        days = _num(va.get("cert_min_days_left"))       # None = no custom certificates installed
        if days is not None and days <= cfg["cert_expiry_warning_days"]:
            out["certificate"] = ("a certificate in /home/sailpoint/ca-certificates has expired" if days < 0 else
                                  f"a certificate expires in {days} days (<= {cfg['cert_expiry_warning_days']})")
    rel = va.get("release")
    if rel != cfg["current_release"]:
        out["release"] = (f"release {rel or 'not reported'} is not the current {cfg['current_release']}: "
                          "VA did not update, restart the cluster")
    if va.get("os_reboot_pending") is not False:
        out["reboot_pending"] = ("OS update installed, reboot pending" if va.get("os_reboot_pending")
                                 else "OS reboot state not reported")
    return out


def va_health(va: dict, cluster: dict | None, cfg: dict) -> VAResult:
    failed = check_va(va, cluster, cfg)
    order = cfg["health_checks_unhealthy"] + cfg["health_checks_degraded"]
    names = [c for c in order if c in failed]
    if any(c in cfg["health_checks_unhealthy"] for c in names):
        health = "UNHEALTHY"
    elif names:
        health = "DEGRADED"
    else:
        health = "HEALTHY"
    reasons = [failed[c] for c in names] or ["every health check passed"]
    return VAResult(va.get("id", "?"), va.get("cluster") or "?", va.get("host") or "?", health, names, reasons)


def assess_health(data: dict, cfg: dict) -> list[VAResult]:
    clusters = {c.get("id"): c for c in data.get("clusters", [])}
    return [va_health(v, clusters.get(v.get("cluster")), cfg) for v in data.get("vas", [])]


def cluster_status(cluster: dict, vas: list[dict], results: list[VAResult], cfg: dict) -> ClusterResult:
    cid = cluster.get("id", "?")
    mine = [r for r in results if r.cluster == cid]
    raw = {v.get("id"): v for v in vas}
    working = [r for r in mine if r.health in ("HEALTHY", "DEGRADED")]
    hosts = {raw.get(r.id, {}).get("host") for r in working}
    known_hosts = {h for h in hosts if h}
    reasons = []
    if not mine:
        status = "DOWN"
        reasons.append("empty cluster: no VAs, so the cluster cannot be used")
    elif not working:
        status = "DOWN"
        reasons.append(f"all {len(mine)} VAs are unhealthy: every source on this cluster fails")
    elif len(working) >= 2 and len(known_hosts) >= 2 and None not in hosts and "" not in hosts:
        status = "REDUNDANT"
        reasons.append(f"{len(working)} working VAs on {len(known_hosts)} different hosts")
    else:
        status = "SINGLE_POINT_OF_FAILURE"
        if len(working) == 1:
            reasons.append(f"only 1 working VA ({working[0].id}); SailPoint recommends at least "
                           f"{cfg['min_vas_per_cluster']}")
        elif len(known_hosts) < len(hosts) or not known_hosts:
            reasons.append("a working VA has no host recorded, so redundancy cannot be proven")
        else:
            reasons.append(f"{len(working)} working VAs but all on host {sorted(known_hosts)[0]}: one host failure "
                           "stops the cluster")
    inactive = [r.id for r in mine if r.health == "UNHEALTHY"]
    if inactive and working:
        reasons.append(f"inactive VA {', '.join(inactive)}: SailPoint pauses updates for the whole cluster while "
                       "a VA is not connected")
    return ClusterResult(cid, status, [r.id for r in working], reasons)


def assess_clusters(data: dict, results: list[VAResult], cfg: dict) -> list[ClusterResult]:
    return [cluster_status(c, data.get("vas", []), results, cfg) for c in data.get("clusters", [])]


# --------------------------------------------------------------------------- #
# Part 2 — troubleshooting tickets
# --------------------------------------------------------------------------- #
CAUSE_CHECKS = {
    "PROXY_MISCONFIGURED": ("proxy",),
    "DNS_FAILURE": ("dns",),
    "OUTBOUND_443_BLOCKED": ("outbound_443",),
    "NTP_TIME_SKEW": ("ntp",),
    "CCG_SERVICE_DOWN": ("ccg",),
    "RESOURCE_EXHAUSTION": ("disk_error", "memory_error", "disk_warning", "memory_warning"),
}


def _next(cause: str, cfg: dict) -> tuple[str, str, str]:
    c = cfg["causes"][cause]
    kn = cfg["va_knowledge"]
    return c["next_step"], kn["commands"][c["command"]], kn["logs"][c["log"]]["path"]


def diagnose(ticket: dict, data: dict, cfg: dict) -> TicketResult:
    tid, symptom = ticket.get("id", "?"), ticket.get("symptom")
    clusters = {c.get("id"): c for c in data.get("clusters", [])}
    vas = {v.get("id"): v for v in data.get("vas", [])}

    def result(cause, checked, reasons):
        step, cmd, log = _next(cause, cfg)
        return TicketResult(tid, symptom or "?", cause, checked, step, cmd, log, reasons + [cfg["do_not"]])

    if symptom not in cfg["symptoms"]:
        return result("NEEDS_EVIDENCE", [], [f"symptom '{symptom}' is not a known VA symptom (deny by default)"])
    if ticket.get("va"):
        if ticket["va"] not in vas:
            return result("NEEDS_EVIDENCE", [], [f"VA {ticket['va']} is not in the inventory"])
        targets = [vas[ticket["va"]]]
    else:
        if ticket.get("cluster") not in clusters:
            return result("NEEDS_EVIDENCE", [], [f"cluster {ticket.get('cluster')} is not in the inventory"])
        targets = [v for v in data.get("vas", []) if v.get("cluster") == ticket["cluster"]]
        if not targets:
            return result("NEEDS_EVIDENCE", [], [f"cluster {ticket['cluster']} has no VAs to check"])
    checked = [v.get("id", "?") for v in targets]
    failed = {v.get("id"): check_va(v, clusters.get(v.get("cluster")), cfg) for v in targets}
    error = (ticket.get("error") or "").lower()
    for cause in cfg["diagnosis_order"]:
        if cause in CAUSE_CHECKS:
            for vid in checked:
                hit = [failed[vid][c] for c in CAUSE_CHECKS[cause] if c in failed[vid]]
                if hit:
                    return result(cause, checked, [f"{vid}: {hit[0]}"])
        elif cause == "CERTIFICATE_TRUST":
            words = [k for k in cfg["certificate_error_keywords"] if k in error]
            if words:
                return result(cause, checked, [f"the error mentions '{words[0]}': the connector does not trust the "
                                               "source's certificate"])
            for vid in checked:
                if "has expired" in failed[vid].get("certificate", ""):
                    return result(cause, checked, [f"{vid}: {failed[vid]['certificate']}"])
        elif cause == "SOURCE_CONNECTIVITY":
            other = [c for vid in checked for c in failed[vid]
                     if c in cfg["health_checks_unhealthy"]]
            if symptom in cfg["source_side_symptoms"] and not other:
                return result(cause, checked, [f"{', '.join(checked)} passed every VA check: the problem is between "
                                               "the VA and the source" + (f" ({ticket['error']})"
                                                                          if ticket.get("error") else "")])
    leftover = sorted({c for vid in checked for c in failed[vid]})
    return result("NEEDS_EVIDENCE", checked, ["no cause found in the reported checks"
                                              + (f" (still failing: {', '.join(leftover)})" if leftover else "")])


# --------------------------------------------------------------------------- #
# Part 3 — deployment checks and change requests
# --------------------------------------------------------------------------- #
def check_placement(data: dict, cfg: dict) -> tuple[list[PlacementResult], list[str]]:
    pl = cfg["placement"]
    vas = data.get("vas", [])
    per_host: dict[str, list[str]] = {}
    for v in vas:
        if v.get("host"):
            per_host.setdefault(v["host"], []).append(v.get("id", "?"))
    out = []
    for c in data.get("clusters", []):
        mine = [v for v in vas if v.get("cluster") == c.get("id")]
        hosts = {v.get("host") for v in mine if v.get("host")}
        dcs = {v.get("datacenter") for v in mine if v.get("datacenter")}
        gaps = []
        if len(mine) < cfg["min_vas_per_cluster"]:
            gaps.append(f"{len(mine)} VA(s); at least {cfg['min_vas_per_cluster']} per cluster are required")
        if any(not v.get("host") or not v.get("datacenter") for v in mine):
            gaps.append("a VA has no host or datacenter recorded (cannot prove HA)")
        if pl["one_va_per_host"]:
            for h in sorted(hosts):
                if len(per_host.get(h, [])) > 1:
                    gaps.append(f"host {h} runs {len(per_host[h])} VAs ({', '.join(per_host[h])}): use 1 VA per host")
        if c.get("environment") == "production" and mine and len(dcs) < pl["production_min_datacenters"]:
            gaps.append(f"all VAs in {len(dcs)} datacenter(s) ({', '.join(sorted(dcs)) or 'unknown'}): spread "
                        f"production VAs over at least {pl['production_min_datacenters']} for HA/DR")
        if c.get("dmz") and not pl["dmz_allowed"]:
            gaps.append("cluster is in the DMZ: DMZ deployment is not recommended")
        if c.get("environment") not in ("production", "sandbox"):
            gaps.append(f"environment '{c.get('environment')}' unknown: label the cluster production or sandbox")
        out.append(PlacementResult(c.get("id", "?"), "NON_COMPLIANT" if gaps else "COMPLIANT", len(mine), len(hosts),
                                   len(dcs), gaps or [f"{len(mine)} VAs on {len(hosts)} hosts in {len(dcs)} "
                                                      "datacenter(s): meets the guidance"]))
    tenant = []
    counts = {c.get("id"): sum(v.get("cluster") == c.get("id") for v in vas) for c in data.get("clusters", [])}
    sandboxes = [c for c in data.get("clusters", []) if c.get("environment") == "sandbox"]
    if pl["require_sandbox_cluster"]:
        if not sandboxes:
            tenant.append("no sandbox cluster: SailPoint requires sandbox VAs to test updates before production")
        for s in sandboxes:
            if counts[s["id"]] < cfg["min_vas_per_cluster"]:
                tenant.append(f"sandbox cluster {s['id']} has {counts[s['id']]} VA(s); at least "
                              f"{cfg['min_vas_per_cluster']} are required")
    if not any(c.get("environment") == "production" for c in data.get("clusters", [])):
        tenant.append("no production cluster")
    return out, tenant


def vas_per_site(data: dict) -> dict[str, int]:
    sites = {c.get("id"): c.get("site") or "unknown" for c in data.get("clusters", [])}
    out: dict[str, int] = {}
    for v in data.get("vas", []):
        s = sites.get(v.get("cluster"), "unknown")
        out[s] = out.get(s, 0) + 1
    return dict(sorted(out.items()))


def review_change(change: dict, data: dict, cfg: dict) -> ChangeResult:
    cid, action = change.get("id", "?"), change.get("action") or ""
    target = change.get("va") or change.get("cluster") or ""
    known = {v.get("id") for v in data.get("vas", [])} | {c.get("id") for c in data.get("clusters", [])}
    if action in cfg["unsupported_changes"]:
        return ChangeResult(cid, action, target or "-", "NOT_SUPPORTED", [cfg["unsupported_changes"][action]])
    if action not in cfg["supported_changes"]:
        return ChangeResult(cid, action or "-", target or "-", "NOT_SUPPORTED",
                            [f"'{action or 'no action'}' is not a documented VA change (deny by default): do not "
                             "change the VA; ask SailPoint Support"])
    if target not in known:
        return ChangeResult(cid, action, target or "-", "NOT_SUPPORTED",
                            [f"target '{target or 'none'}' is not in the VA inventory: cannot approve the change"])
    return ChangeResult(cid, action, target, "VALID", [cfg["supported_changes"][action]])


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SailPoint ISC 2.1 Virtual appliance purpose and health · 2.2 Virtual appliance troubleshooting "
                 "(Engineer 4.1, 4.2, 4.3).",
    "concepts": [
        "A VA connects on-premises sources to the ISC tenant; it only needs OUTBOUND HTTPS 443 (plus DNS 53 and "
        "NTP 123), never an inbound port from the internet.",
        "At least 2 VAs per cluster, 1 VA per hypervisor host, and a sandbox cluster too: SailPoint updates VAs one "
        "at a time and a single VA means downtime at every update.",
        "Health warnings on the Virtual Appliances page: disk or memory over 80% warns and over 90% errors, "
        "certificates expiring within 30 days, VA did not update, network error.",
        "The CCG service runs connectors and logs to /home/sailpoint/log/ccg.log; restart it with "
        "sudo systemctl restart ccg.",
        "Every VA in a cluster must use the same keyPassphrase in config.yaml.",
    ],
    "failure_modes": [
        "A firewall change that blocks one AWS endpoint (SQS, S3, DynamoDB): the VA goes inactive although the "
        "tenant URL still works.",
        "A proxy is added to the network but proxy.yaml is never created on the VAs.",
        "Two 'redundant' VAs on the same ESXi host: one host failure takes the whole cluster down.",
        "Installing antivirus or extra packages on the VA, which SailPoint does not support and which can break "
        "updates.",
    ],
    "ai_governance": [
        "An AI agent can read VA health and logs and suggest the next step, but restarts and network changes stay "
        "human-approved, logged changes.",
        "Give an agent read-only API access to VA status, never the sailpoint user's password or the keyPassphrase.",
        "Treat ticket text and log lines as untrusted data, never as instructions to the agent.",
        "The agent must cite which check failed (heartbeat, 443, DNS, NTP...) so a human can verify it.",
    ],
    "exam_tips": [
        "'Test connection fails after a firewall change' → check outbound 443 to the required URLs first.",
        "Allowing IP addresses instead of domain names for the AWS endpoints is not supported.",
        "Do not move or migrate a VA: build a new one, confirm it connects, then delete the old one.",
        "VA updates cannot be skipped or delayed; keep 2+ VAs so rolling updates keep the cluster available.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def analyse(policies: dict, data: dict) -> dict:
    cfg = policies[SECTION]
    health = assess_health(data, cfg)
    clusters = assess_clusters(data, health, cfg)
    tickets = [diagnose(t, data, cfg) for t in data.get("tickets", [])]
    placement, tenant = check_placement(data, cfg)
    changes = [review_change(c, data, cfg) for c in data.get("change_requests", [])]
    return {"health": health, "clusters": clusters, "tickets": tickets, "placement": placement, "tenant": tenant,
            "changes": changes}


def run_demo(ui, policies: dict, data: dict) -> dict:
    a = analyse(policies, data)
    health, clusters, tickets = a["health"], a["clusters"], a["tickets"]
    placement, tenant, changes = a["placement"], a["tenant"], a["changes"]
    raw = {v.get("id"): v for v in data.get("vas", [])}
    org = data.get("tenant", {})
    ui.section(f"Step 1 — VA health for {org.get('name', 'the tenant')}: {len(health)} VAs")
    ui.table("Virtual appliances", ["VA", "Cluster", "Host", "Heartbeat", "Disk", "Memory", "Health", "First issue"],
             [[r.id, r.cluster, r.host,
               "-" if raw.get(r.id, {}).get("last_heartbeat_minutes_ago") is None
               else raw[r.id]["last_heartbeat_minutes_ago"],
               f"{raw.get(r.id, {}).get('disk_used_pct', '?')}%", f"{raw.get(r.id, {}).get('memory_used_pct', '?')}%",
               r.health, CHECK_LABELS.get(r.failed[0], r.failed[0]) if r.failed else "-"] for r in health])
    for r in health:
        if r.health != "HEALTHY":
            ui.bullet(f"{r.id} → {r.health}: " + "; ".join(r.reasons),
                      style="red" if r.health == "UNHEALTHY" else "yellow")
    ui.section("Step 2 — Cluster redundancy")
    ui.table("Clusters", ["Cluster", "Working VAs", "Status"],
             [[c.id, ", ".join(c.working) or "-", c.status] for c in clusters])
    for c in clusters:
        ui.bullet(f"{c.id} → {c.status}: " + "; ".join(c.reasons),
                  style={"REDUNDANT": "green", "DOWN": "red"}.get(c.status, "yellow"))
    ui.section("Step 3 — Troubleshooting tickets")
    ui.table("Tickets", ["ID", "Symptom", "Checked", "Cause", "Command"],
             [[t.id, t.symptom, ", ".join(t.checked) or "-", t.cause, t.command] for t in tickets])
    for t in tickets:
        ui.bullet(f"{t.id} → {t.cause}: {t.reasons[0]}. Next: {t.next_step} (log: {t.log})",
                  style="yellow" if t.cause == "NEEDS_EVIDENCE" else None)
    ui.section("Step 4 — Deployment checks and change requests")
    sites = vas_per_site(data)
    ui.print("VAs per site: " + ", ".join(f"{s} {n}" for s, n in sites.items()))
    ui.table("Placement (HA/DR)", ["Cluster", "VAs", "Hosts", "Datacenters", "Result"],
             [[p.id, p.vas, p.hosts, p.datacenters, p.outcome] for p in placement])
    for p in placement:
        if p.outcome != "COMPLIANT":
            ui.bullet(f"{p.id}: " + "; ".join(p.reasons), style="yellow")
    for t in tenant:
        ui.bullet(f"Tenant: {t}", style="yellow")
    ui.table("Change requests", ["ID", "Target", "Action", "Result"],
             [[c.id, c.target, c.action, c.outcome] for c in changes])
    for c in changes:
        ui.bullet(f"{c.id} → {c.outcome}: {c.reasons[0]}", style="red" if c.outcome == "NOT_SUPPORTED" else None)
    count = lambda items, attr, vals: {v: sum(getattr(i, attr) == v for i in items) for v in vals}  # noqa: E731
    metrics = {"vas": len(health), "health": count(health, "health", HEALTH),
               "clusters": count(clusters, "status", CLUSTER),
               "tickets_explained": sum(t.cause != "NEEDS_EVIDENCE" for t in tickets), "tickets": len(tickets),
               "placement": count(placement, "outcome", PLACEMENT), "tenant_findings": len(tenant),
               "changes": count(changes, "outcome", CHANGES), "vas_per_site": sites}
    h, cl = metrics["health"], metrics["clusters"]
    ui.print(f"{metrics['vas']} VAs: {h['HEALTHY']} healthy, {h['DEGRADED']} degraded, {h['UNHEALTHY']} unhealthy · "
             f"clusters: {cl['REDUNDANT']} redundant, {cl['SINGLE_POINT_OF_FAILURE']} single point of failure, "
             f"{cl['DOWN']} down · {metrics['tickets_explained']}/{metrics['tickets']} tickets explained · "
             f"changes: {metrics['changes']['VALID']} valid, {metrics['changes']['NOT_SUPPORTED']} not supported")
    ui.insight(INSIGHT)
    return {"health": {r.id: r.health for r in health}, "clusters": {c.id: c.status for c in clusters},
            "tickets": {t.id: t.cause for t in tickets}, "placement": {p.id: p.outcome for p in placement},
            "changes": {c.id: c.outcome for c in changes}, "tenant_findings": tenant, "metrics": metrics}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies[SECTION]
    a = analyse(policies, data)
    raw_va = {v.get("id"): v for v in data.get("vas", [])}
    raw_t = {t.get("id"): t for t in data.get("tickets", [])}
    raw_c = {c.get("id"): c for c in data.get("change_requests", [])}
    commands = sorted(set(cfg["va_knowledge"]["commands"].values()))
    qs: list = []
    seen: set = set()
    for r in a["health"]:
        key = (r.health, r.failed[0] if r.failed else None)
        if key in seen:
            continue
        seen.add(key)
        src = {k: v for k, v in raw_va.get(r.id, {}).items() if k not in ("id", "host", "datacenter")}
        qs.append(Question(prompt=f"{r.id}: what is this virtual appliance's health?", context=f"VA={src}",
                           choices=HEALTH, answer=r.health, explanation="; ".join(r.reasons), objective="2.1"))
        if r.health == "UNHEALTHY" and len(r.failed) > 1:
            pool = [CHECK_LABELS[c] for c in CHECK_LABELS]
            ans = CHECK_LABELS[r.failed[0]]
            qs.append(Question(prompt=f"{r.id}: several checks fail. Which one is evaluated first?", context=f"VA={src}",
                               choices=choices_with(ans, [CHECK_LABELS[c] for c in r.failed] + pool, key=r.id),
                               answer=ans, explanation="check order: " + " → ".join(
                                   CHECK_LABELS[c] for c in r.failed) + "; " + r.reasons[0], objective="2.1"))
    for c in a["clusters"]:
        members = [f"{r.id}={r.health} on {r.host}" for r in a["health"] if r.cluster == c.id]
        qs.append(Question(prompt=f"{c.id}: what is the cluster's status?",
                           context="VAs: " + (", ".join(members) or "none"), choices=CLUSTER, answer=c.status,
                           explanation="; ".join(c.reasons), objective="2.1"))
    for t in a["tickets"]:
        src = {k: v for k, v in raw_t.get(t.id, {}).items() if k != "id"}
        qs.append(Question(prompt=f"{t.id}: what is the most likely cause?", context=f"ticket={src}",
                           choices=choices_with(t.cause, CAUSES, key=t.id), answer=t.cause,
                           explanation="; ".join(t.reasons[:-1]), objective="2.2"))
    for t in a["tickets"]:
        if t.cause in ("CCG_SERVICE_DOWN", "NTP_TIME_SKEW", "OUTBOUND_443_BLOCKED"):
            qs.append(Question(prompt=f"{t.id} ({t.cause}): which command belongs to the next step?",
                               choices=choices_with(t.command, commands, key=t.id), answer=t.command,
                               explanation=t.next_step, objective="2.2"))
    for p in a["placement"]:
        qs.append(Question(prompt=f"{p.id}: does the cluster's placement meet the HA/DR guidance?",
                           context=f"{p.vas} VAs on {p.hosts} hosts in {p.datacenters} datacenter(s)",
                           choices=PLACEMENT, answer=p.outcome, explanation="; ".join(p.reasons), objective="2.1"))
    for c in a["changes"]:
        src = raw_c.get(c.id, {})
        qs.append(Question(prompt=f"{c.id}: is this change on the virtual appliance VALID or NOT_SUPPORTED?",
                           context=f"target {c.target}: {src.get('description', c.action)}", choices=CHANGES,
                           answer=c.outcome, explanation=c.reasons[0], objective="2.2"))
    # Concept and rule questions.
    qs.append(Question(prompt="Which traffic does a VA need to reach the ISC tenant?",
                       choices=["outbound HTTPS 443 to the required SailPoint and AWS URLs",
                                "inbound HTTPS 443 from the tenant to the VA",
                                "inbound SSH 22 from the internet",
                                "outbound LDAP 389 to SailPoint"],
                       answer="outbound HTTPS 443 to the required SailPoint and AWS URLs",
                       explanation=cfg["ports"]["443"] + "; SSH 22 is inbound from the internal network only",
                       objective="2.1"))
    qs.append(Question(prompt="Why does SailPoint require at least two VAs per cluster?",
                       choices=["VAs are updated and rebooted one at a time, so a second VA keeps the cluster working",
                                "each VA can only connect one source",
                                "the tenant load-balances by IP address and needs two addresses",
                                "the keyPassphrase is split between two VAs"],
                       answer="VAs are updated and rebooted one at a time, so a second VA keeps the cluster working",
                       explanation=cfg["concepts"]["rolling update"], objective="2.1"))
    qs.append(Question(prompt="A security team wants its antivirus agent on every VA. What is the right answer?",
                       choices=["not supported: protect the VA with network controls and the hypervisor instead",
                                "install it on one VA per cluster only",
                                "install it after disabling VA updates",
                                "install it with sudo and restart ccg"],
                       answer="not supported: protect the VA with network controls and the hypervisor instead",
                       explanation=cfg["unsupported_changes"]["install_antivirus"], objective="2.2"))
    ccg = cfg["va_knowledge"]["logs"]["ccg"]["path"]
    logs = sorted({v["path"] for v in cfg["va_knowledge"]["logs"].values()} | {"/var/log/sailpoint/agent.log"})
    qs.append(Question(prompt="Which log holds the connector errors for a failed source test connection?",
                       choices=choices_with(ccg, logs, key="ccg"), answer=ccg,
                       explanation=cfg["va_knowledge"]["logs"]["ccg"]["use"], objective="2.2"))
    for term in ("CCG", "charon", "keyPassphrase", "STUNT", "VA cluster"):
        if term in cfg["concepts"]:
            qs.append(Question(prompt=f"Which term is this? \"{cfg['concepts'][term]}\"",
                               choices=choices_with(term, cfg["concepts"], key=term), answer=term,
                               explanation=cfg["concepts"][term], objective="2.2" if term == "STUNT" else "2.1"))
    return qs


# --------------------------------------------------------------------------- #
# Scenario generator
# --------------------------------------------------------------------------- #
SITES = [("AMS", "Amsterdam"), ("CHI", "Chicago"), ("SGP", "Singapore"), ("LON", "London"), ("TOR", "Toronto"),
         ("SYD", "Sydney"), ("FRA", "Frankfurt"), ("DAL", "Dallas")]
COMPANIES = ["Harborview Example Logistics", "Quillmark Example Insurance", "Northbeam Example Health",
             "Copperleaf Example Foods"]


def generate_scenario(rng, policies: dict) -> dict:
    cfg = policies[SECTION]
    company = rng.choice(COMPANIES)
    sites = rng.sample(SITES, 4)
    endpoints = list(cfg["required_endpoints"])
    current = cfg["current_release"]
    clusters, vas = [], []
    n = [0]

    def cluster(code, city, env):
        cid = f"CL-{code}-{'PROD' if env == 'production' else 'SBX'}"
        clusters.append({"id": cid, "name": f"{city} {env.title()}", "environment": env, "site": city,
                         "dmz": False, "key_passphrase_fingerprint": f"kp-{code.lower()}-{rng.randint(100, 999)}"})
        return clusters[-1]

    def va(cl, host, dc, **fault):
        n[0] += 1
        v = {"id": f"VA-{n[0]:02d}", "cluster": cl["id"], "host": host, "datacenter": dc,
             "last_heartbeat_minutes_ago": rng.randint(0, 4),
             "outbound_443": {e: True for e in endpoints}, "dns": "ok",
             "ntp": {"synced": True, "skew_seconds": round(rng.uniform(0, 2), 1)},
             "proxy": {"required": False, "configured": False},
             "disk_used_pct": rng.randint(25, 70), "memory_used_pct": rng.randint(30, 70),
             "services": {"ccg": "running", "charon": "running"}, "ccg_restarts_30min": rng.randint(0, 2),
             "keys": {"config_yaml": True, "key_passphrase_fingerprint": cl["key_passphrase_fingerprint"]},
             "cert_min_days_left": rng.choice([None, rng.randint(60, 400)]),
             "release": current, "os_reboot_pending": False}
        for k, val in fault.items():
            v[k] = val
        vas.append(v)
        return v

    (c1, n1), (c2, n2), (c3, n3), (c4, n4) = sites
    a = cluster(c1, n1, "production")
    b = cluster(c2, n2, "production")
    d = cluster(c3, n3, "production")
    e = cluster(c4, n4, "production")
    s = cluster(c1, n1, "sandbox")
    h = lambda code, i: f"esx-{code.lower()}-{i:02d}"  # noqa: E731
    # A: redundant, two datacenters; one degraded, one blocked on 443 after a firewall change.
    va(a, h(c1, 1), f"{c1}-DC1")
    va(a, h(c1, 11), f"{c1}-DC2", disk_used_pct=rng.randint(81, 89))
    blocked = rng.choice(["sqs", "s3", "dynamodb"])
    va(a, h(c1, 2), f"{c1}-DC1", last_heartbeat_minutes_ago=rng.randint(20, 90),
       outbound_443={x: x != blocked for x in endpoints})
    # B: two healthy VAs on ONE host, plus one with a missing proxy.yaml.
    va(b, h(c2, 1), f"{c2}-DC1")
    va(b, h(c2, 1), f"{c2}-DC1")
    va(b, h(c2, 2), f"{c2}-DC1", proxy={"required": True, "configured": False},
       outbound_443={x: False for x in endpoints}, last_heartbeat_minutes_ago=rng.randint(30, 200))
    # D: down: DNS failure, time skew, keyPassphrase mismatch.
    va(d, h(c3, 1), f"{c3}-DC1", dns="failing", outbound_443={x: False for x in endpoints},
       last_heartbeat_minutes_ago=rng.randint(60, 300))
    va(d, h(c3, 2), f"{c3}-DC2", ntp={"synced": False, "skew_seconds": rng.randint(120, 900)})
    va(d, h(c3, 3), f"{c3}-DC2", keys={"config_yaml": True, "key_passphrase_fingerprint": "kp-other-000"})
    # E: one datacenter; ccg stopped, outdated + expiring cert, no heartbeat, memory pressure.
    va(e, h(c4, 1), f"{c4}-DC1", services={"ccg": "stopped", "charon": "running"})
    va(e, h(c4, 2), f"{c4}-DC1", release="2026.08", cert_min_days_left=rng.randint(3, 29))
    va(e, h(c4, 3), f"{c4}-DC1", last_heartbeat_minutes_ago=None, services={"ccg": "running", "charon": "unknown"})
    va(e, h(c4, 4), f"{c4}-DC1", memory_used_pct=rng.randint(81, 89), ccg_restarts_30min=rng.randint(11, 20))
    # Sandbox: a single VA.
    va(s, h(c1, 21), f"{c1}-DC1")
    ids = [v["id"] for v in vas]
    src = rng.choice(["hr-db01", "ldap02", "erp-app03"])
    port = rng.choice([636, 1433, 1521, 443])
    tickets = [
        {"id": "T1", "symptom": "test_connection_fails", "cluster": b["id"], "source": "Active Directory"},
        {"id": "T2", "symptom": "va_disconnected", "va": ids[6]},
        {"id": "T3", "symptom": "aggregation_timeout", "va": ids[7], "source": "Workday"},
        {"id": "T4", "symptom": "after_network_change", "cluster": a["id"]},
        {"id": "T5", "symptom": "test_connection_fails", "va": ids[9], "source": "SAP"},
        {"id": "T6", "symptom": "aggregation_timeout", "va": ids[12], "source": "Oracle EBS"},
        {"id": "T7", "symptom": "test_connection_fails", "va": ids[0], "source": "LDAP",
         "error": "PKIX path building failed: unable to find valid certification path to requested target"},
        {"id": "T8", "symptom": "test_connection_fails", "va": ids[3], "source": "HR database",
         "error": f"Connection timed out: {src}:{port}"},
        {"id": "T9", "symptom": "va_disconnected", "va": ids[11]},
        {"id": "T10", "symptom": "aggregation_timeout", "cluster": "CL-OLD-01"},
    ]
    rng.shuffle(tickets)
    changes = [
        {"id": "C1", "va": ids[0], "action": "install_antivirus", "description": "Install the corporate antivirus agent"},
        {"id": "C2", "va": ids[5], "action": "configure_proxy", "description": "Create proxy.yaml for the new proxy"},
        {"id": "C3", "va": ids[7], "action": "local_ntp", "description": "Use the internal NTP servers"},
        {"id": "C4", "va": ids[0], "action": "add_ca_certificate", "description": "Trust the LDAP server's CA"},
        {"id": "C5", "va": ids[3], "action": "install_packages", "description": "Install tcpdump and htop"},
        {"id": "C6", "va": ids[13], "action": "migrate_va", "description": "vMotion the VA to a new host"},
        {"id": "C7", "cluster": s["id"], "action": "add_va_to_cluster", "description": "Add a second sandbox VA"},
        {"id": "C8", "cluster": e["id"], "action": "skip_or_delay_update", "description": "Delay next VA update"},
        {"id": "C9", "va": ids[10], "action": "tune_kernel_params", "description": "Change kernel network settings"},
        {"id": "C10", "va": ids[12], "action": "increase_vm_resources", "description": "Raise memory to 32 GB"},
        {"id": "C11", "va": "VA-99", "action": "restart_ccg", "description": "Restart ccg on an old VA"},
    ]
    rng.shuffle(changes)
    return {"_description": f"Generated VA estate for {company}",
            "tenant": {"name": company, "tenant": company.split()[0].lower() + "-example"},
            "clusters": clusters, "vas": vas, "tickets": tickets, "change_requests": changes}
