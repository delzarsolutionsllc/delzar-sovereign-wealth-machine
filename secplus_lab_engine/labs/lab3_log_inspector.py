"""
Lab 3 — Log Forensic Inspector & Hash Verifier
==============================================

Security+ SY0-701 objectives
----------------------------
* 4.9  Use data sources to support an investigation (firewall, OS/Windows
       event, application, endpoint logs; SIEM; metadata).
* 2.4  Indicators of malicious activity (brute force, impossible travel,
       account lockout, blocked content, out-of-cycle logging, missing logs).
* 1.4  Hashing & salting for integrity.
* 4.8  Incident response — chain of custody / evidence integrity.

Pipeline
--------
1. **Parse** heterogeneous raw lines (firewall, Windows Event, web, EDR) into
   one normalised schema (what a SIEM's parser/normaliser does).
2. **Enrich** with offline GeoIP so location-based rules work.
3. **Detect** with correlation rules:
   brute force (Event ID 4625 bursts), password spray, success-after-failure,
   impossible travel, port scans, threat-intel matches (IP / user agent / hash),
   SQL injection, audit-log clearing (Event ID 1102).
4. **Extract IOCs** (IPs, hashes, user agents, domains) by regex.
5. **Verify integrity** of the log set using a salted SHA-256 hash chain and
   an HMAC-signed manifest — detects edited, deleted or injected lines.

Run it
------
    python main.py lab 3
    python main.py lab 3 --file my_logs.json
"""

from __future__ import annotations

import ipaddress
import math
import re
import shlex
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from utils.crypto_helpers import build_hash_chain, hmac_sign, hmac_verify, canonical_json, verify_hash_chain

TITLE = "Lab 3 — Log Forensic Inspector & Hash Verifier"
OBJECTIVES = "SY0-701 4.9 Investigation data sources · 2.4 Indicators · 1.4 Hashing"

IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|ru|cn|io|xyz|top|info|biz)\b", re.I)
SQLI_RE = re.compile(r"('|%27)\s*(or|and)\s+\d+\s*=\s*\d+|union\s+select|--\s*$|;\s*drop\s+table", re.I)


# --------------------------------------------------------------------------- #
# Parsing & normalisation
# --------------------------------------------------------------------------- #
@dataclass
class LogEvent:
    """Normalised event (a tiny version of a SIEM common information model)."""

    line_no: int
    timestamp: datetime
    host: str
    source: str                  # FW | WinEvt | HTTP | EDR | ...
    fields: dict[str, str]
    raw: str
    geo: dict | None = None

    @property
    def event_id(self) -> int | None:
        v = self.fields.get("EventID")
        return int(v) if v and v.isdigit() else None

    @property
    def src_ip(self) -> str | None:
        src = self.fields.get("src")
        return src.split(":")[0] if src else None

    @property
    def user(self) -> str | None:
        return self.fields.get("user")


def parse_line(line: str, line_no: int = 0) -> LogEvent:
    """
    Parse ``<ISO-ts> <host> <source> key=value key="quoted value" ...``.

    Raises ``ValueError`` for malformed lines (count them — gaps in parsing are
    themselves an investigation lead).
    """
    try:
        tokens = shlex.split(line)
    except ValueError as exc:
        raise ValueError(f"line {line_no}: unbalanced quotes ({exc})") from exc
    if len(tokens) < 3:
        raise ValueError(f"line {line_no}: expected '<ts> <host> <source> k=v...'")
    ts_raw, host, source, *rest = tokens
    try:
        ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"line {line_no}: bad timestamp '{ts_raw}'") from exc
    fields: dict[str, str] = {}
    for tok in rest:
        if "=" in tok:
            k, v = tok.split("=", 1)
            fields[k] = v
    return LogEvent(line_no, ts, host, source, fields, line)


def parse_stream(lines: list[str], geoip: dict | None = None) -> tuple[list[LogEvent], list[str]]:
    """Parse + enrich every line. Returns (events, parse_errors)."""
    events, errors = [], []
    for i, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            ev = parse_line(line, i)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if geoip and ev.src_ip:
            ev.geo = geoip.get(ev.src_ip)
        events.append(ev)
    events.sort(key=lambda e: e.timestamp)
    return events, errors


# --------------------------------------------------------------------------- #
# Detection rules
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    rule: str
    severity: str        # LOW | MEDIUM | HIGH | CRITICAL
    summary: str
    evidence_lines: list[int] = field(default_factory=list)
    mitre: str = ""


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def detect_brute_force(events: list[LogEvent], cfg: dict) -> list[Finding]:
    """>= N failed logons (4625) for one user+source inside the window; escalate on later success."""
    fail_id, ok_id = cfg["failed_logon_event_id"], cfg["successful_logon_event_id"]
    threshold, window = cfg["brute_force_threshold"], timedelta(minutes=cfg["brute_force_window_minutes"])
    by_key: dict[tuple, list[LogEvent]] = defaultdict(list)
    for e in events:
        if e.event_id == fail_id:
            by_key[(e.user, e.src_ip)].append(e)

    findings = []
    for (user, ip), fails in by_key.items():
        for i in range(len(fails)):
            burst = [f for f in fails[i:] if f.timestamp - fails[i].timestamp <= window]
            if len(burst) >= threshold:
                last = burst[-1].timestamp
                success = next(
                    (e for e in events if e.event_id == ok_id and e.user == user and e.src_ip == ip and e.timestamp >= last),
                    None,
                )
                lines = [f.line_no for f in burst] + ([success.line_no] if success else [])
                if success:
                    findings.append(Finding("BRUTE_FORCE_SUCCESS", "CRITICAL",
                        f"{len(burst)}x Event 4625 for '{user}' from {ip} then 4624 SUCCESS — likely account compromise",
                        lines, "T1110.001"))
                else:
                    findings.append(Finding("BRUTE_FORCE", "HIGH",
                        f"{len(burst)}x Event 4625 for '{user}' from {ip} within {window}", lines, "T1110.001"))
                break
    return findings


def detect_password_spray(events: list[LogEvent], cfg: dict) -> list[Finding]:
    """One source failing against many DIFFERENT accounts (evades per-user lockout)."""
    fail_id = cfg["failed_logon_event_id"]
    users_by_ip: dict[str, set] = defaultdict(set)
    lines_by_ip: dict[str, list] = defaultdict(list)
    for e in events:
        if e.event_id == fail_id and e.src_ip:
            users_by_ip[e.src_ip].add(e.user)
            lines_by_ip[e.src_ip].append(e.line_no)
    return [
        Finding("PASSWORD_SPRAY", "HIGH", f"{ip} failed logons against {len(u)} distinct accounts: {sorted(u)}",
                lines_by_ip[ip], "T1110.003")
        for ip, u in users_by_ip.items() if len(u) >= 4
    ]


def detect_impossible_travel(events: list[LogEvent], cfg: dict) -> list[Finding]:
    """Two successful logons whose implied travel speed exceeds the threshold."""
    ok_id, max_kmh = cfg["successful_logon_event_id"], cfg["impossible_travel_kmh"]
    last_seen: dict[str, LogEvent] = {}
    findings = []
    for e in events:
        if e.event_id != ok_id or not e.geo or not e.user:
            continue
        prev = last_seen.get(e.user)
        if prev and prev.geo:
            km = haversine_km(prev.geo["lat"], prev.geo["lon"], e.geo["lat"], e.geo["lon"])
            hours = max((e.timestamp - prev.timestamp).total_seconds() / 3600, 1 / 60)
            speed = km / hours
            if km > 500 and speed > max_kmh:
                findings.append(Finding("IMPOSSIBLE_TRAVEL", "HIGH",
                    f"'{e.user}' logged in from {prev.geo['city']} then {e.geo['city']} "
                    f"({km:,.0f} km in {hours*60:.0f} min = {speed:,.0f} km/h)",
                    [prev.line_no, e.line_no], "T1078"))
        last_seen[e.user] = e
    return findings


def detect_port_scan(events: list[LogEvent], cfg: dict) -> list[Finding]:
    """One source hitting many distinct destination ports on the firewall."""
    ports: dict[str, set] = defaultdict(set)
    lines: dict[str, list] = defaultdict(list)
    for e in events:
        if e.source == "FW" and e.fields.get("dst") and e.src_ip:
            ports[e.src_ip].add(e.fields["dst"].split(":")[-1])
            lines[e.src_ip].append(e.line_no)
    return [
        Finding("PORT_SCAN", "MEDIUM", f"{ip} probed {len(p)} distinct ports ({', '.join(sorted(p, key=int))})",
                lines[ip], "T1046")
        for ip, p in ports.items() if len(p) >= cfg["port_scan_distinct_ports"]
    ]


def detect_threat_intel(events: list[LogEvent], cfg: dict) -> list[Finding]:
    """Match events against the offline threat-intel feed (IPs, user agents, file hashes)."""
    ti = cfg["threat_intel"]
    bad_ips, bad_hashes = set(ti["bad_ips"]), {h.lower() for h in ti["bad_file_hashes"]}
    hits: dict[tuple, list[int]] = defaultdict(list)
    for e in events:
        if e.src_ip in bad_ips:
            hits[("IP", e.src_ip)].append(e.line_no)
        ua = e.fields.get("ua", "").lower()
        for pat in ti["bad_user_agent_patterns"]:
            if pat.lower() in ua:
                hits[("USER_AGENT", e.fields["ua"])].append(e.line_no)
        for key in ("sha256", "md5", "sha1"):
            if e.fields.get(key, "").lower() in bad_hashes:
                hits[("FILE_HASH", e.fields[key])].append(e.line_no)
    sev = {"IP": "HIGH", "USER_AGENT": "MEDIUM", "FILE_HASH": "CRITICAL"}
    return [Finding(f"TI_MATCH_{kind}", sev[kind], f"Known-bad {kind.lower().replace('_', ' ')}: {val}", lns)
            for (kind, val), lns in hits.items()]


def detect_sqli(events: list[LogEvent], cfg: dict) -> list[Finding]:
    out = []
    for e in events:
        path = e.fields.get("path", "")
        if e.source == "HTTP" and SQLI_RE.search(path):
            out.append(Finding("SQL_INJECTION", "HIGH", f"SQLi pattern from {e.src_ip}: {path} (status {e.fields.get('status')})",
                               [e.line_no], "T1190"))
    return out


def detect_log_clearing(events: list[LogEvent], cfg: dict) -> list[Finding]:
    """Event ID 1102 (Security log cleared) / 104 (System log cleared): anti-forensics."""
    ids = set(cfg["log_cleared_event_ids"])
    return [Finding("AUDIT_LOG_CLEARED", "CRITICAL",
                    f"Event {e.event_id} on {e.host}: audit log cleared by '{e.user}'", [e.line_no], "T1070.001")
            for e in events if e.event_id in ids]


def detect_time_gaps(events: list[LogEvent], cfg: dict) -> list[Finding]:
    """Unexpected silence from a host that normally logs continuously (missing logs)."""
    max_gap_minutes = cfg.get("max_log_gap_minutes", 30)
    watched = set(cfg.get("continuous_log_hosts", []))
    by_host: dict[str, list[LogEvent]] = defaultdict(list)
    for e in events:
        if not watched or e.host in watched:
            by_host[e.host].append(e)
    out = []
    for host, evs in by_host.items():
        for a, b in zip(evs, evs[1:]):
            gap = (b.timestamp - a.timestamp).total_seconds() / 60
            if gap > max_gap_minutes:
                out.append(Finding("LOGGING_GAP", "MEDIUM", f"{host} silent for {gap:.0f} min ({a.timestamp:%H:%M} -> {b.timestamp:%H:%M})",
                                   [a.line_no, b.line_no], "T1562.002"))
    return out


ALL_RULES = [
    detect_brute_force, detect_password_spray, detect_impossible_travel, detect_port_scan,
    detect_threat_intel, detect_sqli, detect_log_clearing, detect_time_gaps,
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def run_detections(events: list[LogEvent], cfg: dict) -> list[Finding]:
    findings: list[Finding] = []
    for rule in ALL_RULES:
        findings.extend(rule(events, cfg))
    return sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity])


# --------------------------------------------------------------------------- #
# IOC extraction
# --------------------------------------------------------------------------- #
def extract_iocs(lines: list[str], events: list[LogEvent] | None = None) -> dict[str, list[str]]:
    """Pull IOCs out of raw text. Private (RFC1918) IPs are reported separately."""
    blob = "\n".join(lines)
    public, private = set(), set()
    for ip in IPV4_RE.findall(blob):
        (private if ipaddress.ip_address(ip).is_private else public).add(ip)
    sha256 = set(SHA256_RE.findall(blob))
    sha1 = set(SHA1_RE.findall(blob)) - {h[:40] for h in sha256}
    md5 = {h for h in MD5_RE.findall(blob) if not any(h in s for s in sha256 | sha1)}
    uas = sorted({e.fields["ua"] for e in (events or []) if "ua" in e.fields})
    domains = sorted({d.lower() for d in DOMAIN_RE.findall(blob)})
    return {
        "public_ips": sorted(public),
        "internal_ips": sorted(private),
        "sha256": sorted(sha256),
        "sha1": sorted(sha1),
        "md5": sorted(md5),
        "user_agents": uas,
        "domains": domains,
    }


# --------------------------------------------------------------------------- #
# Integrity (hash chain + HMAC manifest)
# --------------------------------------------------------------------------- #
def create_manifest(lines: list[str], salt: str, hmac_key: str) -> dict:
    """Seal a log set at collection time (chain-of-custody step)."""
    chain = build_hash_chain(lines, salt)
    manifest = {"count": len(lines), "chain": chain, "head": chain[-1] if chain else None}
    manifest["signature"] = hmac_sign(hmac_key, canonical_json({k: manifest[k] for k in ("count", "chain", "head")}))
    return manifest


def verify_manifest(lines: list[str], manifest: dict, salt: str, hmac_key: str) -> dict:
    """
    Verify (1) the manifest itself was not altered (HMAC) and (2) the lines
    still match the chain. Returns a report dict with a ``status`` of
    VALID / TAMPERED / MANIFEST_FORGED.
    """
    body = {k: manifest.get(k) for k in ("count", "chain", "head")}
    if not hmac_verify(hmac_key, canonical_json(body), manifest.get("signature", "")):
        return {"status": "MANIFEST_FORGED", "detail": "manifest HMAC invalid — cannot trust the reference hashes"}
    res = verify_hash_chain(lines, manifest["chain"], salt)
    if res["valid"]:
        return {"status": "VALID", "detail": f"{len(lines)} lines match sealed chain", **res}
    delta = res["length_delta"]
    kind = "modified"
    if delta < 0:
        kind = f"{-delta} line(s) deleted"
    elif delta > 0:
        kind = f"{delta} line(s) injected"
    return {"status": "TAMPERED", "detail": f"chain breaks at line {res['first_broken_index'] + 1} ({kind})", **res}


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SY0-701 4.9 (investigation data sources), 2.4 (indicators of malicious activity), 1.4 (hashing).",
    "concepts": [
        "Event ID 4625 = failed logon, 4624 = success, 4672 = special privileges, 1102 = Security log cleared.",
        "Correlation turns weak signals into strong ones: 4625 burst + 4624 from the same IP = compromise.",
        "Impossible travel compares geo distance / time between logons for one identity.",
        "A salted hash chain makes logs tamper-EVIDENT; an HMAC proves who sealed the manifest.",
    ],
    "failure_modes": [
        "Reviewing each log source in isolation, so the cross-source story is missed.",
        "Alerting on 4625 per user only — password spray (one IP, many users) slips under lockout thresholds.",
        "Collecting evidence without hashing it, breaking chain of custody in court.",
        "Not alerting on Event 1102 or on hosts that suddenly stop logging.",
    ],
    "ai_governance": [
        "An AI SOC agent may triage and enrich, but must cite the exact log lines (evidence) behind every claim.",
        "Agents must have READ-ONLY access to logs — never delete, rotate or modify audit data.",
        "Verify integrity before an agent analyses logs; poisoned logs = poisoned conclusions.",
        "Containment actions (blocking an IP, disabling an account) should require human approval on high-impact assets.",
    ],
    "exam_tips": [
        "'Many failed logins for many accounts from one source' => password spraying.",
        "'User logged in from two countries 30 minutes apart' => impossible travel.",
        "'Prove evidence was not altered' => hashing / chain of custody.",
        "Missing or out-of-cycle logs are themselves an indicator of compromise.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    cfg = policies["log_inspection"]
    lines: list[str] = data["raw_stream"]
    events, errors = parse_stream(lines, data.get("geoip", {}))

    ui.section("Step 1 — Parse & normalise raw log stream")
    by_src: dict[str, int] = defaultdict(int)
    for e in events:
        by_src[e.source] += 1
    ui.table("Normalised events by source", ["Source", "Events"], sorted(by_src.items()))
    for err in errors:
        ui.bullet(f"parse error: {err}", style="yellow")

    ui.section("Step 2 — Correlation & detection")
    findings = run_detections(events, cfg)
    ui.table("Findings", ["Severity", "Rule", "MITRE", "Summary", "Evidence lines"],
             [[f.severity, f.rule, f.mitre, f.summary, ",".join(map(str, f.evidence_lines[:8])) +
               ("…" if len(f.evidence_lines) > 8 else "")] for f in findings])

    ui.section("Step 3 — IOC extraction")
    iocs = extract_iocs(lines, events)
    ui.table("Indicators of Compromise", ["Type", "Values"],
             [[k, "\n".join(v) if v else "-"] for k, v in iocs.items()])

    ui.section("Step 4 — Log integrity (salted SHA-256 hash chain + HMAC manifest)")
    salt, key = cfg["integrity_salt"], policies["zero_trust"]["signing_key"]
    manifest = create_manifest(lines, salt, key)
    ui.print(f"  Sealed {manifest['count']} lines. Chain head: {manifest['head'][:32]}…")
    edited = list(lines)
    idx = next((i for i, l in enumerate(lines) if "EventID=4625" in l), 0)
    edited[idx] = re.sub(r"src=\S+", "src=10.0.0.99", edited[idx])  # hide the attacker's IP
    scenarios = {
        "Untouched evidence": list(lines),
        "Attacker deletes the 1102 log-cleared line": [l for l in lines if "EventID=1102" not in l],
        "Attacker edits the source IP of a 4625 line": edited,
        "Attacker injects a fake benign line": lines[:3] + ["2026-11-02T08:00:00Z DC01 WinEvt EventID=4624 user=admin src=10.0.0.5"] + lines[3:],
    }
    integrity = {}
    for label, candidate in scenarios.items():
        rep = verify_manifest(candidate, manifest, salt, key)
        integrity[label] = rep["status"]
        ui.status(label, rep["status"], rep["detail"])
    forged = dict(manifest, head="f" * 64)
    rep = verify_manifest(lines, forged, salt, key)
    integrity["Forged manifest"] = rep["status"]
    ui.status("Attacker rewrites the manifest itself", rep["status"], rep["detail"])

    ui.insight(INSIGHT)
    return {
        "events": len(events),
        "parse_errors": len(errors),
        "findings": len(findings),
        "critical": sum(f.severity == "CRITICAL" for f in findings),
        "integrity": integrity,
    }
