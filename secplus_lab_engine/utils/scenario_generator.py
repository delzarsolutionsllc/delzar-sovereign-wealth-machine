"""
Random scenario generator.

Challenge mode on fixed sample data can be memorised. These generators build
FRESH scenario data for a lab from a seed, so every run asks new questions
while staying reproducible (same seed → same scenario).

Each generator returns data in exactly the same shape as the lab's
``data/sample_*.json`` file, so the engine, ``run_demo`` and
``build_challenges`` work unchanged. Generators draw only from the policy
file (roles, CMDB, catalogs) and from fixed text banks, never the network.

Supported labs: see ``GENERATORS``. Labs whose scenarios are hand-crafted
stories (e.g. the log stream or the SOC pipeline) use their sample data.

Usage
-----
    python main.py challenge 9 --random --seed 42
    python main.py lab 12 --random
"""

from __future__ import annotations

import random
from datetime import date, timedelta

from utils.loader import load_data

AS_OF = "2026-11-03"


def _d(days_ago: int) -> str:
    return (date.fromisoformat(AS_OF) - timedelta(days=days_ago)).isoformat()


# --------------------------------------------------------------------------- #
# Lab 2 — Zero Trust access requests
# --------------------------------------------------------------------------- #
def gen_lab2(rng: random.Random, policies: dict) -> dict:
    zt = policies["zero_trust"]
    subjects = sorted(zt["entitlements"])
    resources = sorted(zt["resource_sensitivity"])
    cities = ["Tulsa, US", "Austin, US", "Denver, US", "Unknown (Tor)", "Lagos, NG"]
    reqs, outcomes = [], {}
    for i in range(1, rng.randint(5, 8) + 1):
        subj = rng.choice(subjects)
        res = rng.choice(zt["entitlements"][subj]) if rng.random() < 0.8 else rng.choice(resources)
        rep = rng.choices(["good", "suspicious", "bad"], [0.7, 0.2, 0.1])[0]
        rid = f"REQ-{i:02d}"
        reqs.append({
            "id": rid, "subject": subj, "resource": res, "action": rng.choice(["read", "write"]),
            "hour": rng.randint(0, 23), "mfa": rng.random() < 0.75,
            "device": {"id": f"DEV-{rng.randint(100, 999)}", "managed": rng.random() < 0.75,
                       "health_score": rng.choice([95, 90, 80, 72, 65, 40, 20])},
            "ip": f"{rng.randint(11, 220)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
            "ip_reputation": rep, "geo": rng.choice(cities), "usual_geo": "Tulsa, US",
            "user_risk": rng.choices(["low", "medium", "high"], [0.75, 0.15, 0.1])[0], "note": "generated scenario",
        })
        outcomes[rid] = rng.random() < 0.8
    return {"requests": reqs, "step_up_outcomes": outcomes,
            "pep_attacks": load_data("sample_access_requests.json")["pep_attacks"]}


# --------------------------------------------------------------------------- #
# Lab 6 — risk register
# --------------------------------------------------------------------------- #
RISK_TITLES = ["Ransomware on file servers", "Insider data theft", "Cloud storage misconfiguration",
               "Payment card skimming", "Regional power outage", "Stolen executive laptop",
               "DDoS on customer portal", "Supplier breach exposing our data"]


def gen_lab6(rng: random.Random, policies: dict) -> dict:
    risks = []
    for i, title in enumerate(rng.sample(RISK_TITLES, rng.randint(4, 6)), 1):
        av = rng.choice([5_000, 20_000, 100_000, 500_000, 2_000_000, 5_000_000])
        ef = rng.choice([0.1, 0.25, 0.4, 0.5, 0.75, 1.0])
        aro = rng.choice([0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 6])
        risk = {"id": f"R-{i:02d}", "title": title, "owner": rng.choice(["app_owner", "ops_lead", "cab_chair"]),
                "asset_value": av, "exposure_factor": ef, "aro": aro, "activity_optional": rng.random() < 0.3,
                "controls": [{"name": f"Control option {i}", "annual_cost": rng.choice([2_000, 10_000, 50_000, 250_000])}]}
        if rng.random() < 0.5:
            risk["controls"][0]["new_aro"] = round(aro * rng.uniform(0.05, 0.5), 3)    # control makes it rarer
        else:
            risk["controls"][0]["new_ef"] = round(rng.uniform(0.05, ef), 2)          # control limits the damage
        if rng.random() < 0.5:
            risk["insurance"] = {"annual_premium": rng.choice([3_000, 12_000, 60_000]), "coverage": rng.choice([0.5, 0.8, 0.9])}
        if risk["activity_optional"]:
            risk["avoidance"] = {"description": "Discontinue the activity", "annual_cost": rng.choice([0, 20_000, 100_000])}
        risks.append(risk)
    bia = []
    for name in rng.sample(sorted(policies["change_management"]["systems"]), 3):
        bia.append({"system": name, "rto_hours": rng.choice([1, 4, 8, 24]), "rpo_hours": rng.choice([1, 4, 24]),
                    "backup_interval_hours": rng.choice([1, 4, 12, 24]), "restore_time_hours": rng.choice([0.5, 2, 6, 12]),
                    "mtbf_hours": rng.choice([720, 4380, 8760]), "mttr_hours": rng.choice([0.5, 2, 6]),
                    "availability_target": rng.choice([0.99, 0.999])})
    return {"risk_appetite_ale": rng.choice([5_000, 10_000, 25_000]), "risks": risks, "bia": bia}


# --------------------------------------------------------------------------- #
# Lab 9 — vulnerability findings
# --------------------------------------------------------------------------- #
def gen_lab9(rng: random.Random, policies: dict) -> dict:
    bank = load_data("sample_vulns.json")["findings"]           # description ↔ type pairs
    assets = sorted(policies["change_management"]["systems"]) + ["ws-unknown-1"]
    controls = sorted(policies["vulnerability_management"]["exceptions"]["compensating_control_reduction"])
    approvers = policies["vulnerability_management"]["exceptions"]["authorized_approvers"] + ["ops_lead", "intern"]
    findings = []
    for i, src in enumerate(rng.sample(bank, rng.randint(5, len(bank))), 1):
        f = {"id": f"V-{i:02d}", "asset": rng.choice(assets), "cve": src["cve"], "cvss": rng.choice(
             [2.1, 3.7, 4.3, 5.3, 6.1, 6.8, 7.0, 7.5, 8.1, 8.8, 9.1, 9.8, 10.0]), "kev": rng.random() < 0.3,
             "patch_available": rng.random() < 0.8, "discovered": _d(rng.randint(0, 120)),
             "vuln_type": src["vuln_type"], "description": src["description"]}
        if rng.random() < 0.3:
            start = rng.randint(10, 200)
            f["exception"] = {"compensating_controls": rng.sample(controls, rng.randint(1, 2)),
                              "approved_by": rng.choice(approvers), "approved_on": _d(start),
                              "expires": _d(start - rng.choice([30, 90, 180, 240, 400])), "justification": "generated"}
        findings.append(f)
    return {"as_of": AS_OF, "findings": findings}


# --------------------------------------------------------------------------- #
# Lab 11 — firewall rule set
# --------------------------------------------------------------------------- #
def gen_lab11(rng: random.Random, policies: dict) -> dict:
    sample = load_data("sample_firewall.json")["rulesets"]
    pool = [r for rs in sample for r in rs["rules"] if not (r["src"] == "any" and r["dst"] == "any" and r["action"] == "deny")]
    rules = [dict(r) for r in rng.sample(pool, rng.randint(5, 9))]
    for i, r in enumerate(rules, 1):
        r["id"] = i
        if rng.random() < 0.15:
            r["comment"] = ""
    if rng.random() < 0.6:
        rules.append({"id": len(rules) + 1, "action": "deny", "src": "any", "dst": "any", "proto": "any", "ports": "any",
                      "log": rng.random() < 0.8, "comment": "default deny"})
    return {"rulesets": [{"name": f"generated-fw-{rng.randint(100, 999)}", "zones": sample[0]["zones"], "rules": rules}]}


# --------------------------------------------------------------------------- #
# Lab 12 — host configuration snapshots
# --------------------------------------------------------------------------- #
def _value_for(check: dict, passing: bool, rng: random.Random):
    op, v = check["op"], check["value"]
    if op == "eq":
        if passing:
            return v
        if isinstance(v, bool):
            return not v
        return {"no": "yes", "enforcing": "permissive", "success_failure": "none"}.get(v, "unknown")
    if op == "ge":
        return v + rng.randint(0, 10) if passing else max(0, v - rng.randint(1, v if v else 1))
    if op == "le":
        return v if passing else v + rng.randint(1, 5)
    if op == "between":
        return rng.randint(v[0], v[1]) if passing else v[1] + rng.randint(1, 5)
    if op == "includes":
        return list(v) if passing else list(v[:-1])
    if op == "excludes":
        return [] if passing else [rng.choice(v)]
    return None


def gen_lab12(rng: random.Random, policies: dict) -> dict:
    profiles = policies["hardening_baselines"]["profiles"]
    hosts = []
    for i in range(rng.randint(3, 5)):
        profile = rng.choice(sorted(profiles))
        settings, previous, deviations = {}, {}, []
        services_now, services_prev = [], []
        for chk in profiles[profile]:
            now_pass, prev_pass = rng.random() < 0.7, rng.random() < 0.75
            if chk["setting"] == "services_running":           # several checks share one list setting
                services_now += _value_for(chk, now_pass, rng)
                services_prev += _value_for(chk, prev_pass, rng)
                continue
            if rng.random() < 0.06:
                continue                                         # not reported → MISSING
            settings[chk["setting"]] = _value_for(chk, now_pass, rng)
            previous[chk["setting"]] = _value_for(chk, prev_pass, rng)
            if not now_pass and rng.random() < 0.15:
                deviations.append({"check": chk["id"], "ticket": f"EXC-{rng.randint(1000, 9999)}",
                                   "reason": "generated deviation", "expires": _d(rng.choice([-120, -30, 10]))})
        settings["services_running"] = sorted(set(services_now) | {"sshd" if "linux" in profile else "W3SVC"})
        previous["services_running"] = sorted(set(services_prev) | {"sshd" if "linux" in profile else "W3SVC"})
        hosts.append({"name": f"{'lnx' if 'linux' in profile else 'WIN'}-{rng.randint(10, 99)}-{i}", "profile": profile,
                      "role": "generated host", "settings": settings, "previous_settings": previous,
                      "approved_deviations": deviations})
    return {"as_of": AS_OF, "hosts": hosts}


# --------------------------------------------------------------------------- #
# Lab 13 — threat scenarios
# --------------------------------------------------------------------------- #
def gen_lab13(rng: random.Random, policies: dict) -> dict:
    from labs.lab13_threat_classifier import UNDETERMINED, classify

    cfg = policies["threat_classification"]
    vectors = sorted(cfg["vectors"])
    scenarios = []
    for i in range(1, rng.randint(5, 7) + 1):
        for _ in range(50):                                      # retry until the evidence is decisive
            actor = rng.choice(sorted(cfg["actors"]))
            pool = sorted(cfg["actors"][actor])
            ind = rng.sample(pool, rng.randint(2, len(pool)))
            sc = {"id": f"T-{i:02d}", "title": f"Generated incident {i}", "indicators": ind,
                  "initial_access": rng.choice(vectors)}
            if classify(sc, cfg).actor != UNDETERMINED:
                break
        sc["narrative"] = ("Analysts observed: " + "; ".join(x.replace("_", " ") for x in sc["indicators"])
                           + f". Initial access: {sc['initial_access'].replace('_', ' ')}.")
        scenarios.append(sc)
    return {"scenarios": scenarios}


# --------------------------------------------------------------------------- #
# Lab 14 — resilience designs
# --------------------------------------------------------------------------- #
def gen_lab14(rng: random.Random, policies: dict) -> dict:
    cfg = policies["resilience"]
    systems = []
    for name in rng.sample(sorted(policies["change_management"]["systems"]), rng.randint(3, 5)):
        systems.append({"name": name,
                        "targets": {"rto_hours": rng.choice([1, 4, 8, 24, 72]), "rpo_hours": rng.choice([0, 0.25, 1, 4, 24]),
                                    "disk_failures": rng.choice([1, 1, 2]), "power_outage_hours": rng.choice([1, 4, 8]),
                                    "survive_site_loss": rng.random() < 0.6},
                        "current": {"site": rng.choice([None, *sorted(cfg["site_types"])]),
                                    "replication": rng.choice([None, None, *sorted(cfg["replication"])]),
                                    "clustering": rng.choice([None, None, *sorted(cfg["clustering"])]),
                                    "raid": rng.choice(sorted(cfg["raid"])),
                                    "backup": {"type": rng.choice(sorted(cfg["backup_restore_multiplier"])),
                                               "frequency_hours": rng.choice([1, 4, 12, 24]), "offsite": rng.random() < 0.7},
                                    "data_tb": rng.choice([0.1, 0.5, 1, 2, 5]), "ups_minutes": rng.choice([0, 10, 30]),
                                    "generator_hours": rng.choice([0, 4, 12]),
                                    "last_restore_test": rng.choice([None, _d(30), _d(200), _d(500)]),
                                    "last_dr_test": rng.choice([None, _d(60), _d(300), _d(600)])}})
    return {"as_of": AS_OF, "systems": systems}


# --------------------------------------------------------------------------- #
# Lab 15 — vendors
# --------------------------------------------------------------------------- #
def gen_lab15(rng: random.Random, policies: dict) -> dict:
    cfg = policies["vendor_risk"]
    every_clause = sorted({c for v in cfg["required_clauses"].values() for c in v} | {"MOU"})
    vendors = []
    for i in range(1, rng.randint(4, 6) + 1):
        answers = {q: rng.choices(["yes", "partial", "no"], [0.65, 0.2, 0.15])[0]
                   for q in cfg["questionnaire"] if rng.random() < 0.9}
        vendors.append({"id": f"VN-{i}", "name": f"Vendor {chr(64 + i)}", "service": "generated service",
                        "relationship": rng.choice(["vendor", "vendor", "partner"]),
                        "data": rng.choice(sorted(cfg["data_sensitivity"])), "access": rng.choice(sorted(cfg["access_level"])),
                        "criticality": rng.choice(sorted(cfg["criticality"])), "answers": answers,
                        "contract": {"clauses": sorted(rng.sample(every_clause, rng.randint(2, len(every_clause)))),
                                     "sla": {"uptime": rng.choice([99.0, 99.5, 99.9, 99.95]),
                                             "breach_notification_hours": rng.choice([24, 48, 72, 120])}}})
    return {"vendors": vendors}


# --------------------------------------------------------------------------- #
# Lab 17 — TLS certificate chains
# --------------------------------------------------------------------------- #
def _fault(name: str, sc: dict, rng: random.Random) -> None:
    leaf, chain = sc["chain"][0], sc["chain"]
    if name == "expired":
        leaf["not_before"], leaf["not_after"] = _d(400), _d(rng.randint(1, 30))
    elif name == "not_yet_valid":
        leaf["not_before"] = _d(-rng.randint(2, 20))
    elif name == "hostname":
        sc["hostname"] = rng.choice(["a.b." + sc["domain"], "other-" + sc["domain"], "dev.portal." + sc["domain"]])
    elif name == "missing_intermediate":
        del chain[1:]
    elif name == "self_signed":
        del chain[1:]
        leaf["issuer"], leaf["is_ca"] = leaf["subject"], True
    elif name == "untrusted_root":
        if len(chain) < 2:            # an earlier fault already removed the intermediate
            return
        chain[1]["issuer"] = "Shady Root CA"
        chain.append({**chain[1], "subject": "Shady Root CA", "issuer": "Shady Root CA", "serial": "9999"})
    elif name == "revoked":
        sc["revocation"] = {"crl": {leaf["issuer"]: [leaf["serial"]]},
                            "ocsp": {c["serial"]: "good" for c in chain[1:]}}
    elif name == "weak_key":
        leaf["key_bits"] = 1024
    elif name == "weak_sig":
        leaf["sig_alg"] = rng.choice(["sha1WithRSAEncryption", "md5WithRSAEncryption"])
    elif name == "eku":
        leaf["eku"] = ["clientAuth"]
    elif name == "no_revocation":
        sc["revocation"] = {"ocsp": {leaf["serial"]: "unknown"}}
    elif name == "pin":
        sc["pinned_spki"] = ["feedfacecafe"]
    elif name == "long_validity":
        leaf["not_before"], leaf["not_after"] = _d(100), _d(-500)


def gen_lab17(rng: random.Random, policies: dict) -> dict:
    faults = ["expired", "not_yet_valid", "hostname", "missing_intermediate", "self_signed", "untrusted_root", "revoked",
              "weak_key", "weak_sig", "eku", "no_revocation", "pin", "long_validity"]
    scenarios = []
    for i in range(1, rng.randint(5, 8) + 1):
        domain = rng.choice(["delzarsolutions.com", "example.org", "acme-partner.com"])
        host = f"{rng.choice(['www', 'api', 'shop', 'mail', 'vpn'])}.{domain}"
        serial = str(3000 + i)
        sc = {"id": f"P-{i:02d}", "title": "Generated connection", "hostname": host, "domain": domain,
              "chain": [
                  {"subject": host, "issuer": "Delzar Issuing CA 1", "serial": serial, "not_before": _d(60), "not_after": _d(-300),
                   "key_type": "RSA", "key_bits": rng.choice([2048, 3072]), "sig_alg": "sha256WithRSAEncryption", "is_ca": False,
                   "san": [host, f"*.{domain}"] if rng.random() < 0.3 else [host], "eku": ["serverAuth"], "spki_sha256": f"{rng.getrandbits(48):012x}"},
                  {"subject": "Delzar Issuing CA 1", "issuer": "Delzar Root CA G2", "serial": "0101", "not_before": "2024-01-01",
                   "not_after": "2030-01-01", "key_type": "RSA", "key_bits": 4096, "sig_alg": "sha384WithRSAEncryption",
                   "is_ca": True, "spki_sha256": "c0ffee0101"}],
              "revocation": {"ocsp": {serial: "good", "0101": "good"}}}
        for f in rng.sample(faults, rng.choice([0, 1, 1, 1, 2])):
            _fault(f, sc, rng)
        del sc["domain"]
        scenarios.append(sc)
    return {"as_of": AS_OF, "scenarios": scenarios}


# --------------------------------------------------------------------------- #
# Lab 23
# --------------------------------------------------------------------------- #
def gen_lab23(rng: random.Random, policies: dict) -> dict:
    cfg = policies["audit"]
    techs = sorted(cfg["techniques"])
    recon = sorted(t for t in techs if cfg["techniques"][t]["category"] in ("passive_recon", "active_recon"))
    allowed = sorted(set(rng.sample(recon, rng.randint(3, len(recon)))) - set(cfg["always_prohibited"]))
    others = [t for t in techs if t not in allowed]
    prohibited = sorted(set(rng.sample(others, rng.randint(1, min(3, len(others))))) | set(cfg["always_prohibited"]))
    start = rng.choice([7, 8, 9, 20])
    end = (start + rng.choice([8, 9, 10])) % 24
    lo, hi = rng.randint(1, 3), rng.randint(6, 12)
    domain = rng.choice(["northwind.example", "contoso-lab.example", "fabrikam.example"])
    eng = {
        "client": rng.choice(["Northwind Fabrication", "Contoso Lab", "Fabrikam Ltd"]) + " (fictional)",
        "authorization": {"signed_by": "A. Tester", "role": rng.choice(cfg["authorized_signer_roles"] * 4 + ["intern"]),
                          "signed": rng.random() < 0.9, "valid_from_day": lo, "valid_to_day": hi},
        "scope": {"in_scope_cidrs": ["198.51.100.0/24", "10.20.0.0/16"], "in_scope_domains": [domain],
                  "out_of_scope": ["10.20.5.0/24", "198.51.100.200", "mail." + domain]},
        "allowed_techniques": allowed, "prohibited": prohibited,
        "window": {"start_hour": start, "end_hour": end},
        "environment": rng.choice(sorted(cfg["environment_types"])),
        "emergency_contact": "SOC duty manager, +1-555-0100" if rng.random() < 0.9 else "",
    }
    targets = ["198.51.100.%d" % rng.randint(1, 254), "10.20.%d.%d" % (rng.randint(0, 9), rng.randint(1, 254)),
               "10.20.5.%d" % rng.randint(1, 254), "198.51.100.200", "203.0.113.%d" % rng.randint(1, 254),
               domain, "portal." + domain, "mail." + domain, "shop.other.example"]
    actions = []
    for i in range(1, rng.randint(6, 10) + 1):
        tech = rng.choice(techs + allowed * 2 + ["unlisted_tool"])
        cat = cfg["techniques"].get(tech, {}).get("category")
        declared = "passive" if cat == "passive_recon" or rng.random() < 0.15 else "active"
        actions.append({"id": f"PT-{i:02d}", "tester": rng.choice(["ai-agent-1", "j.diaz"]),
                        "day": rng.randint(max(0, lo - 1), hi + 2), "hour": rng.choice([rng.randint(0, 23), (start + rng.randint(0, 7)) % 24]),
                        "target": rng.choice(targets + targets[:2] * 2 + targets[5:7]), "technique": tech, "recon": declared})
    drivers = sorted(cfg["assessment_rules"])
    needs = [{"id": f"AN-{i}", "description": "generated assessment need",
              "driver": rng.choice(drivers + ["unknown_driver"]) if i > 1 else rng.choice(drivers),
              "independence_required": rng.random() < 0.5} for i in range(1, rng.randint(3, 5) + 1)]
    return {"engagement": eng, "actions": actions, "assessment_needs": needs}


# --------------------------------------------------------------------------- #
# Lab 20
# --------------------------------------------------------------------------- #
def gen_lab20(rng: random.Random, policies: dict) -> dict:
    cfg = policies["iac"]
    bad = lambda p=0.12: rng.random() < p                     # noqa: E731
    owners = ["web-team", "platform", "data-team", "it-ops", "payments"]
    resources = []
    for i in range(1, rng.randint(6, 10) + 1):
        rtype = rng.choice(cfg["known_types"] + ["dns_zone"]) if bad(0.08) else rng.choice(cfg["known_types"])
        tags = {"owner": rng.choice(owners), "data_classification": rng.choice(["public", "internal", "confidential"])}
        if bad(0.15):
            del tags[rng.choice(sorted(tags))]
        if rng.random() < 0.3:
            tags["criticality"] = "critical"
        r = {"id": f"{rtype.split('_')[0]}-{i}", "type": rtype, "tags": tags}
        if rtype in ("vm", "database", "load_balancer", "container"):
            r["availability_zones"] = ["zone-a"] if bad(0.3) else ["zone-a", "zone-b"]
        if rtype == "storage_bucket":
            r.update(acl="public-read" if bad(0.15) else "private", encryption_at_rest=not bad(), logging=not bad())
        elif rtype == "security_group":
            r["ingress"] = [{"port": 443, "cidr": "0.0.0.0/0"},
                            {"port": rng.choice([22, 3389, 5432]), "cidr": "0.0.0.0/0" if bad(0.2) else "10.0.0.0/8"}]
        elif rtype == "vm":
            r.update(encrypted_disk=not bad(), public_ip=bad())
        elif rtype == "database":
            r.update(publicly_accessible=bad(0.15), encryption_at_rest=not bad(), backup_retention_days=rng.choice([1, 7, 14, 35]))
        elif rtype == "iam_policy":
            r["statements"] = [{"effect": "Allow", "action": "*" if bad(0.15) else "storage:GetObject",
                                "resource": "*" if bad(0.5) else "arn:example:storage:::bucket-1/*"}]
        elif rtype == "container":
            r.update(privileged=bad(0.15), run_as_root=bad(0.3), secrets_in_env=bad(0.1))
        elif rtype == "function":
            r.update(secrets_in_env=bad(0.15), logging=not bad())
        elif rtype == "load_balancer":
            r.update(https_only=not bad(0.15), logging=not bad())
        for k in [k for k in r if k not in ("id", "type", "tags")]:
            if bad(0.04):                                       # an undeclared property -> deny by default
                del r[k]
        resources.append(r)
    return {"plan": {"name": f"generated-plan-{rng.randint(100, 999)}", "resources": resources}}


# --------------------------------------------------------------------------- #
# Lab 22
# --------------------------------------------------------------------------- #
def gen_lab22(rng: random.Random, policies: dict) -> dict:
    cfg = policies["compliance"]
    today = rng.randint(900, 1200)
    regimes = sorted(cfg["regimes"]) + ["unknown_regime"] * (rng.random() < 0.15)
    cases = []
    for i in range(1, rng.randint(2, 3) + 1):
        rtype = rng.choice(sorted(cfg["dsr_types"]))
        received = today - rng.randint(0, 60)
        c = {"id": f"DSR-{i}", "kind": "dsr", "summary": f"generated {rtype} request", "regime": rng.choice(regimes),
             "request_type": rtype, "received_day": received,
             "completed_day": rng.choice([None, min(today, received + rng.randint(5, 60))]),
             "identity_verified": rng.random() < 0.8, "received_by": rng.choice(["controller", "controller", "processor"]),
             "forwarded_to_controller": rng.random() < 0.6}
        if rtype == "erasure" and rng.random() < 0.5:
            c["hold"] = rng.choice(sorted(cfg["erasure_exemption_grounds"]) + ["business_preference"])
            c["hold_documented"] = rng.random() < 0.7
        if rng.random() < 0.08:
            del c["identity_verified"]
        cases.append(c)
    for i in range(1, rng.randint(1, 3) + 1):
        found = today * 24 - rng.randint(1, 200)
        sent = found + rng.randint(1, 120)
        cases.append({"id": f"BR-{i}", "kind": "breach", "summary": "generated breach", "regime": rng.choice(regimes),
                      "discovered_hour": found, "regulator_notified_hour": sent if sent <= today * 24 and rng.random() < 0.7 else None,
                      "risk": rng.choice(["low", "medium", "high"]), "subjects_notified": rng.random() < 0.6})
    for i in range(1, rng.randint(1, 3) + 1):
        rtype = rng.choice(sorted(cfg["retention_schedule"]))
        hi = cfg["retention_schedule"][rtype]["max_days"]
        created = today - rng.randint(1, hi + 120)
        destroyed = rng.randint(created, today) if rng.random() < 0.4 else None
        cases.append({"id": f"RT-{i}", "kind": "retention", "summary": f"generated {rtype}", "record_type": rtype,
                      "created_day": created, "destroyed_day": destroyed, "legal_hold": rng.random() < 0.25})
    for i in range(1, rng.randint(1, 2) + 1):
        atype = rng.choice(sorted(cfg["attestations"]))
        c = {"id": f"AT-{i}", "kind": "attestation", "summary": f"generated {atype}", "attestation": atype,
             "subject": f"employee E-{rng.randint(1000, 9999)}",
             "signed_day": None if rng.random() < 0.15 else today - rng.randint(0, 420)}
        if rng.random() < 0.1:
            c["exception"] = {"documented": True, "reason": "on documented leave; acknowledge on return"}
        cases.append(c)
    return {"as_of_day": today, "cases": cases}


# --------------------------------------------------------------------------- #
# Lab 21
# --------------------------------------------------------------------------- #
def gen_lab21(rng: random.Random, policies: dict) -> dict:
    cfg = policies["asset_mgmt"]
    today, limit = 300, cfg["missing_after_days"]
    names = ["web", "db", "laptop", "print", "vm", "cam", "nas", "kiosk", "badge", "voip"]
    cmdb, scan = [], []
    for i in range(1, rng.randint(5, 9) + 1):
        mac = f"00:1a:2b:00:00:{i:02x}"
        host = f"{rng.choice(names)}-{i:02d}"
        status = rng.choices(["active", "retired", "in_storage"], [0.8, 0.1, 0.1])[0]
        online = status == "active" and rng.random() < 0.6
        last = today if online else today - rng.choice([1, limit - 1, limit, limit + 1, limit + 10, 120])
        cmdb.append({"asset_id": f"A-{i:03d}", "hostname": host, "mac": mac,
                     "owner": rng.choice(["", "it-ops", "dev-team", "hr-it", "finance"]) if rng.random() < 0.3
                     else rng.choice(["it-ops", "dev-team", "hr-it", "finance"]),
                     "classification": "" if rng.random() < 0.2 else rng.choice(cfg["classifications"]),
                     "status": status, "last_seen": last})
        if online:
            scan.append({"mac": mac.upper() if rng.random() < 0.3 else mac, "hostname": host,
                         "ip": f"10.20.{rng.randint(1, 9)}.{10 + i}"})
    for j in range(rng.randint(1, 3)):
        scan.append({"mac": f"b8:27:eb:{rng.randint(0, 255):02x}:{rng.randint(0, 255):02x}:{j:02x}",
                     "hostname": rng.choice(["raspberrypi", "android-phone", "smart-tv", "personal-laptop"]),
                     "ip": f"10.20.7.{100 + j}"})
    media = list(cfg["media_types"])
    methods = sorted(cfg["methods"]) + ["quick_format", "delete_files"]
    disposals = []
    for k in range(1, rng.randint(5, 8) + 1):
        third = rng.random() < 0.4
        disposals.append({
            "id": f"D-{k}", "asset_id": f"A-{100 + k}",
            "media": rng.choice(media) if rng.random() < 0.95 else "floppy",
            "classification": rng.choice(cfg["classifications"]),
            "method": rng.choice(methods),
            "destination": rng.choice(["reuse_within_org", "leaving_org"]),
            "performed_by": "third_party" if third else "internal",
            "certificate_of_destruction": third and rng.random() < 0.7,
            "legal_hold": rng.random() < 0.1,
            "retention_until": rng.choice([0, 0, 150, today - 1, today, today + 30]),
        })
    return {"today": today, "cmdb": cmdb, "scan": scan, "disposals": disposals}


# --------------------------------------------------------------------------- #
# Lab 24
# --------------------------------------------------------------------------- #
def gen_lab24(rng: random.Random, policies: dict) -> dict:
    cfg = policies["awareness"]
    day = rng.randint(380, 420)
    paths = [["delivered"], ["delivered", "opened"], ["delivered", "reported"], ["delivered", "opened", "reported"],
             ["delivered", "opened", "clicked"], ["delivered", "opened", "clicked", "reported"],
             ["delivered", "opened", "clicked", "submitted_credentials"], []]
    roles = cfg["known_roles"] + ["staff", "staff", "contractor"]
    employees = []
    for i in range(1, rng.randint(8, 14) + 1):
        events = list(rng.choice(paths))
        emp = {"id": f"E{i:02d}", "dept": rng.choice(["Finance", "Engineering", "Sales", "HR"]),
               "role": rng.choice(roles), "events": events, "prior_failures": rng.choice([0, 0, 0, 1, 1, 2, 3])}
        if "reported" in events:
            emp["report_minutes"] = rng.choice([1, 3, 5, 8, 15, 30, 90])
        if rng.random() < 0.85:
            emp["training_completed_day"] = day - rng.randint(0, 450)
        employees.append(emp)
    cats = sorted(cfg["technical_controls"]) + ["data_export"]
    behaviours = []
    for i in range(1, rng.randint(3, 6) + 1):
        obs = {"id": f"B{i}", "description": "generated behaviour observation", "category": rng.choice(cats)}
        for attr in cfg["behaviour_required_attributes"]:
            if rng.random() < 0.92:
                obs[attr] = rng.random() < 0.5
        behaviours.append(obs)
    trusted = cfg["trusted_domains"][0]
    look = trusted.replace("l", "1", 1) if "l" in trusted else trusted.replace("o", "0", 1)
    messages = []
    for i in range(1, rng.randint(2, 4) + 1):
        sender = rng.choice([f"it@{trusted}", f"hr@{trusted}", f"helpdesk@{look}", "billing@vendor.example.net", ""])
        subject = rng.choice(["Quarterly update", "URGENT: action required", "Invoice attached", "Team lunch"])
        body = rng.choice(["See the notes below.", "Verify your account password immediately.",
                           "Please send payment by wire transfer today.", "Agenda is on the intranet."])
        links = rng.choice([[], [{"text": "Intranet", "href": f"https://intranet.{trusted}/"}],
                            [{"text": f"https://portal.{trusted}", "href": "http://portal.example-login.net/"}]])
        attachments = rng.choice([[], ["notes.pdf"], ["invoice.html"], ["update.zip"]])
        messages.append({"id": f"MSG-{i}", "from": sender, "subject": subject, "body": body,
                         "links": links, "attachments": attachments})
    return {"campaign": {"id": f"PH-GEN-{day}", "day": day, "template": "generated campaign"},
            "employees": employees, "behaviours": behaviours, "messages": messages}


# --------------------------------------------------------------------------- #
# Lab 18
# --------------------------------------------------------------------------- #
def gen_lab18(rng: random.Random, policies: dict) -> dict:
    cfg = policies["data_protection"]

    def pan(valid: bool) -> str:
        body = [rng.choice([4, 5])] + [rng.randint(0, 9) for _ in range(14)]
        total = 0
        for i, d in enumerate(reversed(body)):          # check digit position is index 0 after append
            d = d * 2 if i % 2 == 0 else d
            total += d - 9 if d > 9 else d
        check = (10 - total % 10) % 10
        digits = "".join(map(str, body + [(check + (0 if valid else rng.randint(1, 9))) % 10]))
        return " ".join(digits[i:i + 4] for i in range(0, 16, 4))

    content = {
        "plain": lambda: f"Store {rng.randint(10, 99)} weekly footfall report",
        "random_number": lambda: f"Order ref {pan(False)} shipped",
        "card": lambda: f"refund to card {pan(True)}",
        "ssn": lambda: f"emp=E{rng.randint(1000, 9999)} ssn={rng.randint(100, 665)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}",
        "email": lambda: f"member=user{rng.randint(1, 999)}@example.eu phone=+49 301-555-01{rng.randint(10, 99)}",
        "health": lambda: f"patient MRN-{rng.randint(100000, 9999999)} follow-up",
        "password": lambda: f"user=u{rng.randint(1, 99)} password=Pw{rng.randint(1000, 9999)}!",
        "api_key": lambda: "aws_access_key_id=AKIA" + "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(16)),
        "trade_secret": lambda: "CONFIDENTIAL - TRADE SECRET: laminate ratios",
        "legal": lambda: "ATTORNEY-CLIENT PRIVILEGED: draft settlement",
    }
    dest_types = sorted({t for v in cfg["allowed_destinations"].values() for t in v} | {"secrets_vault"})
    regions = ["us"] * 5 + ["eu", "uk", "apac"]
    labels = sorted(cfg["classification_rank"]) + ["internal"]
    methods = ["encryption", "hashing", "masking", "tokenization", "permission_restrictions"]
    flows = []
    for i in range(1, rng.randint(5, 8) + 1):
        kinds = rng.sample(sorted(content), rng.choice([1, 1, 2]))
        flow = {"id": f"DF-{i}", "description": f"generated flow ({', '.join(kinds)})",
                "records": [content[k]() for k in kinds],
                "declared_classification": rng.choice(labels) if rng.random() < 0.2 else rng.choice(["public", "private", "confidential"]),
                "state": rng.choice(["at_rest", "in_transit", "in_use"]),
                "destination": {"type": rng.choice(dest_types if rng.random() < 0.3 else ["internal_db", "internal_app", "support_console"]),
                                "region": rng.choice(regions), "approved": rng.random() < 0.9},
                "encrypted_channel": rng.random() < 0.7,
                "protection": rng.sample(methods, rng.choice([0, 1, 1, 2]))}
        if rng.random() < 0.3:
            flow["data_origin"] = rng.choice(["eu", "uk", "us"])
        flows.append(flow)
    return {"flows": flows}


# --------------------------------------------------------------------------- #
# Lab 19
# --------------------------------------------------------------------------- #
def gen_lab19(rng: random.Random, policies: dict) -> dict:
    cfg = policies["siem"]
    rules = {r["id"]: r for r in cfg["rules"]}
    base = 1791936000                              # 2026-10-14T00:00:00Z (a Wednesday)
    evs, scen = [], {"S0": {"label": "benign", "description": "normal background activity"}}

    def ts(sec, as_int=None):
        if as_int if as_int is not None else rng.random() < 0.3:
            return base + sec
        return f"2026-10-14T{sec // 3600:02d}:{sec % 3600 // 60:02d}:{sec % 60:02d}Z"

    def add(sec, sc, **kw):
        evs.append({"ts": ts(sec), "scenario": sc, **kw})

    def S(label, text):
        sid = f"S{len(scen)}"
        scen[sid] = {"label": label, "description": text}
        return sid

    def fail(user, ip):
        return {"source": "auth", "host": "VPN-1", "user": user, "src_ip": ip, "action": "login", "outcome": "failure"}

    def ok(user, ip, geo):
        return {**fail(user, ip), "outcome": "success", "geo": geo}

    # background: every source except possibly a silent one
    gaps = rules["SIEM-005"]["params"]["max_gap_seconds"]
    silent = rng.choice(sorted(gaps)) if rng.random() < 0.6 else None
    for src in sorted(gaps):
        if src == silent:
            sid = S("actionable", f"the {src} log forwarder stops sending events")
            add(rng.randint(600, 3600), sid, source=src, host="LOG-1", action="heartbeat", outcome="ok")
            continue
        for h in (1, 4, 7, 10):
            add(h * 3600 + rng.randint(0, 1500), "S0", source=src, host="WS-11", action="heartbeat", outcome="ok")

    bf = rules["SIEM-001"]["params"]
    n = bf["count"] + rng.choice([-2, -1, 0, 1])
    t = rng.randint(2, 3) * 3600
    sid = S("actionable" if n >= bf["count"] else "benign",
            f"{n} failed logins for user dana from one IP" if n >= bf["count"] else "dana mistypes her password")
    for i in range(n):
        add(t + i * 15, sid, **fail("dana", "203.0.113.50"))
    if rng.random() < 0.5:
        add(t + n * 15 + rng.choice([30, 120, 900]), sid, **ok("dana", "203.0.113.50", "Lagos"))

    sp = rules["SIEM-002"]["params"]
    m = sp["count"] + rng.choice([-1, 0, 1])
    sid = S("actionable" if m >= sp["count"] else "benign", f"one IP fails against {m} different users")
    for i in range(m):
        add(4 * 3600 + i * 20, sid, **fail(f"user{i + 1}", "198.51.100.23"))

    cities = sorted(cfg["geo"])
    a, b = rng.sample(cities, 2)
    gap_min = rng.choice([45, 90, 600])
    sid = S(rng.choice(["actionable", "benign"]), f"erin logs in from {a} then {b} {gap_min} min later")
    add(6 * 3600, sid, **ok("erin", "198.51.100.40", a))
    add(6 * 3600 + gap_min * 60, sid, **ok("erin", "192.0.2.150", b))

    ah = rules["SIEM-004"]["params"]
    hour = rng.choice([2, 3, 6, 10, 11])
    lo, hi = ah["business_hours"]
    sid = S("benign" if lo <= hour < hi else "actionable", f"privileged change at {hour:02d}:30 UTC")
    add(hour * 3600 + 1800, sid, source="app", host="ERP-1", user="frank", action=rng.choice(ah["actions"]),
        outcome="success")

    ps = rules["SIEM-007"]["params"]
    sups = [s for s in cfg.get("suppressions", []) if s.get("rule") == "SIEM-007" and s.get("match", {}).get("src_ip")]
    for k, s in enumerate(rng.sample(sups, min(len(sups), rng.randint(1, 2)))):
        valid = bool(s.get("owner")) and str(s.get("expires", "")) > "2026-10-14"
        sid = S("benign" if valid else "actionable", f"port scan from {s['match']['src_ip']} ({s.get('reason')})")
        for i in range(ps["count"] + rng.choice([-1, 0, 2])):
            add(7 * 3600 + k * 600 + i * 5, sid, source="firewall", host="FW-1", src_ip=s["match"]["src_ip"],
                dst_ip="10.0.2.10", dst_port=20 + i * 3, action="connection", outcome="denied")

    ti = cfg["threat_intel"]
    if rng.random() < 0.7:
        sid = S("actionable", "workstation contacts a known-bad indicator")
        if rng.random() < 0.5:
            add(8 * 3600, sid, source="dns", host="WS-17", src_ip="10.0.3.17", domain=rng.choice(ti["domains"]),
                action="query", outcome="ok")
        else:
            add(8 * 3600, sid, source="firewall", host="FW-1", src_ip="10.0.3.17", dst_ip=rng.choice(ti["ips"]),
                dst_port=443, action="connection", outcome="allowed")

    outcome = rng.choice(["allowed", "quarantined"])
    sid = S("actionable" if outcome == "allowed" else "benign", f"EDR detects malware, outcome {outcome}")
    add(9 * 3600, sid, source="edr", host="WS-22", action="malware_detected", outcome=outcome, file="dropper.exe")

    if rng.random() < 0.4:
        sid = S("actionable", "an app writes a non-ISO timestamp after an update")
        evs.append({"ts": "14/10/2026 10:15", "source": "app", "host": "HR-APP-2", "action": "export_database",
                    "outcome": "success", "scenario": sid})

    for i, e in enumerate(evs, 1):
        e["id"] = f"EV-{i:02d}"
    return {"window": {"start": "2026-10-14T00:00:00Z", "end": "2026-10-14T12:00:00Z"}, "scenarios": scen,
            "events": evs}


GENERATORS = {2: gen_lab2, 6: gen_lab6, 9: gen_lab9, 11: gen_lab11, 12: gen_lab12, 13: gen_lab13, 14: gen_lab14, 15: gen_lab15, 17: gen_lab17, 18: gen_lab18, 19: gen_lab19, 20: gen_lab20, 21: gen_lab21, 22: gen_lab22, 23: gen_lab23, 24: gen_lab24}


def generate(lab: int, policies: dict, seed: int | None = None) -> dict:
    """Return random scenario data for ``lab`` (raises KeyError if unsupported)."""
    if lab not in GENERATORS:
        raise KeyError(f"no random generator for lab {lab}; supported: {sorted(GENERATORS)}")
    rng = random.Random(seed)
    data = GENERATORS[lab](rng, policies)
    data["_description"] = f"Randomly generated scenario for lab {lab} (seed={seed})"
    return data
