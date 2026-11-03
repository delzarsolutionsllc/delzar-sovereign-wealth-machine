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


GENERATORS = {2: gen_lab2, 6: gen_lab6, 9: gen_lab9, 11: gen_lab11, 12: gen_lab12, 13: gen_lab13, 14: gen_lab14, 15: gen_lab15, 17: gen_lab17}


def generate(lab: int, policies: dict, seed: int | None = None) -> dict:
    """Return random scenario data for ``lab`` (raises KeyError if unsupported)."""
    if lab not in GENERATORS:
        raise KeyError(f"no random generator for lab {lab}; supported: {sorted(GENERATORS)}")
    rng = random.Random(seed)
    data = GENERATORS[lab](rng, policies)
    data["_description"] = f"Randomly generated scenario for lab {lab} (seed={seed})"
    return data
