"""Lab 11 — firewall rule & segmentation auditor tests."""

from __future__ import annotations

import pytest

from labs.lab11_firewall_auditor import (
    audit, endpoint_covers, is_default_deny, parse_ports, ports_cover, resolve, rule_covers,
)

ZONES = {"internet": [], "dmz": ["172.16.10.0/24"], "internal": ["10.10.0.0/16"], "guest": ["192.168.50.0/24"],
         "database": ["10.20.0.0/24"], "management": ["10.99.0.0/24"]}
DENY_ALL = {"id": 99, "action": "deny", "src": "any", "dst": "any", "proto": "any", "ports": "any", "log": True,
            "comment": "default deny"}


def R(i, action, src, dst, ports="443", proto="tcp", log=True, comment="c"):
    return {"id": i, "action": action, "src": src, "dst": dst, "proto": proto, "ports": ports, "log": log, "comment": comment}


@pytest.fixture
def cfg(policies):
    return policies["firewall_audit"]


def run(cfg, *rules):
    return audit({"name": "t", "zones": ZONES, "rules": list(rules)}, cfg)


def codes(a, rid=None):
    return {f.code for f in a.findings if rid is None or f.rule_id == rid}


def test_port_parsing_and_cover():
    assert parse_ports("any") == [(0, 65535)]
    assert parse_ports("80,443") == [(80, 80), (443, 443)]
    assert parse_ports("1000-2000") == [(1000, 2000)]
    assert ports_cover("1-1024", "80,443") and not ports_cover("443", "80,443")


def test_resolve_zones_and_cidrs():
    assert resolve("10.10.5.0/24", ZONES)[0][0] == "internal"
    assert resolve("8.8.8.8/32", ZONES)[0][0] == "internet"
    assert {z for z, _ in resolve("10.0.0.0/8", ZONES)} == {"internal", "database", "management"}


def test_endpoint_cover_respects_zones():
    assert endpoint_covers("dmz", "172.16.10.20/32", ZONES)
    assert endpoint_covers("internet", "185.220.101.0/24", ZONES)
    assert not endpoint_covers("internet", "internal", ZONES)          # public space ≠ internal zone
    assert endpoint_covers("any", "internal", ZONES) and not endpoint_covers("internal", "any", ZONES)


def test_rule_cover_needs_all_dimensions():
    a = R(1, "allow", "internet", "dmz", "80,443")
    assert rule_covers(a, R(2, "deny", "1.2.3.0/24", "dmz", "443"), ZONES)
    assert not rule_covers(a, R(2, "deny", "1.2.3.0/24", "dmz", "22"), ZONES)
    assert not rule_covers(R(1, "allow", "internet", "dmz", "443", proto="udp"), R(2, "deny", "internet", "dmz"), ZONES)


def test_clean_ruleset_scores_100(cfg):
    a = run(cfg, R(1, "allow", "internet", "dmz", "80,443"), R(2, "allow", "dmz", "database", "1521"), DENY_ALL)
    assert a.score == 100 and a.grade == "A" and not a.findings


def test_shadowed_vs_redundant(cfg):
    a = run(cfg, R(1, "allow", "internet", "dmz"), R(2, "deny", "185.220.101.0/24", "dmz"),
            R(3, "allow", "internet", "172.16.10.5/32"), DENY_ALL)
    assert "SHADOWED" in codes(a, 2) and "REDUNDANT" in codes(a, 3)


def test_deny_placed_first_is_not_shadowed(cfg):
    a = run(cfg, R(1, "deny", "185.220.101.0/24", "dmz"), R(2, "allow", "internet", "dmz"), DENY_ALL)
    assert not codes(a)


def test_any_any_and_any_service(cfg):
    a = run(cfg, R(1, "allow", "any", "any", "any", "any", log=False), R(2, "allow", "internal", "dmz", "any"), DENY_ALL)
    assert "ANY_ANY" in codes(a, 1) and "ANY_SERVICE" in codes(a, 2)


@pytest.mark.parametrize("src,dst,ports", [("internet", "internal", "443"), ("guest", "internal", "443"),
                                           ("dmz", "internal", "443"), ("internal", "dmz", "8080")])
def test_segmentation_violations(cfg, src, dst, ports):
    assert "SEGMENTATION_VIOLATION" in codes(run(cfg, R(1, "allow", src, dst, ports), DENY_ALL), 1)


def test_intra_zone_and_policy_flows_allowed(cfg):
    a = run(cfg, R(1, "allow", "internal", "internal", "445"), R(2, "allow", "management", "any", "22"), DENY_ALL)
    assert "SEGMENTATION_VIOLATION" not in codes(a)


def test_insecure_protocols(cfg):
    a = run(cfg, R(1, "allow", "internal", "dmz", "23"), R(2, "allow", "internet", "dmz", "3389"),
            R(3, "allow", "management", "any", "3389"), DENY_ALL)
    assert "INSECURE_PROTOCOL" in codes(a, 1) and "INSECURE_PROTOCOL" in codes(a, 2)
    assert "INSECURE_PROTOCOL" not in codes(a, 3)      # RDP from the trusted management zone is OK


def test_missing_default_deny_logging_docs_broad(cfg):
    a = run(cfg, R(1, "deny", "1.2.3.4/32", "dmz", log=False, comment=""), R(2, "allow", "10.0.0.0/8", "dmz", "443"))
    assert {"MISSING_DEFAULT_DENY", "NO_LOGGING", "UNDOCUMENTED"} <= codes(a)
    assert "OVERLY_BROAD" in codes(a, 2)


def test_default_deny_without_logging(cfg):
    a = run(cfg, R(1, "allow", "internet", "dmz"), {**DENY_ALL, "log": False})
    assert codes(a) == {"NO_LOGGING"} and is_default_deny(DENY_ALL)


def test_sample_rulesets(policies, data):
    current, fixed = [audit(rs, policies["firewall_audit"]) for rs in data("sample_firewall.json")["rulesets"]]
    assert fixed.score == 100 and current.grade == "F"
    assert {f.code for f in current.findings} == {
        "REDUNDANT", "SHADOWED", "NO_LOGGING", "SEGMENTATION_VIOLATION", "INSECURE_PROTOCOL", "ANY_SERVICE",
        "UNDOCUMENTED", "OVERLY_BROAD", "ANY_ANY", "MISSING_DEFAULT_DENY"}
    assert "SHADOWED" in current.codes_for(4) and "ANY_ANY" in current.codes_for(11)
