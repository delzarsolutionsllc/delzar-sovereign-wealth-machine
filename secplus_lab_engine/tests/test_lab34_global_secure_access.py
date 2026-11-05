"""Lab 34 — Global Secure Access (traffic forwarding, Private Access, web content filtering) tests."""

from __future__ import annotations

import copy
import json
import random

import pytest

from labs.lab34_global_secure_access import (FLOW_OUTCOMES, build_challenges, evaluate_flow, fqdn_match,
                                             generate_scenario, health_check, run_demo, segments_overlap)
from utils.challenge import check


@pytest.fixture
def cfg(policies):
    return policies["global_secure_access"]


@pytest.fixture
def sample(data):
    return data("sample_global_secure_access.json")


def flow(sample, cfg, **kw):
    base = {"id": "T1", "user": "ava.lind@harrowgate.example", "device": "LT-01", "destination": "news.example",
            "port": 443, "protocol": "tcp"}
    base.update(kw)
    return evaluate_flow(base, sample, cfg)


def test_sample_outcomes(policies, quiet_ui, sample):
    out = run_demo(quiet_ui, policies, sample)
    json.dumps(out)
    assert out["flows"] == {
        "F01": "TUNNELED_MICROSOFT", "F02": "TUNNELED_INTERNET_ALLOWED", "F03": "BLOCKED_BY_WEB_FILTER",
        "F04": "TUNNELED_INTERNET_ALLOWED", "F05": "BLOCKED_BY_WEB_FILTER", "F06": "BLOCKED_BY_WEB_FILTER",
        "F07": "BLOCKED_BY_WEB_FILTER", "F08": "TUNNELED_PRIVATE_ACCESS", "F09": "BLOCKED_NO_SEGMENT",
        "F10": "TUNNELED_PRIVATE_ACCESS", "F11": "BLOCKED_NO_SEGMENT", "F12": "BLOCKED_CONNECTOR_UNAVAILABLE",
        "F13": "TUNNELED_PRIVATE_ACCESS", "F14": "BYPASSED_NOT_FORWARDED", "F15": "BYPASSED_NOT_FORWARDED",
        "F16": "BYPASSED_NOT_FORWARDED"}
    assert set(out["flows"].values()) == set(FLOW_OUTCOMES)
    m = out["metrics"]
    assert (m["tunneled_pct"], m["blocked"], m["bypassed"]) == (37.5, 7, 3)
    assert m["health_findings"] == {"CONNECTOR_GROUP_UNHEALTHY": 2, "SEGMENT_OVERLAP": 1, "PROFILE_UNASSIGNED": 1}


def test_unknown_user_and_device_bypass(sample, cfg):
    assert flow(sample, cfg, user="ghost@harrowgate.example").rule == "identity"
    r = flow(sample, cfg, device="LT-99")
    assert r.outcome == "BYPASSED_NOT_FORWARDED" and r.rule == "client"


def test_missing_client_flag_treated_as_not_installed(sample, cfg):
    r = flow(sample, cfg, user="ben.osei@harrowgate.example", device="LT-07")
    assert r.outcome == "BYPASSED_NOT_FORWARDED" and "treated as not installed" in r.reasons[0]


def test_missing_destination_port_protocol_deny_by_default(sample, cfg):
    assert flow(sample, cfg, destination=None).outcome == "BLOCKED_NO_SEGMENT"
    assert flow(sample, cfg, destination="erp.hgf.internal", port=None).outcome == "BLOCKED_NO_SEGMENT"
    assert flow(sample, cfg, destination="erp.hgf.internal", protocol=None).outcome == "BLOCKED_NO_SEGMENT"


def test_profile_disabled_and_not_assigned(sample, cfg):
    off = copy.deepcopy(sample)
    off["forwarding_profiles"]["microsoft"]["enabled"] = False
    r = flow(off, cfg, destination="harrowgate.sharepoint.com")
    assert r.outcome == "BYPASSED_NOT_FORWARDED" and r.rule == "profile_disabled"
    del off["forwarding_profiles"]["private"]
    assert flow(off, cfg, destination="erp.hgf.internal").rule == "profile_disabled"
    r = flow(sample, cfg, user="dev.patel@harrowgate.example", device="LT-04")
    assert r.outcome == "BYPASSED_NOT_FORWARDED" and r.rule == "profile_assignment"


def test_microsoft_traffic_classified_before_internet(sample, cfg):
    r = flow(sample, cfg, destination="login.microsoftonline.com")
    assert r.outcome == "TUNNELED_MICROSOFT" and r.traffic == "microsoft"


def test_private_segment_port_and_protocol(sample, cfg):
    assert flow(sample, cfg, destination="erp.hgf.internal").outcome == "TUNNELED_PRIVATE_ACCESS"
    assert flow(sample, cfg, destination="erp.hgf.internal", protocol="udp").outcome == "BLOCKED_NO_SEGMENT"
    eng = dict(user="ben.osei@harrowgate.example", device="LT-02")
    assert flow(sample, cfg, destination="10.20.9.9", port=8090, **eng).outcome == "TUNNELED_PRIVATE_ACCESS"
    assert flow(sample, cfg, destination="10.20.9.9", port=8091, **eng).outcome == "BLOCKED_NO_SEGMENT"
    # RFC 1918 address outside every segment is still private traffic, so no internet fallback
    r = flow(sample, cfg, destination="192.168.1.10", **eng)
    assert r.traffic == "private" and r.outcome == "BLOCKED_NO_SEGMENT"


def test_app_assignment_required(sample, cfg):
    r = flow(sample, cfg, destination="10.20.4.15", port=22)
    assert r.outcome == "BLOCKED_NO_SEGMENT" and r.rule == "app_assignment"


def test_enterprise_app_checked_before_quick_access(sample, cfg):
    r = flow(sample, cfg, user="eli.novak@harrowgate.example", device="LT-05", destination="erp.hgf.internal")
    # Eli is not assigned to Finance ERP, so the overlapping Quick Access wildcard serves him instead
    assert r.outcome == "TUNNELED_PRIVATE_ACCESS" and r.app == "Quick Access"
    finance = flow(sample, cfg, destination="erp.hgf.internal")
    assert finance.app == "Finance ERP"


def test_connector_group_unavailable_or_missing(sample, cfg):
    ops = dict(user="fatima.reyes@harrowgate.example", device="LT-06", destination="files.hgf.internal", port=445)
    assert flow(sample, cfg, **ops).outcome == "BLOCKED_CONNECTOR_UNAVAILABLE"
    broken = copy.deepcopy(sample)
    broken["private_apps"][2]["connector_group"] = "CG-Nowhere"
    assert flow(broken, cfg, **ops).outcome == "BLOCKED_CONNECTOR_UNAVAILABLE"
    assert any(h.target == "CG-Nowhere" for h in health_check(broken, cfg))


def test_web_filter_priority_and_baseline(sample, cfg):
    ops = dict(user="fatima.reyes@harrowgate.example", device="LT-06")
    assert flow(sample, cfg, destination="chirp.example", **ops).outcome == "TUNNELED_INTERNET_ALLOWED"
    assert flow(sample, cfg, destination="chirp.example").outcome == "BLOCKED_BY_WEB_FILTER"
    r = flow(sample, cfg, destination="www.wager-example.test")
    assert r.outcome == "BLOCKED_BY_WEB_FILTER" and "Baseline" in r.reasons[-1]


def test_unknown_category_and_default_action_are_policy_driven(sample, cfg):
    assert flow(sample, cfg, destination="mystery.example").rule == "unknown_category"
    lax = copy.deepcopy(cfg)
    lax["unknown_category_action"] = "allow"
    assert evaluate_flow({"id": "x", "user": "ava.lind@harrowgate.example", "device": "LT-01",
                          "destination": "mystery.example", "port": 443, "protocol": "tcp"},
                         sample, lax).outcome == "TUNNELED_INTERNET_ALLOWED"
    assert flow(sample, cfg, destination="news.example").rule == "default_action"


def test_conditional_access_state_target_and_missing_profile(sample, cfg):
    # report-only does not enforce; wrong target resource does not link the profile
    dev = copy.deepcopy(sample)
    dev["forwarding_profiles"]["internet"]["assigned_to"].append("Contractors")
    r = evaluate_flow({"id": "x", "user": "dev.patel@harrowgate.example", "device": "LT-04",
                       "destination": "friendspace.example", "port": 443, "protocol": "tcp"}, dev, cfg)
    assert r.outcome == "TUNNELED_INTERNET_ALLOWED" and any("report-only" in x for x in r.reasons)
    dev["conditional_access_policies"][2]["state"] = "enabled"
    r = evaluate_flow({"id": "x", "user": "dev.patel@harrowgate.example", "device": "LT-04",
                       "destination": "friendspace.example", "port": 443, "protocol": "tcp"}, dev, cfg)
    assert r.outcome == "BLOCKED_BY_WEB_FILTER"
    dev["conditional_access_policies"][2]["security_profile"] = "Does-Not-Exist"
    r = evaluate_flow({"id": "x", "user": "dev.patel@harrowgate.example", "device": "LT-04",
                       "destination": "news.example", "port": 443, "protocol": "tcp"}, dev, cfg)
    assert r.outcome == "BLOCKED_BY_WEB_FILTER" and r.rule == "missing_security_profile"


def test_helpers_wildcards_and_overlap():
    assert fqdn_match("*.hgf.internal", "wiki.hgf.internal") and not fqdn_match("*.hgf.internal", "hgf.internal")
    seg = lambda d, p, proto="tcp": {"destination": d, "ports": p, "protocol": proto}
    assert segments_overlap(seg("10.20.0.0/16", ["22"]), seg("10.20.5.0/24", ["20-25"]))
    assert not segments_overlap(seg("10.20.0.0/16", ["22"]), seg("10.20.5.0/24", ["443"]))
    assert not segments_overlap(seg("a.x.internal", ["443"]), seg("*.x.internal", ["443"], "udp"))
    assert segments_overlap(seg("*.x.internal", ["443"]), seg("*.b.x.internal", ["443"]))


def test_health_check_sample_and_unassigned_profile(sample, cfg):
    found = {(h.type, h.target, h.severity) for h in health_check(sample, cfg)}
    assert found == {("CONNECTOR_GROUP_UNHEALTHY", "CG-Bristol", "medium"),
                     ("CONNECTOR_GROUP_UNHEALTHY", "CG-Archive", "high"),
                     ("SEGMENT_OVERLAP", "Finance ERP / Quick Access", "medium"),
                     ("PROFILE_UNASSIGNED", "security profile Contractor-Strict", "medium")}
    empty = copy.deepcopy(sample)
    empty["forwarding_profiles"]["internet"]["assigned_to"] = ["GSA-Pilot"]
    assert ("PROFILE_UNASSIGNED", "Internet Access profile", "high") in {
        (h.type, h.target, h.severity) for h in health_check(empty, cfg)}


def test_min_healthy_connectors_is_policy_driven(sample, cfg):
    strict = copy.deepcopy(cfg)
    strict["min_healthy_connectors"] = 3
    weak = {h.target for h in health_check(sample, strict) if h.type == "CONNECTOR_GROUP_UNHEALTHY"}
    assert weak == {"CG-Leeds", "CG-Bristol", "CG-Archive"}


def test_challenges_score_100_percent(policies, sample):
    qs = build_challenges(policies, sample)
    assert len(qs) >= 12
    assert all(q.objective in ("2.4", "2.2") for q in qs)
    assert all(len(set(q.choices)) == len(q.choices) for q in qs)
    assert all(" lab" not in (q.prompt + " ".join(q.choices)).lower() for q in qs)
    assert all(check(q, q.answer) for q in qs)


def test_generate_scenario_deterministic_and_runs(policies, quiet_ui):
    a, b = generate_scenario(random.Random(7), policies), generate_scenario(random.Random(7), policies)
    assert a == b
    out = run_demo(quiet_ui, policies, a)
    assert set(FLOW_OUTCOMES) <= set(out["flows"].values())
    assert len(build_challenges(policies, a)) >= 12
    for seed in range(20):
        g = generate_scenario(random.Random(seed), policies)
        assert set(FLOW_OUTCOMES) <= set(run_demo(quiet_ui, policies, g)["flows"].values())
