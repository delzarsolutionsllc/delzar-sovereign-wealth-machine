"""Lab 23 — penetration test RoE gate & audit planner tests."""

from __future__ import annotations

import copy

import pytest

from labs.lab23_audit_roe import build_challenges, check_scope, gate, in_window, plan_assessment, run_demo


@pytest.fixture
def cfg(policies):
    return policies["audit"]


@pytest.fixture
def eng(data):
    return copy.deepcopy(data("sample_engagement.json")["engagement"])


def A(**kw):
    base = {"id": "T", "tester": "t", "day": 3, "hour": 10, "target": "198.51.100.10", "technique": "port_scan",
            "recon": "active"}
    base.update(kw)
    return base


def test_allowed_action_inside_rules(cfg, eng):
    r = gate(A(), eng, cfg)
    assert r.decision == "ALLOW" and not r.rules


def test_unsigned_or_wrong_role_blocks(cfg, eng):
    eng["authorization"]["signed"] = False
    r = gate(A(), eng, cfg)
    assert r.decision == "BLOCK" and r.rules == ["AUTHORIZATION"]
    eng["authorization"].update(signed=True, role="intern")
    assert "signer role" in gate(A(), eng, cfg).reasons[0]


def test_missing_authorization_and_contact_deny_by_default(cfg, eng):
    del eng["authorization"]
    eng["emergency_contact"] = ""
    r = gate(A(), eng, cfg)
    text = " ".join(r.reasons)
    assert r.decision == "BLOCK" and "no signed authorization" in text and "emergency contact" in text


def test_validity_boundaries(cfg, eng):
    assert gate(A(day=1), eng, cfg).decision == "ALLOW"
    assert gate(A(day=10), eng, cfg).decision == "ALLOW"
    assert gate(A(day=0), eng, cfg).rules == ["AUTHORIZATION"]
    assert gate(A(day=11), eng, cfg).rules == ["AUTHORIZATION"]


def test_scope_uses_cidrs_and_out_of_scope_wins(eng):
    s = eng["scope"]
    assert check_scope("10.20.9.9", s) == []
    assert "out-of-scope" in check_scope("10.20.5.1", s)[0]
    assert "out-of-scope" in check_scope("198.51.100.200", s)[0]
    assert "not inside" in check_scope("192.0.2.1", s)[0]
    assert check_scope("vpn.northwind.example", s) == []
    assert "out-of-scope" in check_scope("mail.northwind.example", s)[0]
    assert "not an in-scope domain" in check_scope("northwind.example.evil.example", s)[0]
    assert "no target" in check_scope(None, s)[0]


def test_prohibited_and_unknown_techniques_block(cfg, eng):
    assert gate(A(technique="prod_data_modify"), eng, cfg).rules == ["TECHNIQUE"]
    r = gate(A(technique="mystery_tool"), eng, cfg)
    assert r.decision == "BLOCK" and "unknown" in r.reasons[0]


def test_policy_always_prohibited_applies_even_if_roe_allows(cfg, eng):
    eng["prohibited"], eng["allowed_techniques"] = [], ["dos_flood"]
    assert gate(A(technique="dos_flood"), eng, cfg).decision == "BLOCK"


def test_window_boundaries_and_wraparound(cfg, eng):
    w = eng["window"]
    assert in_window(8, w) and in_window(17, w) and not in_window(18, w) and not in_window(None, w)
    assert in_window(23, {"start_hour": 20, "end_hour": 6}) and not in_window(12, {"start_hour": 20, "end_hour": 6})
    assert gate(A(hour=18), eng, cfg).rules == ["WINDOW"]


def test_passive_recon_exempt_from_window_only_by_policy(cfg, eng):
    act = A(hour=2, technique="osint_search", target="northwind.example", recon="passive")
    assert gate(act, eng, cfg).decision == "ALLOW"
    strict = {**cfg, "passive_recon_ignores_window": False}
    assert gate(act, eng, strict).rules == ["WINDOW"]
    # still needs in-date authorization
    assert gate({**act, "day": 20}, eng, cfg).decision == "BLOCK"


def test_mislabelled_passive_recon_blocks(cfg, eng):
    r = gate(A(technique="vuln_scan", recon="passive"), eng, cfg)
    assert r.decision == "BLOCK" and r.rules == ["RECON_TYPE"]


def test_not_explicitly_allowed_needs_approval(cfg, eng):
    r = gate(A(technique="password_spray"), eng, cfg)
    assert r.decision == "NEEDS_APPROVAL" and "written approval" in r.reasons[0]


def test_audit_planner(cfg):
    assert plan_assessment({"id": "a", "driver": "customer_soc2"}, cfg).assessment == "ATTESTATION"
    assert plan_assessment({"id": "b", "driver": "self_check"}, cfg).assessment == "SELF_ASSESSMENT"
    p = plan_assessment({"id": "c", "driver": "self_check", "independence_required": True}, cfg)
    assert p.assessment == "INDEPENDENT_THIRD_PARTY_AUDIT" and p.category == "external"
    assert plan_assessment({"id": "d", "driver": "regulator_requires"}, cfg).assessment == "REGULATORY_EXAMINATION"
    assert plan_assessment({"id": "e"}, cfg).assessment == "UNCLASSIFIED"


def test_run_demo_summary_and_challenges(policies, quiet_ui, data):
    d = data("sample_engagement.json")
    assert run_demo(quiet_ui, policies, d) == {
        "PT-01": "ALLOW", "PT-02": "ALLOW", "PT-03": "BLOCK", "PT-04": "BLOCK", "PT-05": "BLOCK",
        "PT-06": "BLOCK", "PT-07": "NEEDS_APPROVAL", "PT-08": "BLOCK", "PT-09": "BLOCK", "PT-10": "BLOCK",
        "AN-1": "REGULATORY_EXAMINATION", "AN-2": "INTERNAL_AUDIT", "AN-3": "ATTESTATION",
        "AN-4": "SELF_ASSESSMENT", "AN-5": "INDEPENDENT_THIRD_PARTY_AUDIT"}
    qs = build_challenges(policies, d)
    assert len(qs) >= 8 and all(q.answer in q.choices for q in qs)
