"""Lab 15 — vendor risk assessor tests."""

from __future__ import annotations

import pytest

from labs.lab15_vendor_risk import assess, assess_all, questionnaire_score, required_clauses


@pytest.fixture
def cfg(policies):
    return policies["vendor_risk"]


ALL_YES = {f"Q{i:02d}": "yes" for i in range(1, 12)}


def V(**kw):
    base = {"id": "X", "name": "x", "relationship": "vendor", "data": "internal", "access": "portal", "criticality": "low",
            "answers": dict(ALL_YES), "contract": {"clauses": ["MSA", "NDA"], "sla": {}}}
    base.update(kw)
    return base


def test_questionnaire_scoring(cfg):
    assert questionnaire_score(ALL_YES, cfg["questionnaire"])[0] == 100.0
    s, gaps = questionnaire_score({}, cfg["questionnaire"])
    assert s == 0.0 and len(gaps) == len(cfg["questionnaire"]) and "unanswered" in gaps[0]
    half = {k: "partial" for k in ALL_YES}
    assert questionnaire_score(half, cfg["questionnaire"])[0] == 50.0


def test_required_clauses_scale_with_exposure(cfg):
    rc = cfg["required_clauses"]
    assert required_clauses(V(), rc) == ["MSA", "NDA"]
    assert "DPA" in required_clauses(V(data="regulated"), rc)
    assert "security_requirements_schedule" in required_clauses(V(access="network"), rc)
    assert "BPA" in required_clauses(V(relationship="partner"), rc)


def test_low_risk_clean_vendor_approved(cfg):
    a = assess(V(), cfg)
    assert a.inherent == 2 * 2 * 1 and a.decision == "APPROVE" and a.monitoring


def test_missing_clause_gives_conditions(cfg):
    a = assess(V(access="network"), cfg)
    assert a.decision == "APPROVE_WITH_CONDITIONS" and a.missing_clauses == ["security_requirements_schedule"]


def test_mou_does_not_replace_bpa(cfg):
    a = assess(V(relationship="partner", contract={"clauses": ["MSA", "NDA", "MOU"], "sla": {}}), cfg)
    assert "non-binding" in a.conditions[0]


def test_unverifiable_sensitive_vendor_rejected(cfg):
    answers = {**ALL_YES, "Q01": "no"}
    a = assess(V(data="confidential", answers=answers,
                 contract={"clauses": ["MSA", "NDA", "SLA", "breach_notification", "data_return_destruction"],
                           "sla": {"uptime": 99.9, "breach_notification_hours": 24}}), cfg)
    assert a.decision == "REJECT" and "right-to-audit" in a.reject_reasons[0]


def test_right_to_audit_or_independent_assessment_suffices(cfg):
    clauses = ["MSA", "NDA", "SLA", "right_to_audit", "breach_notification", "data_return_destruction"]
    a = assess(V(data="confidential", answers={**ALL_YES, "Q01": "no"},
                 contract={"clauses": clauses, "sla": {"uptime": 99.9, "breach_notification_hours": 24}}), cfg)
    assert not any("right-to-audit" in r for r in a.reject_reasons)


def test_undisclosed_conflict_of_interest_rejected(cfg):
    a = assess(V(answers={**ALL_YES, "Q11": "no"}), cfg)
    assert a.decision == "REJECT" and "conflict of interest" in a.reject_reasons[0]


def test_sla_shortfalls(cfg):
    clauses = ["MSA", "NDA", "SLA", "right_to_audit", "breach_notification", "data_return_destruction"]
    a = assess(V(data="confidential", criticality="high",
                 contract={"clauses": clauses, "sla": {"uptime": 99.0, "breach_notification_hours": 96}}), cfg)
    text = " ".join(a.conditions)
    assert "uptime" in text and "breach notification" in text


def test_high_residual_rejected(cfg):
    a = assess(V(data="regulated", access="privileged", criticality="high", answers={}), cfg)
    assert a.residual_band == "high" and a.decision == "REJECT"


def test_sample_outcomes(policies, data):
    res = {a.id: a for a in assess_all(data("sample_vendors.json"), policies)}
    assert {k: v.decision for k, v in res.items()} == {
        "VN-1": "APPROVE", "VN-2": "APPROVE_WITH_CONDITIONS", "VN-3": "REJECT",
        "VN-4": "APPROVE_WITH_CONDITIONS", "VN-5": "REJECT"}
    assert res["VN-1"].inherent_band == "high" and res["VN-1"].residual_band == "low"
    assert res["VN-2"].missing_clauses == ["security_requirements_schedule"]
    assert res["VN-4"].missing_clauses == ["BPA"]
    assert any("conflict of interest" in r for r in res["VN-5"].reject_reasons)
