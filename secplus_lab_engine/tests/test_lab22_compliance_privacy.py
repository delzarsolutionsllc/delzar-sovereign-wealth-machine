"""Lab 22 — compliance & privacy obligations tracker tests."""

from __future__ import annotations

import copy

import pytest

from labs.lab22_compliance_privacy import evaluate, evaluate_all, report_summary, run_demo

TODAY = 1000


@pytest.fixture
def cfg(policies):
    return policies["compliance"]


def DSR(**kw):
    base = {"id": "D", "kind": "dsr", "regime": "gdpr_style", "request_type": "access", "received_day": 990,
            "completed_day": None, "identity_verified": True, "received_by": "controller"}
    base.update(kw)
    return base


def test_dsr_deadline_met_late_and_at_risk_boundary(cfg):
    assert evaluate(DSR(completed_day=1000), cfg, TODAY).status == "COMPLIANT"           # due day 1020
    assert evaluate(DSR(received_day=900, completed_day=931), cfg, TODAY).code == "DSR_LATE"
    assert evaluate(DSR(received_day=975), cfg, TODAY).status == "AT_RISK"              # exactly 5 days left
    assert evaluate(DSR(received_day=976), cfg, TODAY).status == "COMPLIANT"            # 6 days left
    assert evaluate(DSR(received_day=960), cfg, TODAY).code == "DSR_LATE"               # open, overdue


def test_regime_deadline_comes_from_policy(cfg):
    assert evaluate(DSR(received_day=970, regime="state_privacy_law"), cfg, TODAY).status == "COMPLIANT"
    cfg2 = copy.deepcopy(cfg)
    cfg2["regimes"]["state_privacy_law"]["dsr_days"] = 30
    assert evaluate(DSR(received_day=960, regime="state_privacy_law"), cfg2, TODAY).code == "DSR_LATE"


def test_unknown_regime_and_missing_fields_deny_by_default(cfg):
    r = evaluate(DSR(regime="atlantis_act"), cfg, TODAY)
    assert r.status == "NON_COMPLIANT" and r.code == "UNKNOWN_REGIME"
    d = DSR(); del d["identity_verified"]
    r = evaluate(d, cfg, TODAY)
    assert r.code == "MISSING_FIELDS" and "identity_verified" in r.reasons[0]
    assert evaluate({"id": "?", "kind": "mystery"}, cfg, TODAY).status == "NON_COMPLIANT"


def test_erasure_hold_is_exempt_only_when_documented(cfg):
    ok = evaluate(DSR(request_type="erasure", hold="retention_obligation", hold_documented=True), cfg, TODAY)
    assert ok.status == "EXEMPT" and "not silently deleted" in ok.reasons[-1]
    bad = evaluate(DSR(request_type="erasure", hold="legal_hold", hold_documented=False), cfg, TODAY)
    assert bad.code == "UNDOCUMENTED_EXCEPTION"


def test_processor_must_forward_and_identity_must_be_verified(cfg):
    assert evaluate(DSR(received_by="processor"), cfg, TODAY).code == "NOT_FORWARDED"
    fwd = evaluate(DSR(received_by="processor", forwarded_to_controller=True), cfg, TODAY)
    assert fwd.status == "COMPLIANT" and "forwarded" in fwd.reasons[0]
    assert evaluate(DSR(identity_verified=False, completed_day=995), cfg, TODAY).code == "UNVERIFIED_IDENTITY"


def test_breach_notification_window_and_subjects(cfg):
    B = {"id": "B", "kind": "breach", "regime": "gdpr_style", "discovered_hour": 23000, "risk": "medium"}
    assert evaluate({**B, "regulator_notified_hour": 23072}, cfg, TODAY).status == "COMPLIANT"   # exactly 72 h
    late = evaluate({**B, "regulator_notified_hour": 23073}, cfg, TODAY)
    assert late.code == "BREACH_LATE" and late.reporting == "external" and late.consequence == "fines"
    high = evaluate({**B, "risk": "high", "regulator_notified_hour": 23010, "subjects_notified": False}, cfg, TODAY)
    assert high.code == "SUBJECTS_NOT_NOTIFIED"
    low = evaluate({**B, "risk": "low"}, cfg, TODAY)
    assert low.status == "COMPLIANT" and low.reporting == "internal"
    pending = evaluate({**B, "discovered_hour": TODAY * 24 - 65}, cfg, TODAY)                  # 7 h left
    assert pending.status == "AT_RISK"


def test_retention_over_early_and_hold(cfg):
    R = {"id": "R", "kind": "retention", "record_type": "cctv_footage", "created_day": 900, "destroyed_day": None}
    assert evaluate(R, cfg, TODAY).code == "OVER_RETENTION"
    assert evaluate({**R, "legal_hold": True}, cfg, TODAY).status == "EXEMPT"
    assert evaluate({**R, "created_day": 990}, cfg, TODAY).status == "AT_RISK"
    logs = {**R, "record_type": "security_audit_logs", "destroyed_day": 950}
    early = evaluate(logs, cfg, TODAY)
    assert early.code == "EARLY_DESTRUCTION" and early.consequence == "sanctions"
    assert evaluate({**logs, "created_day": 100, "legal_hold": True}, cfg, TODAY).code == "DESTROYED_UNDER_HOLD"
    assert evaluate({**R, "record_type": "unlisted"}, cfg, TODAY).code == "UNKNOWN_TYPE"


def test_attestations(cfg):
    A = {"id": "A", "kind": "attestation", "attestation": "acceptable_use_ack", "subject": "E-1"}
    assert evaluate({**A, "signed_day": 900}, cfg, TODAY).status == "COMPLIANT"
    assert evaluate({**A, "signed_day": None}, cfg, TODAY).code == "ATTESTATION_MISSING"
    assert evaluate({**A, "exception": {"documented": True, "reason": "leave"}}, cfg, TODAY).status == "EXEMPT"
    ext = evaluate({**A, "attestation": "control_attestation", "signed_day": 600}, cfg, TODAY)
    assert ext.code == "ATTESTATION_EXPIRED" and ext.reporting == "external" and ext.consequence == "loss of license"


def test_sample_outcomes_and_report(policies, data, quiet_ui):
    sample = data("sample_privacy_cases.json")
    expected = {"DSR-1": "COMPLIANT", "DSR-2": "EXEMPT", "DSR-3": "AT_RISK", "DSR-4": "NON_COMPLIANT",
                "DSR-5": "NON_COMPLIANT", "BR-1": "COMPLIANT", "BR-2": "NON_COMPLIANT", "BR-3": "NON_COMPLIANT",
                "RT-1": "NON_COMPLIANT", "RT-2": "NON_COMPLIANT", "RT-3": "EXEMPT", "AT-1": "NON_COMPLIANT",
                "AT-2": "AT_RISK"}
    assert run_demo(quiet_ui, policies, sample) == expected
    s = report_summary(evaluate_all(sample, policies))
    assert s["by_status"] == {"COMPLIANT": 2, "AT_RISK": 2, "NON_COMPLIANT": 7, "EXEMPT": 2}
    assert s["reporting"] == {"internal": 8, "external": 4, "none": 1}


def test_challenges_are_valid(policies, data):
    from labs.lab22_compliance_privacy import build_challenges
    qs = build_challenges(policies, data("sample_privacy_cases.json"))
    assert len(qs) >= 8 and all(q.answer in q.choices for q in qs)
    assert {q.objective for q in qs} <= {"5.1", "5.4"}
