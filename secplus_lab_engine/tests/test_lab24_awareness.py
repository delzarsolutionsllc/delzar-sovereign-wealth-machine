"""Lab 24 — security awareness program analyzer tests."""

from __future__ import annotations

import pytest

from labs.lab24_awareness import (analyze, build_challenges, check_message, classify_behaviour,
                                  evaluate_employee, is_lookalike, outcome_of, run_demo)


@pytest.fixture
def cfg(policies):
    return policies["awareness"]


def E(**kw):
    base = {"id": "X", "dept": "Ops", "role": "staff", "events": ["delivered", "opened"], "prior_failures": 0,
            "training_completed_day": 390}
    base.update(kw)
    return base


def test_outcome_precedence():
    assert outcome_of(["delivered", "clicked", "submitted_credentials", "reported"]) == "COMPROMISED"
    assert outcome_of(["delivered", "clicked", "reported"]) == "CLICKED"
    assert outcome_of(["delivered", "reported"]) == "REPORTED"
    assert outcome_of(["delivered", "opened"]) == "PASSED"
    assert outcome_of(None) == "NO_DATA" and outcome_of(["clicked"]) == "NO_DATA"


def test_clean_pass_needs_no_action(cfg):
    r = evaluate_employee(E(), 400, cfg)
    assert (r.outcome, r.action, r.rule) == ("PASSED", "NONE", "outcome mapping") and r.trained


def test_high_risk_roles_get_stricter_mapping(cfg):
    staff = evaluate_employee(E(events=["delivered", "clicked"]), 400, cfg)
    fin = evaluate_employee(E(role="finance", events=["delivered", "clicked"]), 400, cfg)
    assert staff.action == "MICRO_TRAINING" and fin.action == "REMEDIAL_TRAINING"
    assert fin.rule == "high-risk role mapping"


def test_unknown_role_and_missing_events_deny_by_default(cfg):
    r = evaluate_employee(E(role="contractor", events=[]), 400, cfg)
    assert r.tier == "high_risk" and r.outcome == "NO_DATA" and r.action == "REMEDIAL_TRAINING"
    assert any("unknown role" in x for x in r.reasons)


def test_repeat_offender_threshold_boundary(cfg):
    clicked = ["delivered", "clicked"]
    assert evaluate_employee(E(events=clicked, prior_failures=1), 400, cfg).action == "MICRO_TRAINING"
    r = evaluate_employee(E(events=clicked, prior_failures=2), 400, cfg)          # 3 ≥ 3
    assert r.action == "ESCALATE_TO_MANAGER" and r.rule == "repeat-offender threshold"
    assert evaluate_employee(E(role="exec", events=clicked, prior_failures=1), 400, cfg).action == "ESCALATE_TO_MANAGER"


def test_missing_and_overdue_training(cfg):
    r = evaluate_employee(E(training_completed_day=None), 400, cfg)
    assert r.action == "REMEDIAL_TRAINING" and r.rule == "no training record" and not r.trained
    assert evaluate_employee(E(training_completed_day=35), 400, cfg).action == "NONE"        # exactly 365 days
    r = evaluate_employee(E(training_completed_day=34), 400, cfg)
    assert r.action == "MICRO_TRAINING" and r.rule == "recurring training overdue"


def test_policy_drives_thresholds(cfg):
    strict = {**cfg, "escalate_after_failures": {"standard": 1, "high_risk": 1}}
    assert evaluate_employee(E(events=["delivered", "clicked"]), 400, strict).action == "ESCALATE_TO_MANAGER"


def test_behaviour_classification(cfg):
    b = lambda **kw: classify_behaviour({"id": "B", **kw}, cfg).cls
    assert b(intentional=True, policy_violation=True, expected_for_role=True) == "RISKY"
    assert b(intentional=False, policy_violation=True, expected_for_role=False) == "UNINTENTIONAL"
    assert b(intentional=True, policy_violation=False, expected_for_role=False) == "UNEXPECTED"
    assert b(intentional=True, policy_violation=False, expected_for_role=True) == "NOT_ANOMALOUS"
    c = classify_behaviour({"id": "B", "policy_violation": False, "expected_for_role": True, "category": "removable_media"}, cfg)
    assert c.cls == "RISKY" and "missing intentional" in c.reasons[0] and "USB" in c.response


def test_lookalike_domains(cfg):
    assert is_lookalike("examp1e.com", cfg) and is_lookalike("exarnple.com", cfg) and is_lookalike("exampel.com", cfg)
    assert not is_lookalike("example.com", cfg) and not is_lookalike("mail.example.com", cfg)
    assert not is_lookalike("fabrikam.example.org", cfg)


def test_phishing_indicators(cfg):
    phish = {"id": "M", "from": "it@examp1e.com", "subject": "Act now", "body": "confirm your password",
             "links": [{"text": "www.example.com", "href": "https://evil.example.net/x"}], "attachments": ["a.zip"]}
    m = check_message(phish, cfg)
    kinds = {i.split(":")[0] for i in m.indicators}
    assert m.verdict == "REPORT_AS_PHISHING" and kinds == {"lookalike_sender_domain", "urgency_language",
                                                         "mismatched_link", "credential_or_payment_request",
                                                         "unexpected_attachment_type"}
    safe = check_message({"id": "S", "from": "hr@example.com", "subject": "Hi", "body": "Lunch is served."}, cfg)
    assert safe.verdict == "LIKELY_SAFE" and safe.score == 0
    assert check_message({"id": "N", "subject": "Hi", "body": "hello"}, cfg).verdict == "REPORT_AS_PHISHING"


def test_department_flags_and_kpis(policies, data):
    a = analyze(data("sample_awareness.json"), policies)
    depts = {d.dept: d for d in a["departments"]}
    assert depts["Engineering"].status == "OK" and depts["Engineering"].median_report_minutes == 5.5
    assert depts["HR"].flags == ["click rate 33.3% > 20%"]
    assert {k: v["status"] for k, v in a["kpis"].items()} == {
        "report_rate": "MET", "click_rate": "MISSED", "credential_rate": "MISSED",
        "median_report_minutes": "MET", "training_completion": "MISSED"}


def test_sample_demo_and_challenges(policies, data, quiet_ui):
    d = data("sample_awareness.json")
    s = run_demo(quiet_ui, policies, d)
    assert s["employees"] == {
        "E01": ["REPORTED", "NONE"], "E02": ["CLICKED", "REMEDIAL_TRAINING"],
        "E03": ["COMPROMISED", "ESCALATE_TO_MANAGER"], "E04": ["REPORTED", "NONE"], "E05": ["PASSED", "NONE"],
        "E06": ["REPORTED", "NONE"], "E07": ["CLICKED", "ESCALATE_TO_MANAGER"],
        "E08": ["COMPROMISED", "REMEDIAL_TRAINING"], "E09": ["PASSED", "REMEDIAL_TRAINING"],
        "E10": ["REPORTED", "MICRO_TRAINING"], "E11": ["NO_DATA", "REMEDIAL_TRAINING"],
        "E12": ["CLICKED", "MICRO_TRAINING"]}
    assert s["behaviours"] == {"B1": "RISKY", "B2": "UNINTENTIONAL", "B3": "UNEXPECTED", "B4": "RISKY",
                               "B5": "NOT_ANOMALOUS"}
    assert s["messages"] == {"MSG-1": "REPORT_AS_PHISHING", "MSG-2": "LIKELY_SAFE",
                             "MSG-3": "REPORT_AS_PHISHING", "MSG-4": "LIKELY_SAFE"}
    qs = build_challenges(policies, d)
    assert len(qs) >= 8 and all(q.answer in q.choices for q in qs)
