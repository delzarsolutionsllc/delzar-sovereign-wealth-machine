"""Lab 18 — data protection & DLP gate tests."""

from __future__ import annotations

import pytest

from labs.lab18_data_protection import build_challenges, detect, evaluate, luhn_ok, run_demo


@pytest.fixture
def cfg(policies):
    return policies["data_protection"]


def F(**kw):
    base = {"id": "X", "description": "x", "records": ["quarterly newsletter"], "declared_classification": "public",
            "state": "in_transit", "destination": {"type": "internal_app", "region": "us", "approved": True},
            "encrypted_channel": True, "protection": []}
    base.update(kw)
    return base


def test_luhn_filters_random_numbers(cfg):
    assert luhn_ok("4111111111111111") and not luhn_ok("1234567890123456")
    assert [f.detector for f in detect("card 4111-1111-1111-1111", cfg["detectors"])] == ["payment_card"]
    assert detect("order ref 1234 5678 9012 3456", cfg["detectors"]) == []


def test_detectors_map_to_types_and_classes(cfg):
    found = {f.detector: (f.data_type, f.classification)
             for f in detect("ssn 123-45-6789 MRN-0045512 a@example.com password=x", cfg["detectors"])}
    assert found["us_ssn"] == ("regulated", "restricted")
    assert found["health_record_id"] == ("regulated", "restricted")
    assert found["password"] == ("credential", "critical")


def test_clean_public_flow_allowed(cfg):
    r = evaluate(F(), cfg)
    assert r.decision == "ALLOW" and r.classification == "public"


def test_detection_raises_classification(cfg):
    r = evaluate(F(records=["ssn 123-45-6789"], declared_classification="private", protection=["encryption"]), cfg)
    assert r.classification == "restricted" and any("raises the label" in x for x in r.reasons)


def test_pan_in_use_requires_masking(cfg):
    r = evaluate(F(records=["card 4111 1111 1111 1111"], declared_classification="restricted", state="in_use",
                   destination={"type": "support_console", "region": "us", "approved": True}), cfg)
    assert r.decision == "ALLOW_WITH_PROTECTION" and "last 4" in r.required[0]
    ok = evaluate(F(records=["card 4111 1111 1111 1111"], declared_classification="restricted", state="in_use",
                    protection=["masking"], destination={"type": "support_console", "region": "us", "approved": True}), cfg)
    assert ok.decision == "ALLOW"


def test_unencrypted_channel_needs_tls(cfg):
    r = evaluate(F(records=["TRADE SECRET recipe"], declared_classification="confidential", encrypted_channel=False), cfg)
    assert r.decision == "ALLOW_WITH_PROTECTION" and "TLS" in r.required[0]
    assert evaluate(F(records=["TRADE SECRET recipe"], declared_classification="confidential"), cfg).decision == "ALLOW"


def test_password_encryption_rejected_hash_accepted(cfg):
    base = dict(records=["password=Hunter2!"], declared_classification="critical", state="at_rest",
                destination={"type": "internal_db", "region": "us", "approved": True})
    r = evaluate(F(protection=["encryption"], **base), cfg)
    assert r.decision == "BLOCK" and r.block_rules == ["protection"] and "salted" in r.reasons[-1]
    assert evaluate(F(protection=["hashing"], **base), cfg).decision == "ALLOW"


def test_region_and_sovereignty(cfg):
    r = evaluate(F(records=["ssn 123-45-6789"], declared_classification="restricted", state="at_rest",
                   protection=["encryption"], destination={"type": "internal_db", "region": "apac", "approved": True}), cfg)
    assert r.decision == "BLOCK" and r.block_rules == ["region"]
    eu = dict(records=["x@example.eu"], declared_classification="private", data_origin="eu",
              destination={"type": "analytics", "region": "us", "approved": True})
    assert evaluate(F(**eu), cfg).block_rules == ["sovereignty"]
    eu["destination"] = {"type": "analytics", "region": "eu", "approved": True}
    assert evaluate(F(**eu), cfg).decision == "ALLOW"


def test_deny_by_default(cfg):
    assert evaluate(F(declared_classification=None), cfg).block_rules[0] == "classification"
    assert evaluate(F(destination=None), cfg).block_rules[0] == "destination"
    assert evaluate(F(state="archived"), cfg).block_rules == ["state"]
    assert evaluate(F(destination={"type": "public_web", "region": "us", "approved": False}), cfg).decision == "BLOCK"


def test_policy_driven_regions(cfg):
    flow = F(records=["ssn 123-45-6789"], declared_classification="restricted", state="at_rest",
             protection=["encryption"], destination={"type": "internal_db", "region": "eu", "approved": True})
    assert evaluate(flow, cfg).decision == "BLOCK"
    relaxed = {**cfg, "allowed_regions": {**cfg["allowed_regions"], "restricted": ["us", "eu"]}}
    assert evaluate(flow, relaxed).decision == "ALLOW"


def test_sample_outcomes_and_challenges(policies, quiet_ui, data):
    sample = data("sample_data_flows.json")
    assert run_demo(quiet_ui, policies, sample) == {
        "DF-1": "ALLOW", "DF-2": "ALLOW_WITH_PROTECTION", "DF-3": "ALLOW", "DF-4": "BLOCK",
        "DF-5": "BLOCK", "DF-6": "BLOCK", "DF-7": "BLOCK", "DF-8": "ALLOW_WITH_PROTECTION"}
    qs = build_challenges(policies, sample)
    assert len(qs) >= 8 and all(q.answer in q.choices for q in qs)
    tok = [q for q in qs if "random surrogate" in q.prompt]
    assert tok and tok[0].answer == "tokenization"
