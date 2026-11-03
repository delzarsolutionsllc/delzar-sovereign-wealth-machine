"""Lab 13 — threat actor & vector classifier tests."""

from __future__ import annotations

import pytest

from labs.lab13_threat_classifier import UNDETERMINED, classify, classify_all


@pytest.fixture
def cfg(policies):
    return policies["threat_classification"]


def S(ind, access="phishing_email"):
    return {"id": "X", "indicators": ind, "initial_access": access}


def test_nation_state(cfg):
    r = classify(S(["high_funding", "advanced_tools", "long_dwell_time", "espionage_data_theft"], "watering_hole"), cfg)
    assert (r.actor, r.motivation) == ("Nation-state", "Espionage")
    assert r.vector.startswith("Watering hole")


def test_blackmail_beats_generic_financial_gain(cfg):
    r = classify(S(["demands_payment", "threatens_to_leak_unless_paid"]), cfg)
    assert r.actor == "Organized crime" and r.motivation == "Blackmail"
    assert classify(S(["demands_payment", "ransomware"]), cfg).motivation == "Financial gain"


def test_insider_vs_shadow_it(cfg):
    assert classify(S(["authorized_access_abused", "recently_disgruntled"]), cfg).actor == "Insider threat"
    assert classify(S(["unapproved_service", "no_malicious_intent"]), cfg).actor == "Shadow IT"


def test_ambiguous_evidence_is_undetermined(cfg):
    r = classify(S(["political_message", "demands_payment"]), cfg)       # 3 vs 3
    assert r.actor == UNDETERMINED and "too close" in r.actor_reasons[0]


def test_no_evidence_is_undetermined(cfg):
    r = classify(S([], "nonexistent_vector"), cfg)
    assert r.actor == UNDETERMINED and r.motivation == UNDETERMINED and r.vector == UNDETERMINED


def test_unknown_indicators_are_reported_not_used(cfg):
    r = classify(S(["ransomware", "demands_payment", "aliens"]), cfg)
    assert r.unknown_indicators == ["aliens"] and r.actor == "Organized crime"


def test_vector_and_mitigation_mapping(cfg):
    r = classify(S(["noisy_attack", "public_exploit_tools"], "default_credentials"), cfg)
    assert r.vector == "Default credentials" and "change default credentials" in r.mitigation


def test_sample_outcomes(policies, data):
    res = {r.id: r for r in classify_all(data("sample_threat_scenarios.json"), policies)}
    assert {k: v.actor for k, v in res.items()} == {
        "T-01": "Nation-state", "T-02": "Organized crime", "T-03": "Hacktivist", "T-04": "Insider threat",
        "T-05": "Unskilled attacker", "T-06": "Shadow IT", "T-07": "Organized crime", "T-08": "Organized crime"}
    assert {k: v.motivation for k, v in res.items()} == {
        "T-01": "Espionage", "T-02": "Financial gain", "T-03": "Philosophical/political beliefs", "T-04": "Revenge",
        "T-05": "Disruption/chaos", "T-06": "Convenience (no malicious intent)", "T-07": "Financial gain",
        "T-08": "Blackmail"}
    # every sample is decisive by at least the configured margin
    margin = policies["threat_classification"]["min_margin"]
    for r in res.values():
        top = sorted(r.actor_scores.values(), reverse=True)
        assert top[0] - top[1] >= margin
