"""Lab 16 — security control classifier tests."""

from __future__ import annotations

import pytest

from labs.lab16_control_classifier import UNCLASSIFIED, classify, classify_all, pick


@pytest.fixture
def cfg(policies):
    return policies["control_classification"]


def test_sample_matches_answer_key(policies, data):
    d = data("sample_controls.json")
    for c, r in zip(d["controls"], classify_all(d, policies)):
        assert (r.category, r.type) == (c["expected_category"], c["expected_type"]), c["id"]


def test_whole_word_matching(cfg):
    # 'logs' must not match inside 'login'
    r = classify({"id": "x", "description": "The login page uses MFA."}, cfg)
    assert r.category == "Technical" and "logs" not in r.type_evidence


def test_tie_is_unclassified():
    label, ev, scores = pick("alpha beta", {"A": {"alpha": 2}, "B": {"beta": 2}})
    assert label == UNCLASSIFIED and scores == {"A": 2, "B": 2}


def test_no_evidence_is_unclassified(cfg):
    r = classify({"id": "x", "description": "Something vague happens."}, cfg)
    assert (r.category, r.type) == (UNCLASSIFIED, UNCLASSIFIED)


def test_compensating_outweighs_preventive_wording(cfg):
    r = classify({"id": "x", "description": "The app cannot be patched, so a firewall blocks its port instead."}, cfg)
    assert r.type == "Compensating" and r.type_scores["Compensating"] > r.type_scores["Preventive"]


def test_signs_directive_vs_deterrent(cfg):
    d = classify({"id": "a", "description": "A sign on the door reads authorized personnel only."}, cfg)
    w = classify({"id": "b", "description": "Posted warning signs say trespassers will be prosecuted."}, cfg)
    assert (d.category, d.type) == ("Physical", "Directive")
    assert (w.category, w.type) == ("Physical", "Deterrent")


def test_evidence_is_reported(cfg):
    r = classify({"id": "x", "description": "Backups are used to recover data."}, cfg)
    assert "backups" in r.category_evidence and "recover" in r.type_evidence
