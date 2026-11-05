"""Lab 27 — entitlement management (access packages, assignment policies, lifecycle) tests."""

from __future__ import annotations

import copy
import json
import random

import pytest

from labs.lab27_entitlement_management import (ASSIGNMENT_OUTCOMES, DENY_RULES, GUEST_OUTCOMES, REQUEST_OUTCOMES,
                                               assess_assignments, assess_guests, audit_packages, build_challenges,
                                               evaluate_requests, generate_scenario, run_demo)
from utils.challenge import run_challenge

SAMPLE = "sample_entitlement_management.json"


@pytest.fixture
def cfg(policies):
    return policies["entitlement_management"]


@pytest.fixture
def sample(data):
    return data(SAMPLE)


def base():
    return {
        "users": [
            {"id": "M1", "type": "member", "manager": "BOSS"},
            {"id": "BOSS", "type": "member", "manager": None},
            {"id": "E1", "type": "external", "organization": "ORG", "in_directory": True,
             "added_by_entitlement_management": True},
        ],
        "connected_organizations": [{"id": "ORG", "state": "configured", "internal_sponsors": ["BOSS"],
                                     "external_sponsors": ["E1"]}],
        "catalogs": [{"id": "C", "enabled_for_external_users": True, "resources": [{"id": "R", "type": "group"}]}],
        "access_packages": [{"id": "P", "catalog": "C", "resources": ["R"], "incompatible_packages": [],
                             "policies": [{"id": "POL", "scope": {"type": "internal_users"},
                                           "approval": {"stages": []}, "require_justification": False,
                                           "expiry_days": 30, "access_review": None}]}],
        "requests": [], "assignments": [],
    }


def one(cfg, d, **req):
    d["requests"] = [{"id": "Q", "package": "P", "justification": "a valid business reason", **req}]
    return evaluate_requests(d, cfg)[0]


def policy(d):
    return d["access_packages"][0]["policies"][0]


def test_auto_approved_and_unknown_inputs_denied(cfg):
    r = one(cfg, base(), requester="M1")
    assert (r.outcome, r.rule) == ("AUTO_APPROVED", "auto_approval")
    assert one(cfg, base(), requester="NOBODY").rule == "unknown_requester"
    assert one(cfg, base()).rule == "unknown_requester"                      # missing requester
    d = base()
    d["requests"] = [{"id": "Q", "requester": "M1", "package": "NOPE"}]
    assert evaluate_requests(d, cfg)[0].rule == "unknown_package"
    assert evaluate_requests({"requests": [{"id": "Q"}]}, cfg)[0].outcome == "DENIED"


def test_scope_internal_vs_external(cfg):
    assert one(cfg, base(), requester="E1").rule == "not_in_scope"
    d = base()
    policy(d)["scope"] = {"type": "any_external"}
    assert one(cfg, d, requester="E1").outcome == "AUTO_APPROVED"
    assert one(cfg, copy.deepcopy(d), requester="M1").rule == "not_in_scope"
    policy(d)["scope"] = {"type": "admin_only"}
    assert one(cfg, d, requester="M1").rule == "not_in_scope"


def test_specific_and_all_connected_organizations(cfg):
    d = base()
    policy(d)["scope"] = {"type": "connected_organizations", "organizations": ["OTHER"]}
    assert one(cfg, d, requester="E1").rule == "not_in_scope"
    policy(d)["scope"] = {"type": "all_connected_organizations"}
    assert one(cfg, d, requester="E1").outcome == "AUTO_APPROVED"
    d["connected_organizations"][0]["state"] = "proposed"
    r = one(cfg, d, requester="E1")
    assert r.rule == "not_in_scope" and "proposed" in r.reasons[0]


def test_unknown_scope_type_denies(cfg):
    d = base()
    policy(d)["scope"] = {"type": "everyone?"}
    assert one(cfg, d, requester="M1").rule == "not_in_scope"


def test_catalog_not_enabled_for_external(cfg):
    d = base()
    policy(d)["scope"] = {"type": "any_external"}
    d["catalogs"][0]["enabled_for_external_users"] = False
    assert one(cfg, d, requester="E1").rule == "catalog_not_external"


def test_sod_conflict_uses_requested_package_list(cfg):
    d = base()
    other = copy.deepcopy(d["access_packages"][0])
    other["id"] = "P2"
    d["access_packages"].append(other)
    d["access_packages"][0]["incompatible_packages"] = ["P2"]
    d["assignments"] = [{"id": "A", "user": "M1", "package": "P2", "expires_in_days": 50}]
    assert one(cfg, copy.deepcopy(d), requester="M1").rule == "sod_conflict"
    d["assignments"][0]["expires_in_days"] = -1                              # expired: no longer held
    assert one(cfg, copy.deepcopy(d), requester="M1").outcome == "AUTO_APPROVED"
    # one-way: holding P does not block requests for P2, but it is flagged
    d["assignments"] = [{"id": "A", "user": "M1", "package": "P", "expires_in_days": 50}]
    d["requests"] = [{"id": "Q", "requester": "M1", "package": "P2"}]
    r = evaluate_requests(d, cfg)[0]
    assert r.outcome == "AUTO_APPROVED" and r.flags and "one-way" in r.flags[0]
    assert "SOD_ONE_WAY" in {k for k, _ in audit_packages(d, cfg)["P2"]}


def test_justification_required_and_minimum_length(cfg):
    d = base()
    policy(d)["require_justification"] = True
    assert one(cfg, copy.deepcopy(d), requester="M1", justification="").rule == "missing_justification"
    short = "x" * (cfg["min_justification_chars"] - 1)
    assert one(cfg, copy.deepcopy(d), requester="M1", justification=short).rule == "missing_justification"
    ok = "x" * cfg["min_justification_chars"]
    assert one(cfg, copy.deepcopy(d), requester="M1", justification=ok).outcome == "AUTO_APPROVED"
    del policy(d)["require_justification"]                                  # missing flag = required
    assert one(cfg, d, requester="M1", justification="").rule == "missing_justification"


def test_single_and_two_stage_approval(cfg):
    d = base()
    policy(d)["approval"] = {"stages": [{"approvers": ["manager"], "fallback": []}]}
    r = one(cfg, copy.deepcopy(d), requester="M1")
    assert (r.outcome, r.rule, r.approvers) == ("PENDING_APPROVAL", "single_stage", [["BOSS"]])
    policy(d)["approval"]["stages"].append({"approvers": ["M1", "BOSS"], "fallback": []})
    r = one(cfg, d, requester="M1")
    assert r.rule == "two_stage" and r.approvers == [["BOSS"], ["BOSS"]]     # requester dropped from stage 2


def test_approver_is_requester_and_fallback(cfg):
    d = base()
    policy(d)["approval"] = {"stages": [{"approvers": ["manager"], "fallback": ["BOSS"]}]}
    assert one(cfg, copy.deepcopy(d), requester="BOSS").rule == "approver_is_requester"
    policy(d)["approval"]["stages"][0]["fallback"] = ["BOSS", "M1"]
    r = one(cfg, d, requester="BOSS")
    assert r.outcome == "PENDING_APPROVAL" and r.approvers == [["M1"]]


def test_sponsor_approvers_and_no_approver(cfg):
    d = base()
    policy(d)["scope"] = {"type": "any_external"}
    policy(d)["approval"] = {"stages": [{"approvers": ["external_sponsor"], "fallback": ["internal_sponsor"]}]}
    r = one(cfg, copy.deepcopy(d), requester="E1")                          # E1 is its own org's external sponsor
    assert r.outcome == "PENDING_APPROVAL" and r.approvers == [["BOSS"]]
    d["users"].append({"id": "E2", "type": "external", "organization": None, "in_directory": False})
    assert one(cfg, d, requester="E2").rule == "no_approver"


def test_assignment_lifecycle(cfg):
    soon = cfg["expiring_soon_days"]
    d = base()
    d["assignments"] = [{"id": "A1", "user": "M1", "package": "P", "expires_in_days": soon + 1},
                        {"id": "A2", "user": "M1", "package": "P", "expires_in_days": soon},
                        {"id": "A3", "user": "M1", "package": "P", "expires_in_days": -1},
                        {"id": "A4", "user": "M1", "package": "P", "expires_in_days": 50, "removed_days_ago": 2},
                        {"id": "A5", "user": "GHOST", "package": "P", "expires_in_days": 50},
                        {"id": "A6", "user": "M1", "package": "GONE", "expires_in_days": 50},
                        {"id": "A7", "user": "M1", "package": "P", "expires_in_days": None}]
    assert [a.outcome for a in assess_assignments(d, cfg)] == ["ACTIVE", "EXPIRING_SOON", "EXPIRED", "REMOVED",
                                                               "INVALID", "INVALID", "ACTIVE"]


def test_guest_lifecycle(cfg):
    n = cfg["guest_removal_after_days"]
    d = base()
    d["users"] += [{"id": f"E{i}", "type": "external", "organization": "ORG", "in_directory": True,
                    "added_by_entitlement_management": True} for i in (2, 3, 4)]
    d["users"].append({"id": "E5", "type": "external", "organization": "ORG", "in_directory": True,
                       "added_by_entitlement_management": False})
    d["users"].append({"id": "E6", "type": "external", "organization": "ORG", "in_directory": False})
    d["assignments"] = [{"id": "A1", "user": "E1", "package": "P", "expires_in_days": 5},
                        {"id": "A2", "user": "E2", "package": "P", "expires_in_days": -(n - 1)},
                        {"id": "A3", "user": "E3", "package": "P", "expires_in_days": -n}]
    out = {g.user: g.outcome for g in assess_guests(d, cfg)}
    assert out == {"E1": "GUEST_ACTIVE", "E2": "GUEST_BLOCKED", "E3": "GUEST_REMOVAL_DUE",
                   "E4": "GUEST_REMOVAL_DUE", "E5": "GUEST_NOT_MANAGED"}          # E4: no history; E6 not in dir


def test_package_audit_risks(cfg, sample):
    risks = {k: {r for r, _ in v} for k, v in audit_packages(sample, cfg).items()}
    assert risks["AP-AUDIT"] == {"CATALOG_NOT_EXTERNAL", "EXTERNAL_NO_REVIEW"}
    assert risks["AP-SHIPDATA"] == {"EXTERNAL_AUTO_APPROVE", "EXTERNAL_NO_REVIEW"}
    assert risks["AP-VENDOR"] == {"SOD_ONE_WAY"} and risks["AP-DEALS"] == {"NO_FALLBACK"}
    assert risks["AP-PAYAPPROVE"] == set() and risks["AP-PARTNER"] == {"NO_EXPIRY"}


def test_sample_expected_outcomes(policies, quiet_ui, sample):
    out = run_demo(quiet_ui, policies, sample)
    json.dumps(out)
    assert out["requests"] == {"R01": "AUTO_APPROVED", "R02": "PENDING_APPROVAL", "R03": "DENIED", "R04": "DENIED",
                               "R05": "PENDING_APPROVAL", "R06": "DENIED", "R07": "PENDING_APPROVAL",
                               "R08": "PENDING_APPROVAL", "R09": "DENIED", "R10": "PENDING_APPROVAL",
                               "R11": "DENIED", "R12": "DENIED", "R13": "AUTO_APPROVED", "R14": "DENIED",
                               "R15": "AUTO_APPROVED", "R16": "DENIED"}
    assert set(out["request_rules"].values()) >= set(DENY_RULES) | {"auto_approval", "single_stage", "two_stage"}
    assert set(out["assignments"].values()) == set(ASSIGNMENT_OUTCOMES)
    assert out["guests"] == {"X01": "GUEST_ACTIVE", "X02": "GUEST_BLOCKED", "X04": "GUEST_REMOVAL_DUE",
                             "X06": "GUEST_NOT_MANAGED"}
    m = out["metrics"]
    assert m["request_outcomes"] == {"AUTO_APPROVED": 3, "PENDING_APPROVAL": 5, "DENIED": 8}
    assert m["packages_with_risks"] == 5 and m["sod_gaps_flagged"] == 1


def test_challenges_valid_and_score_100(policies, quiet_ui, sample):
    qs = build_challenges(policies, sample)
    assert len(qs) >= 12
    for q in qs:
        assert q.answer in q.choices and len(set(q.choices)) == len(q.choices)
        assert q.objective in ("4.1", "1.3") and "lab" not in (q.prompt + " ".join(q.choices)).lower()
    answers = iter([q.answer for q in qs])
    res = run_challenge(quiet_ui, 27, qs, ask=lambda _p: next(answers), shuffle=False)
    assert res.percent == 100.0


def test_generator_deterministic_and_complete(policies, quiet_ui):
    a = generate_scenario(random.Random(7), policies)
    assert a == generate_scenario(random.Random(7), policies)
    assert a != generate_scenario(random.Random(8), policies)
    for seed in range(10):
        g = generate_scenario(random.Random(seed), policies)
        out = run_demo(quiet_ui, policies, g)
        json.dumps(out)
        assert set(out["requests"].values()) == set(REQUEST_OUTCOMES)
        assert set(out["request_rules"].values()) >= set(DENY_RULES)
        assert set(out["assignments"].values()) == set(ASSIGNMENT_OUTCOMES)
        assert set(out["guests"].values()) == set(GUEST_OUTCOMES)
        assert len(build_challenges(policies, g)) >= 12
