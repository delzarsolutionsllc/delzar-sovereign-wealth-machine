"""Lab 47 — ISC roles, access profiles and access request approvals tests."""

from __future__ import annotations

import copy
import json
import random

import pytest

from labs.lab47_isc_access_requests import (REQUEST_OUTCOMES, build_challenges, eval_criteria, evaluate_request,
                                            evaluate_role, generate_scenario, run_demo)
from utils.challenge import check


@pytest.fixture
def cfg(policies):
    return policies["isc_access_requests"]


def person(iid, **kw):
    base = {"id": iid, "name": iid, "department": "Finance", "location": "US", "title": "Analyst",
            "cloudLifecycleState": "active", "manager": "M1"}
    base.update(kw)
    return base


def world(**kw):
    w = {
        "identities": [person("U1"), person("U2"), person("M1", manager="M2"), person("M2", manager=None),
                       person("O1", manager="M2"), person("E1099", manager="M2"), person("G1", manager="M2")],
        "access_profiles": [{"id": "AP1", "owner": "O1", "enabled": True, "requestable": True,
                             "entitlements": ["X:READ"], "approval_schemes": ["manager", "owner"]}],
        "roles": [], "governance_groups": {"Grp": ["G1"]}, "requests": [],
    }
    w.update(kw)
    return w


def req(**kw):
    base = {"id": "R1", "requester": "U1", "beneficiary": "U1", "item": "AP1", "decisions": {}, "days_pending": 0}
    base.update(kw)
    return base


def leaf(attr, op, value):
    return {"attribute": attr, "operation": op, "value": value}


# --------------------------------------------------------------------------- role membership
def test_criteria_and_or_nested(cfg):
    ident = person("U1", title="Systems Engineer", department="IT")
    tree = {"operation": "AND", "children": [leaf("department", "EQUALS", "it"), {"operation": "OR", "children": [
        leaf("title", "CONTAINS", "Engineer"), leaf("title", "ENDS_WITH", "Administrator")]}]}
    assert eval_criteria(tree, ident, cfg)[0] is True
    tree["children"][0] = leaf("department", "NOT_EQUALS", "IT")
    assert eval_criteria(tree, ident, cfg)[0] is False
    assert eval_criteria(leaf("title", "STARTS_WITH", "Sys"), ident, cfg)[0] is True


def test_missing_attribute_never_matches_even_not_equals(cfg):
    ident = person("U1")
    del ident["location"]
    ok, reasons, err = eval_criteria(leaf("location", "NOT_EQUALS", "UK"), ident, cfg)
    assert ok is False and err is None and "missing" in reasons[0]


def test_bad_criteria_and_disabled_role_assign_nobody(cfg):
    ident = person("U1")
    unknown = {"id": "R", "enabled": True, "membership": {"type": "STANDARD", "criteria": leaf("department",
                                                                                                 "LIKE", "Fin")}}
    deep = {"operation": "AND", "children": [{"operation": "AND", "children": [{"operation": "AND", "children": [
        leaf("department", "EQUALS", "Finance")]}]}]}
    too_deep = {"id": "R", "enabled": True, "membership": {"type": "STANDARD", "criteria": deep}}
    disabled = {"id": "R", "enabled": False, "membership": {"type": "STANDARD",
                                                            "criteria": leaf("department", "EQUALS", "Finance")}}
    for role in (unknown, too_deep, disabled, {"id": "R", "enabled": True, "membership": {"type": "MAGIC"}}):
        assert evaluate_role(role, ident, cfg).outcome == "NOT_ASSIGNED"


def test_identity_list_role(cfg):
    role = {"id": "R", "enabled": True, "membership": {"type": "IDENTITY_LIST", "identities": ["U1"]}}
    assert evaluate_role(role, person("U1"), cfg).outcome == "ASSIGNED"
    assert evaluate_role(role, person("U2"), cfg).outcome == "NOT_ASSIGNED"


# --------------------------------------------------------------------------- request gates
def test_unknown_or_inactive_identity_denied(cfg):
    w = world()
    w["identities"][1]["cloudLifecycleState"] = "inactive"
    assert evaluate_request(req(requester="NOBODY"), w, cfg).outcome == "DENIED"
    assert evaluate_request(req(requester="U2", beneficiary="U2"), w, cfg).outcome == "DENIED"


def test_request_for_others_managers_only(cfg):
    w = world()
    assert evaluate_request(req(requester="U2", beneficiary="U1"), w, cfg).rule == "request_for_others"
    ok = evaluate_request(req(requester="M1", beneficiary="U1", decisions={"manager": "approve", "owner": "approve"}),
                          w, cfg)
    assert ok.outcome == "APPROVED"


def test_unknown_item_denied_and_not_requestable(cfg):
    w = world()
    assert evaluate_request(req(item="NOPE"), w, cfg).outcome == "DENIED"
    w["access_profiles"][0]["requestable"] = False
    assert evaluate_request(req(), w, cfg).outcome == "NOT_REQUESTABLE"
    w["access_profiles"][0].update(requestable=True, enabled=False)
    assert evaluate_request(req(), w, cfg).outcome == "NOT_REQUESTABLE"


def test_already_has_access_via_role(cfg):
    role = {"id": "RF", "enabled": True, "requestable": True, "access_profiles": ["AP1"], "entitlements": [],
            "membership": {"type": "STANDARD", "criteria": leaf("department", "EQUALS", "Finance")}}
    w = world(roles=[role])
    r = evaluate_request(req(), w, cfg)
    assert r.outcome == "ALREADY_HAS_ACCESS" and "role RF" in r.reasons[0]
    assert evaluate_request(req(item="RF"), w, cfg).outcome == "ALREADY_HAS_ACCESS"


def test_unknown_reviewer_type_denied(cfg):
    w = world()
    w["access_profiles"][0]["approval_schemes"] = ["manager", "hr_partner"]
    r = evaluate_request(req(decisions={"manager": "approve"}), w, cfg)
    assert r.outcome == "DENIED" and r.rule == "reviewer_type"


def test_sod_flag_routes_and_block_stops(cfg):
    pol = cfg["sod_policies"][0]
    w = world()
    w["identities"][0]["entitlements"] = [pol["right"][0]]
    w["access_profiles"][0]["entitlements"] = [pol["left"][0]]
    r = evaluate_request(req(decisions={"manager": "approve"}), w, cfg)
    assert r.outcome == "SOD_VIOLATION" and r.approval_status == "PENDING" and pol["name"] in r.reasons[0]
    strict = copy.deepcopy(cfg)
    strict["sod_action"] = "block"
    b = evaluate_request(req(), w, strict)
    assert b.outcome == "SOD_VIOLATION" and b.approval_status == "-"


# --------------------------------------------------------------------------- approvals
def test_levels_in_order_and_deny_stops(cfg):
    w = world()
    assert evaluate_request(req(decisions={"manager": "approve", "owner": "approve"}), w, cfg).outcome == "APPROVED"
    d = evaluate_request(req(decisions={"manager": "deny", "owner": "approve"}), w, cfg)
    assert d.outcome == "DENIED" and len(d.steps) == 1
    p = evaluate_request(req(decisions={"manager": "approve"}), w, cfg)
    assert p.outcome == "PENDING" and p.current_approver == "O1 (O1)"
    w["access_profiles"][0]["approval_schemes"] = []
    assert evaluate_request(req(), w, cfg).outcome == "APPROVED"


def test_self_approval_prevention_and_auto_approve(cfg):
    w = world()
    r = evaluate_request(req(requester="M1", beneficiary="U1"), w, cfg)
    assert r.outcome == "PENDING" and r.current_approver == "M2 (M2)"
    auto = copy.deepcopy(cfg)
    auto["auto_approve"] = "DIRECT"
    a = evaluate_request(req(requester="M1", beneficiary="U1"), w, auto)
    assert a.steps[0]["result"] == "AUTO_APPROVED" and a.current_approver == "O1 (O1)"


def test_work_reassignment_chain_and_loop(cfg):
    w = world()
    people = {p["id"]: p for p in w["identities"]}
    people["M1"]["work_reassignment"] = {"active": True, "delegate": "M2"}
    assert evaluate_request(req(), w, cfg).current_approver == "M2 (M2)"
    people["M2"]["work_reassignment"] = {"active": True, "delegate": "M1"}
    loop = evaluate_request(req(), w, cfg)
    fb = cfg["escalation"]["fallback_approver"]
    assert loop.current_approver == f"{fb} ({fb})" and any("loops" in x for x in loop.reasons)


def test_missing_manager_goes_to_fallback_then_owner_then_denied(cfg):
    w = world()
    w["identities"][0]["manager"] = None
    fb = cfg["escalation"]["fallback_approver"]
    assert evaluate_request(req(), w, cfg).current_approver == f"{fb} ({fb})"
    w["identities"] = [p for p in w["identities"] if p["id"] != fb]
    assert evaluate_request(req(), w, cfg).current_approver == "O1 (O1)"
    w["access_profiles"][0]["owner"] = "GONE"
    assert evaluate_request(req(), w, cfg).outcome == "DENIED"


def test_reminders_escalation_and_timeout(cfg):
    w = world()
    esc, rem = cfg["escalation"], cfg["reminders"]
    before = evaluate_request(req(days_pending=esc["start_after_days"] - 1), w, cfg)
    assert before.escalations == 0 and before.current_approver == "M1 (M1)"
    assert before.reminders == min(rem["max_reminders"], 1 + (esc["start_after_days"] - 1 - rem["start_after_days"]))
    after = evaluate_request(req(days_pending=esc["start_after_days"]), w, cfg)
    assert after.escalations == 1 and after.current_approver == "M2 (M2)"
    expired = evaluate_request(req(days_pending=cfg["timeout_days"]), w, cfg)
    assert expired.outcome == "DENIED" and "expired" in expired.reasons[-1]


def test_governance_group_any_member_and_self_exclusion(cfg):
    w = world()
    w["access_profiles"][0]["approval_schemes"] = ["governance_group:Grp"]
    assert evaluate_request(req(), w, cfg).current_approver.startswith("governance group Grp (G1")
    assert evaluate_request(req(decisions={"governance_group:Grp": "approve"}), w, cfg).outcome == "APPROVED"
    only_me = evaluate_request(req(requester="G1", beneficiary="G1"), w, cfg)
    assert only_me.current_approver == "M2 (M2)"
    w["governance_groups"] = {}
    fb = cfg["escalation"]["fallback_approver"]
    assert evaluate_request(req(), w, cfg).current_approver == f"{fb} ({fb})"


# --------------------------------------------------------------------------- sample, generator, challenges
def test_sample_demo(policies, quiet_ui, data):
    out = run_demo(quiet_ui, policies, data("sample_isc_access_requests.json"))
    json.dumps(out)
    assert out["roles"]["R-FIN-US"] == ["E1001", "E1005", "E1009"]
    assert out["roles"]["R-SALES"] == ["E1003", "E1006", "E1013"] and out["roles"]["R-FIN-LEGACY"] == []
    assert out["requests"] == {
        "REQ-01": "APPROVED", "REQ-02": "SOD_VIOLATION", "REQ-03": "APPROVED", "REQ-04": "PENDING",
        "REQ-05": "PENDING", "REQ-06": "DENIED", "REQ-07": "DENIED", "REQ-08": "NOT_REQUESTABLE",
        "REQ-09": "NOT_REQUESTABLE", "REQ-10": "ALREADY_HAS_ACCESS", "REQ-11": "PENDING", "REQ-12": "DENIED",
        "REQ-13": "APPROVED", "REQ-14": "DENIED", "REQ-15": "DENIED", "REQ-16": "DENIED"}
    assert out["current_approvers"]["REQ-04"] == "Mo Fischer (E1013)"
    assert out["current_approvers"]["REQ-05"] == "Hugo Brandt (E1008)"
    m = out["metrics"]
    assert (m["role_assignments"], m["reminders_sent"], m["escalations"]) == (10, 6, 1)


def test_generated_scenario_is_deterministic_and_covers_every_outcome(policies, quiet_ui):
    g = generate_scenario(random.Random(11), policies)
    assert g == generate_scenario(random.Random(11), policies)
    assert g != generate_scenario(random.Random(12), policies)
    out = run_demo(quiet_ui, policies, g)
    assert set(out["requests"].values()) == set(REQUEST_OUTCOMES)
    assert len(build_challenges(policies, g)) >= 12


def test_challenges_score_full_marks(policies, data):
    qs = build_challenges(policies, data("sample_isc_access_requests.json"))
    assert len(qs) >= 12
    assert {q.objective for q in qs} <= {"5.2", "6.1", "5.1"}
    for q in qs:
        assert len(set(q.choices)) == len(q.choices) and q.answer in q.choices
        assert "lab" not in (q.prompt + " ".join(q.choices)).lower().split()
    assert sum(check(q, q.answer) for q in qs) == len(qs)
