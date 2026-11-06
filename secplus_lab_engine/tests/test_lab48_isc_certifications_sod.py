"""Lab 48 — ISC certification campaigns and Separation of Duties tests."""

from __future__ import annotations

import copy
import random

import pytest

from labs.lab48_isc_certifications_sod import (ITEM_OUTCOMES, PLAN_OUTCOMES, REQUEST_OUTCOMES, SOD_OUTCOMES,
                                               build_challenges, evaluate_identity, evaluate_request, plan_campaign,
                                               run_campaign, run_demo, transition, generate_scenario)
from utils.challenge import run_challenge

SAMPLE = "sample_isc_certifications_sod.json"


@pytest.fixture
def cfg(policies):
    return policies["isc_certifications_sod"]


@pytest.fixture
def sample(data):
    return data(SAMPLE)


def items_by_id(res):
    return {r.id: r for r in res.items}


def mini(items, identities=None, camp_type="MANAGER", **camp):
    ids = identities or [{"id": "M", "manager": "B"}, {"id": "B", "manager": None}, {"id": "U", "manager": "M"},
                         {"id": "O", "manager": "B"}]
    return {"identities": ids, "sources": {"ERP": {"owner": "M", "connection": "direct"},
                                           "CSV": {"owner": "M", "connection": "flat_file"}},
            "campaign": {"type": camp_type, "status": "STAGED", "owner": "O", "deadline_passed": True,
                         "undecided_action": "REVOKE", "signed_off": [], "items": items, **camp}}


def it(n, who="U", decision="approve", **kw):
    return {"id": n, "identity": who, "source": kw.pop("source", "ERP"), "access_type": kw.pop("access_type", "ENTITLEMENT"),
            "access": "X", "assignment": kw.pop("assignment", "requested"), "decision": decision, **kw}


# ----------------------------------------------------------------- planner
def test_planner_maps_each_requirement_type(cfg):
    p = lambda text, **kw: plan_campaign({"id": "R", "text": text, **kw}, cfg)  # noqa: E731
    assert p("Managers review all access of their direct reports").campaign_type == "MANAGER"
    assert p("The owner of the ERP source reviews it", source="ERP").campaign_type == "SOURCE_OWNER"
    r = p("Review what the role contains", role="X")
    assert r.campaign_type == "ROLE_COMPOSITION" and r.reviewer == "role owner"
    r = p("Review all access held by one identity", query="id:1", reviewer="individual: A")
    assert (r.campaign_type, r.search_type) == ("SEARCH", "IDENTITIES")
    r = p("Review everyone who has the Admin entitlement", reviewer="access owner")
    assert (r.campaign_type, r.search_type) == ("SEARCH", "ACCESS_ITEMS")
    assert p("Review uncorrelated accounts on CSV").search_type == "UNCORRELATED_ACCOUNTS"


def test_rule_order_single_identity_beats_all_access(cfg):
    r = plan_campaign({"id": "R", "text": "Review all access held by one identity", "query": "id:1",
                       "reviewer": "individual: A"}, cfg)
    assert r.subject == "single_identity" and "one identity" in r.reasons[0]


def test_manager_review_without_managers_becomes_search(cfg):
    r = plan_campaign({"id": "R", "text": "Manager review including people without a manager"}, cfg)
    assert (r.campaign_type, r.search_type, r.reviewer) == ("SEARCH", "IDENTITIES", "manager")


def test_planner_deny_by_default(cfg):
    assert plan_campaign({"id": "R", "text": "Make access fine"}, cfg).campaign_type == "NEEDS_CLARIFICATION"
    assert plan_campaign({}, cfg).campaign_type == "NEEDS_CLARIFICATION"
    # search campaign without a reviewer, without a query; source owner without a source
    assert plan_campaign({"id": "R", "text": "everyone who has the X entitlement"}, cfg).campaign_type == \
        "NEEDS_CLARIFICATION"
    assert plan_campaign({"id": "R", "text": "identities in Treasury", "reviewer": "x"}, cfg).campaign_type == \
        "NEEDS_CLARIFICATION"
    assert plan_campaign({"id": "R", "text": "the source owner reviews"}, cfg).campaign_type == "NEEDS_CLARIFICATION"


# ----------------------------------------------------------------- lifecycle
def test_transitions_refuse_unknown_actions(cfg):
    assert transition("STAGED", "activate", cfg)[0] == "ACTIVE"
    assert transition("ACTIVE", "complete", cfg)[0] == "COMPLETED"
    new, why = transition("STAGED", "complete", cfg)
    assert new == "STAGED" and "refused" in why
    assert transition("COMPLETED", "activate", cfg)[0] == "COMPLETED"


def test_approve_revoke_and_remediation_by_connection(cfg):
    res = run_campaign(mini([it("A"), it("R", "U", "revoke", comment="no"),
                             it("F", "U", "revoke", comment="no", source="CSV"),
                             it("Z", "U", "revoke", comment="no", source="Mystery")], signed_off=["M"]), cfg)
    r = items_by_id(res)
    assert r["A"].outcome == "APPROVED" and r["A"].remediation == "NONE"
    assert r["R"].outcome == "REVOKED" and r["R"].remediation == "PROVISIONING_TASK"
    assert r["F"].remediation == "MANUAL_WORK_ITEM"
    assert r["Z"].remediation == "MANUAL_WORK_ITEM"          # unknown source: manual, deny by default
    assert res.status == "COMPLETED" and res.signed_off == ["M"]


def test_revoke_without_required_comment_is_not_recorded(cfg):
    res = run_campaign(mini([it("R", "U", "revoke", comment="  ")], deadline_passed=False, signed_off=["M"]), cfg)
    r = res.items[0]
    assert r.outcome == "UNDECIDED" and res.status == "ACTIVE" and "M" in res.not_signed_off


def test_undecided_at_deadline_follows_undecided_action(cfg):
    revoke = run_campaign(mini([it("U1", "U", None)]), cfg)
    assert revoke.items[0].outcome == "UNDECIDED" and revoke.items[0].remediation == "PROVISIONING_TASK"
    keep = run_campaign(mini([it("U1", "U", None)], undecided_action="MAINTAIN"), cfg)
    assert keep.items[0].remediation == "NONE" and keep.status == "COMPLETED"
    missing = run_campaign(mini([it("U1", "U", None)], undecided_action=None), cfg)
    assert missing.undecided_action == "REVOKE" and missing.items[0].remediation == "PROVISIONING_TASK"
    early = run_campaign(mini([it("U1", "U", None)], deadline_passed=False), cfg)
    assert early.status == "ACTIVE" and early.items[0].remediation == "NONE"


def test_unsigned_revoke_waits_for_sign_off(cfg):
    res = run_campaign(mini([it("R", "U", "revoke", comment="x"), it("U2", "U", None)], deadline_passed=False,
                            signed_off=[]), cfg)
    assert items_by_id(res)["R"].remediation == "PENDING_SIGN_OFF"


def test_criteria_role_can_only_be_acknowledged(cfg):
    res = run_campaign(mini([it("C", "U", "revoke", comment="x", access_type="ROLE", assignment="criteria")]), cfg)
    assert res.items[0].outcome == "ACKNOWLEDGED" and res.items[0].remediation == "NONE"


def test_data_issues_missing_manager_unknown_manager_uncorrelated(cfg):
    ids = [{"id": "B", "manager": None}, {"id": "G", "manager": "GHOST"}, {"id": "O", "manager": None}]
    res = run_campaign(mini([it("1", "B"), it("2", "G"), it("3", None), it("4", "NOBODY")], identities=ids), cfg)
    r = items_by_id(res)
    assert r["1"].outcome == r["2"].outcome == "REVIEWER_MISSING"
    assert r["3"].outcome == r["4"].outcome == "NOT_CERTIFIABLE"
    # A search campaign with Manager as reviewer sends the no-manager identity to the campaign owner.
    s = run_campaign(mini([it("1", "B")], identities=ids, camp_type="SEARCH"), cfg)
    assert s.items[0].reviewer == "O" and s.items[0].outcome == "APPROVED"


def test_self_certification_is_rerouted(cfg):
    # Source owner M reviews their own ERP access: moved to M's manager B.
    res = run_campaign(mini([it("S", "M")], camp_type="SOURCE_OWNER"), cfg)
    assert res.items[0].reviewer == "B" and "self-certification" in " ".join(res.items[0].reasons)
    assert run_campaign(mini([it("S", "U")], camp_type="WEIRD"), cfg).items[0].outcome == "REVIEWER_MISSING"


def test_reassignment_rules(cfg):
    ok = run_campaign(mini([it("1", reassigned_to="O", reassign_reason="knows it")]), cfg).items[0]
    assert ok.reviewer == "O"
    for target, reason in (("U", "self"), ("NOPE", "x"), ("O", "")):
        r = run_campaign(mini([it("1", reassigned_to=target, reassign_reason=reason)]), cfg).items[0]
        assert r.reviewer == "M" and "refused" in " ".join(r.reasons)


def test_sign_off_refused_with_undecided_items(cfg):
    res = run_campaign(mini([it("1"), it("2", "U", None)], signed_off=["M"]), cfg)
    assert res.not_signed_off == ["M"] and any("sign-off refused" in x for x in res.reasons)


# ----------------------------------------------------------------- SoD
def test_sod_violation_through_decomposition_and_disabled_policy(sample):
    sod = sample["sod"]
    ana = evaluate_identity({"id": "A", "access": [{"type": "ROLE", "id": "Finance Analyst"},
                                                   {"type": "ENTITLEMENT", "id": "ns.je_approve"}]}, sod)
    assert ana.outcome == "VIOLATION" and ana.conflicts[0]["policy"] == "SOD-02"
    assert (ana.conflicts[0]["a"], ana.conflicts[0]["b"]) == ("Journal Entry Post", "Journal Entry Approve")
    jun = evaluate_identity({"id": "J", "access": [{"type": "ENTITLEMENT", "id": "pay.admin"},
                                                   {"type": "ENTITLEMENT", "id": "pay.worker_edit"}]}, sod)
    assert jun.outcome == "OK"
    on = copy.deepcopy(sod)
    del on["policies"][2]["enabled"]                         # missing flag = enabled (deny by default)
    assert evaluate_identity({"id": "J", "access": [{"type": "ENTITLEMENT", "id": "pay.admin"},
                                                    {"type": "ENTITLEMENT", "id": "pay.worker_edit"}]}, on).outcome \
        == "VIOLATION"


def test_sod_unknown_access_cannot_be_cleared(sample):
    r = evaluate_identity({"id": "X", "access": [{"type": "ROLE", "id": "Nope"}]}, sample["sod"])
    assert r.outcome == "CANNOT_EVALUATE"


def test_request_checks_and_actions(sample, cfg):
    sod = sample["sod"]
    req = lambda who, items: evaluate_request({"id": "Q", "identity": who, "items": items}, sod, cfg)  # noqa: E731
    r = req("IW1002", [{"type": "ROLE", "id": "Controller"}])
    assert (r.outcome, r.action) == ("WOULD_VIOLATE", "ROUTED_TO_APPROVERS")
    assert req("IW0900", [{"type": "ENTITLEMENT", "id": "ns.ap_payment"}]).action == "BLOCKED"
    assert req("IW1100", [{"type": "ENTITLEMENT", "id": "ns.je_post"}]).outcome == "OK"
    assert req("GHOST", [{"type": "ENTITLEMENT", "id": "ns.je_post"}]).outcome == "CANNOT_EVALUATE"
    assert req("IW1100", [{"type": "ACCESS_PROFILE", "id": "Nope"}]).outcome == "CANNOT_EVALUATE"
    assert req("IW1100", []).outcome == "CANNOT_EVALUATE"
    # A policy with no access-request setting blocks (deny by default).
    s2 = copy.deepcopy(sod)
    del s2["policies"][1]["access_requests"]
    assert evaluate_request({"id": "Q", "identity": "IW1002", "items": [{"type": "ROLE", "id": "Controller"}]},
                            s2, cfg).action == "BLOCKED"


def test_both_conflicting_items_in_one_request_needs_in_flight_check(sample, cfg):
    q = {"id": "Q", "identity": "IW1003", "items": [{"type": "ENTITLEMENT", "id": "ns.vendor_maintain"},
                                                     {"type": "ACCESS_PROFILE", "id": "NetSuite Payment Release"}]}
    assert evaluate_request(q, sample["sod"], cfg).outcome == "WOULD_VIOLATE"
    old = copy.deepcopy(cfg)
    old["sod"]["include_in_flight_access"] = False
    assert evaluate_request(q, sample["sod"], old).outcome == "OK"


# ----------------------------------------------------------------- sample, generator, challenges
def test_sample_expected_outcomes(policies, quiet_ui, sample):
    out = run_demo(quiet_ui, policies, sample)
    assert out["plans"] == {"R1": "MANAGER", "R2": "SOURCE_OWNER", "R3": "SEARCH", "R4": "ROLE_COMPOSITION",
                            "R5": "SEARCH", "R6": "SEARCH", "R7": "SEARCH", "R8": "NEEDS_CLARIFICATION",
                            "R9": "SEARCH"}
    assert out["items"] == {"C01": "APPROVED", "C02": "REVOKED", "C03": "REVOKED", "C04": "ACKNOWLEDGED",
                            "C05": "UNDECIDED", "C06": "APPROVED", "C07": "REVIEWER_MISSING",
                            "C08": "REVIEWER_MISSING", "C09": "NOT_CERTIFIABLE", "C10": "APPROVED",
                            "C11": "UNDECIDED", "C12": "APPROVED"}
    assert out["remediation"] == {"C02": "PROVISIONING_TASK", "C03": "MANUAL_WORK_ITEM", "C05": "PROVISIONING_TASK",
                                  "C11": "PROVISIONING_TASK"}
    assert out["campaign_status"] == "COMPLETED"
    assert out["sod"] == {"IW1001": "VIOLATION", "IW1002": "OK", "IW1004": "VIOLATION", "IW1003": "OK",
                          "IW1000": "CANNOT_EVALUATE", "IW0900": "OK", "IW1100": "OK"}
    assert out["request_actions"] == {"AR-301": "ROUTED_TO_APPROVERS", "AR-302": "NORMAL_APPROVAL",
                                      "AR-303": "BLOCKED", "AR-304": "HELD", "AR-305": "BLOCKED"}
    assert out["metrics"]["remediation_tasks"] == 4 and out["metrics"]["violations"] == 2
    assert set(out["plans"].values()) == set(PLAN_OUTCOMES)
    assert set(out["items"].values()) == set(ITEM_OUTCOMES)
    assert set(out["sod"].values()) == set(SOD_OUTCOMES)
    assert set(out["requests"].values()) == set(REQUEST_OUTCOMES)


def test_generator_is_deterministic_and_covers_every_outcome(policies, quiet_ui):
    a, b = generate_scenario(random.Random(7), policies), generate_scenario(random.Random(7), policies)
    assert a == b and a != generate_scenario(random.Random(8), policies)
    out = run_demo(quiet_ui, policies, a)
    assert set(out["plans"].values()) == set(PLAN_OUTCOMES)
    assert set(out["items"].values()) == set(ITEM_OUTCOMES)
    assert set(out["sod"].values()) == set(SOD_OUTCOMES)
    assert set(out["requests"].values()) == set(REQUEST_OUTCOMES)
    assert len(build_challenges(policies, a)) >= 12


def test_challenges_are_valid_and_self_answering_scores_100(policies, quiet_ui, sample):
    qs = build_challenges(policies, sample)
    assert len(qs) >= 12
    assert all(q.objective in ("6.2", "6.3") for q in qs)
    assert all(len(set(q.choices)) == len(q.choices) for q in qs)
    assert not any("lab" in (q.prompt + " ".join(q.choices)).lower().split() for q in qs)
    answers = iter([q.answer for q in qs])
    res = run_challenge(quiet_ui, 48, qs, ask=lambda _: next(answers), shuffle=False)
    assert res.correct == res.total == len(qs)
