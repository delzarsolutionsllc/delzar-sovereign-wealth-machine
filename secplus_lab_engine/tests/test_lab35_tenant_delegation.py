"""Lab 35 — tenant delegation (roles, administrative units, dynamic groups) tests."""

from __future__ import annotations

import copy
import json
import random

import pytest

from labs.lab35_tenant_delegation import (FINDINGS, PLAN_OUTCOMES, RuleError, audit_assignments, build_challenges,
                                          check_dynamic_groups, evaluate_rule, generate_scenario, global_admin_check,
                                          parse_rule, plan_request, run_demo)
from utils.challenge import run_challenge


@pytest.fixture
def cfg(policies):
    return policies["tenant_delegation"]


@pytest.fixture
def sample(data):
    return data("sample_tenant_delegation.json")


BASE = {
    "administrative_units": [
        {"id": "AU-EMEA", "region": "EMEA", "restricted": False, "members": ["m@x.example"]},
        {"id": "AU-VIP", "region": "VIP", "restricted": True, "members": ["vip@x.example"]},
    ],
    "principals": {
        "m@x.example": {"userType": "Member", "department": "IT", "country": "Germany"},
        "g@partner.example": {"userType": "Guest", "department": "Sales", "country": "Germany"},
        "vip@x.example": {"userType": "Member", "department": "Executive", "country": "Germany"},
        "bg1@x.example": {"userType": "Member", "emergency_access": True},
        "bg2@x.example": {"userType": "Member", "emergency_access": True},
    },
}


def plan(cfg, **req):
    return plan_request({"id": "R1", "requester": "m@x.example", **req}, BASE, cfg)


def audit(cfg, *assignments):
    return audit_assignments({**BASE, "assignments": list(assignments)}, cfg)


# ---- Part 1: planner -------------------------------------------------------------------------------------
def test_tenant_least_privileged_roles(cfg):
    assert (plan(cfg, task="reset_password").role, plan(cfg, task="reset_password").outcome) == \
        ("Password Administrator", "TENANT")
    assert plan(cfg, task="register_apps").role == "Application Developer"
    assert plan(cfg, task="manage_conditional_access").role == "Conditional Access Administrator"
    assert plan(cfg, task="assign_licenses").role == "License Administrator"


def test_unknown_or_missing_task_escalates(cfg):
    for req in ({"task": "rotate_bitlocker_keys"}, {}):
        p = plan(cfg, **req)
        assert p.outcome == "ESCALATE" and p.role is None and "deny by default" in p.reasons[0]


def test_region_scopes_to_administrative_unit_case_insensitive(cfg):
    p = plan(cfg, task="manage_users", region="emea")
    assert (p.outcome, p.role, p.scope) == ("ADMINISTRATIVE_UNIT", "User Administrator", "au:AU-EMEA")


def test_region_without_au_or_tenant_only_role_escalates(cfg):
    assert plan(cfg, task="manage_users", region="APAC").outcome == "ESCALATE"
    p = plan(cfg, task="manage_conditional_access", region="EMEA")
    assert p.outcome == "ESCALATE" and "tenant-wide" in p.reasons[0]


def test_custom_role_for_narrow_app_permissions(cfg):
    p = plan(cfg, task="update_app_credentials", target_object="app:Expense")
    assert p.outcome == "CUSTOM_ROLE" and p.scope == "app:Expense" and p.permissions
    assert plan(cfg, task="update_app_credentials").scope == "tenant"


def test_object_scope_only_for_object_scopable_roles(cfg):
    p = plan(cfg, task="configure_enterprise_app", target_object="app:Payroll")
    assert (p.outcome, p.role, p.scope) == ("OBJECT", "Cloud Application Administrator", "app:Payroll")
    assert plan(cfg, task="manage_groups", target_object="group:Team").outcome == "ESCALATE"


def test_guest_or_unknown_requester_cannot_get_privileged_role(cfg):
    assert plan(cfg, task="manage_security_policies", requester="g@partner.example").outcome == "ESCALATE"
    assert plan(cfg, task="reset_password", requester="nobody@else.example").outcome == "ESCALATE"
    # a non-privileged role may go to a guest
    assert plan(cfg, task="invite_guests", requester="g@partner.example").outcome == "TENANT"


def test_asked_for_role_is_noted(cfg):
    p = plan(cfg, task="reset_password", asked_for="Global Administrator")
    assert any("asked for Global Administrator" in r for r in p.reasons)


# ---- Part 2: audit --------------------------------------------------------------------------------------
def ga(upn, i):
    return {"id": f"A{i}", "principal": upn, "role": "Global Administrator", "scope": "tenant"}


def test_global_admin_excess_and_emergency_accounts(cfg):
    extra = {f"u{i}@x.example": {"userType": "Member"} for i in range(4)}
    data = copy.deepcopy(BASE)
    data["principals"].update(extra)
    data["assignments"] = [ga("bg1@x.example", 1), ga("bg2@x.example", 2)] + [ga(u, i + 3) for i, u in
                                                                               enumerate(sorted(extra))]
    chk = global_admin_check(data, cfg)
    assert chk["count"] == 6 and chk["outcome"] == "GLOBAL_ADMIN_EXCESS"
    res = audit_assignments(data, cfg)
    assert [r.finding for r in res] == ["OK", "OK"] + ["GLOBAL_ADMIN_EXCESS"] * 4
    data["assignments"] = data["assignments"][:5]
    assert global_admin_check(data, cfg)["outcome"] == "OK"
    data["assignments"] = [ga("m@x.example", 1), ga("bg1@x.example", 2)]
    chk = global_admin_check(data, cfg)
    assert chk["outcome"] == "GLOBAL_ADMIN_EXCESS" and "1 emergency" in chk["reasons"][1]


def test_privileged_role_on_guest_unknown_role_and_unknown_principal(cfg):
    g, unk_role, unk_user, ok = audit(
        cfg, {"id": "A1", "principal": "g@partner.example", "role": "Security Administrator", "scope": "tenant"},
        {"id": "A2", "principal": "g@partner.example", "role": "Mystery Role", "scope": "tenant"},
        {"id": "A3", "principal": "ghost@nowhere.example", "role": "Security Reader", "scope": "tenant"},
        {"id": "A4", "principal": "g@partner.example", "role": "License Administrator", "scope": "tenant"})
    assert g.finding == unk_role.finding == unk_user.finding == "PRIVILEGED_ROLE_ON_GUEST"
    assert any("treated as privileged" in r for r in unk_role.reasons)
    assert any("treated as a guest" in r for r in unk_user.reasons)
    assert ok.finding == "OK"


def test_restricted_au_member_needs_au_scoped_assignment(cfg):
    tenant, scoped = audit(
        cfg, {"id": "A1", "principal": "m@x.example", "role": "Helpdesk Administrator", "scope": "tenant",
              "manages": ["vip@x.example"]},
        {"id": "A2", "principal": "m@x.example", "role": "Helpdesk Administrator", "scope": "au:AU-VIP",
         "manages": ["vip@x.example"]})
    assert tenant.finding == "RESTRICTED_AU_MEMBER" and scoped.finding == "OK"


def test_assignment_too_broad(cfg):
    au, task, ca, unknown = audit(
        cfg, {"id": "A1", "principal": "m@x.example", "role": "User Administrator", "scope": "tenant",
              "intended_scope": "au:AU-EMEA"},
        {"id": "A2", "principal": "m@x.example", "role": "Application Administrator", "scope": "tenant",
         "needed_for": "register_apps"},
        {"id": "A3", "principal": "m@x.example", "role": "Conditional Access Administrator", "scope": "tenant",
         "intended_scope": "au:AU-EMEA"},
        {"id": "A4", "principal": "m@x.example", "role": "Groups Administrator", "scope": "tenant",
         "needed_for": "mystery"})
    assert au.finding == task.finding == unknown.finding == "ASSIGNMENT_TOO_BROAD"
    assert ca.finding == "OK" and "cannot be AU-scoped" in ca.reasons[0]


def test_severity_order(cfg):
    r = audit(cfg, {"id": "A1", "principal": "g@partner.example", "role": "User Administrator", "scope": "tenant",
                    "intended_scope": "au:AU-EMEA", "manages": ["vip@x.example"]})[0]
    assert r.findings == ["PRIVILEGED_ROLE_ON_GUEST", "RESTRICTED_AU_MEMBER", "ASSIGNMENT_TOO_BROAD"]


# ---- Part 3: dynamic groups ------------------------------------------------------------------------------
def test_rule_parser_and_evaluation():
    t = parse_rule('(user.department -eq "Sales") -and (user.country -in ["Germany","DE"]) -or '
                   'user.department -startsWith "Exec"')
    assert evaluate_rule(t, {"department": "sales", "country": "de"})
    assert evaluate_rule(t, {"department": "Executive", "country": "France"})
    assert not evaluate_rule(t, {"department": "Sales", "country": "France"})
    assert not evaluate_rule(parse_rule('user.department -eq "Sales"'), {"country": "Germany"})
    for bad in ("", "user.department -like \"Sales*\"", "(user.department -eq \"Sales\"", "user.department -eq Sales"):
        with pytest.raises(RuleError):
            parse_rule(bad)


def test_dynamic_group_mismatches_and_deny_by_default(cfg):
    groups = [
        {"id": "G1", "name": "wrong", "rule": 'user.department -eq "Sales"',
         "intent": {"department": ["Sales"], "userType": ["Member"]}},
        {"id": "G2", "name": "right", "rule": '(user.department -eq "Sales") -and (user.userType -eq "Member")',
         "intent": {"department": ["Sales"], "userType": ["Member"]}},
        {"id": "G3", "name": "noparse", "rule": "department = Sales", "intent": {"department": ["Sales"]}},
        {"id": "G4", "name": "nointent", "rule": 'user.department -eq "Sales"'},
    ]
    data = copy.deepcopy(BASE)
    data["principals"]["s@x.example"] = {"userType": "Member", "department": "Sales", "country": "Germany"}
    wrong, right, noparse, nointent = check_dynamic_groups({**data, "dynamic_groups": groups}, cfg)
    assert wrong.outcome == "DYNAMIC_GROUP_RULE" and wrong.wrongly_included == ["g@partner.example"]
    assert right.outcome == "OK" and right.members == ["s@x.example"]
    assert noparse.outcome == nointent.outcome == "DYNAMIC_GROUP_RULE"


# ---- Sample, generator, challenges -----------------------------------------------------------------------
def test_sample_expected_outcomes(policies, quiet_ui, sample):
    out = run_demo(quiet_ui, policies, sample)
    json.dumps(out)
    assert out["plans"] == {"R01": "TENANT", "R02": "ADMINISTRATIVE_UNIT", "R03": "ADMINISTRATIVE_UNIT",
                            "R04": "TENANT", "R05": "ESCALATE", "R06": "TENANT", "R07": "ESCALATE",
                            "R08": "CUSTOM_ROLE", "R09": "OBJECT", "R10": "ESCALATE", "R11": "ESCALATE",
                            "R12": "ESCALATE", "R13": "TENANT"}
    assert out["audit"] == {"A01": "OK", "A02": "OK", "A03": "GLOBAL_ADMIN_EXCESS", "A04": "GLOBAL_ADMIN_EXCESS",
                            "A05": "GLOBAL_ADMIN_EXCESS", "A06": "PRIVILEGED_ROLE_ON_GUEST", "A07": "OK",
                            "A08": "ASSIGNMENT_TOO_BROAD", "A09": "RESTRICTED_AU_MEMBER", "A10": "OK",
                            "A11": "ASSIGNMENT_TOO_BROAD", "A12": "PRIVILEGED_ROLE_ON_GUEST",
                            "A13": "PRIVILEGED_ROLE_ON_GUEST", "A14": "OK"}
    assert out["groups"] == {"G01": "DYNAMIC_GROUP_RULE", "G02": "OK", "G03": "DYNAMIC_GROUP_RULE"}
    assert out["global_admin_check"]["outcome"] == "GLOBAL_ADMIN_EXCESS" and out["global_admin_check"]["count"] == 6
    assert set(out["plans"].values()) == set(PLAN_OUTCOMES)
    assert set(out["audit"].values()) | set(out["groups"].values()) == set(FINDINGS)


def test_briefing_talking_point_matches_demo(policies, quiet_ui, sample, data):
    tp = data("briefings/lab35.json")["talking_point"]
    m = run_demo(quiet_ui, policies, sample)["metrics"]
    assert f"Planned {m['requests']} " in tp and f"at {m['global_admins']} Global" in tp
    flagged = m["assignments"] - m["finding_counts"]["OK"]
    assert f"flagged {flagged} of {m['assignments']}" in tp
    assert f"fixed {m['group_counts']['DYNAMIC_GROUP_RULE']} of {m['groups']}" in tp


def test_generator_is_deterministic_and_covers_outcomes(policies, quiet_ui):
    for seed in (1, 7, 42):
        g = generate_scenario(random.Random(seed), policies)
        assert g == generate_scenario(random.Random(seed), policies)
        out = run_demo(quiet_ui, policies, g)
        assert set(out["plans"].values()) == set(PLAN_OUTCOMES)
        assert set(out["audit"].values()) | set(out["groups"].values()) == set(FINDINGS)
        assert len(build_challenges(policies, g)) >= 12
    assert generate_scenario(random.Random(1), policies) != generate_scenario(random.Random(2), policies)


def test_challenges_valid_and_full_score(policies, quiet_ui, sample):
    qs = build_challenges(policies, sample)
    assert len(qs) >= 12
    for q in qs:
        assert q.objective in ("1.1", "1.2") and q.answer in q.choices
        assert len(set(q.choices)) == len(q.choices)
        assert "lab" not in (q.prompt + " ".join(q.choices)).lower()
    answers = iter([q.answer for q in qs])
    res = run_challenge(quiet_ui, 35, qs, ask=lambda _: next(answers), progress=None, shuffle=False)
    assert res.correct == res.total == len(qs)
