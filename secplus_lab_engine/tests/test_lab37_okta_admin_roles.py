"""Lab 37 — Okta admin roles (standard roles, custom roles, resource sets) tests."""

from __future__ import annotations

import copy
import json
import random

import pytest

from labs.lab37_okta_admin_roles import (COURSES, DENIALS, EVAL_OUTCOMES, FINDINGS, PLAN_OUTCOMES, audit_assignments,
                                         build_challenges, evaluate_attempt, generate_scenario, plan_request, run_demo,
                                         super_admin_check)
from utils.challenge import run_challenge


@pytest.fixture
def cfg(policies):
    return policies["okta_admin_roles"]


@pytest.fixture
def sample(data):
    return data("sample_okta_admin_roles.json")


BASE = {
    "users": {u: {} for u in ("hd", "orgadm", "boss", "s1", "f1", "gm", "nobody", "cust")},
    "groups": {"Sales": ["s1"], "Finance": ["f1", "cust"], "HD-Admins": ["hd"], "Supers": ["boss"], "Ops": ["cust"]},
    "apps": ["AppA", "AppB"],
    "custom_roles": {"Reset Only": ["okta.users.read", "okta.users.credentials.resetPassword"]},
    "resource_sets": {"RS-FIN": {"users_in_groups": ["Finance"]}, "RS-EMPTY": {"apps": []}},
    "assignments": [
        {"id": "A1", "assignee": {"group": "HD-Admins"}, "role": "Help Desk Administrator",
         "constraints": {"groups": ["Sales", "Finance"]}},
        {"id": "A2", "assignee": {"group": "Supers"}, "role": "Super Administrator"},
        {"id": "A3", "assignee": {"user": "orgadm"}, "role": "Organization Administrator"},
        {"id": "A4", "assignee": {"group": "Ops"}, "custom_role": "Reset Only", "resource_set": "RS-FIN"},
        {"id": "A5", "assignee": {"user": "gm"}, "role": "Group Membership Administrator",
         "constraints": {"groups": ["Sales"]}},
    ],
}


def ev(cfg, actor, action, target=None, data=BASE):
    att = {"id": "T", "actor": actor, "action": action}
    if target is not None:
        att["target"] = target
    return evaluate_attempt(att, data, cfg)


def plan(cfg, tasks, scope=None, assign_to=None, data=BASE):
    return plan_request({"id": "R", "team": "T", "tasks": tasks, "scope": scope or {},
                         "assign_to": assign_to or {"group": "X"}}, data, cfg)


# ---- Planner -----------------------------------------------------------------------------------------------
def test_planner_picks_least_privileged_standard_roles(cfg):
    cases = {("reset_passwords", "unlock_users"): "Help Desk Administrator",
             ("manage_group_membership",): "Group Membership Administrator",
             ("create_users", "edit_user_profiles"): "Group Administrator",
             ("manage_apps", "assign_apps"): "Application Administrator",
             ("view_directory", "view_apps", "run_reports", "view_system_log"): "Read-only Administrator",
             ("run_reports",): "Report Administrator",
             ("manage_admins",): "Super Administrator",
             ("manage_group_rules",): "Organization Administrator"}
    for tasks, role in cases.items():
        p = plan(cfg, list(tasks))
        assert (p.outcome, p.role) == ("STANDARD_ROLE", role), tasks


def test_planner_constrains_role_to_named_groups_and_apps(cfg):
    p = plan(cfg, ["reset_passwords"], {"groups": ["Sales"]})
    assert p.role == "Help Desk Administrator" and p.constraint == {"groups": ["Sales"]}
    a = plan(cfg, ["assign_apps"], {"apps": ["AppA"]})
    assert a.role == "Application Administrator" and a.constraint == {"apps": ["AppA"]}


def test_planner_custom_role_when_no_standard_role_fits(cfg):
    p = plan(cfg, ["reset_passwords", "assign_apps"], {"groups": ["Finance"], "apps": ["AppA"]})
    assert p.outcome == "CUSTOM_ROLE" and "okta.users.credentials.resetPassword" in p.permissions
    assert p.resource_set == {"users_in_groups": ["Finance"], "apps": ["AppA"]}
    # unscoped: only Super Administrator holds both, which is too broad → custom role on "all" resources
    q = plan(cfg, ["reset_passwords", "assign_apps"])
    assert q.outcome == "CUSTOM_ROLE" and q.resource_set == {"all_users": True, "all_apps": True}


def test_planner_read_only_request_never_gets_write_role(cfg):
    p = plan(cfg, ["view_directory"], {"groups": ["Sales"]})
    assert p.outcome == "CUSTOM_ROLE" and p.permissions == ["okta.groups.read", "okta.users.read"]


def test_planner_escalates_unknown_missing_and_unscopable(cfg):
    assert plan(cfg, []).outcome == "ESCALATE"
    assert plan(cfg, ["make_coffee"]).outcome == "ESCALATE"
    assert plan(cfg, ["reset_passwords"], {"groups": ["Ghosts"]}).outcome == "ESCALATE"
    # org settings exist only in standard roles, and Organization Administrator cannot be constrained
    assert plan(cfg, ["edit_org_settings"], {"groups": ["Sales"]}).outcome == "ESCALATE"


def test_planner_recommends_group_assignment(cfg):
    p = plan(cfg, ["run_reports"], assign_to={"user": "s1"})
    assert any("instead of s1" in r for r in p.reasons)


# ---- Evaluator ---------------------------------------------------------------------------------------------
def test_evaluator_allowed_and_outside_scope(cfg):
    assert ev(cfg, "hd", "okta.users.credentials.resetPassword", "s1").outcome == "ALLOWED"
    e = ev(cfg, "hd", "okta.users.credentials.resetPassword", "gm")
    assert (e.outcome, e.rule) == ("DENIED", "OUTSIDE_SCOPE")
    assert ev(cfg, "hd", "okta.users.credentials.resetPassword", "no.such.user").rule == "OUTSIDE_SCOPE"


def test_evaluator_missing_permission_unknown_action_and_not_assigned(cfg):
    assert ev(cfg, "hd", "okta.users.lifecycle.manage", "s1").rule == "MISSING_PERMISSION"
    assert ev(cfg, "hd", "okta.users.fly", "s1").rule == "UNKNOWN_ACTION"
    assert ev(cfg, "nobody", "okta.users.read", "s1").rule == "NOT_ASSIGNED"
    assert ev(cfg, "s1", None).rule == "UNKNOWN_ACTION"          # missing action → denied


def test_evaluator_protected_admin_targets(cfg):
    # Help Desk may not reset a fellow admin (cust holds a custom role) even inside its constraint
    assert ev(cfg, "hd", "okta.users.credentials.resetPassword", "cust").rule == "PROTECTED_ADMIN_TARGET"
    # Org admin: can manage other admins, cannot reset a super admin's password, can clear their sessions
    assert ev(cfg, "orgadm", "okta.users.credentials.resetPassword", "hd").outcome == "ALLOWED"
    assert ev(cfg, "orgadm", "okta.users.credentials.resetPassword", "boss").rule == "PROTECTED_ADMIN_TARGET"
    assert ev(cfg, "orgadm", "okta.users.lifecycle.clearSessions", "boss").outcome == "ALLOWED"
    # Admin groups: only super admins change membership
    assert ev(cfg, "orgadm", "okta.groups.members.manage", "HD-Admins").rule == "PROTECTED_ADMIN_TARGET"
    assert ev(cfg, "boss", "okta.groups.members.manage", "HD-Admins").outcome == "ALLOWED"
    assert ev(cfg, "orgadm", "okta.groups.members.manage", "Sales").outcome == "ALLOWED"


def test_evaluator_custom_role_and_resource_set(cfg):
    assert ev(cfg, "cust", "okta.users.credentials.resetPassword", "f1").outcome == "ALLOWED"
    assert ev(cfg, "cust", "okta.users.credentials.resetPassword", "s1").rule == "OUTSIDE_SCOPE"
    assert ev(cfg, "cust", "okta.users.credentials.resetFactors", "f1").rule == "MISSING_PERMISSION"
    data = copy.deepcopy(BASE)
    data["assignments"][3]["resource_set"] = "RS-EMPTY"
    assert ev(cfg, "cust", "okta.users.credentials.resetPassword", "f1", data).rule == "OUTSIDE_SCOPE"
    data["assignments"][3]["custom_role"] = "Undefined Role"
    assert ev(cfg, "cust", "okta.users.credentials.resetPassword", "f1", data).rule == "MISSING_PERMISSION"


def test_evaluator_unknown_standard_role_grants_nothing(cfg):
    data = copy.deepcopy(BASE)
    data["assignments"].append({"id": "A9", "assignee": {"user": "nobody"}, "role": "Galaxy Administrator"})
    assert ev(cfg, "nobody", "std.reports.run", data=data).rule == "MISSING_PERMISSION"


def test_group_membership_admin_is_membership_only(cfg):
    assert ev(cfg, "gm", "okta.groups.members.manage", "Sales").outcome == "ALLOWED"
    assert ev(cfg, "gm", "okta.groups.members.manage", "Finance").rule == "OUTSIDE_SCOPE"
    assert ev(cfg, "gm", "okta.groups.manage", "Sales").rule == "MISSING_PERMISSION"
    assert ev(cfg, "gm", "okta.users.credentials.resetPassword", "s1").rule == "MISSING_PERMISSION"


# ---- Audit -------------------------------------------------------------------------------------------------
def test_audit_findings(cfg):
    data = copy.deepcopy(BASE)
    data["assignments"] += [
        {"id": "A6", "assignee": {"group": "Ops"}, "custom_role": "Reset Only", "resource_set": "RS-EMPTY"},
        {"id": "A7", "assignee": {"group": "Ops"}, "role": "Application Administrator"},
        {"id": "A8", "assignee": {"group": "Ops"}, "role": "Application Administrator",
         "org_wide_justification": "central team"},
        {"id": "A9", "assignee": {"group": "Ops"}, "role": "Galaxy Administrator"},
    ]
    res = {a.id: a for a in audit_assignments(data, cfg)}
    assert res["A1"].finding == "OK" and res["A2"].finding == "OK"
    assert res["A3"].finding == "ROLE_ASSIGNED_TO_INDIVIDUAL"
    assert res["A6"].finding == "CUSTOM_ROLE_EMPTY_RESOURCE_SET"
    assert res["A7"].finding == "UNSCOPED_ROLE" and res["A8"].finding == "OK"
    assert res["A9"].finding == "UNSCOPED_ROLE"          # unknown role → privileged and unscoped


def test_super_admin_excess_is_policy_driven(cfg):
    n = cfg["max_super_admins"]
    data = copy.deepcopy(BASE)
    data["groups"]["Supers"] = [f"sa{i}" for i in range(n)]
    assert super_admin_check(data, cfg)["outcome"] == "OK"
    data["assignments"].append({"id": "A9", "assignee": {"user": "sa0"}, "role": "Super Administrator"})
    assert super_admin_check(data, cfg)["count"] == n               # same person counted once
    data["assignments"].append({"id": "A10", "assignee": {"user": "extra"}, "role": "Super Administrator"})
    res = {a.id: a for a in audit_assignments(data, cfg)}
    assert res["A2"].finding == "SUPER_ADMIN_EXCESS"
    assert res["A10"].findings == ["SUPER_ADMIN_EXCESS", "ROLE_ASSIGNED_TO_INDIVIDUAL"]


# ---- Sample, briefing, generator, challenges ---------------------------------------------------------------
def test_sample_expected_outcomes(policies, quiet_ui, sample):
    out = run_demo(quiet_ui, policies, sample)
    json.dumps(out)
    assert out["plans"] == {"R01": "STANDARD_ROLE", "R02": "STANDARD_ROLE", "R03": "STANDARD_ROLE",
                            "R04": "STANDARD_ROLE", "R05": "STANDARD_ROLE", "R06": "STANDARD_ROLE",
                            "R07": "STANDARD_ROLE", "R08": "STANDARD_ROLE", "R09": "CUSTOM_ROLE",
                            "R10": "CUSTOM_ROLE", "R11": "ESCALATE", "R12": "ESCALATE", "R13": "ESCALATE"}
    assert out["roles"]["R01"] == "Help Desk Administrator" and out["roles"]["R02"] == "Group Membership Administrator"
    assert out["rules"] == {"T01": "ALLOWED", "T02": "OUTSIDE_SCOPE", "T03": "PROTECTED_ADMIN_TARGET",
                            "T04": "MISSING_PERMISSION", "T05": "ALLOWED", "T06": "ALLOWED", "T07": "OUTSIDE_SCOPE",
                            "T08": "PROTECTED_ADMIN_TARGET", "T09": "PROTECTED_ADMIN_TARGET", "T10": "ALLOWED",
                            "T11": "MISSING_PERMISSION", "T12": "NOT_ASSIGNED", "T13": "ALLOWED",
                            "T14": "OUTSIDE_SCOPE", "T15": "UNKNOWN_ACTION", "T16": "MISSING_PERMISSION"}
    assert out["audit"] == {"A01": "OK", "A02": "SUPER_ADMIN_EXCESS", "A03": "SUPER_ADMIN_EXCESS",
                            "A04": "UNSCOPED_ROLE", "A05": "OK", "A06": "ROLE_ASSIGNED_TO_INDIVIDUAL",
                            "A07": "CUSTOM_ROLE_EMPTY_RESOURCE_SET", "A08": "OK",
                            "A09": "ROLE_ASSIGNED_TO_INDIVIDUAL", "A10": "OK", "A11": "OK", "A12": "UNSCOPED_ROLE"}
    assert out["super_admin_check"] == {"outcome": "SUPER_ADMIN_EXCESS", "count": 4}
    assert set(out["plans"].values()) == set(PLAN_OUTCOMES)
    assert set(out["attempts"].values()) == set(EVAL_OUTCOMES)
    assert set(DENIALS) <= set(out["rules"].values())
    assert set(out["audit"].values()) == set(FINDINGS)


def test_briefing_talking_point_matches_demo(policies, quiet_ui, sample, data):
    tp = data("briefings/lab37.json")["talking_point"]
    m = run_demo(quiet_ui, policies, sample)["metrics"]
    pc, ec = m["plan_counts"], m["eval_counts"]
    assert f"Planned {m['requests']} " in tp
    assert f"({pc['STANDARD_ROLE']} standard roles" in tp and f"{pc['CUSTOM_ROLE']} custom roles" in tp
    assert f"{pc['ESCALATE']} escalated" in tp
    assert f"explained {m['attempts']} logged" in tp and f"{ec['ALLOWED']} allowed, {ec['DENIED']} denied" in tp
    assert f"{m['denial_counts']['PROTECTED_ADMIN_TARGET']} blocked" in tp
    flagged = m["assignments"] - m["finding_counts"]["OK"]
    assert f"flagged {flagged} of {m['assignments']}" in tp
    assert f"{m['super_admins']} super admins against a policy maximum of {policies['okta_admin_roles']['max_super_admins']}" in tp


def test_generator_is_deterministic_and_covers_outcomes(policies, quiet_ui):
    for seed in (1, 7, 42):
        g = generate_scenario(random.Random(seed), policies)
        assert g == generate_scenario(random.Random(seed), policies)
        out = run_demo(quiet_ui, policies, g)
        json.dumps(out)
        assert set(out["plans"].values()) == set(PLAN_OUTCOMES)
        assert set(out["attempts"].values()) == set(EVAL_OUTCOMES)
        assert set(DENIALS) <= set(out["rules"].values())
        assert set(out["audit"].values()) == set(FINDINGS)
        assert len(build_challenges(policies, g)) >= 12
    assert generate_scenario(random.Random(1), policies) != generate_scenario(random.Random(2), policies)


def test_challenges_valid_and_full_score(policies, quiet_ui, sample):
    qs = build_challenges(policies, sample)
    assert len(qs) >= 12
    for q in qs:
        assert q.objective in ("1.3", "1.2") and q.answer in q.choices
        assert len(set(q.choices)) == len(q.choices)
        assert "lab" not in (q.prompt + " ".join(q.choices)).lower()
    answers = iter([q.answer for q in qs])
    res = run_challenge(quiet_ui, 37, qs, ask=lambda _: next(answers), progress=None, shuffle=False)
    assert res.correct == res.total == len(qs)


def test_course_membership():
    assert COURSES == ("okta",)
