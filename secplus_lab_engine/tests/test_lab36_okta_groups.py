"""Lab 36 — Okta Universal Directory (profile schema, group rules, membership troubleshooting) tests."""

from __future__ import annotations

import copy
import json
import random

import pytest

from labs.lab36_okta_groups import (CAUSES, RULE_FLAGS, UPDATE_OUTCOMES, RuleError, apply_updates, build_challenges,
                                    build_schema, check_rules, evaluate, generate_scenario, parse_expression,
                                    run_all, run_demo, validate_update)
from utils.challenge import run_challenge

D = "x.example"


@pytest.fixture
def cfg(policies):
    return policies["okta_groups"]


@pytest.fixture
def sample(data):
    return data("sample_okta_groups.json")


def prof(login, **kw):
    return {"login": f"{login}@{D}", "email": f"{login}@{D}", "firstName": "A", "lastName": "B",
            "businessUnit": "Ops", **kw}


BASE = {
    "custom_attributes": {"businessUnit": {"type": "string", "required": True}, "badgeNumber": {"type": "integer"},
                          "remoteWorker": {"type": "boolean"},
                          "certifications": {"type": "array", "items": "string"}},
    "users": {
        f"sam@{D}": {"status": "ACTIVE", "profile": prof("sam", department="Sales", countryCode="US",
                                                        employeeType="Employee")},
        f"lou@{D}": {"status": "ACTIVE", "profile": prof("lou", department="sales", countryCode="US")},
        f"old@{D}": {"status": "DEPROVISIONED", "profile": prof("old", department="Sales", countryCode="US")},
        f"nos@{D}": {"profile": prof("nos", department="Sales", countryCode="US")},
        f"man@{D}": {"status": "ACTIVE", "profile": prof("man", department="IT", countryCode="FR")},
    },
    "groups": {
        "g-sales": {"name": "Sales-US", "type": "OKTA_GROUP", "manual_members": [f"man@{D}"]},
        "g-ad": {"name": "AD-Sales", "type": "APP_GROUP", "source": "Active Directory"},
        "g-adm": {"name": "Helpdesk-Admins", "type": "OKTA_GROUP", "admin_roles": ["Help Desk Administrator"],
                  "manual_members": [f"man@{D}"]},
        "g-beta": {"name": "Beta", "type": "OKTA_GROUP", "manual_members": [f"old@{D}", f"ghost@{D}"]},
        "g-none": {"name": "Empty", "type": "OKTA_GROUP"},
    },
}
SALES = 'user.department == "Sales" AND user.countryCode == "US"'


def scenario(rules, tickets=(), updates=()):
    d = copy.deepcopy(BASE)
    d["group_rules"] = [{"id": f"R{i}", "name": f"rule {i}", "exclude": [], **r} for i, r in enumerate(rules, 1)]
    d["tickets"] = [{"id": f"T{i}", **t} for i, t in enumerate(tickets, 1)]
    d["profile_updates"] = [{"id": f"P{i}", **u} for i, u in enumerate(updates, 1)]
    return d


def causes(cfg, rules, *tickets):
    return [t.cause for t in run_all(scenario(rules, [{"user": f"{u}@{D}", "group": g} for u, g in tickets]),
                                     cfg)["tickets"]]


# ---- Part 1: schema validation ---------------------------------------------------------------------------
def v(cfg, op="update", user=f"sam@{D}", **profile):
    return validate_update({"id": "P1", "operation": op, "user": user, "profile": profile},
                           BASE["users"], build_schema(BASE, cfg))


def test_valid_update_and_types_accepted(cfg):
    r = v(cfg, title="VP Sales", badgeNumber=12, remoteWorker=True, certifications=["PMP"])
    assert r.outcome == "ACCEPTED" and r.reasons


def test_unknown_attribute_is_case_sensitive(cfg):
    r = v(cfg, Department="Sales")
    assert r.outcome == "REJECTED" and "did you mean 'department'" in r.reasons[0]


def test_wrong_types_rejected(cfg):
    for bad in ({"badgeNumber": "12"}, {"badgeNumber": True}, {"remoteWorker": "true"},
                {"certifications": "PMP"}, {"certifications": ["PMP", 3]}, {"title": 5}):
        assert v(cfg, **bad).outcome == "REJECTED", bad


def test_required_attributes(cfg):
    assert v(cfg, lastName=None).outcome == "REJECTED"
    assert v(cfg, businessUnit="").outcome == "REJECTED"
    assert v(cfg, title=None).outcome == "ACCEPTED"          # clearing an optional attribute is fine
    new = {"login": f"new@{D}", "email": f"new@{D}", "firstName": "N", "lastName": "H"}
    r = v(cfg, op="create", user=f"new@{D}", **new)
    assert r.outcome == "REJECTED" and "businessUnit" in r.reasons[0]
    assert v(cfg, op="create", user=f"new@{D}", businessUnit="Ops", **new).outcome == "ACCEPTED"


def test_request_shape_deny_by_default(cfg):
    assert v(cfg, user=f"ghost@{D}", title="x").outcome == "REJECTED"
    assert v(cfg, op="create", title="x").outcome == "REJECTED"              # login already exists
    assert v(cfg, op="delete", title="x").outcome == "REJECTED"
    assert v(cfg).outcome == "REJECTED"                                      # no attributes
    assert validate_update({}, BASE["users"], build_schema(BASE, cfg)).outcome == "REJECTED"


def test_accepted_updates_are_applied_before_rules(cfg):
    d = scenario([{"status": "ACTIVE", "expression": SALES, "assign_to": ["g-sales"]}],
                 [{"user": f"lou@{D}", "group": "g-sales"}],
                 [{"operation": "update", "user": f"lou@{D}", "profile": {"department": "Sales"}},
                  {"operation": "create", "user": f"kim@{D}", "profile": prof("kim", department="Sales",
                                                                              countryCode="US")}])
    res, users = apply_updates(d, cfg)
    assert [r.outcome for r in res] == ["ACCEPTED", "ACCEPTED"]
    assert users[f"lou@{D}"]["profile"]["department"] == "Sales" and users[f"kim@{D}"]["status"] == "STAGED"
    st = run_all(d, cfg)
    assert st["tickets"][0].cause == "RULE_MATCHED" and f"kim@{D}" in st["members"]["g-sales"]
    assert BASE["users"][f"lou@{D}"]["profile"]["department"] == "sales"     # input not mutated


# ---- Part 2: expression language -------------------------------------------------------------------------
def test_expression_parser_and_evaluation():
    p = {"department": "Sales", "countryCode": "US", "title": "VP Sales", "badgeNumber": 5200,
         "certifications": ["PMP"], "remoteWorker": True}
    assert evaluate(parse_expression(SALES), p)
    assert evaluate(parse_expression('String.startsWith(user.title, "VP") && user.badgeNumber >= 5000'), p)
    assert evaluate(parse_expression('Arrays.contains(user.certifications, "PMP") OR user.title == "x"'), p)
    assert evaluate(parse_expression('String.toLowerCase(user.department) == "sales"'), p)
    assert evaluate(parse_expression("user.remoteWorker"), p)
    assert evaluate(parse_expression('NOT (user.countryCode == "FR")'), p)
    assert not evaluate(parse_expression('user.department == "sales"'), p)          # case-sensitive
    assert not evaluate(parse_expression('user.badgeNumber > "5000"'), p)           # mixed types
    assert evaluate(parse_expression('user.employeeType != "Contractor"'), p)       # null != value is true
    assert not evaluate(parse_expression('String.stringContains(user.employeeType, "C")'), p)


def test_unparseable_expressions():
    attrs = {"department", "title"}
    for bad in ("", 'user.department = "Sales"', '(user.department == "Sales"', 'isMemberOfAnyGroup("00g1")',
                'user.Department == "Sales"', 'String.substring(user.title, 0, 2) == "VP"',
                'user.department == "Sales" AND'):
        with pytest.raises(RuleError):
            parse_expression(bad, attrs)


def test_rule_flags(cfg):
    rules = check_rules(scenario([
        {"status": "ACTIVE", "expression": SALES, "assign_to": ["g-sales"]},
        {"status": "INACTIVE", "expression": SALES, "assign_to": ["g-sales"]},
        {"status": "ACTIVE", "expression": 'user.department = "Sales"', "assign_to": ["g-sales"]},
        {"status": "ACTIVE", "expression": SALES, "assign_to": ["g-adm"]},
        {"status": "ACTIVE", "expression": SALES, "assign_to": ["g-missing"]},
        {"expression": SALES, "assign_to": ["g-sales"]},
        {"status": "ACTIVE", "expression": SALES, "assign_to": ["g-ad"]},
    ]), cfg)
    assert [r.flag for r in rules] == ["OK", "INACTIVE", "UNPARSEABLE", "INVALID_TARGET", "INVALID_TARGET",
                                       "INACTIVE", "OK"]
    assert rules[3].valid_targets == [] and rules[6].valid_targets == ["g-ad"]   # AD groups can be populated
    assert rules[0].matched == [f"sam@{D}"]            # deactivated and status-less users are not evaluated


# ---- Part 3: troubleshooting -----------------------------------------------------------------------------
def test_matched_mismatch_and_case_hint(cfg):
    st = run_all(scenario([{"status": "ACTIVE", "expression": SALES, "assign_to": ["g-sales"]}],
                          [{"user": f"sam@{D}", "group": "g-sales"}, {"user": f"lou@{D}", "group": "g-sales"}]), cfg)
    ok, bad = st["tickets"]
    assert (ok.cause, ok.rule, ok.is_member) == ("RULE_MATCHED", "R1", True)
    assert bad.cause == "ATTRIBUTE_MISMATCH" and any("letter case" in r for r in bad.reasons)


def test_excluded_inactive_and_manual(cfg):
    excl = [{"status": "ACTIVE", "expression": SALES, "assign_to": ["g-sales"], "exclude": [f"sam@{D}"]}]
    assert causes(cfg, excl, ("sam", "g-sales")) == ["USER_EXCLUDED"]
    idle = [{"status": "INACTIVE", "expression": SALES, "assign_to": ["g-sales"]}]
    assert causes(cfg, idle, ("sam", "g-sales"), ("man", "g-sales")) == ["RULE_INACTIVE", "MANUAL_ASSIGNMENT"]
    # manual membership beats an exclusion: the rule cannot remove a manually added member
    excl_man = [{"status": "ACTIVE", "expression": 'user.countryCode == "FR"', "assign_to": ["g-sales"],
                 "exclude": [f"man@{D}"]}]
    assert causes(cfg, excl_man, ("man", "g-sales")) == ["MANUAL_ASSIGNMENT"]


def test_user_not_active_and_unknown_user(cfg):
    rules = [{"status": "ACTIVE", "expression": SALES, "assign_to": ["g-sales"]}]
    assert causes(cfg, rules, ("old", "g-sales"), ("nos", "g-sales"), ("ghost", "g-sales")) == \
        ["USER_NOT_ACTIVE"] * 3


def test_no_rule_cases(cfg):
    rules = [{"status": "ACTIVE", "expression": SALES, "assign_to": ["g-adm"]},
             {"status": "ACTIVE", "expression": 'user.department = "IT"', "assign_to": ["g-none"]}]
    assert causes(cfg, rules, ("sam", "g-adm"), ("man", "g-none"), ("sam", "g-missing"), ("sam", "g-sales")) == \
        ["NO_RULE"] * 4
    assert causes(cfg, rules, ("man", "g-adm")) == ["MANUAL_ASSIGNMENT"]     # admins add members by hand


def test_rules_populate_active_directory_groups(cfg):
    st = run_all(scenario([{"status": "ACTIVE", "expression": SALES, "assign_to": ["g-ad"]}],
                          [{"user": f"sam@{D}", "group": "g-ad"}]), cfg)
    assert st["tickets"][0].cause == "RULE_MATCHED" and st["members"]["g-ad"] == [f"sam@{D}"]


def test_deactivated_user_keeps_memberships_but_is_not_evaluated(cfg):
    rules = [{"status": "ACTIVE", "expression": SALES, "assign_to": ["g-sales"]}]
    st = run_all(scenario(rules, [{"user": f"old@{D}", "group": "g-beta"}]), cfg)
    assert st["members"]["g-beta"] == [f"old@{D}"]                 # kept; unknown ghost dropped
    assert f"old@{D}" not in st["members"]["g-sales"]              # rules do not evaluate them
    t = st["tickets"][0]
    assert (t.cause, t.is_member) == ("USER_NOT_ACTIVE", True) and any("until the user is deleted" in r
                                                                        for r in t.reasons)
    assert causes(cfg, [], ("sam", "g-none")) == ["NO_RULE"]


# ---- Sample, generator, challenges -----------------------------------------------------------------------
def test_sample_expected_outcomes(policies, quiet_ui, sample):
    out = run_demo(quiet_ui, policies, sample)
    json.dumps(out)
    assert out["updates"] == {"P01": "ACCEPTED", "P02": "REJECTED", "P03": "REJECTED", "P04": "ACCEPTED",
                              "P05": "REJECTED", "P06": "REJECTED", "P07": "REJECTED", "P08": "ACCEPTED",
                              "P09": "REJECTED", "P10": "ACCEPTED"}
    assert out["rules"] == {"R01": "OK", "R02": "OK", "R03": "OK", "R04": "INACTIVE", "R05": "OK",
                            "R06": "OK", "R07": "UNPARSEABLE", "R08": "INVALID_TARGET"}
    assert out["tickets"] == {"T01": "ATTRIBUTE_MISMATCH", "T02": "USER_EXCLUDED", "T03": "USER_NOT_ACTIVE",
                              "T04": "RULE_INACTIVE", "T05": "MANUAL_ASSIGNMENT", "T06": "RULE_MATCHED",
                              "T07": "ATTRIBUTE_MISMATCH", "T08": "NO_RULE", "T09": "NO_RULE",
                              "T10": "RULE_MATCHED", "T11": "RULE_MATCHED", "T12": "ATTRIBUTE_MISMATCH",
                              "T13": "USER_NOT_ACTIVE", "T14": "RULE_MATCHED"}
    assert set(out["updates"].values()) == set(UPDATE_OUTCOMES)
    assert set(out["rules"].values()) == set(RULE_FLAGS)
    assert set(out["tickets"].values()) == set(CAUSES)
    assert "chloe.martin@harrowgate.example" in out["memberships"]["00g-sales-us"]     # manual, from France
    assert "grace.kim@harrowgate.example" in out["memberships"]["00g-beta"]            # deactivated, kept
    assert out["memberships"]["00g-ad-finance"] == ["omar.haddad@harrowgate.example"]  # rule-populated AD group
    assert out["memberships"]["00g-helpdesk-admins"] == []                             # admin group: no rules


def test_briefing_talking_point_matches_demo(policies, quiet_ui, sample, data):
    tp = data("briefings/lab36.json")["talking_point"]
    m = run_demo(quiet_ui, policies, sample)["metrics"]
    uc, flagged = m["update_counts"], m["rules"] - m["rule_flags"]["OK"]
    assert f"Validated {m['updates']} HR" in tp and f"({uc['ACCEPTED']} accepted, {uc['REJECTED']} rejected" in tp
    assert f"found {flagged} of {m['rules']} group rules" in tp
    assert f"closed {m['tickets']} group" in tp and f"{m['cause_counts']['ATTRIBUTE_MISMATCH']} of them" in tp
    assert f"and {m['cause_counts']['USER_NOT_ACTIVE']} by deactivated users" in tp


def test_generator_is_deterministic_and_covers_outcomes(policies, quiet_ui):
    for seed in (1, 7, 42):
        g = generate_scenario(random.Random(seed), policies)
        assert g == generate_scenario(random.Random(seed), policies)
        out = run_demo(quiet_ui, policies, g)
        assert set(out["updates"].values()) == set(UPDATE_OUTCOMES)
        assert set(out["rules"].values()) == set(RULE_FLAGS)
        assert set(out["tickets"].values()) == set(CAUSES)
        assert len(build_challenges(policies, g)) >= 12
    assert generate_scenario(random.Random(1), policies) != generate_scenario(random.Random(2), policies)


def test_challenges_valid_and_full_score(policies, quiet_ui, sample):
    qs = build_challenges(policies, sample)
    assert len(qs) >= 12
    for q in qs:
        assert q.objective in ("1.1", "1.2", "5.2") and q.answer in q.choices
        assert len(set(q.choices)) == len(q.choices)
        assert "lab" not in (q.prompt + " ".join(q.choices)).lower()
    assert {q.objective for q in qs} == {"1.1", "1.2", "5.2"}
    answers = iter([q.answer for q in qs])
    res = run_challenge(quiet_ui, 36, qs, ask=lambda _: next(answers), progress=None, shuffle=False)
    assert res.correct == res.total == len(qs)
