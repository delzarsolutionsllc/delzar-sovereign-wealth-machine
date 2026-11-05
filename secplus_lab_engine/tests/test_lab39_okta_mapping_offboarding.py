"""Lab 39 — Okta attribute mapping, user lifecycle and offboarding tests."""

from __future__ import annotations

import copy
import json
import random

import pytest

from labs.lab39_okta_mapping_offboarding import (ACCOUNT_STATES, LIFECYCLE_OUTCOMES, MAP_OUTCOMES, OFFBOARD_OUTCOMES,
                                                 ExprError, base_catalog, build_challenges, evaluate,
                                                 generate_scenario, map_user, run_demo, transition,
                                                 verify_offboarding)
from utils.challenge import run_challenge


@pytest.fixture
def cfg(policies):
    return policies["okta_mapping_offboarding"]


@pytest.fixture
def sample(data):
    return data("sample_okta_mapping_offboarding.json")


def catalog():
    schema, sources, apps = base_catalog()
    return {"okta_schema": schema, "profile_sources": sources, "apps": apps}


HR = {"workEmail": "Ana.Ruiz@larkspur.example", "givenName": "Ana", "familyName": "Ruiz", "dept": "Sales",
      "jobTitle": "Account Executive", "empId": "E2001", "isPeopleManager": False, "mobile": "+1-555-0200"}


def user(**kw):
    base = {"id": "U1", "event": "create", "profile_source": "PeopleHub HR", "hr_record": dict(HR),
            "okta_profile": {"managerId": "E1002"}, "assigned_apps": ["Expense Portal", "Team Chat"]}
    base.update(kw)
    return base


def okta_of(hr):
    return {"login": hr["workEmail"].lower(), "email": hr["workEmail"].lower(), "firstName": hr["givenName"],
            "lastName": hr["familyName"], "department": hr["dept"], "title": hr["jobTitle"],
            "employeeNumber": hr["empId"], "isManager": False, "mobilePhone": hr["mobile"], "managerId": "E1002"}


# ------------------------------------------------------------------ expressions
def test_expression_forms(cfg):
    ctx = {"user": {"firstName": "Ana", "lastName": "Ruiz", "email": "Ana@X.example", "costCenter": None}}
    assert evaluate("user.firstName", ctx, cfg) == "Ana"
    assert evaluate("String.toLowerCase(user.email)", ctx, cfg) == "ana@x.example"
    assert evaluate('user.firstName + " " + user.lastName', ctx, cfg) == "Ana Ruiz"
    assert evaluate('user.costCenter != null ? user.costCenter : "CC-000"', ctx, cfg) == "CC-000"
    assert evaluate('String.toLowerCase(user.firstName + "." + user.lastName)', ctx, cfg) == "ana.ruiz"


def test_expression_errors_deny_by_default(cfg):
    ctx = {"user": {"n": 5}}
    for bad in ("user.missing", "String.toLowerCase(user.n)", "String.reverse(user.n)", "this is not EL", "",
                "appuser.dept"):
        with pytest.raises(ExprError):
            evaluate(bad, ctx, cfg)


# ------------------------------------------------------------------ mappings
def test_create_computes_okta_and_app_profiles(cfg):
    r = map_user(user(), catalog(), cfg)
    assert r.outcome == "OK"
    assert r.okta_profile["login"] == r.okta_profile["email"] == "ana.ruiz@larkspur.example"
    ep = r.app_profiles["Expense Portal"]
    assert ep["displayName"] == "Ana Ruiz" and ep["costCenter"] == "CC-000" and ep["approver"] is False
    assert r.app_profiles["Team Chat"]["handle"] == "ana.ruiz"


def test_admin_edit_to_sourced_attribute_is_overwritten(cfg):
    u = user(event="update", okta_profile=okta_of(HR), okta_admin_edits={"department": "Legal"},
             assigned_apps=[])
    r = map_user(u, catalog(), cfg)
    assert r.outcome == "OVERWRITTEN_BY_SOURCE" and r.okta_profile["department"] == "Sales"


def test_inherit_from_okta_and_okta_mastered_edits_stick(cfg):
    sourced = map_user(user(event="update", okta_profile=okta_of(HR), assigned_apps=[],
                            okta_admin_edits={"mobilePhone": "+1-555-0999"}), catalog(), cfg)
    assert sourced.outcome == "OK" and sourced.okta_profile["mobilePhone"] == "+1-555-0999"
    mastered = map_user(user(event="update", profile_source=None, okta_profile=okta_of(HR), assigned_apps=[],
                             okta_admin_edits={"department": "Legal"}), catalog(), cfg)
    assert mastered.outcome == "OK" and mastered.okta_profile["department"] == "Legal"


def test_app_edit_overwritten_by_okta_push_unless_create_only(cfg):
    cur = {"handle": "ana.ruiz", "email": "ana.ruiz@larkspur.example", "jobTitle": "AE", "manager": "E1002"}
    pushed = map_user(user(event="update", okta_profile=okta_of(HR), assigned_apps=["Team Chat"],
                           app_profiles={"Team Chat": cur}, app_edits={"Team Chat": {"email": "ana@home.example"}}),
                      catalog(), cfg)
    assert pushed.outcome == "OVERWRITTEN_BY_SOURCE"
    kept = map_user(user(event="update", okta_profile=okta_of(HR), assigned_apps=["Team Chat"],
                         app_profiles={"Team Chat": cur}, app_edits={"Team Chat": {"jobTitle": "Lead AE"}}),
                    catalog(), cfg)
    assert kept.outcome == "OK" and kept.app_profiles["Team Chat"]["jobTitle"] == "Lead AE"


def test_create_only_login_survives_rename(cfg):
    hr = dict(HR, familyName="Ortega", workEmail="Ana.Ortega@larkspur.example")
    r = map_user(user(event="update", hr_record=hr, okta_profile=okta_of(HR), assigned_apps=[]), catalog(), cfg)
    assert r.okta_profile["login"] == "ana.ruiz@larkspur.example"
    assert r.okta_profile["email"] == "ana.ortega@larkspur.example" and r.outcome == "OK"


def test_type_mismatch_and_missing_source_attribute(cfg):
    typed = map_user(user(hr_record=dict(HR, isPeopleManager="Yes")), catalog(), cfg)
    assert typed.outcome == "MAPPING_ERROR" and any("type mismatch" in x for x in typed.reasons)
    missing = map_user(user(okta_profile={}), catalog(), cfg)
    assert missing.outcome == "MAPPING_ERROR" and any("managerId is missing" in x for x in missing.reasons)


def test_unknown_inputs_are_mapping_errors(cfg):
    for u in (user(event="sync"), user(profile_source="Nowhere"), user(hr_record=None),
              user(assigned_apps=["Unknown App"])):
        assert map_user(u, catalog(), cfg).outcome == "MAPPING_ERROR"


def test_provisioning_features_gate_the_push(cfg):
    cat = catalog()
    cat["apps"]["Team Chat"]["provisioning"]["update_attributes"] = False
    r = map_user(user(event="update", okta_profile=okta_of(HR), assigned_apps=["Team Chat"],
                      app_edits={"Team Chat": {"email": "ana@home.example"}}), cat, cfg)
    assert r.outcome == "OK" and r.app_profiles["Team Chat"]["email"] == "ana@home.example"


# ------------------------------------------------------------------ lifecycle
def req(cur, to, apps=()):
    return {"id": "L1", "user": "x", "current": cur, "requested": to, "apps": list(apps)}


def test_valid_and_invalid_transitions(cfg):
    d = catalog()
    for cur, to in [("STAGED", "PENDING_USER_ACTION"), ("STAGED", "ACTIVE"), ("PENDING_USER_ACTION", "ACTIVE"),
                    ("ACTIVE", "SUSPENDED"), ("SUSPENDED", "ACTIVE"), ("ACTIVE", "DEACTIVATED"),
                    ("SUSPENDED", "DEACTIVATED"), ("DEACTIVATED", "DELETED"), ("DEACTIVATED", "PENDING_USER_ACTION")]:
        assert transition(req(cur, to), d, cfg).outcome == "ALLOWED", (cur, to)
    for cur, to in [("ACTIVE", "DELETED"), ("SUSPENDED", "DELETED"), ("STAGED", "SUSPENDED"),
                    ("DEACTIVATED", "ACTIVE"), ("DELETED", "ACTIVE"), ("ACTIVE", "ACTIVE"), ("ACTIVE", "LOCKED_OUT"),
                    ("ACTIVE", "ARCHIVED"), (None, "ACTIVE")]:
        assert transition(req(cur, to), d, cfg).outcome == "INVALID_TRANSITION", (cur, to)
    assert "deactivate first" in transition(req("ACTIVE", "DELETED"), d, cfg).reasons[0]


def test_suspend_keeps_assignments_deactivate_removes_them(cfg):
    d = catalog()
    s = transition(req("ACTIVE", "SUSPENDED", ["Expense Portal"]), d, cfg)
    assert (s.can_sign_in, s.sessions_cleared, s.assignments) == (False, True, "kept")
    assert s.app_accounts == {"Expense Portal": "UNCHANGED"}
    x = transition(req("ACTIVE", "DEACTIVATED", ["Expense Portal", "Team Chat", "Benefits Link", "Mystery"]), d, cfg)
    assert (x.can_sign_in, x.sessions_cleared, x.assignments) == (False, True, "removed")
    assert x.app_accounts == {"Expense Portal": "DEACTIVATED", "Team Chat": "LEFT_ACTIVE_ORPHAN",
                              "Benefits Link": "NO_ACCOUNT", "Mystery": "LEFT_ACTIVE_ORPHAN"}


def test_deactivate_users_toggle_is_data_driven(cfg):
    d = catalog()
    d["apps"]["Team Chat"]["provisioning"]["deactivate_users"] = True
    assert transition(req("ACTIVE", "DEACTIVATED", ["Team Chat"]), d, cfg).app_accounts["Team Chat"] == "DEACTIVATED"


# ------------------------------------------------------------------ offboarding
def off(status, app, **kw):
    return {"id": "O1", "user": "x", "status": status, "app": app, **kw}


def test_offboarding_rules(cfg):
    d = catalog()
    got = {a: verify_offboarding(off("DEACTIVATED", a), d, cfg).outcome
           for a in ("Expense Portal", "Team Chat", "Vendor Wiki", "Legacy CRM", "Benefits Link", "Analytics Hub",
                     "Unknown")}
    assert got == {"Expense Portal": "ACCESS_REMOVED", "Team Chat": "ACCESS_REMOVED",
                   "Vendor Wiki": "STILL_HAS_ACCESS", "Legacy CRM": "STILL_HAS_ACCESS",
                   "Benefits Link": "ACCESS_REMOVED", "Analytics Hub": "ACCESS_REMOVED", "Unknown": "STILL_HAS_ACCESS"}
    assert verify_offboarding(off("DELETED", "Expense Portal"), d, cfg).outcome == "ACCESS_REMOVED"
    assert verify_offboarding(off("DEACTIVATED", "Vendor Wiki", manually_deactivated_in_app=True), d,
                              cfg).outcome == "ACCESS_REMOVED"


def test_suspended_active_or_unknown_leaver_still_has_access(cfg):
    d = catalog()
    for status in ("SUSPENDED", "ACTIVE", "LOCKED_OUT", "gone?", None):
        r = verify_offboarding(off(status, "Expense Portal"), d, cfg)
        assert r.outcome == "STILL_HAS_ACCESS", status
    assert "unsuspend" in verify_offboarding(off("SUSPENDED", "Expense Portal"), d, cfg).reasons[0]


# ------------------------------------------------------------------ sample, briefing, generator, challenges
def test_sample_outcomes(policies, quiet_ui, sample):
    out = run_demo(quiet_ui, policies, sample)
    json.dumps(out)
    assert out["mappings"] == {"U01": "OK", "U02": "OVERWRITTEN_BY_SOURCE", "U03": "OVERWRITTEN_BY_SOURCE",
                               "U04": "MAPPING_ERROR", "U05": "MAPPING_ERROR", "U06": "OK", "U07": "OK",
                               "U08": "MAPPING_ERROR", "U09": "OK"}
    assert [k for k, v in out["lifecycle"].items() if v == "INVALID_TRANSITION"] == ["L06", "L07", "L08", "L09"]
    assert out["app_accounts"]["L04"] == {"Expense Portal": "DEACTIVATED", "Team Chat": "LEFT_ACTIVE_ORPHAN",
                                          "Vendor Wiki": "LEFT_ACTIVE_ORPHAN", "Benefits Link": "NO_ACCOUNT"}
    assert [k for k, v in out["offboarding"].items() if v == "STILL_HAS_ACCESS"] == ["O03", "O04", "O07", "O08",
                                                                                     "O09"]


def test_briefing_talking_point_matches_demo(policies, quiet_ui, sample, data):
    m = run_demo(quiet_ui, policies, sample)["metrics"]
    tp = data("briefings/lab39.json")["talking_point"]
    c = m["mapping_counts"]
    assert f"for {m['users']} users ({c['OK']} OK, {c['OVERWRITTEN_BY_SOURCE']} edits overwritten" in tp
    assert f"{c['MAPPING_ERROR']} mapping errors" in tp
    assert f"validated {m['requests']} Okta status changes ({m['allowed']} allowed, {m['invalid']} invalid" in tp
    assert f"found {m['account_counts']['LEFT_ACTIVE_ORPHAN']} app accounts left active" in tp
    assert f"{m['still_has_access']} of {m['checks']} offboarding checks" in tp


def test_generator_is_deterministic_and_covers_outcomes(policies, quiet_ui):
    for seed in (1, 7, 42):
        g = generate_scenario(random.Random(seed), policies)
        assert g == generate_scenario(random.Random(seed), policies)
        out = run_demo(quiet_ui, policies, g)
        assert set(out["mappings"].values()) == set(MAP_OUTCOMES)
        assert set(out["lifecycle"].values()) == set(LIFECYCLE_OUTCOMES)
        assert set(out["offboarding"].values()) == set(OFFBOARD_OUTCOMES)
        assert {s for a in out["app_accounts"].values() for s in a.values()} == set(ACCOUNT_STATES)
        assert len(build_challenges(policies, g)) >= 12
    assert generate_scenario(random.Random(1), policies) != generate_scenario(random.Random(2), policies)


def test_policy_change_moves_answers(policies, sample):
    strict = copy.deepcopy(policies)
    strict["okta_mapping_offboarding"]["local_credential_sso_types"] = []
    cfg = strict["okta_mapping_offboarding"]
    assert verify_offboarding(off("DEACTIVATED", "Vendor Wiki"), catalog(), cfg).outcome == "STILL_HAS_ACCESS"
    sample = copy.deepcopy(sample)
    sample["apps"]["Vendor Wiki"]["local_login"] = False
    assert verify_offboarding(off("DEACTIVATED", "Vendor Wiki"), sample, cfg).outcome == "ACCESS_REMOVED"


def test_challenges_valid_and_full_score(policies, quiet_ui, sample):
    qs = build_challenges(policies, sample)
    assert len(qs) >= 12
    for q in qs:
        assert q.objective in ("3.1", "3.2") and q.answer in q.choices
        assert len(set(q.choices)) == len(q.choices)
        assert "lab" not in (q.prompt + " ".join(q.choices)).lower()
    answers = iter([q.answer for q in qs])
    res = run_challenge(quiet_ui, 39, qs, ask=lambda _: next(answers), progress=None, shuffle=False)
    assert res.correct == res.total == len(qs)
