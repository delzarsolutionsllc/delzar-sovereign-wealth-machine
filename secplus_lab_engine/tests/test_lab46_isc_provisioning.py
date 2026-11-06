"""Lab 46 — SailPoint ISC provisioning engine (plans, create account policies, channels) tests."""

from __future__ import annotations

import copy
import json
import random

import pytest

from labs.lab46_isc_provisioning import (CHANNELS, OUTCOMES, base_catalog, build_challenges, channel_for,
                                         generate_scenario, plan_change, render_create_policy, run_demo)
from utils.challenge import run_challenge

SAMPLE = "sample_isc_provisioning.json"


@pytest.fixture
def cfg(policies):
    return policies["isc_provisioning"]


def world(**identities):
    d = base_catalog("t.example")
    d["identities"] = identities
    return d


def person(dept="Finance", roles=(), aps=(), direct=(), accounts=None, **attrs):
    a = {"firstname": "Ada", "lastname": "Byron", "displayName": "Ada Byron", "email": "ada@t.example",
         "department": dept, "title": "Analyst", "costCenter": "CC-1", "employeeNumber": "E1",
         "cloudLifecycleState": "active"}
    a.update(attrs)
    return {"attributes": a, "roles": list(roles), "access_profiles": list(aps), "direct_entitlements": list(direct),
            "accounts": accounts or {}}


def acct(aid, ents=(), enabled=True, **attrs):
    return {"id": aid, "enabled": enabled, "entitlements": list(ents), "attributes": attrs}


def plan(cfg, data, **change):
    change.setdefault("id", "X")
    change.setdefault("identity", "ada")
    return plan_change(change, data, cfg)


def ops(res):
    return {(ln.source, ln.operation) for ln in res.lines}


def test_new_hire_creates_accounts_from_create_policy(cfg):
    d = world(ada=person())
    d["sources"]["Active Directory"]["existing_usernames"] = ["ada.byron", "ada.byron1"]
    r = plan(cfg, d, type="role_assigned", role="Finance Analyst", via="membership_criteria")
    ad = next(ln for ln in r.lines if ln.source == "Active Directory")
    assert ad.operation == "CREATE_ACCOUNT" and ad.channel == "DIRECT" and ad.status == "COMPLETED"
    assert ad.attributes["sAMAccountName"] == "ada.byron2"
    assert ad.attributes["mail"] == "ada@t.example" and ad.attributes["description"].startswith("Provisioned")
    assert sorted(ad.entitlements) == ["CN=Finance-Share", "CN=VPN-Users"]
    assert ops(r) >= {("Finance ERP", "CREATE_ACCOUNT"), ("Legacy Payroll", "CREATE_ACCOUNT")}


def test_missing_required_field_is_plan_error(cfg):
    d = world(ada=person(costCenter=None))
    r = plan(cfg, d, type="role_assigned", role="Finance Analyst", via="membership_criteria")
    erp = next(ln for ln in r.lines if ln.source == "Finance ERP")
    assert erp.operation == "PLAN_ERROR" and erp.status == "FAILED" and erp.channel is None
    assert any("costCenter" in x for x in erp.reasons)
    assert "Create Account provisioning policy" in erp.troubleshooting[0]


def test_generator_exhausted_and_unknown_field_type_are_plan_errors(cfg):
    d = world(ada=person())
    d["sources"]["Active Directory"]["existing_usernames"] = ["ada.byron"] + [f"ada.byron{i}" for i in range(1, 5)]
    _, errors, _ = render_create_policy(d["sources"]["Active Directory"], d["identities"]["ada"], cfg)
    assert errors and "no unique value after 5" in errors[0]
    src = {"create_policy": [{"name": "x", "type": "rule", "required": True}]}
    assert "unknown field type" in render_create_policy(src, d["identities"]["ada"], cfg)[1][0]
    assert render_create_policy({}, d["identities"]["ada"], cfg)[1]       # no policy at all = error


def test_add_entitlement_existing_account_and_already_held(cfg):
    d = world(ada=person(accounts={"Finance ERP": [acct("e1", ["AP Invoice Entry"])]}))
    r = plan(cfg, d, type="access_profile_granted", access_profile="AP-ERP-Approver", via="access_request")
    assert ops(r) == {("Finance ERP", "ADD_ENTITLEMENT")}
    r = plan(cfg, d, type="access_profile_granted", access_profile="AP-ERP-AP-Clerk", via="admin")
    assert ops(r) == {("Finance ERP", "NO_CHANGE")}


def test_remove_only_when_no_other_assignment_grants_it(cfg):
    d = world(ada=person("Sales", roles=["Sales Rep"], aps=["AP-AD-VPN"],
                         accounts={"Active Directory": [acct("ada", ["CN=Sales-Team", "CN=VPN-Users"])],
                                   "Badge System": [acct("b1", ["HQ Floor 3"])]}))
    r = plan(cfg, d, type="role_removed", role="Sales Rep", via="admin")
    by = {ln.target: ln for ln in r.lines}
    assert by["CN=Sales-Team"].operation == "REMOVE_ENTITLEMENT"
    assert by["CN=VPN-Users"].operation == "NO_CHANGE" and "AP-AD-VPN" in by["CN=VPN-Users"].reasons[0]
    assert by["HQ Floor 3"].operation == "REMOVE_ENTITLEMENT" and by["HQ Floor 3"].channel == "SERVICE_DESK"


def test_direct_request_also_keeps_entitlement(cfg):
    d = world(ada=person("Sales", roles=["Sales Rep"],
                         direct=[{"source": "Active Directory", "entitlement": "CN=VPN-Users"}],
                         accounts={"Active Directory": [acct("ada", ["CN=Sales-Team", "CN=VPN-Users"])]}))
    r = plan(cfg, d, type="role_removed", role="Sales Rep", via="admin")
    vpn = next(ln for ln in r.lines if ln.target == "CN=VPN-Users")
    assert vpn.operation == "NO_CHANGE" and "directly requested" in vpn.reasons[0]


def test_multiple_accounts_needs_selection(cfg):
    d = world(ada=person(accounts={"Active Directory": [acct("ada"), acct("adm-ada")]}))
    r = plan(cfg, d, type="access_profile_granted", access_profile="AP-AD-VPN", via="access_request")
    assert ops(r) == {("Active Directory", "MULTIPLE_ACCOUNTS")} and r.lines[0].status == "FAILED"
    r = plan(cfg, d, type="access_profile_granted", access_profile="AP-AD-VPN", via="access_request",
             account_selection={"Active Directory": "ada"})
    assert ops(r) == {("Active Directory", "ADD_ENTITLEMENT")} and r.lines[0].account == "ada"
    r = plan(cfg, d, type="access_profile_granted", access_profile="AP-AD-VPN", via="access_request",
             account_selection={"Active Directory": "nobody"})
    assert r.lines[0].operation == "MULTIPLE_ACCOUNTS"


def test_lifecycle_disable_and_already_disabled(cfg):
    d = world(ada=person(accounts={"Active Directory": [acct("ada")], "Finance ERP": [acct("e1", enabled=False)],
                                   "Legacy Payroll": [acct("p1")]}))
    r = plan(cfg, d, type="lifecycle_state", to="inactive")
    got = {ln.source: (ln.operation, ln.channel) for ln in r.lines}
    assert got == {"Active Directory": ("DISABLE", "DIRECT"), "Finance ERP": ("NO_CHANGE", None),
                   "Legacy Payroll": ("DISABLE", "MANUAL_TASK")}
    leave = plan(cfg, d, type="lifecycle_state", to="leave")
    assert ops(leave) == {("Active Directory", "DISABLE")}
    assert ops(plan(cfg, d, type="lifecycle_state", to="active")) == {("-", "NO_CHANGE")}


def test_attribute_sync_modify_match_and_non_direct(cfg):
    d = world(ada=person(accounts={"Active Directory": [acct("ada", title="Analyst")],
                                   "Legacy Payroll": [acct("p1", jobTitle="Analyst")]}))
    r = plan(cfg, d, type="attribute_change", attribute="title", value="Lead")
    got = {ln.source: ln.operation for ln in r.lines}
    assert got == {"Active Directory": "MODIFY", "Legacy Payroll": "NO_CHANGE"}
    assert next(ln for ln in r.lines if ln.operation == "MODIFY").attributes == {"title": "Lead"}
    same = plan(cfg, d, type="attribute_change", attribute="title", value="Analyst")
    assert {ln.operation for ln in same.lines} == {"NO_CHANGE"}
    assert ops(plan(cfg, d, type="attribute_change", attribute="costCenter", value="CC-9")) == {("-", "NO_CHANGE")}


def test_membership_criteria_not_met_is_no_change(cfg):
    d = world(ada=person("Sales"))
    r = plan(cfg, d, type="role_assigned", role="Finance Analyst", via="membership_criteria")
    assert ops(r) == {("-", "NO_CHANGE")} and "criteria not met" in r.lines[0].reasons[0]
    r = plan(cfg, d, type="role_assigned", role="Facilities Access", via="membership_criteria")
    assert ops(r) == {("-", "NO_CHANGE")}                                  # no criteria = never automatic


def test_channel_rules_in_order(cfg):
    assert channel_for({"service_desk": "SNOW", "provisioning": True}, cfg)[0] == "SERVICE_DESK"
    assert channel_for({"provisioning": True}, cfg)[0] == "DIRECT"
    assert channel_for({"provisioning": True, "read_only": True}, cfg)[0] == "MANUAL_TASK"
    assert channel_for({"provisioning": False}, cfg)[0] == "MANUAL_TASK"
    ch, why = channel_for({}, cfg)                                          # capability unknown
    assert ch == "MANUAL_TASK" and "deny by default" in why


@pytest.mark.parametrize("change", [
    {"identity": "ghost", "type": "role_assigned", "role": "Sales Rep", "via": "admin"},
    {"identity": None, "type": "role_assigned", "role": "Sales Rep", "via": "admin"},
    {"type": "grant_admin_rights", "via": "admin"},
    {"type": None},
    {"type": "role_assigned", "role": "Wizard", "via": "admin"},
    {"type": "access_profile_granted", "access_profile": "AP-Nope", "via": "admin"},
    {"type": "role_assigned", "role": "Sales Rep", "via": "magic"},
    {"type": "role_assigned", "role": "Sales Rep"},
    {"type": "role_assigned", "role": "Finance Analyst", "via": "access_request"},   # not requestable
    {"type": "lifecycle_state", "to": "retired"},
    {"type": "attribute_change", "value": "x"},
])
def test_deny_by_default_rejects(cfg, change):
    d = world(ada=person())
    r = plan(cfg, d, **change) if "identity" in change else plan(cfg, d, identity="ada", **change)
    assert [ln.operation for ln in r.lines] == ["REJECTED"] and r.lines[0].status == "FAILED"
    assert r.lines[0].troubleshooting


def test_unknown_source_in_access_profile_rejected(cfg):
    d = world(ada=person())
    r = plan(cfg, d, type="access_profile_granted", access_profile="AP-Old-CRM", via="access_request")
    assert ops(r) == {("Old CRM", "REJECTED")}


def test_connector_error_marks_direct_failed_with_log_steps(cfg):
    d = world(ada=person(accounts={"Finance ERP": [acct("e1")]}))
    r = plan(cfg, d, type="access_profile_granted", access_profile="AP-ERP-Approver", via="access_request",
             execution={"Finance ERP": "HTTP 403"})
    ln = r.lines[0]
    assert ln.status == "FAILED" and ln.channel == "DIRECT"
    assert "Account Activities" in ln.troubleshooting[0] and any("ccg.log" in s for s in ln.troubleshooting)


def test_sample_outcomes(policies, quiet_ui, data):
    out = run_demo(quiet_ui, policies, data(SAMPLE))
    json.dumps(out)
    assert set(out["lines"].values()) == set(OUTCOMES)
    assert set(out["channels"].values()) == set(CHANNELS)
    m = out["metrics"]
    assert m["changes"] == 14 and m["lines"] == 23
    assert m["operations"] == {"CREATE_ACCOUNT": 3, "ADD_ENTITLEMENT": 2, "REMOVE_ENTITLEMENT": 2, "MODIFY": 1,
                               "DISABLE": 4, "NO_CHANGE": 6, "PLAN_ERROR": 1, "MULTIPLE_ACCOUNTS": 1, "REJECTED": 3}
    assert m["channels"] == {"DIRECT": 7, "SERVICE_DESK": 3, "MANUAL_TASK": 2}
    assert m["failed"] == ["C01-2", "C02-1", "C04-1", "C10-1", "C12-1", "C13-1"]
    assert out["lines"]["C03-2"] == "NO_CHANGE" and out["lines"]["C05-1"] == "ADD_ENTITLEMENT"


def test_talking_point_matches_sample(policies, quiet_ui, data):
    from utils.loader import ROOT, load_json
    tp = load_json(ROOT / "data" / "briefings" / "lab46.json")["talking_point"]
    m = run_demo(quiet_ui, policies, data(SAMPLE))["metrics"]
    for phrase in (f"{m['changes']} ISC changes", f"{m['lines']} provisioning lines",
                   f"{m['operations']['CREATE_ACCOUNT']} accounts created", "maria.lopez2",
                   f"{m['channels']['DIRECT']} lines went direct", f"{len(m['failed'])} failed transactions"):
        assert phrase in tp


def test_planning_does_not_mutate_input(cfg, data):
    d = data(SAMPLE)
    before = copy.deepcopy(d)
    for c in d["changes"]:
        plan_change(c, d, cfg)
    assert d == before


def test_generator_is_deterministic_and_covers_every_outcome(policies, quiet_ui):
    a, b = generate_scenario(random.Random(11), policies), generate_scenario(random.Random(11), policies)
    assert a == b and a != generate_scenario(random.Random(12), policies)
    out = run_demo(quiet_ui, policies, a)
    assert set(out["lines"].values()) == set(OUTCOMES)
    assert set(out["channels"].values()) == set(CHANNELS)
    assert len(build_challenges(policies, a)) >= 12


def test_challenges_are_valid_and_self_answering_scores_100(policies, quiet_ui, data):
    qs = build_challenges(policies, data(SAMPLE))
    assert len(qs) >= 12
    assert all(q.objective in ("4.1", "4.2") for q in qs)
    assert {q.objective for q in qs} == {"4.1", "4.2"}
    assert all(len(set(q.choices)) == len(q.choices) for q in qs)
    assert not any("lab" in (q.prompt + " ".join(q.choices)).lower().split() for q in qs)
    answers = iter([q.answer for q in qs])
    res = run_challenge(quiet_ui, 46, qs, ask=lambda _: next(answers), shuffle=False)
    assert res.correct == res.total == len(qs)


def test_course_scoping():
    import labs.lab46_isc_provisioning as m
    assert m.COURSES == ("spadmin", "speng") and m.TITLE.startswith("Lab 46 — ")
