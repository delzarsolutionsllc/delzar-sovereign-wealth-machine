"""Lab 38 — Okta OIN app integration (protocol chooser, SAML checker, provisioning) tests."""

from __future__ import annotations

import copy
import json
import random

import pytest

from labs.lab38_okta_app_integration import (ACTIONS, PROTOCOLS, SSO_OUTCOMES, VERIFICATIONS, build_challenges,
                                             check_sign_in, choose_protocol, generate_scenario, provision, run_demo)
from utils.challenge import run_challenge


@pytest.fixture
def cfg(policies):
    return policies["okta_app_integration"]


@pytest.fixture
def sample(data):
    return data("sample_okta_app_integration.json")


def proto(cfg, **kw):
    return choose_protocol({"id": "R1", "app": "x", **kw}, cfg)


HOST = "app.example"
BASE = {
    "users": [
        {"login": "a@x.example", "email": "a@x.example", "status": "ACTIVE", "groups": ["G"]},
        {"login": "b@x.example", "email": "bee@x.example", "status": "ACTIVE", "groups": []},
        {"login": "c@x.example", "email": "c@x.example", "status": "DEPROVISIONED", "groups": ["G"]},
    ],
    "apps": {"app": {
        "name": "App", "status": "ACTIVE",
        "saml": {"sso_url": f"https://{HOST}/acs", "audience": f"https://{HOST}/sp", "name_id_format": "EmailAddress",
                 "application_username": "email", "assertion_signed": True, "signing_cert": "c1"},
        "sp": {"acs_url": f"https://{HOST}/acs", "entity_id": f"https://{HOST}/sp", "name_id_format": "EmailAddress",
               "requires_signed_assertion": True, "idp_cert": "c1", "accounts": ["a@x.example", "bee@x.example"]},
        "assignments": {"users": ["b@x.example"], "groups": ["G"]},
        "provisioning": {"api_integration": True, "features": {"create_users": True, "update_attributes": True,
                                                               "deactivate_users": True, "sync_password": False}},
    }},
}


def sso(cfg, user="a@x.example", flow="idp_initiated", mutate=None, **attempt):
    d = copy.deepcopy(BASE)
    if mutate:
        mutate(d["apps"]["app"])
    return check_sign_in({"id": "S1", "user": user, "app": "app", "flow": flow, **attempt}, d, cfg)


def prov(cfg, event, user="a@x.example", mutate=None, app="app"):
    d = copy.deepcopy(BASE)
    if mutate:
        mutate(d["apps"]["app"])
    return provision({"id": "P1", "user": user, "app": app, "event": event}, d, cfg)


# --- Part 1: protocol chooser ------------------------------------------------
def test_protocol_rules_in_order(cfg):
    assert proto(cfg, protocols=["saml2"], app_type="web").outcome == "SAML"
    assert proto(cfg, protocols=["saml2", "oidc"], app_type="mobile").outcome == "OIDC"
    assert proto(cfg, protocols=["oidc"], app_type="web").outcome == "OIDC"
    assert proto(cfg, protocols=[], app_type="web", login_form=True).outcome == "SWA"
    assert proto(cfg, protocols=["saml2"], app_type="web", sign_in_required=False).outcome == "BOOKMARK"


def test_saml_beats_swa_when_both_available(cfg):
    r = proto(cfg, protocols=["SAML2"], app_type="web", login_form=True)
    assert r.outcome == "SAML" and "federation beats" in r.reasons[0]


def test_protocol_unknown_input_needs_review(cfg):
    assert proto(cfg, protocols=["oidc"]).outcome == "NEEDS_REVIEW"
    r = proto(cfg, protocols=["ldap_bind"], app_type="web")
    assert r.outcome == "NEEDS_REVIEW" and any("ldap_bind" in x for x in r.reasons)


# --- Part 2: SAML checker ----------------------------------------------------
def test_sso_success_direct_and_group(cfg):
    assert sso(cfg).outcome == "SSO_SUCCESS"
    r = sso(cfg, "b@x.example", flow="sp_initiated")
    assert r.outcome == "SSO_SUCCESS" and "direct" in r.reasons[0]


def test_not_assigned_beats_config_errors(cfg):
    d_unassigned = sso(cfg, "b@x.example", mutate=lambda a: a["assignments"].update(users=[], groups=[]))
    assert d_unassigned.outcome == "NOT_ASSIGNED"
    r = sso(cfg, "b@x.example", mutate=lambda a: (a["assignments"].update(users=[]), a["saml"].update(audience="bad")))
    assert r.outcome == "NOT_ASSIGNED" and "AUDIENCE_MISMATCH" in r.problems


def test_unknown_user_is_not_assigned(cfg):
    assert sso(cfg, "ghost@x.example").outcome == "NOT_ASSIGNED"


def test_user_not_active_names_the_status(cfg):
    r = sso(cfg, "c@x.example")                                   # DEPROVISIONED (Deactivated)
    assert r.outcome == "USER_NOT_ACTIVE" and "DEPROVISIONED" in r.reasons[0] and "lose" in r.reasons[0]
    for status in ("SUSPENDED", "LOCKED_OUT"):
        d = copy.deepcopy(BASE)
        d["users"][0]["status"] = status
        r = check_sign_in({"id": "S", "user": "a@x.example", "app": "app", "flow": "idp_initiated"}, d, cfg)
        assert r.outcome == "USER_NOT_ACTIVE" and status in r.reasons[0]
        assert "keep their app assignments" in r.reasons[0]
    d = copy.deepcopy(BASE)
    d["users"][0]["status"] = "WEIRD"
    r = check_sign_in({"id": "S", "user": "a@x.example", "app": "app"}, d, cfg)
    assert r.outcome == "USER_NOT_ACTIVE" and "fail closed" in r.reasons[0]


def test_user_not_active_checked_after_app_and_before_assignment(cfg):
    inactive = sso(cfg, "c@x.example", mutate=lambda a: a.update(status="INACTIVE"))
    assert inactive.problems[:2] == ["APP_INACTIVE", "USER_NOT_ACTIVE"]
    d = copy.deepcopy(BASE)
    d["users"][0].update(status="SUSPENDED", groups=[])
    r = check_sign_in({"id": "S", "user": "a@x.example", "app": "app"}, d, cfg)
    assert r.outcome == "USER_NOT_ACTIVE"


def test_app_inactive_and_unknown(cfg):
    assert sso(cfg, mutate=lambda a: a.update(status="INACTIVE")).outcome == "APP_INACTIVE"
    assert sso(cfg, mutate=lambda a: a.pop("status")).outcome == "APP_INACTIVE"
    d = copy.deepcopy(BASE)
    assert check_sign_in({"id": "S", "user": "a@x.example", "app": "nope"}, d, cfg).outcome == "APP_INACTIVE"


def test_acs_mismatch_config_and_sp_initiated_request(cfg):
    assert sso(cfg, mutate=lambda a: a["saml"].update(sso_url="https://app.example/sso")).outcome == "ACS_MISMATCH"
    assert sso(cfg, flow="sp_initiated", request_acs="https://eu.app.example/acs").outcome == "ACS_MISMATCH"
    allowed = sso(cfg, flow="sp_initiated", request_acs="https://eu.app.example/acs",
                  mutate=lambda a: a["saml"].update(other_requestable_sso_urls=["https://eu.app.example/acs"]))
    assert allowed.outcome == "SSO_SUCCESS"
    # an IdP-initiated sign-in sends no request, so request_acs is ignored
    assert sso(cfg, request_acs="https://eu.app.example/acs").outcome == "SSO_SUCCESS"


def test_audience_mismatch(cfg):
    r = sso(cfg, mutate=lambda a: a["saml"].update(audience="https://app.example/metadata"))
    assert r.outcome == "AUDIENCE_MISMATCH"


def test_cert_mismatch_rotation_and_unsigned(cfg):
    assert sso(cfg, mutate=lambda a: a["saml"].update(signing_cert="c2")).outcome == "CERT_MISMATCH"
    assert sso(cfg, mutate=lambda a: a["saml"].update(assertion_signed=False)).outcome == "CERT_MISMATCH"
    # a missing signature setting counts as unsigned
    assert sso(cfg, mutate=lambda a: a["saml"].pop("assertion_signed")).outcome == "CERT_MISMATCH"


def test_nameid_username_vs_email(cfg):
    username = lambda a: a["saml"].update(application_username="okta_username")
    assert sso(cfg, "b@x.example", mutate=username).outcome == "NAMEID_MISMATCH"   # login b@, SP stores bee@
    assert sso(cfg, "a@x.example", mutate=username).outcome == "SSO_SUCCESS"        # login equals email


def test_nameid_unknown_or_wrong_format_fails_closed(cfg):
    assert sso(cfg, mutate=lambda a: a["saml"].update(name_id_format="Weird")).outcome == "NAMEID_MISMATCH"
    assert sso(cfg, mutate=lambda a: a["saml"].update(name_id_format="Persistent")).outcome == "NAMEID_MISMATCH"
    assert sso(cfg, mutate=lambda a: a["saml"].pop("application_username")).outcome == "NAMEID_MISMATCH"


def test_check_order_cert_before_audience(cfg):
    r = sso(cfg, mutate=lambda a: a["saml"].update(signing_cert="c9", audience="bad"))
    assert r.outcome == "CERT_MISMATCH" and r.problems == ["CERT_MISMATCH", "AUDIENCE_MISMATCH"]


# --- Part 3: provisioning ----------------------------------------------------
def test_provisioning_create_update_password(cfg):
    assert (prov(cfg, "assigned").action, prov(cfg, "assigned").verification) == ("CREATE", "VERIFIED")
    assert prov(cfg, "profile_updated").action == "UPDATE"
    p = prov(cfg, "password_changed")
    assert (p.action, p.verification) == ("NONE", "VERIFIED")
    on = prov(cfg, "password_changed", mutate=lambda a: a["provisioning"]["features"].update(sync_password=True))
    assert on.action == "UPDATE"


def test_provisioning_features_off_need_manual_action(cfg):
    off = lambda a: a["provisioning"]["features"].update(create_users=False, update_attributes=False)
    assert prov(cfg, "assigned", mutate=off).verification == "MANUAL_ACTION"
    assert prov(cfg, "profile_updated", mutate=off).verification == "MANUAL_ACTION"
    no_api = prov(cfg, "assigned", mutate=lambda a: a["provisioning"].update(api_integration=False))
    assert (no_api.action, no_api.verification) == ("NONE", "MANUAL_ACTION")


def test_unassign_and_deactivate(cfg):
    still = prov(cfg, "unassigned", user="b@x.example")                 # still direct-assigned
    assert (still.action, still.verification) == ("NONE", "VERIFIED")
    gone = prov(cfg, "unassigned", user="b@x.example", mutate=lambda a: a["assignments"].update(users=[]))
    assert gone.action == "DEACTIVATE"
    assert prov(cfg, "okta_deactivated", user="c@x.example").action == "DEACTIVATE"
    keep = prov(cfg, "okta_deactivated", user="c@x.example",
                mutate=lambda a: a["provisioning"]["features"].update(deactivate_users=False))
    assert (keep.action, keep.verification) == ("NONE", "ACCESS_REMAINS")


def test_provisioning_fails_closed_on_unknowns(cfg):
    assert prov(cfg, "role_changed").verification == "NEEDS_REVIEW"
    missing = prov(cfg, "okta_deactivated", mutate=lambda a: a["provisioning"]["features"].pop("deactivate_users"))
    assert (missing.action, missing.verification) == ("NONE", "NEEDS_REVIEW")
    assert prov(cfg, "assigned", app="nope").verification == "NEEDS_REVIEW"
    assert prov(cfg, "assigned", mutate=lambda a: a.update(status="INACTIVE")).action == "NONE"
    assert prov(cfg, "assigned", user="ghost@x.example").verification == "NEEDS_REVIEW"


# --- Sample, briefing, generator, challenges ---------------------------------
def test_sample_outcomes(policies, quiet_ui, sample):
    out = run_demo(quiet_ui, policies, sample)
    json.dumps(out)
    assert out["protocols"] == {"R01": "SAML", "R02": "OIDC", "R03": "SAML", "R04": "OIDC", "R05": "SWA",
                                "R06": "BOOKMARK", "R07": "NEEDS_REVIEW", "R08": "NEEDS_REVIEW"}
    assert out["sign_ins"] == {"S01": "SSO_SUCCESS", "S02": "SSO_SUCCESS", "S03": "NOT_ASSIGNED",
                               "S04": "USER_NOT_ACTIVE", "S05": "NAMEID_MISMATCH", "S06": "SSO_SUCCESS",
                               "S07": "ACS_MISMATCH", "S08": "AUDIENCE_MISMATCH", "S09": "NOT_ASSIGNED",
                               "S10": "APP_INACTIVE", "S11": "ACS_MISMATCH", "S12": "CERT_MISMATCH",
                               "S13": "CERT_MISMATCH", "S14": "USER_NOT_ACTIVE"}
    assert out["provisioning"]["P05"] == ["NONE", "VERIFIED"]
    assert out["provisioning"]["P08"] == ["NONE", "ACCESS_REMAINS"]
    assert set(out["protocols"].values()) == set(PROTOCOLS)
    assert set(out["sign_ins"].values()) == set(SSO_OUTCOMES)
    assert {a for a, _ in out["provisioning"].values()} == set(ACTIONS)
    assert {v for _, v in out["provisioning"].values()} == set(VERIFICATIONS)


def test_briefing_talking_point_matches_demo(policies, quiet_ui, sample, data):
    tp = data("briefings/lab38.json")["talking_point"]
    m = run_demo(quiet_ui, policies, sample)["metrics"]
    pc, sc, ac, vc = m["protocol_counts"], m["sso_counts"], m["action_counts"], m["verification_counts"]
    assert f"for {m['requirements']} app requests ({pc['SAML']} SAML, {pc['OIDC']} OIDC, {pc['SWA']} SWA, " \
           f"{pc['BOOKMARK']} Bookmark and {pc['NEEDS_REVIEW']} sent back" in tp
    assert f"traced {m['sign_ins']} sign-in attempts across {len(sample['apps'])} SAML" in tp
    assert f"({sc['SSO_SUCCESS']} succeeded; {sc['USER_NOT_ACTIVE']} users were not active (1 deactivated, " \
           f"1 suspended), {sc['NOT_ASSIGNED']} users were not assigned, " \
           f"{sc['ACS_MISMATCH']} ACS URL mismatches, {sc['CERT_MISMATCH']} certificate" in tp
    assert f"{sc['AUDIENCE_MISMATCH']} audience mismatch, {sc['NAMEID_MISMATCH']} NameID mismatch and " \
           f"{sc['APP_INACTIVE']} inactive app" in tp
    assert f"checked {m['events']} provisioning events: {ac['CREATE']} accounts created, {ac['UPDATE']} updated, " \
           f"{ac['DEACTIVATE']} deactivated, {vc['ACCESS_REMAINS']} account left active" in tp
    assert f"{vc['NEEDS_REVIEW']} events held for review" in tp


def test_generator_is_deterministic_and_covers_outcomes(policies, quiet_ui):
    for seed in (1, 7, 42):
        g = generate_scenario(random.Random(seed), policies)
        assert g == generate_scenario(random.Random(seed), policies)
        out = run_demo(quiet_ui, policies, g)
        json.dumps(out)
        assert set(out["protocols"].values()) == set(PROTOCOLS)
        assert set(out["sign_ins"].values()) == set(SSO_OUTCOMES)
        assert {a for a, _ in out["provisioning"].values()} == set(ACTIONS)
        assert {v for _, v in out["provisioning"].values()} == set(VERIFICATIONS)
        assert len(build_challenges(policies, g)) >= 12
    assert generate_scenario(random.Random(1), policies) != generate_scenario(random.Random(2), policies)


def test_challenges_valid_and_full_score(policies, quiet_ui, sample):
    qs = build_challenges(policies, sample)
    assert len(qs) >= 12
    for q in qs:
        assert q.objective in ("2.1", "2.2") and q.answer in q.choices
        assert len(set(q.choices)) == len(q.choices)
        assert "lab" not in (q.prompt + " ".join(q.choices)).lower()
    answers = iter([q.answer for q in qs])
    res = run_challenge(quiet_ui, 38, qs, ask=lambda _: next(answers), progress=None, shuffle=False)
    assert res.correct == res.total == len(qs)


def test_challenge_answers_follow_the_engine(policies, sample):
    d = copy.deepcopy(sample)
    d["apps"]["hr"]["status"] = "ACTIVE"
    q = next(q for q in build_challenges(policies, d) if q.prompt.startswith("S10:"))
    assert q.answer == "SSO_SUCCESS"
