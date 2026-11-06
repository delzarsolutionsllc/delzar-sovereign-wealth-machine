"""Lab 51 — ISC API access, user levels and tenant sign-in security tests."""

from __future__ import annotations

import copy
import random

import pytest

from labs.lab51_isc_api_security import (FLAGS, LEVEL_OUTCOMES, METHODS, SIGNIN, build_challenges, check_action,
                                         choose_api_method, generate_scenario, review_elevated, review_profile,
                                         review_signin, review_session, review_sso, run_demo)
from utils.challenge import run_challenge

SAMPLE = "sample_isc_api_security.json"


@pytest.fixture
def cfg(policies):
    return policies["isc_api_security"]


@pytest.fixture
def d(data):
    return copy.deepcopy(data(SAMPLE))


def person(d, pid):
    return next(p for p in d["people"] if p["id"] == pid)


# ------------------------------------------------------------------ API access
def test_script_gets_pat_and_token_url(cfg, d):
    r = choose_api_method({"id": "X", "integration_type": "script", "requester": "P01", "task": "read_identities",
                           "scopes": ["idn:identity:read"], "expiry_days": 30, "secret_storage": "vault"}, d, cfg)
    assert r.method == "PERSONAL_ACCESS_TOKEN" and r.flags == [] and r.acts_as == "P01"
    assert r.token_url == "https://larkspur-example.api.identitynow.com/oauth/token"


def test_service_gets_client_credentials_unless_user_context_or_segmentation(cfg, d):
    base = {"id": "X", "integration_type": "service", "scopes": ["idn:sources:read"], "secret_storage": "vault"}
    assert choose_api_method({**base, "task": "read_sources"}, d, cfg).method == "OAUTH_CLIENT_CREDENTIALS"
    # User-context task without a named user: deny.
    r = choose_api_method({**base, "task": "manage_roles"}, d, cfg)
    assert r.method == "DENY" and any("user context" in x for x in r.reasons)
    # Identity search with Data Segmentation on needs a named user's PAT.
    r = choose_api_method({**base, "task": "read_identities", "acts_as": "P06", "expiry_days": 30}, d, cfg)
    assert r.method == "PERSONAL_ACCESS_TOKEN"
    d["tenant"]["data_segmentation"] = False
    assert choose_api_method({**base, "task": "read_identities"}, d, cfg).method == "OAUTH_CLIENT_CREDENTIALS"


def test_web_app_needs_redirect_url(cfg, d):
    base = {"id": "X", "integration_type": "web_app", "task": "submit_access_request", "secret_storage": "vault"}
    assert choose_api_method(base, d, cfg).method == "DENY"
    r = choose_api_method({**base, "redirect_url": "https://app.example/cb"}, d, cfg)
    assert r.method == "AUTHORIZATION_CODE" and any("login.sailpoint.com/oauth/authorize" in x for x in r.reasons)


@pytest.mark.parametrize("req", [
    {"id": "X"}, {"id": "X", "integration_type": "script", "requester": "P01", "task": "export_passwords"},
    {"id": "X", "requester": "P01", "task": "read_sources"},
    {"id": "X", "integration_type": "mobile", "requester": "P01", "task": "read_sources"},
    {"id": "X", "integration_type": "script", "requester": "P99", "task": "read_sources"},
    {"id": "X", "integration_type": "script", "requester": "P12", "task": "read_sources"},
    {"id": "X", "integration_type": "script", "requester": "P11", "task": "read_identities"},
])
def test_api_deny_by_default(cfg, d, req):
    assert choose_api_method(req, d, cfg).method == "DENY"


def test_flags(cfg, d):
    base = {"id": "X", "integration_type": "script", "requester": "P01", "task": "read_identities",
            "expiry_days": 30, "secret_storage": "vault"}
    assert choose_api_method({**base, "scopes": ["sp:scopes:all"]}, d, cfg).flags == ["OVER_BROAD_SCOPE"]
    # sp:scopes:all is fine when no narrower scope exists for the task.
    r = choose_api_method({**base, "task": "download_reports", "scopes": ["sp:scopes:all"]}, d, cfg)
    assert r.flags == []
    r = choose_api_method({**base, "task": "read_sources", "scopes": ["idn:sources:manage"]}, d, cfg)
    assert r.flags == ["OVER_BROAD_SCOPE"]
    assert choose_api_method({**base, "expiry_days": None}, d, cfg).flags == ["NO_EXPIRY"]
    assert choose_api_method({**base, "secret_storage": "env_file"}, d, cfg).flags == ["STORE_SECRET_SECURELY"]
    assert choose_api_method({**base, "secret_storage": None}, d, cfg).flags == ["STORE_SECRET_SECURELY"]
    leaver = {**base, "requester": "P08", "task": "download_reports"}
    assert choose_api_method({**leaver, "expiry_days": 60}, d, cfg).flags == ["OUTLIVES_OWNER"]
    assert choose_api_method({**leaver, "expiry_days": 10}, d, cfg).flags == []


# ------------------------------------------------------------------ user levels
@pytest.mark.parametrize("pid, action, target, outcome", [
    ("P02", "manage_virtual_appliances", {}, "ALLOWED"),
    ("P04", "edit_source", {"source": "SRC-WD"}, "ALLOWED"),
    ("P04", "edit_source", {"source": "SRC-SAP"}, "DENIED"),
    ("P04", "edit_source", {}, "DENIED"),
    ("P04", "search", {}, "ALLOWED"),
    ("P05", "edit_role", {"role": "ROLE-FIN-AP"}, "ALLOWED"),
    ("P05", "edit_role", {"role": "ROLE-FIN-HR"}, "DENIED"),
    ("P05", "edit_role", {"role": "ROLE-NOPE"}, "DENIED"),
    ("P05", "role_discovery", {}, "DENIED"),
    ("P06", "reset_mfa", {}, "ALLOWED"),
    ("P06", "set_lifecycle_state", {}, "DENIED"),
    ("P07", "manage_campaigns", {}, "ALLOWED"),
    ("P09", "edit_role", {"role": "ROLE-FIN-AP"}, "DENIED"),
    ("P10", "security_settings", {}, "DENIED"),
    ("P11", "submit_access_request", {}, "ALLOWED"),
    ("P12", "manage_virtual_appliances", {}, "DENIED"),
    ("P01", "delete_tenant", {}, "DENIED"),
    ("P01", None, {}, "DENIED"),
])
def test_user_level_rules(cfg, d, pid, action, target, outcome):
    assert check_action(person(d, pid), action, target, d, cfg).outcome == outcome


def test_unknown_person_and_level_reasons(cfg, d):
    assert check_action(None, "search", {}, d, cfg).outcome == "DENIED"
    r = check_action(person(d, "P10"), "security_settings", {}, d, cfg)
    assert "unknown user level SUPER_USER grants nothing" in r.reasons[0]
    r = check_action(person(d, "P09"), "edit_role", {"role": "ROLE-FIN-AP"}, d, cfg)
    assert "cannot be assigned together" in r.reasons[0]


def test_grant_user_levels_tenant_setting(cfg, d):
    assert check_action(person(d, "P03"), "grant_user_levels", {}, d, cfg).outcome == "DENIED"
    d["tenant"]["non_org_admins_manage_levels"] = True
    assert check_action(person(d, "P03"), "grant_user_levels", {}, d, cfg).outcome == "ALLOWED"


# ------------------------------------------------------------------ sign-in review
def test_profile_review(cfg, d):
    assert review_profile({"id": "X", "sign_in_method": "MFA"}, d, cfg).outcome == "OK"
    assert review_profile({"id": "X"}, d, cfg).outcome == "SIGNIN_METHOD_UNKNOWN"
    assert review_profile({"id": "X", "sign_in_method": "MAGIC"}, d, cfg).outcome == "SIGNIN_METHOD_UNKNOWN"
    for src in ("SRC-LDAP", "SRC-WD", "SRC-NOPE", None):
        assert review_profile({"id": "X", "sign_in_method": "PASS_THROUGH", "auth_source": src}, d,
                              cfg).outcome == "PTA_SOURCE_UNHEALTHY"
    d["sources"][0]["aggregated"] = False
    assert review_profile({"id": "X", "sign_in_method": "PASS_THROUGH", "auth_source": "SRC-AD"}, d,
                          cfg).outcome == "PTA_SOURCE_UNHEALTHY"


def test_elevated_mfa_sso_and_session(cfg, d):
    assert review_elevated({"id": "X", "totp_registered": True}, cfg).outcome == "OK"
    assert review_elevated({"id": "X"}, cfg).outcome == "ADMIN_WITHOUT_MFA"
    assert review_sso({"enabled": False}, d, cfg).outcome == "OK"
    good = {"enabled": True, "emergency_admins": ["P01", "P02"], "bypass_documented": True}
    assert review_sso(good, d, cfg).outcome == "OK"
    assert review_sso({**good, "bypass_documented": False}, d, cfg).outcome == "SSO_WITHOUT_BYPASS_PLAN"
    r = review_sso({**good, "emergency_admins": ["P01", "P12"]}, d, cfg)
    assert r.outcome == "SSO_WITHOUT_BYPASS_PLAN" and "larkspur-example.identitynow.com/login/login?prompt=true" in \
        r.reasons[0]
    # A non-Admin or an Admin without TOTP does not count as an emergency admin.
    assert review_sso({**good, "emergency_admins": ["P01", "P06"]}, d, cfg).outcome == "SSO_WITHOUT_BYPASS_PLAN"
    assert review_session({"max_session_hours": 12, "idle_minutes": 15}, cfg).outcome == "OK"
    assert review_session({"max_session_hours": 13, "idle_minutes": 15}, cfg).outcome == "SESSION_TOO_LONG"
    assert review_session({}, cfg).outcome == "SESSION_TOO_LONG"


def test_unknown_level_counts_as_elevated_and_end_users_are_skipped(cfg, d):
    ids = {r.id: r.outcome for r in review_signin(d, cfg)}
    assert ids["P10"] == "ADMIN_WITHOUT_MFA" and "P11" not in ids and "P12" not in ids


# ------------------------------------------------------------------ sample, generator, challenges
def test_sample_expected_outcomes(policies, quiet_ui, data):
    out = run_demo(quiet_ui, policies, data(SAMPLE))
    assert out["api"] == {"R1": "PERSONAL_ACCESS_TOKEN", "R2": "OAUTH_CLIENT_CREDENTIALS",
                          "R3": "PERSONAL_ACCESS_TOKEN", "R4": "AUTHORIZATION_CODE", "R5": "PERSONAL_ACCESS_TOKEN",
                          "R6": "DENY", "R7": "DENY", "R8": "DENY", "R9": "PERSONAL_ACCESS_TOKEN", "R10": "DENY",
                          "R11": "OAUTH_CLIENT_CREDENTIALS", "R12": "DENY"}
    assert out["flags"]["R1"] == ["OVER_BROAD_SCOPE"] and out["flags"]["R3"] == ["STORE_SECRET_SECURELY"]
    assert out["flags"]["R5"] == ["NO_EXPIRY", "OUTLIVES_OWNER"] and out["flags"]["R11"] == ["OVER_BROAD_SCOPE"]
    assert [k for k, v in out["actions"].items() if v == "ALLOWED"] == ["A1", "A3", "A6", "A8", "A9", "A13", "A14"]
    m = out["metrics"]
    assert m["methods"] == {"PERSONAL_ACCESS_TOKEN": 4, "OAUTH_CLIENT_CREDENTIALS": 2, "AUTHORIZATION_CODE": 1,
                            "DENY": 5}
    assert m["actions"] == {"ALLOWED": 7, "DENIED": 8}
    assert m["signin"] == {"OK": 11, "ADMIN_WITHOUT_MFA": 2, "PTA_SOURCE_UNHEALTHY": 2, "SSO_WITHOUT_BYPASS_PLAN": 1,
                           "SESSION_TOO_LONG": 1, "SIGNIN_METHOD_UNKNOWN": 1}
    assert set(out["api"].values()) == set(METHODS) and set(out["actions"].values()) == set(LEVEL_OUTCOMES)
    assert set(out["signin"].values()) == set(SIGNIN)
    assert {f for fl in out["flags"].values() for f in fl} == set(FLAGS)


def test_generator_is_deterministic_and_covers_every_outcome(policies, quiet_ui):
    a, b = generate_scenario(random.Random(11), policies), generate_scenario(random.Random(11), policies)
    assert a == b
    assert any(generate_scenario(random.Random(s), policies) != a for s in range(12, 20))
    out = run_demo(quiet_ui, policies, a)
    assert set(out["api"].values()) == set(METHODS) and set(out["actions"].values()) == set(LEVEL_OUTCOMES)
    assert set(out["signin"].values()) == set(SIGNIN)
    assert {f for fl in out["flags"].values() for f in fl} == set(FLAGS)
    assert len(build_challenges(policies, a)) >= 12


def test_challenges_are_valid_and_self_answering_scores_100(policies, quiet_ui, data):
    qs = build_challenges(policies, data(SAMPLE))
    assert len(qs) >= 12
    assert all(q.objective == "1.2" for q in qs)
    assert all(len(set(q.choices)) == len(q.choices) for q in qs)
    assert not any("lab" in (q.prompt + " " + " ".join(q.choices)).lower().split() for q in qs)
    answers = iter([q.answer for q in qs])
    res = run_challenge(quiet_ui, 51, qs, ask=lambda _: next(answers), shuffle=False)
    assert res.correct == res.total == len(qs)
