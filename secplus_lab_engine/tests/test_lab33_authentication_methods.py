"""Lab 33 — authentication methods policy, authentication strengths, SSPR readiness and TAP tests."""

from __future__ import annotations

import copy
import random

import pytest

from labs.lab33_authentication_methods import (
    build_challenges, evaluate_sign_in, evaluate_sspr, evaluate_tap, generate_scenario, run_demo,
)
from utils.challenge import check


@pytest.fixture
def cfg(policies):
    return policies["authentication_methods"]


@pytest.fixture
def sample(data):
    return data("sample_authentication_methods.json")


TENANT = {
    "methods": {
        "fido2": {"state": "enabled", "include": ["all_users"], "exclude": []},
        "windowsHelloForBusiness": {"state": "enabled", "include": ["all_users"], "exclude": []},
        "x509Certificate": {"state": "enabled", "include": ["Staff"], "exclude": []},
        "microsoftAuthenticator": {"state": "enabled", "include": ["Staff", "Vendors"], "exclude": [],
                                   "modes": {"Staff": "any", "Vendors": "push"}},
        "sms": {"state": "enabled", "include": ["Staff"], "exclude": ["Admins"]},
        "voice": {"state": "disabled", "include": ["all_users"], "exclude": []},
        "temporaryAccessPass": {"state": "enabled", "include": ["Staff"], "exclude": []},
        "email": {"state": "enabled", "include": ["all_users"], "exclude": []},
    },
    "custom_strengths": {"keys": {"name": "Keys", "combinations": ["fido2"], "fido2_allowed_aaguids": ["good"]}},
    "sspr": {"enabled_for": "selected", "groups": ["Staff"], "methods_required": 2,
             "allowed_methods": ["mobileApp", "mobilePhone", "email", "securityQuestions"]},
    "tap": {"min_lifetime_minutes": 60, "max_lifetime_minutes": 480, "one_time_only": True},
}


def scenario(*users):
    return {"tenant": copy.deepcopy(TENANT), "users": list(users)}


def user(uid="u1", groups=("Staff",), roles=(), registered=()):
    return {"id": uid, "groups": list(groups), "roles": list(roles), "registered": list(registered)}


def sign(cfg, method, strength, u=None, **kw):
    d = scenario(u or user())
    return evaluate_sign_in({"id": "S", "user": (u or user())["id"], "method": method,
                             "required_strength": strength, **kw}, d, cfg)


# ----------------------------------------------------------------- strengths
def test_phishing_resistant_list_is_exactly_the_three(cfg):
    assert sorted(cfg["builtin_strengths"]["phishing_resistant_mfa"]["combinations"]) == sorted(
        ["fido2", "windowsHelloForBusiness", "x509CertificateMultiFactor"])
    assert "deviceBasedPush" in cfg["builtin_strengths"]["passwordless_mfa"]["combinations"]
    assert "temporaryAccessPassOneTime" not in cfg["builtin_strengths"]["passwordless_mfa"]["combinations"]


@pytest.mark.parametrize("method", ["fido2", "windowsHelloForBusiness", "x509CertificateMultiFactor"])
def test_phishing_resistant_methods_satisfy(cfg, method):
    assert sign(cfg, method, "phishing_resistant_mfa").outcome == "SATISFIED"


@pytest.mark.parametrize("method", ["deviceBasedPush", "password,microsoftAuthenticatorPush", "password,sms",
                                    "x509CertificateSingleFactor", "temporaryAccessPassOneTime"])
def test_non_phishing_resistant_methods_do_not_satisfy(cfg, method):
    r = sign(cfg, method, "phishing_resistant_mfa")
    assert r.outcome == "NOT_SATISFIED" and r.rule == "not in strength"
    assert "fido2" in r.satisfying


def test_mfa_strength_accepts_password_plus_sms_but_not_sms_sign_in_or_email(cfg):
    assert sign(cfg, "password,sms", "mfa").outcome == "SATISFIED"
    assert sign(cfg, "sms", "mfa").outcome == "NOT_SATISFIED"
    assert sign(cfg, "email", "mfa").outcome == "NOT_SATISFIED"
    assert sign(cfg, "temporaryAccessPassOneTime", "mfa").outcome == "SATISFIED"


def test_custom_strength_aaguid_restriction(cfg):
    assert sign(cfg, "fido2", "keys", aaguid="good").outcome == "SATISFIED"
    bad = sign(cfg, "fido2", "keys", aaguid="other")
    missing = sign(cfg, "fido2", "keys")
    assert bad.outcome == missing.outcome == "NOT_SATISFIED" and bad.rule == "AAGUID not allowed"


# ----------------------------------------------------------------- methods policy
def test_disabled_method_and_exclusion_wins(cfg):
    assert sign(cfg, "password,voice", "mfa").outcome == "METHOD_DISABLED"
    admin = user(groups=("Staff", "Admins"))
    r = sign(cfg, "password,sms", "mfa", u=admin)
    assert r.outcome == "METHOD_DISABLED" and "exclusion wins" in r.reasons[0]


def test_untargeted_group_is_method_disabled(cfg):
    r = sign(cfg, "x509CertificateMultiFactor", "phishing_resistant_mfa", u=user(groups=("Vendors",)))
    assert r.outcome == "METHOD_DISABLED" and r.rule == "method not enabled"


def test_authenticator_mode_push_only_blocks_passwordless(cfg):
    vendor = user(groups=("Vendors",))
    assert sign(cfg, "deviceBasedPush", "mfa", u=vendor).outcome == "METHOD_DISABLED"
    assert sign(cfg, "password,microsoftAuthenticatorPush", "mfa", u=vendor).outcome == "SATISFIED"
    assert sign(cfg, "deviceBasedPush", "passwordless_mfa").outcome == "SATISFIED"


def test_method_disabled_checked_before_strength(cfg):
    # voice is disabled AND not phishing-resistant: the policy check comes first.
    assert sign(cfg, "password,voice", "phishing_resistant_mfa").outcome == "METHOD_DISABLED"


def test_deny_by_default_sign_in(cfg):
    d = scenario(user())
    assert evaluate_sign_in({"id": "x", "user": "ghost", "method": "fido2", "required_strength": "mfa"}, d,
                            cfg).outcome == "METHOD_DISABLED"
    assert evaluate_sign_in({"id": "x", "user": "u1", "method": "fido2"}, d, cfg).outcome == "NOT_SATISFIED"
    assert evaluate_sign_in({"id": "x", "user": "u1", "method": "fido2", "required_strength": "nope"}, d,
                            cfg).outcome == "NOT_SATISFIED"
    assert evaluate_sign_in({"id": "x", "user": "u1", "method": "magic", "required_strength": "mfa"}, d,
                            cfg).outcome == "NOT_SATISFIED"
    d["tenant"]["methods"].pop("fido2")
    assert evaluate_sign_in({"id": "x", "user": "u1", "method": "fido2", "required_strength": "mfa"}, d,
                            cfg).outcome == "METHOD_DISABLED"


# ----------------------------------------------------------------- SSPR
def sspr(cfg, u):
    return evaluate_sspr(u["id"], scenario(u), cfg)


def test_sspr_ready_and_insufficient(cfg):
    assert sspr(cfg, user(registered=["microsoftAuthenticator", "email"])).outcome == "SSPR_READY"
    assert sspr(cfg, user(registered=["email"])).outcome == "INSUFFICIENT_METHODS"


def test_sms_and_voice_count_as_one_phone(cfg):
    r = sspr(cfg, user(registered=["sms", "voice"]))
    assert r.outcome == "INSUFFICIENT_METHODS" and r.counted == ["mobilePhone"]


def test_passwordless_only_user_is_not_registered_for_sspr(cfg):
    assert sspr(cfg, user(registered=["fido2", "windowsHelloForBusiness"])).outcome == "NOT_REGISTERED"


def test_method_not_allowed_by_tenant_is_not_counted(cfg):
    assert sspr(cfg, user(registered=["officePhone", "email"])).outcome == "INSUFFICIENT_METHODS"


def test_out_of_scope_user_not_registered(cfg):
    assert sspr(cfg, user(groups=("Interns",), registered=["email", "sms"])).outcome == "NOT_REGISTERED"


def test_admin_policy_two_methods_no_security_questions(cfg):
    adm = user(groups=("Interns",), roles=["Helpdesk Administrator"], registered=["email", "securityQuestions"])
    r = sspr(cfg, adm)
    assert r.admin and r.outcome == "ADMIN_POLICY"
    ok = user(groups=("Interns",), roles=["Global Administrator"], registered=["email", "microsoftAuthenticator"])
    assert sspr(cfg, ok).outcome == "SSPR_READY"  # admin SSPR applies even outside the user SSPR scope


def test_unknown_role_treated_as_admin_and_unknown_user(cfg):
    assert sspr(cfg, user(roles=["Mystery Role"], registered=["email"])).outcome == "ADMIN_POLICY"
    assert evaluate_sspr("ghost", scenario(user()), cfg).outcome == "NOT_REGISTERED"


# ----------------------------------------------------------------- TAP
def tap(cfg, u=None, **kw):
    req = {"id": "T", "user": "u1", "lifetime_minutes": 60, "one_time": True, "uses": 0, "minutes_since_issue": 0}
    req.update(kw)
    return evaluate_tap(req, scenario(u or user()), cfg)


def test_tap_lifetime_bounds(cfg):
    assert tap(cfg, lifetime_minutes=480).outcome == "TAP_VALID"
    assert tap(cfg, lifetime_minutes=481).outcome == "TAP_REJECTED"
    assert tap(cfg, lifetime_minutes=59).outcome == "TAP_REJECTED"
    assert tap(cfg, lifetime_minutes=None).outcome == "TAP_REJECTED"


def test_tap_one_time_use_rules(cfg):
    assert tap(cfg, uses=1).outcome == "TAP_REJECTED"
    assert tap(cfg, one_time=False).outcome == "TAP_REJECTED"  # policy demands one-time only
    assert tap(cfg, minutes_since_issue=61).outcome == "TAP_REJECTED"


def test_tap_not_enabled_or_unknown_user(cfg):
    assert tap(cfg, u=user(groups=("Vendors",))).outcome == "TAP_REJECTED"
    assert tap(cfg, user="ghost").outcome == "TAP_REJECTED"


# ----------------------------------------------------------------- sample, generator, challenges
def test_sample_expected_outcomes(policies, quiet_ui, sample):
    out = run_demo(quiet_ui, policies, sample)
    assert out["sign_ins"] == {"S01": "SATISFIED", "S02": "METHOD_DISABLED", "S03": "NOT_SATISFIED",
                               "S04": "SATISFIED", "S05": "NOT_SATISFIED", "S06": "METHOD_DISABLED",
                               "S07": "SATISFIED", "S08": "NOT_SATISFIED", "S09": "NOT_SATISFIED",
                               "S10": "SATISFIED", "S11": "METHOD_DISABLED", "S12": "NOT_SATISFIED",
                               "S13": "NOT_SATISFIED", "S14": "METHOD_DISABLED", "S15": "NOT_SATISFIED"}
    assert out["sspr"] == {"ana.ruiz": "SSPR_READY", "ben.okafor": "ADMIN_POLICY", "cara.lind": "SSPR_READY",
                           "dev.patel": "SSPR_READY", "eli.moreau": "NOT_REGISTERED", "fay.chen": "NOT_REGISTERED",
                           "gus.berg": "SSPR_READY", "hana.sato": "NOT_REGISTERED",
                           "ivan.novak": "INSUFFICIENT_METHODS", "jo.reyes": "INSUFFICIENT_METHODS"}
    assert out["metrics"]["tap"] == {"TAP_VALID": 2, "TAP_REJECTED": 6}
    assert out["metrics"]["sign_ins"] == {"SATISFIED": 4, "NOT_SATISFIED": 7, "METHOD_DISABLED": 4}


def test_talking_point_matches_demo(policies, quiet_ui, sample, data):
    tp = data("briefings/lab33.json")["talking_point"]
    m = run_demo(quiet_ui, policies, sample)["metrics"]
    not_ready = sum(v for k, v in m["sspr"].items() if k != "SSPR_READY")
    assert f"Checked {sum(m['sign_ins'].values())} sign-ins" in tp
    assert f"({m['sign_ins']['SATISFIED']} satisfied, {m['sign_ins']['NOT_SATISFIED']} not satisfied, " \
           f"{m['sign_ins']['METHOD_DISABLED']} blocked" in tp
    assert f"{not_ready} of {sum(m['sspr'].values())} users" in tp
    assert f"rejected {m['tap']['TAP_REJECTED']} of {sum(m['tap'].values())}" in tp


def test_generate_scenario_deterministic_and_runs(policies, quiet_ui):
    a = generate_scenario(random.Random(7), policies)
    assert a == generate_scenario(random.Random(7), policies)
    assert a != generate_scenario(random.Random(8), policies)
    out = run_demo(quiet_ui, policies, a)
    for section in ("sign_ins", "sspr", "tap"):
        assert all(v > 0 for v in out["metrics"][section].values()), section
    assert len(build_challenges(policies, a)) >= 12


def test_challenges_valid_and_full_score(policies, sample):
    qs = build_challenges(policies, sample)
    assert len(qs) >= 12
    for q in qs:
        assert q.objective in ("2.1", "2.2")
        assert len(set(q.choices)) == len(q.choices)
        assert "lab" not in (q.prompt + " ".join(q.choices)).lower()
        assert q.explanation
    assert all(check(q, q.answer) for q in qs)
