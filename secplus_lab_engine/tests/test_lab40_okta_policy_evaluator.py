"""Lab 40 — Okta sign-on policy evaluator (network zones, global session, authentication, enrollment) tests."""

from __future__ import annotations

import json
import random

import pytest

from labs.lab40_okta_policy_evaluator import (OUTCOMES, build_challenges, evaluate_attempt, generate_scenario,
                                              in_zone, run_demo, satisfies)
from utils.challenge import run_challenge


@pytest.fixture
def cfg(policies):
    return policies["okta_policy_evaluator"]


@pytest.fixture
def sample(data):
    return data("sample_okta_policy_evaluator.json")


USERS = {
    "staff@x.example": {"groups": ["Sales"], "enrolled": ["password", "email", "okta_verify"]},
    "admin@x.example": {"groups": ["Okta Admins"], "enrolled": ["password", "email", "okta_verify", "webauthn"]},
    "newadmin@x.example": {"groups": ["Okta Admins"], "enrolled": ["password", "email"]},
    "fin@x.example": {"groups": ["Finance"], "enrolled": ["password", "email", "okta_verify"]},
    "con@x.example": {"groups": ["Contractors"], "enrolled": ["password", "email"]},
}
APPS = {"admin": {"name": "Admin", "authentication_policy": "AP-ADMIN-CONSOLE"},
        "erp": {"name": "ERP", "authentication_policy": "AP-FINANCE"},
        "chat": {"name": "Chat", "authentication_policy": "AP-STANDARD"}}
HQ, HOME, WH = "198.51.100.10", "203.0.113.200", "203.0.113.70"
REG = {"registered": True}


def ev(cfg, org=None, users=None, **att):
    att = {"id": "T1", "user": "staff@x.example", "app": "chat", "ip": HOME, "country": "US",
           "presented": ["password", "okta_verify_push"], **att}
    data = {"users": users or USERS, "apps": APPS, "attempts": [att]}
    if org:
        data["org"] = org
    return evaluate_attempt(att, data, cfg)


# ---- Zones and deny by default ---------------------------------------------------------------------------
def test_zone_matching_ip_and_dynamic(cfg):
    zones = {z["id"]: z for z in cfg["org"]["network_zones"]}
    assert in_zone(zones["Z-HQ"], {"ip": HQ}) and not in_zone(zones["Z-HQ"], {"ip": HOME})
    assert in_zone(zones["Z-ALLOWED-COUNTRIES"], {"ip": HOME, "country": "ca"})
    assert in_zone(zones["Z-HOSTING-ASN"], {"ip": HOME, "asn": 64512})
    assert not in_zone(zones["Z-ALLOWED-COUNTRIES"], {"ip": HOME})            # missing country never matches


def test_blocklist_ip_and_anonymizer_deny_before_authentication(cfg):
    r = ev(cfg, ip="192.0.2.5")
    assert (r.outcome, r.blocked_by, r.gsp) == ("DENIED_BLOCKED_ZONE", "BlockedIpZone", None)
    r = ev(cfg, anonymizer=True, user="admin@x.example", app="admin", device=REG, presented=["password", "webauthn"])
    assert (r.outcome, r.blocked_by) == ("DENIED_BLOCKED_ZONE", "DefaultEnhancedDynamicZone")


def test_deactivated_blocklist_zone_is_ignored(cfg):
    r = ev(cfg, ip="198.18.4.9")
    assert r.outcome == "MFA_REQUIRED_SATISFIED" and r.blocked_by is None
    assert any("deactivated" in x for x in r.reasons)


def test_unknown_user_missing_ip_unknown_app_deny_by_default(cfg):
    assert ev(cfg, user="ghost@x.example").outcome == "DENIED_BY_GLOBAL_SESSION_POLICY"
    for bad in (None, "not-an-ip"):
        r = ev(cfg, ip=bad)
        assert r.outcome == "DENIED_BLOCKED_ZONE" and "deny by default" in r.reasons[-1]
    r = ev(cfg, app="unknown-app")
    assert r.outcome == "DENIED_BY_AUTHENTICATION_POLICY" and "deny by default" in r.reasons[-1]


# ---- Global session policy -------------------------------------------------------------------------------
def test_gsp_first_matching_policy_and_rule_by_priority(cfg):
    r = ev(cfg, ip=HQ, presented=["okta_verify_fastpass"])
    assert (r.gsp, r.gsp_rule, r.outcome) == ("GSP-DEFAULT", "GSP-DEFAULT-R1", "ACCESS_GRANTED")
    assert r.session_lifetime_minutes == 720
    r = ev(cfg, user="admin@x.example", app="admin", device=REG, presented=["password", "webauthn"])
    assert (r.gsp, r.gsp_rule, r.session_lifetime_minutes) == ("GSP-ADMINS", "GSP-ADMINS-R2", 60)


def test_gsp_deny_rules(cfg):
    r = ev(cfg, user="admin@x.example", app="admin", country="DE", device=REG, presented=["password", "webauthn"])
    assert (r.outcome, r.gsp_rule) == ("DENIED_BY_GLOBAL_SESSION_POLICY", "GSP-ADMINS-R1")
    r = ev(cfg, user="admin@x.example", app="admin", country=None, device=REG, presented=["password", "webauthn"])
    assert r.outcome == "DENIED_BY_GLOBAL_SESSION_POLICY"                     # unknown country is outside the zone
    r = ev(cfg, user="con@x.example", asn=64513, presented=["password", "email"])
    assert (r.outcome, r.gsp_rule) == ("DENIED_BY_GLOBAL_SESSION_POLICY", "GSP-CONTRACTORS-R1")


def test_gsp_no_rule_matched_falls_through_to_next_policy(cfg):
    r = ev(cfg, user="con@x.example", presented=["password", "email"])
    assert (r.gsp, r.gsp_rule, r.outcome) == ("GSP-DEFAULT", "GSP-DEFAULT-CATCHALL", "MFA_REQUIRED_SATISFIED")
    assert any("next policy" in x for x in r.reasons)
    r = ev(cfg, user="con@x.example", ip=WH, presented=["password"])
    # The contractor GSP rule needs no MFA, but the app's catch-all still wants 2 factor types.
    assert (r.gsp_rule, r.auth_rule, r.outcome) == ("GSP-CONTRACTORS-R2", "AP-STANDARD-CATCHALL",
                                                    "INSUFFICIENT_AUTHENTICATORS")


def test_no_matching_gsp_rule_at_all_denies(cfg):
    org = {"global_session_policies": [p for p in cfg["org"]["global_session_policies"] if p["id"] != "GSP-DEFAULT"]}
    r = ev(cfg, org=org)
    assert r.outcome == "DENIED_BY_GLOBAL_SESSION_POLICY" and "deny by default" in r.reasons[-1]


def test_inactive_rule_is_skipped(cfg):
    pols = json.loads(json.dumps(cfg["org"]["global_session_policies"]))
    pols[2]["rules"][0]["status"] = "INACTIVE"                                  # passwordless-on-HQ rule off
    r = ev(cfg, org={"global_session_policies": pols}, ip=HQ, presented=["okta_verify_fastpass"])
    assert (r.gsp_rule, r.outcome) == ("GSP-DEFAULT-CATCHALL", "INSUFFICIENT_AUTHENTICATORS")


# ---- Authentication policy -------------------------------------------------------------------------------
def test_auth_policy_device_and_group_conditions(cfg):
    managed = {"registered": True, "managed": True, "assurance": ["DA-MACOS-BASELINE"]}
    r = ev(cfg, user="fin@x.example", app="erp", device=managed, presented=["password", "okta_verify_push"])
    assert (r.auth_rule, r.outcome) == ("AP-FINANCE-R1", "MFA_REQUIRED_SATISFIED")
    for dev in ({}, {"registered": True, "managed": True}, {"registered": True, "managed": True, "assurance": ["X"]}):
        r = ev(cfg, user="fin@x.example", app="erp", device=dev)
        assert (r.auth_rule, r.outcome) == ("AP-FINANCE-CATCHALL", "DENIED_BY_AUTHENTICATION_POLICY")
    r = ev(cfg, user="con@x.example", app="erp", ip=WH, presented=["password"])
    assert (r.gsp_rule, r.auth_rule, r.outcome) == ("GSP-CONTRACTORS-R2", "AP-FINANCE-R2",
                                                    "DENIED_BY_AUTHENTICATION_POLICY")


def test_admin_console_requires_registered_device(cfg):
    r = ev(cfg, user="admin@x.example", app="admin", presented=["password", "webauthn"])
    assert (r.auth_rule, r.outcome) == ("AP-ADMIN-CATCHALL", "DENIED_BY_AUTHENTICATION_POLICY")


def test_both_policies_must_be_satisfied(cfg):
    # The app accepts one factor on HQ, but a GSP that demands a password still applies.
    pols = json.loads(json.dumps(cfg["org"]["global_session_policies"]))
    pols[2]["rules"][0]["primary_factor"] = "password"
    r = ev(cfg, org={"global_session_policies": pols}, ip=HQ, presented=["okta_verify_fastpass"])
    assert r.auth_rule == "AP-STANDARD-R1" and r.outcome == "INSUFFICIENT_AUTHENTICATORS"
    assert ev(cfg, ip=HQ, presented=["password"]).outcome == "ACCESS_GRANTED"


# ---- Authenticators and enrollment -----------------------------------------------------------------------
def test_factor_types_and_possession_constraints(cfg):
    assert satisfies(["okta_verify_fastpass_biometric"], 2, False, [], cfg)[0]
    assert not satisfies(["password", "security_question"], 2, False, [], cfg)[0]
    assert not satisfies(["password", "phone_sms"], 2, False, ["phishing_resistant"], cfg)[0]
    assert satisfies(["password", "webauthn"], 2, True, ["phishing_resistant"], cfg)[0]
    assert not satisfies(["password", "okta_verify_totp"], 2, True, ["hardware_protected"], cfg)[0]
    assert not satisfies(["webauthn"], 1, True, [], cfg)[0]                   # password required by the GSP


def test_presented_but_not_enrolled_is_ignored(cfg):
    r = ev(cfg, presented=["password", "webauthn"])
    assert r.outcome == "INSUFFICIENT_AUTHENTICATORS"
    assert any("not enrolled" in x for x in r.reasons)


def test_insufficient_when_enrolled_could_satisfy(cfg):
    r = ev(cfg, user="admin@x.example", app="admin", device=REG, presented=["password", "okta_verify_push"])
    assert r.outcome == "INSUFFICIENT_AUTHENTICATORS" and "could satisfy" in r.reasons[-1]


def test_enrollment_required_when_policy_allows_missing_authenticator(cfg):
    r = ev(cfg, user="newadmin@x.example", app="admin", device=REG, presented=["password", "email"])
    assert r.outcome == "ENROLLMENT_REQUIRED" and r.enroll == ["okta_verify", "webauthn"]


def test_enrollment_disabled_gives_insufficient(cfg):
    eps = json.loads(json.dumps(cfg["org"]["enrollment_policies"]))
    eps[0]["authenticators"].update({"okta_verify": "disabled", "webauthn": "disabled"})
    r = ev(cfg, org={"enrollment_policies": eps}, user="newadmin@x.example", app="admin", device=REG,
           presented=["password", "email"])
    assert r.outcome == "INSUFFICIENT_AUTHENTICATORS" and "allows none" in r.reasons[-1]


def test_required_authenticator_not_enrolled_prompts_enrollment(cfg):
    users = {**USERS, "noemail@x.example": {"groups": ["Sales"], "enrolled": ["password", "okta_verify"]}}
    r = ev(cfg, users=users, user="noemail@x.example", ip=HQ, presented=["okta_verify_fastpass"])
    assert r.outcome == "ENROLLMENT_REQUIRED" and r.enroll == ["email"]


# ---- Sample, briefing, generator, challenges -------------------------------------------------------------
def test_sample_expected_outcomes(policies, quiet_ui, sample):
    out = run_demo(quiet_ui, policies, sample)
    json.dumps(out)
    assert out["outcomes"] == {
        "A01": "ACCESS_GRANTED", "A02": "MFA_REQUIRED_SATISFIED", "A03": "DENIED_BLOCKED_ZONE",
        "A04": "DENIED_BLOCKED_ZONE", "A05": "MFA_REQUIRED_SATISFIED", "A06": "INSUFFICIENT_AUTHENTICATORS",
        "A07": "DENIED_BY_GLOBAL_SESSION_POLICY", "A08": "MFA_REQUIRED_SATISFIED",
        "A09": "DENIED_BY_AUTHENTICATION_POLICY", "A10": "DENIED_BY_AUTHENTICATION_POLICY",
        "A11": "MFA_REQUIRED_SATISFIED", "A12": "DENIED_BY_GLOBAL_SESSION_POLICY", "A13": "ENROLLMENT_REQUIRED",
        "A14": "ENROLLMENT_REQUIRED", "A15": "INSUFFICIENT_AUTHENTICATORS", "A16": "DENIED_BY_GLOBAL_SESSION_POLICY"}
    assert set(out["outcomes"].values()) == set(OUTCOMES)
    assert out["matched"]["A11"]["global_session"] == ["GSP-DEFAULT", "GSP-DEFAULT-CATCHALL"]
    assert out["matched"]["A10"]["authentication"] == ["AP-FINANCE", "AP-FINANCE-R2"]


def test_briefing_talking_point_matches_demo(policies, quiet_ui, sample, data):
    tp = data("briefings/lab40.json")["talking_point"]
    m = run_demo(quiet_ui, policies, sample)["metrics"]
    c = m["outcome_counts"]
    assert f"Traced {m['attempts']} " in tp and f"{m['granted']} granted ({c['MFA_REQUIRED_SATISFIED']} after" in tp
    assert f"{m['denied']} denied ({c['DENIED_BLOCKED_ZONE']} by blocklist" in tp
    assert f"{c['DENIED_BY_GLOBAL_SESSION_POLICY']} by the global session policy and " \
           f"{c['DENIED_BY_AUTHENTICATION_POLICY']} by app" in tp
    assert f"{m['enrollment_required']} users prompted to enroll" in tp and f"and {m['insufficient']} who" in tp


def test_generator_is_deterministic_and_covers_outcomes(policies, quiet_ui):
    for seed in (1, 7, 42):
        g = generate_scenario(random.Random(seed), policies)
        assert g == generate_scenario(random.Random(seed), policies)
        out = run_demo(quiet_ui, policies, g)
        assert set(out["outcomes"].values()) == set(OUTCOMES)
        assert len(build_challenges(policies, g)) >= 12
    assert generate_scenario(random.Random(1), policies) != generate_scenario(random.Random(2), policies)


def test_challenges_valid_and_full_score(policies, quiet_ui, sample):
    qs = build_challenges(policies, sample)
    assert len(qs) >= 12
    for q in qs:
        assert q.objective in ("4.1", "4.2", "4.3") and q.answer in q.choices
        assert len(set(q.choices)) == len(q.choices)
        assert "lab" not in (q.prompt + " ".join(q.choices)).lower()
    answers = iter([q.answer for q in qs])
    res = run_challenge(quiet_ui, 40, qs, ask=lambda _: next(answers), progress=None, shuffle=False)
    assert res.correct == res.total == len(qs)
