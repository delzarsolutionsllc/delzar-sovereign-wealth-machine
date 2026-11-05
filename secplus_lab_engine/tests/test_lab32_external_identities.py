"""Lab 32 — external identities (B2B collaboration, cross-tenant access, guest lifecycle) tests."""

from __future__ import annotations

import copy
import random
import re

import pytest

from labs.lab32_external_identities import (build_challenges, effective_settings, evaluate_invitations,
                                            evaluate_signin, generate_scenario, review_guests, run_demo)
from utils.challenge import check

COBALT = "c0ba1700-0000-4000-8000-00000000c001"
LARK = "1a4c5000-0000-4000-8000-00000000d002"
QUILL = "9f11e000-0000-4000-8000-00000000e003"
UNKNOWN = "00000000-0000-4000-8000-000000000999"

MEMBERS = [
    {"id": "M1", "user_type": "member", "roles": [], "account_enabled": True},
    {"id": "M2", "user_type": "member", "roles": [], "account_enabled": False},
    {"id": "GU", "user_type": "guest", "roles": [], "account_enabled": True},
    {"id": "GI", "user_type": "guest", "roles": ["Guest Inviter"], "account_enabled": True},
]


@pytest.fixture
def cfg(policies):
    return policies["external_identities"]


def invite(cfg, inviter="M1", email="a@partner.example"):
    data = {"members": MEMBERS, "invitations": [{"id": "I1", "inviter": inviter, "guest_email": email}]}
    return evaluate_invitations(data, cfg)[0]


def signin(cfg, **kw):
    base = {"id": "S1", "user": "x@p.example", "home_tenant_id": COBALT, "access_type": "b2b_collaboration",
            "app": "project-hub", "home_mfa": True}
    base.update(kw)
    return evaluate_signin(base, cfg)


def guest(cfg, **kw):
    base = {"id": "G1", "upn": "g#EXT#@x", "sponsor": "M1", "invitation_state": "Accepted",
            "last_sign_in_days_ago": 5}
    base.update(kw)
    return review_guests({"members": MEMBERS, "guests": [base]}, cfg)[0]


# ----------------------------------------------------------------- invitations
def test_member_and_guest_inviter_role_may_invite(cfg):
    assert invite(cfg).outcome == "INVITE_ALLOWED"
    assert invite(cfg, inviter="GI").outcome == "INVITE_ALLOWED"


def test_guest_without_role_and_disabled_member_blocked(cfg):
    r = invite(cfg, inviter="GU")
    assert r.outcome == "INVITE_BLOCKED" and r.rule == "inviter rights"
    assert invite(cfg, inviter="M2").outcome == "INVITE_BLOCKED"


def test_invite_level_is_policy_driven(cfg):
    strict = copy.deepcopy(cfg)
    strict["external_collaboration"]["guest_invite_level"] = "admin_roles_only"
    assert evaluate_invitations({"members": MEMBERS, "invitations": [
        {"id": "I1", "inviter": "M1", "guest_email": "a@partner.example"}]}, strict)[0].outcome == "INVITE_BLOCKED"
    strict["external_collaboration"]["guest_invite_level"] = "no_one"
    assert evaluate_invitations({"members": MEMBERS, "invitations": [
        {"id": "I1", "inviter": "GI", "guest_email": "a@partner.example"}]}, strict)[0].outcome == "INVITE_BLOCKED"
    loose = copy.deepcopy(cfg)
    loose["external_collaboration"]["guest_invite_level"] = "anyone"
    assert evaluate_invitations({"members": MEMBERS, "invitations": [
        {"id": "I1", "inviter": "GU", "guest_email": "a@partner.example"}]}, loose)[0].outcome == "INVITE_ALLOWED"


def test_deny_list_is_case_insensitive_and_allow_list_mode(cfg):
    denied = cfg["external_collaboration"]["collaboration_restrictions"]["domains"][0]
    r = invite(cfg, email=f"Someone@{denied.upper()}")
    assert r.outcome == "INVITE_BLOCKED" and r.rule == "domain"
    allow = copy.deepcopy(cfg)
    allow["external_collaboration"]["collaboration_restrictions"] = {"mode": "allow_list", "domains": ["ok.example"]}
    data = lambda e: {"members": MEMBERS, "invitations": [{"id": "I1", "inviter": "M1", "guest_email": e}]}
    assert evaluate_invitations(data("a@ok.example"), allow)[0].outcome == "INVITE_ALLOWED"
    assert evaluate_invitations(data("a@other.example"), allow)[0].outcome == "INVITE_BLOCKED"


def test_invite_missing_input_denied(cfg):
    assert invite(cfg, inviter=None).rule == "missing input"
    assert invite(cfg, email="not-an-email").outcome == "INVITE_BLOCKED"
    assert invite(cfg, inviter="NOBODY").outcome == "INVITE_BLOCKED"


# ----------------------------------------------------------------- sign-ins
def test_unknown_tenant_uses_default_and_direct_connect_denied(cfg):
    eff, label = effective_settings(UNKNOWN, cfg)
    assert label == "default" and eff["b2b_direct_connect"]["inbound"]["access"] == "block"
    r = signin(cfg, home_tenant_id=UNKNOWN, access_type="b2b_direct_connect", app="teams-shared-channels",
               partner_outbound_allows=True)
    assert r.outcome == "BLOCK" and r.rule == "inbound access"
    assert signin(cfg, home_tenant_id=UNKNOWN).outcome == "REQUIRE_MFA_IN_RESOURCE_TENANT"


def test_org_override_inherits_unset_parts(cfg):
    eff, label = effective_settings(LARK, cfg)
    assert label == "Larkspur Analytics"
    assert eff["trust"]["hybrid_joined"] is True and eff["trust"]["mfa"] is False      # mfa inherited
    assert eff["b2b_direct_connect"] == cfg["cross_tenant_access"]["default"]["b2b_direct_connect"]


def test_trusted_mfa_no_second_prompt(cfg):
    assert signin(cfg).outcome == "ALLOW_TRUSTED_MFA"
    assert signin(cfg, home_mfa=False).outcome == "REQUIRE_MFA_IN_HOME_TENANT"
    assert signin(cfg, home_tenant_id=LARK, home_mfa=True).outcome == "REQUIRE_MFA_IN_RESOURCE_TENANT"


def test_inbound_blocked_tenant_and_app_not_allowed(cfg):
    assert signin(cfg, home_tenant_id=QUILL, app="partner-portal").outcome == "BLOCK"
    r = signin(cfg, home_tenant_id=LARK, app="finance-erp", hybrid_joined=True)
    assert r.outcome == "BLOCK" and "not in the inbound" in r.reasons[-1]


def test_no_grant_controls_allow(cfg):
    r = signin(cfg, home_tenant_id=LARK, app="partner-portal", home_mfa=False)
    assert r.outcome == "ALLOW" and r.rule == "no grant controls"


def test_device_trust_compliant_or_hybrid(cfg):
    assert signin(cfg, app="finance-erp", device_compliant=True).outcome == "ALLOW_TRUSTED_MFA"
    r = signin(cfg, app="finance-erp", device_compliant=False, hybrid_joined=True)   # Cobalt: hybrid not trusted
    assert r.outcome == "BLOCK" and r.rule == "device trust"
    hybrid = copy.deepcopy(cfg)
    hybrid["cross_tenant_access"]["organizations"][COBALT]["trust"]["hybrid_joined"] = True
    assert evaluate_signin({"id": "S", "home_tenant_id": COBALT, "access_type": "b2b_collaboration",
                            "app": "finance-erp", "home_mfa": True, "hybrid_joined": True},
                           hybrid).outcome == "ALLOW_TRUSTED_MFA"
    assert signin(cfg, home_tenant_id=UNKNOWN, app="finance-erp", device_compliant=True).outcome == "BLOCK"


def test_direct_connect_mutual_consent_and_mfa_trust(cfg):
    dc = dict(access_type="b2b_direct_connect", app="teams-shared-channels")
    assert signin(cfg, partner_outbound_allows=True, **dc).outcome == "ALLOW_TRUSTED_MFA"
    assert signin(cfg, partner_outbound_allows=False, **dc).outcome == "BLOCK"
    assert signin(cfg, **dc).outcome == "BLOCK"                                    # missing = not allowed
    no_trust = copy.deepcopy(cfg)
    no_trust["cross_tenant_access"]["organizations"][COBALT]["trust"]["mfa"] = False
    r = evaluate_signin({"id": "S", "home_tenant_id": COBALT, "partner_outbound_allows": True, "home_mfa": True,
                         **dc}, no_trust)
    assert r.outcome == "BLOCK" and r.rule == "MFA trust"


def test_signin_missing_input_blocked(cfg):
    for kw in ({"home_tenant_id": None}, {"app": None}, {"access_type": "something_else"}):
        r = signin(cfg, **kw)
        assert r.outcome == "BLOCK" and r.rule == "missing input"


# ----------------------------------------------------------------- guests
def test_guest_lifecycle_rules(cfg):
    lc = cfg["guest_lifecycle"]
    assert guest(cfg).outcome == "KEEP"
    assert guest(cfg, last_sign_in_days_ago=lc["review_after_days"]).outcome == "KEEP"            # boundary
    assert guest(cfg, last_sign_in_days_ago=lc["review_after_days"] + 1).outcome == "REVIEW"
    assert guest(cfg, last_sign_in_days_ago=lc["remove_after_days"] + 1).outcome == "REMOVE"
    assert guest(cfg, sponsor=None).outcome == "REVIEW"
    assert guest(cfg, sponsor="M2").outcome == "REVIEW"                                          # disabled sponsor
    assert guest(cfg, sponsor=None, last_sign_in_days_ago=lc["review_after_days"] + 1).outcome == "REMOVE"


def test_guest_pending_and_missing_sign_in(cfg):
    lc = cfg["guest_lifecycle"]
    pending = dict(invitation_state="PendingAcceptance", last_sign_in_days_ago=None)
    assert guest(cfg, invited_days_ago=lc["pending_invitation_expire_days"] + 1, **pending).outcome == "REMOVE"
    assert guest(cfg, invited_days_ago=2, **pending).outcome == "KEEP"
    assert guest(cfg, **pending).outcome == "REMOVE"                                            # unknown age
    g = {"id": "G1", "upn": "x", "sponsor": "M1", "invitation_state": "Accepted"}
    assert review_guests({"members": MEMBERS, "guests": [g]}, cfg)[0].outcome == "REMOVE"


# ----------------------------------------------------------------- sample, generator, challenges
def test_sample_expected_outcomes(policies, quiet_ui, data):
    out = run_demo(quiet_ui, policies, data("sample_external_identities.json"))
    assert out["invitations"] == {"I01": "INVITE_ALLOWED", "I02": "INVITE_BLOCKED", "I03": "INVITE_ALLOWED",
                                  "I04": "INVITE_BLOCKED", "I05": "INVITE_BLOCKED", "I06": "INVITE_BLOCKED"}
    assert out["sign_ins"] == {"S01": "ALLOW_TRUSTED_MFA", "S02": "ALLOW_TRUSTED_MFA", "S03": "ALLOW_TRUSTED_MFA",
                               "S04": "BLOCK", "S05": "REQUIRE_MFA_IN_HOME_TENANT",
                               "S06": "REQUIRE_MFA_IN_RESOURCE_TENANT", "S07": "ALLOW", "S08": "BLOCK",
                               "S09": "BLOCK", "S10": "REQUIRE_MFA_IN_RESOURCE_TENANT", "S11": "BLOCK",
                               "S12": "BLOCK"}
    assert out["guests"] == {"G01": "KEEP", "G02": "REVIEW", "G03": "REMOVE", "G04": "REVIEW", "G05": "REMOVE",
                             "G06": "REMOVE", "G07": "REVIEW", "G08": "REMOVE"}
    assert out["metrics"]["default_settings_sign_ins"] == 2


def test_generate_scenario_deterministic_and_runs(policies, quiet_ui):
    a = generate_scenario(random.Random(7), policies)
    assert a == generate_scenario(random.Random(7), policies)
    assert a != generate_scenario(random.Random(8), policies)
    out = run_demo(quiet_ui, policies, a)
    assert set(out["guests"].values()) == {"KEEP", "REVIEW", "REMOVE"}
    assert set(out["invitations"].values()) == {"INVITE_ALLOWED", "INVITE_BLOCKED"}
    assert set(out["sign_ins"].values()) == {"ALLOW", "ALLOW_TRUSTED_MFA", "REQUIRE_MFA_IN_HOME_TENANT",
                                             "REQUIRE_MFA_IN_RESOURCE_TENANT", "BLOCK"}
    assert len(build_challenges(policies, a)) >= 12


def test_challenges_valid_and_self_answer_scores_100(policies, data):
    qs = build_challenges(policies, data("sample_external_identities.json"))
    assert len(qs) >= 12
    for q in qs:
        assert q.objective in ("1.3", "2.2")
        assert len(q.choices) == len(set(q.choices))
        assert not re.search(r"\blabs?\b", " ".join([q.prompt, *q.choices]), re.I)
    assert sum(check(q, q.answer) for q in qs) == len(qs)
