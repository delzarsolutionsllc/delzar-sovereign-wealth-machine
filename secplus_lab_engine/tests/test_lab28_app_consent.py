"""Lab 28 — app consent & permission governance tests."""

from __future__ import annotations

import copy
import json
import random

import pytest

from labs.lab28_app_consent import (GRANT_OUTCOMES, REQUEST_OUTCOMES, build_challenges, classify,
                                    evaluate_request, generate_scenario, matching_rules, review_grant, run_demo)
from utils.challenge import check


@pytest.fixture
def cfg(policies):
    return policies["app_consent"]


TENANT = {"user_consent": "verified_publishers_low_impact",
          "admin_consent_workflow": {"enabled": True, "reviewers": [
              {"name": "CAA", "role": "Cloud Application Administrator"},
              {"name": "PRA", "role": "Privileged Role Administrator"}]}}


def d(n):
    return {"name": n, "type": "delegated"}


def a(n):
    return {"name": n, "type": "application"}


def req(**kw):
    base = {"id": "R1", "app": "X", "app_id": "x1", "publisher_verified": True, "tenancy": "multi",
            "permissions": [d("User.Read")]}
    base.update(kw)
    return base


def grant(**kw):
    base = {"id": "G1", "app": "X", "app_id": "x1", "publisher_verified": True, "tenancy": "multi",
            "consent_type": "admin", "consented_users": 10, "last_used_days_ago": 5,
            "permissions": [d("User.Read")]}
    base.update(kw)
    return base


def test_verified_low_impact_user_may_consent(cfg):
    r = evaluate_request(req(permissions=[d("openid"), d("User.Read")]), TENANT, cfg)
    assert (r.outcome, r.rule) == ("USER_CONSENT_ALLOWED", "low_impact_verified")


def test_in_tenant_unverified_app_counts_like_verified(cfg):
    r = evaluate_request(req(publisher_verified=False, tenancy="single"), TENANT, cfg)
    assert r.outcome == "USER_CONSENT_ALLOWED"
    r2 = evaluate_request(req(publisher_verified=False, tenancy="multi"), TENANT, cfg)
    assert (r2.outcome, r2.rule) == ("ADMIN_CONSENT_REQUIRED", "publisher_not_verified")


def test_high_risk_delegated_needs_admin(cfg):
    r = evaluate_request(req(permissions=[d("Mail.Read")]), TENANT, cfg)
    assert (r.outcome, r.rule) == ("ADMIN_CONSENT_REQUIRED", "not_low_impact")


def test_application_permissions_always_need_admin_even_under_allow_all(cfg):
    for setting in ("verified_publishers_low_impact", "allow_all"):
        r = evaluate_request(req(permissions=[a("Calendars.Read")]), {**TENANT, "user_consent": setting}, cfg)
        assert (r.outcome, r.rule) == ("ADMIN_CONSENT_REQUIRED", "application_permission")


def test_admin_only_delegated_permission(cfg):
    r = evaluate_request(req(permissions=[d("Directory.Read.All")]), {**TENANT, "user_consent": "allow_all"}, cfg)
    assert (r.outcome, r.rule) == ("ADMIN_CONSENT_REQUIRED", "admin_only_permission")


def test_unknown_permission_is_critical(cfg):
    p = classify(d("Totally.Unknown"), cfg)
    assert p.risk == "critical" and p.admin_only and not p.known
    assert evaluate_request(req(permissions=[d("Totally.Unknown")]), TENANT, cfg).outcome == "ADMIN_CONSENT_REQUIRED"
    blocked = evaluate_request(req(publisher_verified=False, permissions=[d("Totally.Unknown")]), TENANT, cfg)
    assert (blocked.outcome, blocked.rule) == ("BLOCKED", "unverified_critical")


def test_missing_type_treated_as_application(cfg):
    p = classify({"name": "User.Read"}, cfg)
    assert p.type == "application" and p.risk == "critical"  # User.Read has no application form in the catalog


def test_unverified_multitenant_critical_blocked_but_single_tenant_not(cfg):
    perms = [d("RoleManagement.ReadWrite.Directory")]
    assert evaluate_request(req(publisher_verified=False, permissions=perms), TENANT, cfg).outcome == "BLOCKED"
    single = evaluate_request(req(publisher_verified=False, tenancy="single", permissions=perms), TENANT, cfg)
    assert (single.outcome, single.rule) == ("ADMIN_CONSENT_REQUIRED", "admin_only_permission")
    off = copy.deepcopy(cfg)
    off["block_unverified_multitenant_critical"] = False
    assert evaluate_request(req(publisher_verified=False, permissions=perms), TENANT, off).outcome == "ADMIN_CONSENT_REQUIRED"


def test_banned_app_blocked_even_with_low_permissions(cfg):
    r = evaluate_request(req(defender_status="banned"), TENANT, cfg)
    assert (r.outcome, r.rule) == ("BLOCKED", "banned_app")


def test_deny_by_default_on_missing_input(cfg):
    assert evaluate_request({"id": "R"}, TENANT, cfg).outcome == "BLOCKED"
    assert evaluate_request(req(permissions=[]), TENANT, cfg).rule == "invalid_request"
    r = evaluate_request(req(), {}, cfg)
    assert (r.outcome, r.rule) == ("ADMIN_CONSENT_REQUIRED", "consent_disabled")
    assert any("missing/unknown" in x for x in r.reasons)
    r2 = evaluate_request(req(publisher_verified=None, tenancy=None), TENANT, cfg)
    assert r2.rule == "publisher_not_verified"


def test_consent_disabled_and_legacy_allow_all(cfg):
    assert evaluate_request(req(), {**TENANT, "user_consent": "do_not_allow"}, cfg).rule == "consent_disabled"
    r = evaluate_request(req(publisher_verified=False, permissions=[d("Mail.Read")]),
                         {**TENANT, "user_consent": "allow_all"}, cfg)
    assert (r.outcome, r.rule) == ("USER_CONSENT_ALLOWED", "allow_all")


def test_routing_only_to_reviewers_who_can_grant(cfg):
    app = evaluate_request(req(permissions=[a("User.Read.All")]), TENANT, cfg)
    assert app.routed_to == ["PRA"]
    dlg = evaluate_request(req(permissions=[d("Mail.Read")]), TENANT, cfg)
    assert dlg.routed_to == ["CAA", "PRA"]
    off = evaluate_request(req(permissions=[d("Mail.Read")]), {**TENANT, "admin_consent_workflow": {"enabled": False}}, cfg)
    assert off.outcome == "ADMIN_CONSENT_REQUIRED" and off.routed_to == [] and "workflow is off" in off.reasons[-1]
    weak = {**TENANT, "admin_consent_workflow": {"enabled": True, "reviewers": [{"name": "SR", "role": "Security Reader"}]}}
    assert evaluate_request(req(permissions=[d("Mail.Read")]), weak, cfg).routed_to == []


def test_matching_rules_first_is_the_deciding_rule(cfg, data):
    sample = data("sample_app_consent.json")
    for r in sample["requests"]:
        assert matching_rules(r, sample["tenant"], cfg)[0] == evaluate_request(r, sample["tenant"], cfg).rule


def test_grant_revoke_rules(cfg):
    assert review_grant(grant(defender_status="banned"), cfg).rule == "banned_app"
    g = review_grant(grant(publisher_verified=False, permissions=[a("Files.Read.All")], credential_expires_in_days=50), cfg)
    assert (g.outcome, g.rule) == ("REVOKE_GRANT", "unverified_app_permission")
    u = review_grant(grant(consent_type="user", permissions=[d("Mail.Read")]), cfg)
    assert (u.outcome, u.rule) == ("REVOKE_GRANT", "user_consented_high")
    s = review_grant(grant(last_used_days_ago=200, permissions=[a("Directory.ReadWrite.All")],
                           credential_expires_in_days=30), cfg)
    assert (s.outcome, s.rule) == ("REVOKE_GRANT", "stale_critical")


def test_grant_review_rules_and_boundaries(cfg):
    limit = cfg["review"]["unused_after_days"]
    assert review_grant(grant(last_used_days_ago=limit), cfg).outcome == "OK"
    assert review_grant(grant(last_used_days_ago=limit + 1), cfg).rule == "unused"
    assert review_grant(grant(last_used_days_ago=None), cfg).rule == "unused"
    e = review_grant(grant(permissions=[a("User.Read.All")], credential_expires_in_days=-1), cfg)
    assert (e.outcome, e.rule) == ("REVIEW", "credential_expired")
    assert review_grant(grant(permissions=[a("User.Read.All")]), cfg).rule == "credential_expired"
    p = review_grant(grant(permissions=[a("RoleManagement.ReadWrite.Directory")], credential_expires_in_days=90), cfg)
    assert (p.outcome, p.rule) == ("REVIEW", "privileged_grant")
    n = cfg["review"]["wide_grant_users"]
    assert review_grant(grant(consented_users=n, permissions=[d("Mail.Read")]), cfg).rule == "wide_high"
    assert review_grant(grant(consented_users=n - 1, permissions=[d("Mail.Read")]), cfg).outcome == "OK"


def test_grant_deny_by_default(cfg):
    assert review_grant({"id": "G"}, cfg).outcome == "REVIEW"
    g = review_grant(grant(consent_type=None, permissions=[d("Mail.Read")]), cfg)
    assert g.outcome == "REVOKE_GRANT"  # unknown consent type is treated as user consent
    assert review_grant(grant(publisher_verified=False, permissions=[a("Unknown.App")],
                              credential_expires_in_days=10), cfg).outcome == "REVOKE_GRANT"


def test_sample_expected_outcomes(policies, quiet_ui, data):
    out = run_demo(quiet_ui, policies, data("sample_app_consent.json"))
    json.dumps(out)
    assert out["requests"] == {"R01": "USER_CONSENT_ALLOWED", "R02": "USER_CONSENT_ALLOWED",
                               "R03": "ADMIN_CONSENT_REQUIRED", "R04": "ADMIN_CONSENT_REQUIRED",
                               "R05": "ADMIN_CONSENT_REQUIRED", "R06": "BLOCKED", "R07": "BLOCKED",
                               "R08": "ADMIN_CONSENT_REQUIRED", "R09": "ADMIN_CONSENT_REQUIRED", "R10": "BLOCKED"}
    assert out["grants"] == {"G01": "OK", "G02": "REVOKE_GRANT", "G03": "REVOKE_GRANT", "G04": "REVIEW",
                             "G05": "REVIEW", "G06": "REVIEW", "G07": "REVOKE_GRANT", "G08": "OK",
                             "G09": "REVIEW", "G10": "REVIEW"}
    assert out["metrics"]["admin_queue"][0] == "R09" and out["metrics"]["unrouted"] == []
    assert set(out["requests"].values()) == set(REQUEST_OUTCOMES)
    assert set(out["grants"].values()) == set(GRANT_OUTCOMES)


def test_challenges_valid_and_self_answer_scores_100(policies, data):
    qs = build_challenges(policies, data("sample_app_consent.json"))
    assert len(qs) >= 12
    assert all(q.objective in ("3.2", "3.3", "3.4") for q in qs)
    assert all(len(set(q.choices)) == len(q.choices) and q.explanation for q in qs)
    assert all("lab" not in (q.prompt + " ".join(q.choices)).lower().split() for q in qs)
    assert sum(check(q, q.answer) for q in qs) == len(qs)


def test_generate_scenario_deterministic_and_runs(policies, quiet_ui):
    g1, g2 = generate_scenario(random.Random(7), policies), generate_scenario(random.Random(7), policies)
    assert g1 == g2 and g1 != generate_scenario(random.Random(8), policies)
    out = run_demo(quiet_ui, policies, g1)
    assert set(out["requests"].values()) == set(REQUEST_OUTCOMES)
    assert set(out["grants"].values()) == set(GRANT_OUTCOMES)
    assert len(build_challenges(policies, g1)) >= 12
