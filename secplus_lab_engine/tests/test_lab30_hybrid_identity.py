"""Lab 30 — hybrid identity planner (sync tool, sign-in method, sync health) tests."""

from __future__ import annotations

import copy
import json
import random

import pytest

from labs.lab30_hybrid_identity import (AUTH_METHODS, CLOUD_SYNC, CONNECT_SYNC, FED, PHS, PTA, build_challenges,
                                        check_health, generate_scenario, plan_org, run_demo)


@pytest.fixture
def cfg(policies):
    return policies["hybrid_identity"]


BASE = {"id": "X", "name": "Test Org", "forests": 1, "disconnected_forests": False, "features": [],
        "passwords_must_not_leave_onprem": False, "onprem_signin_policies": False, "adfs_third_party_mfa": False,
        "needs_leaked_credential_detection": False, "resilience_required": False}


def org(**kw):
    p = dict(BASE)
    p.update(kw)
    return p


def test_default_is_phs_and_cloud_sync(cfg):
    p = plan_org(org(), cfg)
    assert (p.auth_method, p.auth_rule, p.sync_tool, p.sync_rule) == (PHS, "DEFAULT_PHS", CLOUD_SYNC,
                                                                      "DEFAULT_CLOUD_SYNC")
    assert p.backup == "NOT_NEEDED" and not p.needs_review


def test_passwords_stay_onprem_gives_pta_no_backup_and_leaked_gap(cfg):
    p = plan_org(org(passwords_must_not_leave_onprem=True, needs_leaked_credential_detection=True,
                     resilience_required=True), cfg)
    assert (p.auth_method, p.auth_rule, p.backup) == (PTA, "PASSWORDS_STAY_ONPREM", "NONE")
    assert p.leaked_credential_gap and p.sync_tool == CONNECT_SYNC
    assert any("resilience" in r for r in p.reasons)


def test_onprem_signin_policies_give_pta_with_phs_backup(cfg):
    p = plan_org(org(onprem_signin_policies=True, needs_leaked_credential_detection=True), cfg)
    assert (p.auth_method, p.auth_rule, p.backup) == (PTA, "ONPREM_SIGNIN_POLICIES", PHS)
    assert not p.leaked_credential_gap


def test_adfs_third_party_mfa_wins_over_passwords_rule(cfg):
    p = plan_org(org(adfs_third_party_mfa=True, passwords_must_not_leave_onprem=True), cfg)
    assert (p.auth_method, p.auth_rule, p.backup, p.sync_tool) == (FED, "ADFS_THIRD_PARTY_MFA", "NONE", CONNECT_SYNC)
    assert plan_org(org(adfs_third_party_mfa=True), cfg).backup == PHS


def test_existing_adfs_alone_does_not_force_federation(cfg):
    p = plan_org(org(existing_adfs=True), cfg)
    assert p.auth_method == PHS and any("staged rollout" in r for r in p.reasons)


def test_disconnected_forests_choose_cloud_sync(cfg):
    p = plan_org(org(forests=3, disconnected_forests=True), cfg)
    assert (p.sync_tool, p.sync_rule, p.coexistence) == (CLOUD_SYNC, "DISCONNECTED_FORESTS", False)
    single = plan_org(org(forests=1, disconnected_forests=True), cfg)
    assert single.sync_rule == "DEFAULT_CLOUD_SYNC"


def test_connect_only_feature_and_coexistence(cfg):
    p = plan_org(org(features=["device_sync_hybrid_join"]), cfg)
    assert (p.sync_tool, p.sync_rule) == (CONNECT_SYNC, "CONNECT_ONLY_REQUIREMENT")
    both = plan_org(org(forests=2, disconnected_forests=True, features=["device_writeback"]), cfg)
    assert both.sync_tool == CONNECT_SYNC and both.coexistence


def test_cloud_sync_supported_features_stay_on_cloud_sync(cfg):
    p = plan_org(org(features=["exchange_hybrid_writeback", "password_writeback"]), cfg)
    assert p.sync_tool == CLOUD_SYNC


def test_unknown_feature_is_treated_as_connect_only(cfg):
    p = plan_org(org(features=["mystery_flow"]), cfg)
    assert p.sync_tool == CONNECT_SYNC and any("assumed Connect-only" in r for r in p.reasons)


def test_missing_requirements_default_safely_and_are_listed(cfg):
    p = plan_org({}, cfg)
    assert p.auth_method == PHS and p.sync_tool == CLOUD_SYNC
    assert set(p.needs_review) >= {"passwords_must_not_leave_onprem", "adfs_third_party_mfa", "disconnected_forests"}
    assert any("not stated" in r for r in p.reasons)
    assert plan_org("not a dict", cfg).auth_method == PHS
    # a value that is not an explicit True never switches the method
    assert plan_org(org(passwords_must_not_leave_onprem="yes"), cfg).needs_review == ["passwords_must_not_leave_onprem"]


def health(**kw):
    h = {"scope_ous": ["OU=Staff,DC=x,DC=example"], "verified_domains": ["x.example"], "cloud_objects": [],
         "objects": [], "agent_sets": [], "staged_rollout_groups": [], "sync_servers": []}
    h.update(kw)
    return {"health": h}


def obj(oid, upn, ou="OU=Staff", proxies=()):
    return {"id": oid, "dn": f"CN={oid},{ou},DC=x,DC=example", "upn": upn, "proxy_addresses": list(proxies)}


def test_object_scope_duplicates_and_suffix(cfg):
    res = check_health(health(cloud_objects=[{"id": "C1", "upn": "c@x.example"}], objects=[
        obj("O1", "a@x.example", proxies=["SMTP:a@x.example"]),
        obj("O2", "b@x.example", ou="OU=Leavers", proxies=["SMTP:A@X.EXAMPLE"]),
        obj("O3", "c@x.example"),
        obj("O4", "d@x.example", proxies=["smtp:A@x.example"]),
        obj("O5", "e@x.local"),
        {"id": "O6", "upn": "f@x.example"}]), cfg)
    assert [r.finding for r in res] == ["OK", "OBJECT_FILTERED", "DUPLICATE_ATTRIBUTE", "DUPLICATE_ATTRIBUTE",
                                        "UPN_SUFFIX_NOT_VERIFIED", "OBJECT_FILTERED"]


def test_agent_minimums_count_only_active(cfg):
    n = cfg["min_pta_agents"]
    res = check_health(health(agent_sets=[
        {"id": "A1", "type": "pta", "agents": [{"status": "active"}] * (n - 1) + [{"status": "inactive"}]},
        {"id": "A2", "type": "pta", "agents": [{"status": "active"}] * n},
        {"id": "A3", "type": "provisioning", "agents": [{"status": "active"}, {}]},
        {"id": "A4", "type": "weird", "agents": []}]), cfg)
    assert [r.finding for r in res] == ["PTA_AGENT_SINGLE", "OK", "AGENT_REDUNDANCY_LOW", "PTA_AGENT_SINGLE"]


def test_staged_rollout_limits(cfg):
    mx = cfg["staged_rollout"]["max_initial_group_members"]
    g = {"feature": "password_hash_sync", "group_type": "assigned", "nested": False}
    res = check_health(health(staged_rollout_groups=[
        dict(g, id="G1", initial_members=mx), dict(g, id="G2", initial_members=mx + 1),
        dict(g, id="G3", group_type="dynamic", initial_members=5), dict(g, id="G4", nested=True, initial_members=5),
        dict(g, id="G5", feature="seamless_magic", initial_members=5), dict(g, id="G6", initial_members=None)]), cfg)
    assert [r.finding for r in res] == ["OK", "STAGED_ROLLOUT_GROUP_TOO_LARGE", "STAGED_ROLLOUT_GROUP_UNSUPPORTED",
                                        "STAGED_ROLLOUT_GROUP_UNSUPPORTED", "STAGED_ROLLOUT_GROUP_UNSUPPORTED",
                                        "STAGED_ROLLOUT_GROUP_TOO_LARGE"]


def test_staged_rollout_groups_per_feature_limit(cfg):
    sr = copy.deepcopy(cfg)
    sr["staged_rollout"]["max_groups_per_feature"] = 1
    g = {"feature": "password_hash_sync", "group_type": "assigned", "nested": False, "initial_members": 5}
    res = check_health(health(staged_rollout_groups=[dict(g, id="G1"), dict(g, id="G2")]), sr)
    assert [r.finding for r in res] == ["OK", "STAGED_ROLLOUT_GROUP_UNSUPPORTED"]


def test_sync_server_stale_and_unknown(cfg):
    lim = cfg["sync_stale_after_minutes"]
    res = check_health(health(sync_servers=[{"id": "S1", "minutes_since_last_sync": lim},
                                            {"id": "S2", "minutes_since_last_sync": lim + 1}, {"id": "S3"}]), cfg)
    assert [r.finding for r in res] == ["OK", "SYNC_STALE", "SYNC_STALE"]


def test_empty_data_is_safe(policies, quiet_ui, cfg):
    assert check_health({}, cfg) == []
    out = run_demo(quiet_ui, policies, {})
    assert out["metrics"]["organisations"] == 0


def test_sample_expected_outcomes(policies, quiet_ui, data):
    out = run_demo(quiet_ui, policies, data("sample_hybrid_identity.json"))
    auth = {k: v["auth"] for k, v in out["plans"].items()}
    sync = {k: v["sync"] for k, v in out["plans"].items()}
    assert auth == {"P01": PHS, "P02": PHS, "P03": PTA, "P04": PTA, "P05": FED, "P06": PHS, "P07": PHS, "P08": PHS,
                    "P09": PHS, "P10": PHS, "P11": FED}
    assert [k for k, v in sync.items() if v == CLOUD_SYNC] == ["P01", "P02", "P08", "P09"]
    assert out["health"] == {"O01": "OK", "O02": "OBJECT_FILTERED", "O03": "DUPLICATE_ATTRIBUTE",
                             "O04": "DUPLICATE_ATTRIBUTE", "O05": "UPN_SUFFIX_NOT_VERIFIED", "O06": "OBJECT_FILTERED",
                             "O07": "OBJECT_FILTERED", "A01": "PTA_AGENT_SINGLE", "A02": "OK",
                             "A03": "AGENT_REDUNDANCY_LOW", "G01": "OK", "G02": "STAGED_ROLLOUT_GROUP_TOO_LARGE",
                             "G03": "STAGED_ROLLOUT_GROUP_UNSUPPORTED", "S01": "OK", "S02": "SYNC_STALE"}
    m = out["metrics"]
    assert (m["phs_backup"], m["no_backup"], m["coexistence"], m["leaked_credential_gaps"], m["health_issues"]) == \
        (2, 2, 1, 1, 11)
    json.dumps(out)


def test_challenges_valid_and_full_marks(policies, data):
    qs = build_challenges(policies, data("sample_hybrid_identity.json"))
    assert len(qs) >= 12
    assert all(q.objective in ("1.4", "2.1") for q in qs)
    assert all(len(set(q.choices)) == len(q.choices) for q in qs)
    assert all("lab" not in (q.prompt + " ".join(q.choices)).lower().split() for q in qs)
    assert sum(q.check(q.answer) for q in qs) / len(qs) == 1.0
    assert {q.answer for q in qs} >= set(AUTH_METHODS)


def test_generate_scenario_deterministic_and_runs(policies, quiet_ui):
    a, b = generate_scenario(random.Random(11), policies), generate_scenario(random.Random(11), policies)
    assert a == b and a != generate_scenario(random.Random(12), policies)
    out = run_demo(quiet_ui, policies, a)
    assert {v["auth"] for v in out["plans"].values()} == set(AUTH_METHODS)
    assert {v["sync"] for v in out["plans"].values()} == {CLOUD_SYNC, CONNECT_SYNC}
    assert len(set(out["health"].values())) >= 8
    qs = build_challenges(policies, a)
    assert len(qs) >= 12 and all(q.check(q.answer) for q in qs)
