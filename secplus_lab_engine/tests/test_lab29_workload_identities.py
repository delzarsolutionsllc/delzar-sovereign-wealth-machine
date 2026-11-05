"""Lab 29 — workload identities (identity-type planner and service principal / managed identity audit) tests."""

from __future__ import annotations

import json
import random

import pytest

import labs.lab29_workload_identities as m
from utils.loader import load_json, load_policies
from utils.terminal_ui import UI


@pytest.fixture(scope="module")
def pol():
    return load_policies()


@pytest.fixture(scope="module")
def cfg(pol):
    return pol["workload_identities"]


@pytest.fixture(scope="module")
def sample():
    return load_json(m.__file__.replace("labs/lab29_workload_identities.py", "data/sample_workload_identities.json"))


def plan(cfg, **w):
    return m.plan_identity({"id": "W", "name": "w", **w}, cfg)


def sp(**kw):
    base = {"id": "P", "name": "p", "type": "service_principal", "hosting": "on_premises", "oidc_capable": False,
            "owners": ["owner"], "credentials": [{"type": "certificate", "expires_in_days": 300}],
            "role_assignments": [{"role": "Reader", "scope": "resource_group"}], "last_sign_in_days_ago": 1}
    base.update(kw)
    return base


# ----------------------------------------------------------------- planner
def test_single_azure_resource_gets_system_assigned(cfg):
    r = plan(cfg, hosting="app_service", resources=1)
    assert (r.outcome, r.rule) == ("SYSTEM_ASSIGNED_MI", "azure_single_resource")


def test_shared_resources_get_user_assigned(cfg):
    n = cfg["user_assigned_min_resources"]
    assert plan(cfg, hosting="function_app", resources=n).outcome == "USER_ASSIGNED_MI"
    assert plan(cfg, hosting="function_app", resources=n - 1).outcome == "SYSTEM_ASSIGNED_MI"


def test_pre_provisioned_single_resource_gets_user_assigned(cfg):
    r = plan(cfg, hosting="vm_scale_set", resources=1, pre_provisioned=True)
    assert r.outcome == "USER_ASSIGNED_MI" and r.rule == "azure_shared_or_preprovisioned"


def test_external_oidc_gets_federated_credential(cfg):
    for h in ("github_actions", "kubernetes"):
        assert plan(cfg, hosting=h, oidc_federation=True).outcome == "SERVICE_PRINCIPAL_WITH_FEDERATED_CREDENTIAL"


def test_external_without_federation_gets_certificate(cfg):
    assert plan(cfg, hosting="on_premises", oidc_federation=False).outcome == "SERVICE_PRINCIPAL_WITH_CERTIFICATE"
    # missing flag is not assumed true (deny by default)
    assert plan(cfg, hosting="github_actions").outcome == "SERVICE_PRINCIPAL_WITH_CERTIFICATE"


def test_unknown_or_missing_hosting_is_certificate(cfg):
    for w in ({}, {"hosting": "mainframe"}, {"hosting": None, "oidc_federation": True}):
        r = plan(cfg, **w)
        assert r.outcome == "SERVICE_PRINCIPAL_WITH_CERTIFICATE"
        assert any("deny by default" in x for x in r.reasons)


def test_azure_without_managed_identity_support_falls_through(cfg):
    r = plan(cfg, hosting="app_service", resources=1, managed_identity_supported=False)
    assert r.outcome == "SERVICE_PRINCIPAL_WITH_CERTIFICATE"


def test_missing_resource_count_assumes_one(cfg):
    r = plan(cfg, hosting="logic_app")
    assert r.outcome == "SYSTEM_ASSIGNED_MI" and any("assumed a single" in x for x in r.reasons)


def test_never_recommends_client_secret(cfg):
    assert all("SECRET" not in o for o in m.IDENTITY_TYPES)


# ----------------------------------------------------------------- audit
def test_clean_service_principal_is_ok(cfg):
    r = m.audit_principal(sp(), cfg)
    assert r.action == "OK" and r.findings == [] and r.reasons


def test_secret_on_oidc_platform_replaced_with_federation(cfg):
    r = m.audit_principal(sp(hosting="github_actions", oidc_capable=True,
                             credentials=[{"type": "secret", "lifetime_days": 90, "expires_in_days": 60}]), cfg)
    assert r.action == "REPLACE_SECRET_WITH_FEDERATION"


@pytest.mark.parametrize("cred,finding", [
    ({"type": "secret", "lifetime_days": 90, "expires_in_days": -1}, "SECRET_EXPIRED"),
    ({"type": "secret", "lifetime_days": 90, "expires_in_days": 30}, "SECRET_EXPIRING"),
    ({"type": "secret", "lifetime_days": 181, "expires_in_days": 100}, "SECRET_LONG_LIFETIME"),
    ({"type": "secret", "lifetime_days": 90, "expires_in_days": 80}, "SECRET_PRESENT"),
    ({"type": "secret", "lifetime_days": 90}, "CREDENTIAL_EXPIRY_UNKNOWN"),
    ({"type": "certificate", "expires_in_days": -3}, "CERT_EXPIRED"),
    ({"type": "certificate", "expires_in_days": 10}, "CERT_EXPIRING"),
])
def test_credential_findings_rotate(cfg, cred, finding):
    r = m.audit_principal(sp(credentials=[cred]), cfg)
    assert finding in r.findings and r.action == "ROTATE"


def test_secret_boundaries(cfg):
    soon, life = cfg["expiring_soon_days"], cfg["max_secret_lifetime_days"]
    r = m.audit_principal(sp(credentials=[{"type": "secret", "lifetime_days": life, "expires_in_days": soon + 1}]), cfg)
    assert r.findings == ["SECRET_PRESENT"]


def test_no_owner_assign_owner(cfg):
    assert m.audit_principal(sp(owners=[]), cfg).action == "ASSIGN_OWNER"
    # managed identities are not checked for owners or credentials
    mi = {"id": "M", "type": "managed_identity", "last_sign_in_days_ago": 0,
          "credentials": [{"type": "secret", "expires_in_days": -10}],
          "role_assignments": [{"role": "Reader", "scope": "resource"}]}
    assert m.audit_principal(mi, cfg).action == "OK"


def test_privileged_role_at_broad_scope(cfg):
    for role in ("Owner", "Contributor", "User Access Administrator"):
        r = m.audit_principal(sp(role_assignments=[{"role": role, "scope": "subscription"}]), cfg)
        assert r.action == "REDUCE_SCOPE"
    narrow = m.audit_principal(sp(role_assignments=[{"role": "Contributor", "scope": "resource_group"}]), cfg)
    reader = m.audit_principal(sp(role_assignments=[{"role": "Reader", "scope": "subscription"}]), cfg)
    assert narrow.action == reader.action == "OK"


def test_unknown_role_and_scope_treated_as_privileged_and_broad(cfg):
    assert m.audit_principal(sp(role_assignments=[{"role": "Mystery Admin", "scope": "subscription"}]),
                             cfg).action == "REDUCE_SCOPE"
    assert m.audit_principal(sp(role_assignments=[{"role": "Owner"}]), cfg).action == "REDUCE_SCOPE"
    assert m.audit_principal(sp(role_assignments=[{"scope": "management_group"}]), cfg).action == "REDUCE_SCOPE"


def test_unused_and_missing_sign_in(cfg):
    limit = cfg["unused_after_days"]
    assert m.audit_principal(sp(last_sign_in_days_ago=limit), cfg).action == "OK"
    assert m.audit_principal(sp(last_sign_in_days_ago=limit + 1), cfg).action == "DISABLE_UNUSED"
    assert m.audit_principal(sp(last_sign_in_days_ago=None), cfg).action == "DISABLE_UNUSED"


def test_priority_unused_beats_scope_beats_secret(cfg):
    r = m.audit_principal(sp(last_sign_in_days_ago=500, owners=[],
                             role_assignments=[{"role": "Owner", "scope": "subscription"}],
                             credentials=[{"type": "secret", "lifetime_days": 999, "expires_in_days": -1}]), cfg)
    assert r.actions == ["DISABLE_UNUSED", "REDUCE_SCOPE", "ROTATE", "ASSIGN_OWNER"]


def test_unknown_type_audited_as_service_principal(cfg):
    r = m.audit_principal({"id": "Z", "type": "robot", "last_sign_in_days_ago": 1,
                           "role_assignments": [{"role": "Reader", "scope": "resource"}]}, cfg)
    assert r.type == "service_principal" and r.action == "ASSIGN_OWNER"


def test_empty_input_is_safe(pol):
    s = m.run_demo(UI(plain=True, quiet=True), pol, {})
    assert s["plans"] == {} and s["audit"] == {}


# ----------------------------------------------------------------- sample, demo, challenges, generator
def test_sample_expected_outcomes(pol, sample):
    s = m.run_demo(UI(plain=True, quiet=True), pol, sample)
    json.dumps(s)
    assert s["plans"] == {"W1": "SYSTEM_ASSIGNED_MI", "W2": "USER_ASSIGNED_MI", "W3": "USER_ASSIGNED_MI",
                          "W4": "SERVICE_PRINCIPAL_WITH_FEDERATED_CREDENTIAL",
                          "W5": "SERVICE_PRINCIPAL_WITH_CERTIFICATE", "W6": "SERVICE_PRINCIPAL_WITH_CERTIFICATE",
                          "W7": "SERVICE_PRINCIPAL_WITH_CERTIFICATE"}
    assert s["audit"] == {"P1": "REPLACE_SECRET_WITH_FEDERATION", "P2": "ROTATE", "P3": "ROTATE",
                          "P4": "ASSIGN_OWNER", "P5": "REDUCE_SCOPE", "P6": "DISABLE_UNUSED", "P7": "OK",
                          "P8": "REDUCE_SCOPE", "P9": "OK"}
    assert s["metrics"]["flagged"] == 7 and s["metrics"]["secrets_found"] == 4


def test_sample_covers_every_outcome(pol, sample):
    s = m.run_demo(UI(plain=True, quiet=True), pol, sample)
    assert set(s["plans"].values()) == set(m.IDENTITY_TYPES)
    assert set(s["audit"].values()) == set(m.ACTIONS)


def test_challenges_valid_and_full_score(pol, sample):
    qs = m.build_challenges(pol, sample)
    assert len(qs) >= 12
    for q in qs:
        assert q.objective in ("3.1", "4.3")
        assert len(set(q.choices)) == len(q.choices)
        assert "lab" not in (q.prompt + " ".join(q.choices)).lower().split()
        assert q.explanation
    assert sum(q.check(q.answer) for q in qs) == len(qs)


def test_generator_deterministic_and_runs(pol):
    a, b = m.generate_scenario(random.Random(7), pol), m.generate_scenario(random.Random(7), pol)
    assert a == b and a != m.generate_scenario(random.Random(8), pol)
    for seed in range(20):
        g = m.generate_scenario(random.Random(seed), pol)
        s = m.run_demo(UI(plain=True, quiet=True), pol, g)
        assert set(s["plans"].values()) == set(m.IDENTITY_TYPES)
        assert set(s["audit"].values()) == set(m.ACTIONS)
        qs = m.build_challenges(pol, g)
        assert len(qs) >= 12 and all(q.check(q.answer) for q in qs)


def test_metadata():
    assert m.COURSES == ("sc300",)
    assert m.TITLE.startswith("Lab 29 — ")
    assert m.OBJECTIVES.startswith("SC-300 3.1")
    for k in ("objective", "concepts", "failure_modes", "ai_governance", "exam_tips"):
        assert m.INSIGHT[k]
