"""Lab 20 — IaC misconfiguration gate tests."""

from __future__ import annotations

import copy

import pytest

from labs.lab20_iac_scanner import build_challenges, gate, responsible_party, run_demo, scan_resource


@pytest.fixture
def cfg(policies):
    return policies["iac"]


TAGS = {"owner": "web-team", "data_classification": "internal"}


def R(rtype, **kw):
    return {"id": "r1", "type": rtype, "tags": dict(TAGS), **kw}


def checks(res):
    return [f.check for f in res.findings]


def test_clean_bucket_passes(cfg):
    r = scan_resource(R("storage_bucket", acl="private", encryption_at_rest=True, logging=True), cfg)
    assert r.status == "PASS" and r.findings == []


def test_public_bucket_is_critical(cfg):
    r = scan_resource(R("storage_bucket", acl="public-read", encryption_at_rest=True, logging=True), cfg)
    assert checks(r) == ["IAC-S1"] and r.worst == "critical" and r.findings[0].fix


def test_missing_property_fails_deny_by_default(cfg):
    r = scan_resource(R("storage_bucket", acl="private", logging=True), cfg)
    assert checks(r) == ["IAC-S2"] and "not declared" in r.findings[0].detail


def test_admin_port_only_flagged_from_internet(cfg):
    internal = scan_resource(R("security_group", ingress=[{"port": 22, "cidr": "10.0.0.0/8"},
                                                           {"port": 443, "cidr": "0.0.0.0/0"}]), cfg)
    assert internal.status == "PASS"
    public = scan_resource(R("security_group", ingress=[{"port": 5432, "cidr": "0.0.0.0/0"}]), cfg)
    assert checks(public) == ["IAC-N1"] and "PostgreSQL" in public.findings[0].detail


def test_iam_wildcard_needs_both_action_and_resource(cfg):
    scoped = scan_resource(R("iam_policy", statements=[{"effect": "Allow", "action": "*", "resource": "arn:x"}]), cfg)
    admin = scan_resource(R("iam_policy", statements=[{"effect": "Allow", "action": "*", "resource": "*"}]), cfg)
    assert scoped.status == "PASS" and checks(admin) == ["IAC-I1"]


def test_container_privileged_and_root_sorted_by_severity(cfg):
    r = scan_resource(R("container", privileged=True, run_as_root=True, secrets_in_env=False), cfg)
    assert checks(r) == ["IAC-C1", "IAC-C2"] and r.worst == "high"


def test_high_availability_only_for_critical(cfg):
    base = dict(publicly_accessible=False, encryption_at_rest=True, backup_retention_days=7, availability_zones=["a"])
    assert scan_resource(R("database", **base), cfg).status == "PASS"
    crit = R("database", **base)
    crit["tags"]["criticality"] = "critical"
    assert checks(scan_resource(crit, cfg)) == ["IAC-H1"]


def test_unknown_type_and_missing_tags(cfg):
    u = scan_resource({"id": "x", "type": "quantum_widget"}, cfg)
    assert u.worst == "critical" and "Unreviewed" in u.findings[0].title
    t = scan_resource({"id": "f", "type": "function", "secrets_in_env": False, "logging": True, "tags": {"owner": "a"}}, cfg)
    assert checks(t) == ["IAC-T1"] and "data_classification" in t.findings[0].detail


def test_gate_decisions_and_high_boundary(policies, cfg):
    ok = R("function", secrets_in_env=False, logging=True)
    medium = R("function", secrets_in_env=False, logging=False)
    high = R("function", secrets_in_env=True, logging=True)
    assert gate({"resources": [ok]}, policies).decision == "PASS"
    assert gate({"resources": [ok, medium]}, policies).decision == "WARN"
    limit = cfg["decision"]["max_high_before_block"]
    assert gate({"resources": [high] * limit}, policies).decision == "WARN"
    assert gate({"resources": [high] * (limit + 1)}, policies).decision == "BLOCK"
    empty = gate({"resources": []}, policies)
    assert empty.decision == "BLOCK" and "no resources" in empty.reasons[0]


def test_policy_drives_gate(policies):
    pol = copy.deepcopy(policies)
    pol["iac"]["decision"]["block_if_any"] = []
    pol["iac"]["unknown_type_severity"] = "low"
    assert gate({"resources": [{"id": "x", "type": "quantum_widget"}]}, pol).decision == "WARN"


def test_responsibility_matrix(cfg):
    assert responsible_party("IaaS", "guest_os_patching", cfg) == "customer"
    assert responsible_party("PaaS", "guest_os_patching", cfg) == "cloud provider"
    assert responsible_party("SaaS", "data", cfg) == "customer"


def test_sample_demo_and_challenges(policies, data, quiet_ui):
    sample = data("sample_iac.json")
    out = run_demo(quiet_ui, policies, sample)
    assert out == {"sg-web": "PASS", "sg-admin": "FAIL", "lb-shop": "PASS", "bucket-marketing": "FAIL",
                   "db-orders": "FAIL", "db-analytics": "FAIL", "iam-ci-deployer": "FAIL", "vm-bastion": "FAIL",
                   "ctr-payments": "FAIL", "fn-thumbnails": "PASS", "dns-shop": "FAIL", "deployment": "BLOCK"}
    qs = build_challenges(policies, sample)
    assert len(qs) >= 8 and all(q.answer in q.choices for q in qs)
