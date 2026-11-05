"""Lab 21 — asset inventory & secure disposal tests."""

from __future__ import annotations

import copy

import pytest

from labs.lab21_asset_management import evaluate_disposal, methods_for, reconcile, run_demo


@pytest.fixture
def cfg(policies):
    return policies["asset_mgmt"]


def A(**kw):
    base = {"asset_id": "A-1", "hostname": "h1", "mac": "00:00:00:00:00:01", "owner": "it-ops",
            "classification": "internal", "status": "active", "last_seen": 100}
    base.update(kw)
    return base


def D(**kw):
    base = {"id": "D-X", "media": "ssd", "classification": "confidential", "method": "crypto_erase",
            "destination": "leaving_org", "performed_by": "internal", "certificate_of_destruction": False,
            "legal_hold": False, "retention_until": 0}
    base.update(kw)
    return base


def inv(cfg, cmdb, scan=(), today=100):
    return {r.key: r for r in reconcile({"today": today, "cmdb": cmdb, "scan": list(scan)}, cfg)}


def test_seen_asset_ok_and_mac_matching_is_case_insensitive(cfg):
    r = inv(cfg, [A(last_seen=1)], [{"mac": "00:00:00:00:00:01".upper(), "hostname": "h1", "ip": "10.0.0.1"}])
    assert r["A-1"].findings == ["OK"] and len(r) == 1


def test_unmanaged_scan_host(cfg):
    r = inv(cfg, [A()], [{"mac": "aa:bb:cc:dd:ee:ff", "hostname": "pi", "ip": "10.0.0.9"}])
    assert r["scan:10.0.0.9"].primary == "UNMANAGED" and "NAC" in r["scan:10.0.0.9"].action


def test_missing_boundary_is_strictly_greater(cfg):
    n = cfg["missing_after_days"]
    assert inv(cfg, [A(last_seen=100 - n)])["A-1"].primary == "OK"
    assert inv(cfg, [A(last_seen=99 - n)])["A-1"].primary == "MISSING"
    assert inv(cfg, [A(last_seen=None)])["A-1"].primary == "MISSING"        # deny by default
    assert inv(cfg, [A(status="retired", last_seen=1)])["A-1"].primary == "OK"


def test_no_owner_and_unclassified(cfg):
    r = inv(cfg, [A(owner="", classification="secret-ish")], [{"mac": "00:00:00:00:00:01", "ip": "10.0.0.1"}])
    assert r["A-1"].findings == ["NO_OWNER", "UNCLASSIFIED"] and r["A-1"].primary == "NO_OWNER"


def test_purge_ssd_leaving_org_approved(cfg):
    d = evaluate_disposal(D(), cfg, 300)
    assert d.decision == "APPROVE" and d.required_level == "purge" and d.method_level == "purge"


def test_degauss_and_overwrite_do_not_work_on_ssd(cfg):
    for m in ("degauss", "overwrite"):
        d = evaluate_disposal(D(method=m), cfg, 300)
        assert d.decision == "REJECT" and "method_media" in d.rules


def test_level_too_low_for_restricted_leaving_org(cfg):
    d = evaluate_disposal(D(media="hdd", classification="restricted", method="crypto_erase"), cfg, 300)
    assert d.rules == ["level_too_low"] and d.required_level == "destroy"
    ok = evaluate_disposal(D(media="hdd", classification="restricted", method="crypto_erase",
                             destination="reuse_within_org"), cfg, 300)
    assert ok.decision == "APPROVE"


def test_third_party_destruction_needs_certificate(cfg):
    d = evaluate_disposal(D(method="shred", performed_by="third_party"), cfg, 300)
    assert d.rules == ["certificate"]
    assert evaluate_disposal(D(method="shred", performed_by="third_party", certificate_of_destruction=True),
                             cfg, 300).decision == "APPROVE"


def test_legal_hold_and_retention_block_disposal(cfg):
    assert evaluate_disposal(D(legal_hold=True), cfg, 300).rules == ["legal_hold"]
    assert evaluate_disposal(D(retention_until=301), cfg, 300).rules == ["retention"]
    assert evaluate_disposal(D(retention_until=300), cfg, 300).decision == "APPROVE"


def test_unknown_or_missing_inputs_rejected(cfg):
    assert evaluate_disposal(D(media="floppy"), cfg, 300).rules == ["unknown_input"]
    assert evaluate_disposal(D(method="quick_format"), cfg, 300).rules == ["unknown_input"]
    bare = evaluate_disposal({"id": "D-0", "media": "ssd", "method": "crypto_erase"}, cfg, 300)
    assert bare.decision == "REJECT" and {"unknown_input", "legal_hold", "retention"} <= set(bare.rules)


def test_policy_driven_min_level(cfg):
    stricter = copy.deepcopy(cfg)
    stricter["min_level"]["confidential"]["leaving_org"] = "destroy"
    assert evaluate_disposal(D(), stricter, 300).rules == ["level_too_low"]
    assert methods_for("ssd", "purge", cfg) == ["crypto_erase", "secure_erase"]


def test_sample_summary(policies, quiet_ui, data):
    s = run_demo(quiet_ui, policies, data("sample_assets.json"))
    assert s == {"A-001": "OK", "A-002": "OK", "A-003": "MISSING", "A-004": "OK", "A-005": "NO_OWNER",
                 "A-006": "UNCLASSIFIED", "A-007": "OK", "A-008": "NO_OWNER", "scan:10.20.5.77": "UNMANAGED",
                 "scan:10.20.7.101": "UNMANAGED", "scan:10.20.7.140": "UNMANAGED",
                 "D-1": "APPROVE", "D-2": "APPROVE", "D-3": "APPROVE", "D-4": "REJECT", "D-5": "REJECT",
                 "D-6": "REJECT", "D-7": "REJECT", "D-8": "REJECT", "D-9": "REJECT"}
