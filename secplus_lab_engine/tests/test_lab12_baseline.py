"""Lab 12 — secure baseline & hardening checker tests."""

from __future__ import annotations

from datetime import date

import pytest

from labs.lab12_baseline_checker import check_all, check_host, evaluate_check

AS_OF = date(2026, 11, 3)


@pytest.mark.parametrize("op,value,actual,status", [
    ("eq", True, True, "PASS"), ("eq", True, False, "FAIL"),
    ("ge", 14, 14, "PASS"), ("ge", 14, 13, "FAIL"),
    ("le", 0, 0, "PASS"), ("le", 0, 2, "FAIL"),
    ("between", [1, 5], 0, "FAIL"), ("between", [1, 5], 5, "PASS"),
    ("includes", ["a", "b"], ["a", "b", "c"], "PASS"), ("includes", ["a", "b"], ["a"], "FAIL"),
    ("excludes", ["x"], ["a"], "PASS"), ("excludes", ["x"], ["x", "a"], "FAIL"),
    ("ge", 14, "fourteen", "FAIL"),            # wrong type fails closed
    ("bogus", 1, 1, "FAIL"),                   # unknown operator fails closed
])
def test_operators(op, value, actual, status):
    assert evaluate_check({"setting": "s", "op": op, "value": value}, {"s": actual})[0] == status


def test_missing_setting_is_missing():
    assert evaluate_check({"setting": "s", "op": "eq", "value": 1}, {}) == ("MISSING", None)


def test_excludes_reports_offenders_only():
    _, actual = evaluate_check({"setting": "s", "op": "excludes", "value": ["telnet", "ftp"]}, {"s": ["sshd", "telnet"]})
    assert actual == ["telnet"]


@pytest.fixture
def cfg(policies):
    return policies["hardening_baselines"]


def _linux(settings, **kw):
    good = {"ssh_permit_root_login": "no", "ssh_password_auth": "no", "pass_min_len": 14,
            "services_running": ["sshd", "auditd", "rsyslog"], "firewall_enabled": True, "selinux_mode": "enforcing",
            "auto_updates": True, "world_writable_files": 0, "tmp_noexec": True}
    good.update(settings)
    return {"name": "h", "profile": "linux_server", "settings": good, **kw}


def test_fully_hardened_host(cfg):
    r = check_host(_linux({}), cfg, AS_OF)
    assert r.compliance == 100.0 and r.verdict == "COMPLIANT"


def test_one_high_failure_means_non_compliant_even_above_threshold(cfg):
    r = check_host(_linux({"ssh_permit_root_login": "yes"}), cfg, AS_OF)
    assert r.compliance >= 85 and r.verdict == "NON_COMPLIANT"


def test_low_failure_alone_can_stay_compliant(cfg):
    r = check_host(_linux({"tmp_noexec": False}), cfg, AS_OF)
    assert r.verdict == "COMPLIANT" and r.by_id("L-10").status == "FAIL"


def test_missing_counts_as_failure(cfg):
    host = _linux({})
    del host["settings"]["firewall_enabled"]
    r = check_host(host, cfg, AS_OF)
    assert r.by_id("L-06").status == "MISSING" and r.verdict == "NON_COMPLIANT"


def test_valid_and_expired_deviations(cfg):
    dev = [{"check": "L-01", "ticket": "T1", "reason": "r", "expires": "2027-01-01"}]
    ok = check_host(_linux({"ssh_permit_root_login": "yes"}, approved_deviations=dev), cfg, AS_OF)
    assert ok.by_id("L-01").status == "EXCEPTION" and ok.verdict == "COMPLIANT"
    old = [{**dev[0], "expires": "2026-01-01"}]
    bad = check_host(_linux({"ssh_permit_root_login": "yes"}, approved_deviations=old), cfg, AS_OF)
    assert bad.by_id("L-01").status == "FAIL" and "expired" in bad.by_id("L-01").note
    no_ticket = [{**dev[0], "ticket": ""}]
    assert check_host(_linux({"ssh_permit_root_login": "yes"}, approved_deviations=no_ticket),
                      cfg, AS_OF).by_id("L-01").status == "FAIL"


def test_drift(cfg):
    prev = _linux({})["settings"]
    r = check_host(_linux({"firewall_enabled": False}, previous_settings={**prev, "ssh_password_auth": "yes"}), cfg, AS_OF)
    assert r.regressed == ["L-06"] and r.remediated == ["L-02"]


def test_unknown_profile(cfg):
    with pytest.raises(ValueError):
        check_host({"name": "x", "profile": "mainframe", "settings": {}}, cfg, AS_OF)


def test_sample_outcomes(policies, data):
    rep = {r.name: r for r in check_all(data("sample_hosts.json"), policies)}
    assert {k: v.verdict for k, v in rep.items()} == {
        "DC01": "NON_COMPLIANT", "WEB01": "NON_COMPLIANT", "lnx-app-01": "COMPLIANT", "lnx-db-01": "NON_COMPLIANT"}
    assert rep["DC01"].regressed == ["W-07"] and rep["lnx-app-01"].remediated == ["L-02"]
    assert rep["lnx-db-01"].by_id("L-07").status == "MISSING"
    assert rep["lnx-db-01"].by_id("L-08").status == "FAIL"            # its deviation expired 2026-10-31
    assert rep["lnx-app-01"].by_id("L-10").status == "EXCEPTION"
