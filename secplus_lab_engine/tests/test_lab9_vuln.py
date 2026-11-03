"""Lab 9 — vulnerability triage engine tests."""

from __future__ import annotations

import copy
from datetime import date

import pytest

from labs.lab9_vulnerability_triage import (
    combined_reduction, cvss_rating, priority_for, review_exception, triage, triage_all,
)

AS_OF = date(2026, 11, 3)


@pytest.fixture
def cfg(policies):
    return policies["vulnerability_management"]


@pytest.fixture
def cmdb(policies):
    return policies["change_management"]["systems"]


def _f(**kw):
    base = {"id": "X", "asset": "file-server", "cvss": 5.0, "kev": False, "patch_available": True,
            "discovered": "2026-11-01", "vuln_type": "t", "description": "d"}
    base.update(kw)
    return base


@pytest.mark.parametrize("score,band", [(10.0, "Critical"), (9.0, "Critical"), (8.9, "High"), (7.0, "High"),
                                        (6.9, "Medium"), (4.0, "Medium"), (3.9, "Low"), (0.0, "None")])
def test_cvss_bands(cfg, score, band):
    assert cvss_rating(score, cfg["cvss_bands"]) == band


def test_cvss_out_of_range(cfg):
    with pytest.raises(ValueError):
        cvss_rating(11, cfg["cvss_bands"])


def test_priority_thresholds(cfg):
    t = cfg["priority_thresholds"]
    assert [priority_for(s, t) for s in (12, 11.99, 8, 4, 3.99)] == ["P1", "P2", "P2", "P3", "P4"]


def test_score_uses_cmdb_criticality_exposure_and_kev(cmdb, cfg):
    r = triage(_f(asset="web-frontend", cvss=8.0, kev=True), cmdb, cfg, AS_OF)
    assert r.score == pytest.approx(8.0 * 1.2 * 1.5 * 1.3) and r.priority == "P1"
    plain = triage(_f(asset="file-server", cvss=8.0), cmdb, cfg, AS_OF)
    assert plain.score == 8.0 and plain.priority == "P2"


def test_same_cvss_different_context_different_priority(cmdb, cfg):
    hi = triage(_f(asset="edge-fw", cvss=7.0, kev=True), cmdb, cfg, AS_OF)
    lo = triage(_f(asset="file-server", cvss=7.0), cmdb, cfg, AS_OF)
    assert hi.priority == "P1" and lo.priority == "P3"


def test_unknown_asset_is_worst_case(cmdb, cfg):
    r = triage(_f(asset="mystery-box", cvss=7.0), cmdb, cfg, AS_OF)
    assert not r.in_cmdb and r.criticality == 5 and r.exposure == "internet" and r.priority == "P1"
    assert any("CMDB" in a for a in r.actions)


def test_kev_caps_sla(cmdb, cfg):
    r = triage(_f(asset="file-server", cvss=5.0, kev=True), cmdb, cfg, AS_OF)   # 7.5 → P3 (90d) capped to 14
    assert r.priority == "P3" and r.sla_days == cfg["kev_max_sla_days"]


def test_overdue(cmdb, cfg):
    r = triage(_f(asset="web-frontend", cvss=9.8, kev=True, discovered="2026-10-01"), cmdb, cfg, AS_OF)
    assert r.overdue and r.status == "OVERDUE" and any("escalate" in a for a in r.actions)


def test_no_patch_recommends_compensating_controls(cmdb, cfg):
    r = triage(_f(patch_available=False), cmdb, cfg, AS_OF)
    assert any("compensating controls" in a for a in r.actions)


def test_combined_reduction():
    red, unknown = combined_reduction(["a", "b", "zzz"], {"a": 0.5, "b": 0.5})
    assert red == pytest.approx(0.75) and unknown == ["zzz"]


class TestExceptions:
    EXC = {"compensating_controls": ["network_isolation"], "approved_by": "sec_architect",
           "approved_on": "2026-10-01", "expires": "2027-01-01"}

    def test_accepted(self, cfg):
        assert review_exception(self.EXC, 9.0, AS_OF, cfg).status == "EXCEPTION_ACCEPTED"

    def test_expired(self, cfg):
        assert review_exception({**self.EXC, "expires": "2026-11-02"}, 9.0, AS_OF, cfg).status == "EXCEPTION_EXPIRED"

    def test_unauthorized_approver(self, cfg):
        r = review_exception({**self.EXC, "approved_by": "intern"}, 9.0, AS_OF, cfg)
        assert r.status == "EXCEPTION_REJECTED" and "not authorised" in r.reasons[0]

    def test_too_long(self, cfg):
        r = review_exception({**self.EXC, "expires": "2027-12-31"}, 9.0, AS_OF, cfg)
        assert r.status == "EXCEPTION_REJECTED" and any("maximum" in x for x in r.reasons)

    def test_residual_too_high(self, cfg):
        r = review_exception({**self.EXC, "compensating_controls": ["enhanced_monitoring"]}, 25.0, AS_OF, cfg)
        assert r.status == "EXCEPTION_REJECTED" and any("residual" in x for x in r.reasons)

    def test_unknown_control_gets_no_credit(self, cfg):
        r = review_exception({**self.EXC, "compensating_controls": ["prayer"]}, 9.0, AS_OF, cfg)
        assert r.status == "EXCEPTION_REJECTED" and r.residual_score == 9.0


def test_sample_outcomes(policies, data):
    res = {r.id: r for r in triage_all(data("sample_vulns.json"), policies)}
    assert [r.id for r in triage_all(data("sample_vulns.json"), policies)][0] == "V-04"
    assert {k: v.priority for k, v in res.items()} == {
        "V-01": "P1", "V-02": "P2", "V-03": "P2", "V-04": "P1", "V-05": "P3",
        "V-06": "P2", "V-07": "P3", "V-08": "P1", "V-09": "P1"}
    assert res["V-03"].status == "EXCEPTION_ACCEPTED"
    assert res["V-04"].status == "EXCEPTION_REJECTED"
    assert res["V-07"].status == "EXCEPTION_EXPIRED"
    assert res["V-01"].status == "OVERDUE"
    assert not res["V-08"].in_cmdb


def test_custom_policy_changes_outcome(policies, data):
    p = copy.deepcopy(policies)
    p["vulnerability_management"]["exceptions"]["authorized_approvers"].append("ops_lead")
    p["vulnerability_management"]["exceptions"]["max_residual_score"] = 30
    res = {r.id: r for r in triage_all(data("sample_vulns.json"), p)}
    assert res["V-04"].status == "EXCEPTION_ACCEPTED"
