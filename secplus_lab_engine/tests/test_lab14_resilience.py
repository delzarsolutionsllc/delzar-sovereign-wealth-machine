"""Lab 14 — resilience & recovery planner tests."""

from __future__ import annotations

import copy
import math
from datetime import date

import pytest

from labs.lab14_resilience_planner import cheapest, plan, plan_all, raid_for

AS_OF = date(2026, 11, 3)


@pytest.fixture
def cfg(policies):
    return policies["resilience"]


def system(targets=None, **current):
    t = {"rto_hours": 24, "rpo_hours": 24, "disk_failures": 1, "power_outage_hours": 2, "survive_site_loss": False}
    t.update(targets or {})
    c = {"site": None, "replication": None, "clustering": None, "raid": "RAID1",
         "backup": {"type": "full", "frequency_hours": 24, "offsite": True}, "data_tb": 1,
         "ups_minutes": 15, "generator_hours": 4, "last_restore_test": "2026-10-01", "last_dr_test": "2026-10-01"}
    c.update(current)
    return {"name": "s", "targets": t, "current": c}


def test_baseline_meets(cfg):
    assert plan(system(), cfg, AS_OF).verdict == "MEETS_TARGETS"


@pytest.mark.parametrize("btype,restore", [("full", 1.5), ("differential", 2.25), ("incremental", 3.75)])
def test_restore_time_by_backup_type(cfg, btype, restore):
    p = plan(system(backup={"type": btype, "frequency_hours": 24, "offsite": True}), cfg, AS_OF)
    assert p.restore_hours == restore and p.host_rto == cfg["host_rebuild_hours"] + restore


def test_clustering_sets_host_rto(cfg):
    p = plan(system({"rto_hours": 1}, clustering="active-passive"), cfg, AS_OF)
    assert p.host_rto == 0.25 and not p.has("RTO")


def test_rpo_gap_recommends_frequency_or_replication(cfg):
    p = plan(system({"rpo_hours": 4}), cfg, AS_OF)
    assert p.has("RPO") and any("every 4h" in r for r in p.recommendations)
    p = plan(system({"rpo_hours": 0.25}), cfg, AS_OF)
    assert any("asynchronous replication" in r for r in p.recommendations)
    p = plan(system({"rpo_hours": 0}), cfg, AS_OF)
    assert any("synchronous replication" in r for r in p.recommendations)


def test_site_loss_without_offsite_copy_is_unrecoverable(cfg):
    p = plan(system({"survive_site_loss": True}, site="warm", backup={"type": "full", "frequency_hours": 24, "offsite": False}),
             cfg, AS_OF)
    assert p.site_rto == math.inf and p.has("no offsite copy")


def test_site_rto_adds_restore_unless_replicated(cfg):
    p = plan(system({"survive_site_loss": True, "rto_hours": 30}, site="warm"), cfg, AS_OF)
    assert p.site_rto == 24 + 1.5 and p.verdict == "MEETS_TARGETS"
    p = plan(system({"survive_site_loss": True, "rto_hours": 24}, site="warm", replication="asynchronous"), cfg, AS_OF)
    assert p.site_rto == 24 and p.site_rpo == 0.25


def test_site_gap_recommends_cheapest_sufficient_site(cfg):
    p = plan(system({"survive_site_loss": True, "rto_hours": 30}, site="cold"), cfg, AS_OF)
    assert any("warm site" in r for r in p.recommendations)


def test_no_recovery_site(cfg):
    p = plan(system({"survive_site_loss": True}), cfg, AS_OF)
    assert p.has("no recovery site")


def test_raid(cfg):
    assert raid_for(1, cfg["raid"]) == "RAID5" and raid_for(2, cfg["raid"]) == "RAID6" and raid_for(3, cfg["raid"]) is None
    assert plan(system({"disk_failures": 2}), cfg, AS_OF).has("DISK")


def test_power(cfg):
    p = plan(system({"power_outage_hours": 4}, generator_hours=0), cfg, AS_OF)
    assert p.has("POWER") and any("generator" in r for r in p.recommendations)


def test_stale_or_missing_tests(cfg):
    p = plan(system(last_restore_test=None, last_dr_test="2024-01-01"), cfg, AS_OF)
    assert sum("TEST" in g for g in p.gaps) == 2


def test_cheapest_helper(cfg):
    assert cheapest(cfg["site_types"], lambda v: v["rto_hours"] <= 30)[0] == "warm"
    assert cheapest(cfg["site_types"], lambda v: v["rto_hours"] <= 0.1) is None


def test_sample_outcomes(policies, data):
    plans = {p.name: p for p in plan_all(data("sample_resilience.json"), policies)}
    assert {k: v.verdict for k, v in plans.items()} == {
        "payroll-app": "GAPS", "web-frontend": "MEETS_TARGETS", "auth-service": "GAPS",
        "erp-legacy": "GAPS", "file-server": "MEETS_TARGETS"}
    assert plans["erp-legacy"].site_rto == math.inf
    assert plans["auth-service"].has("DISK") and plans["auth-service"].has("POWER")


def test_fixing_payroll_closes_its_gaps(policies, data):
    d = copy.deepcopy(data("sample_resilience.json"))
    c = d["systems"][0]["current"]
    c.update(site="hot", replication="asynchronous", clustering="active-passive", last_dr_test="2026-10-01")
    assert plan_all(d, policies)[0].verdict == "MEETS_TARGETS"
