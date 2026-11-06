"""Lab 44 — SailPoint ISC lifecycle states and joiner-mover-leaver automation tests."""

from __future__ import annotations

import copy
import json
import random
from pathlib import Path

import pytest

from labs.lab44_isc_lifecycle_states import (OUTCOMES, base_profiles, build_challenges, calculate_state,
                                             generate_scenario, process_event, run_demo, state_actions)
from utils.challenge import run_challenge

TODAY = "2026-11-06"


@pytest.fixture
def cfg(policies):
    return policies["isc_lifecycle_states"]


@pytest.fixture
def sample(data):
    return data("sample_isc_lifecycle_states.json")


def ev(profile="Employees", prev="active", accounts=None, **hr):
    e = {"id": "T1", "identity": "Test Person", "identity_profile": profile, "event": "test",
         "previous_state": prev, "hr": hr}
    if accounts is not None:
        e["accounts"] = accounts
    return e


def run(cfg, e, profiles=None):
    return process_event(e, profiles or base_profiles(), TODAY, cfg)


# --- Step 1: calculation ------------------------------------------------------
def test_prehire_then_active_on_start_date(cfg):
    assert calculate_state({"status": "active", "start_date": "2026-11-07"}, TODAY, cfg)[0] == "prehire"
    assert calculate_state({"status": "active", "start_date": TODAY}, TODAY, cfg)[0] == "active"


def test_unknown_or_missing_status_is_inactive(cfg):
    for hr in ({"status": "suspended_pending"}, {}, None, {"status": ""}):
        value, rule, why = calculate_state(hr, TODAY, cfg)
        assert value == cfg["deny_by_default_state"] and rule == "unknown_status" and "deny by default" in why


def test_missing_start_date_or_today_is_deny_by_default(cfg):
    assert calculate_state({"status": "active"}, TODAY, cfg)[:2] == ("inactive", "missing_start_date")
    assert calculate_state({"status": "active", "start_date": "not-a-date"}, TODAY, cfg)[0] == "inactive"
    assert calculate_state({"status": "active", "start_date": "2020-01-01"}, None, cfg)[0] == "inactive"


def test_end_date_boundary_and_hr_lag(cfg):
    hr = {"status": "active", "start_date": "2020-01-01"}
    assert calculate_state({**hr, "end_date": TODAY}, TODAY, cfg)[0] == "active"          # last working day
    assert calculate_state({**hr, "end_date": "2026-11-05"}, TODAY, cfg)[0] == "terminated"


def test_post_termination_window(cfg):
    w = cfg["post_termination_days"]
    from datetime import date, timedelta
    at = (date.fromisoformat(TODAY) - timedelta(days=w)).isoformat()
    over = (date.fromisoformat(TODAY) - timedelta(days=w + 1)).isoformat()
    assert calculate_state({"status": "terminated", "end_date": at}, TODAY, cfg)[0] == "terminated"
    assert calculate_state({"status": "terminated", "end_date": over}, TODAY, cfg)[:2] == ("inactive",
                                                                                         "post_termination")


def test_rehire_ignores_old_end_date(cfg):
    value, _, why = calculate_state({"status": "active", "start_date": "2026-11-02", "end_date": "2025-06-30"},
                                    TODAY, cfg)
    assert value == "active" and "rehire" in why


def test_leave_status(cfg):
    assert calculate_state({"status": "Leave", "start_date": "2020-01-01"}, TODAY, cfg)[0] == "leave"


# --- Step 2: applying the state -----------------------------------------------
def test_transition_runs_only_configured_actions(cfg):
    r = run(cfg, ev(prev="prehire", accounts=["Active Directory"], status="active", start_date="2026-11-01"))
    assert r.outcome == "TRANSITIONED"
    assert r.actions == ["GRANT Birthright - All Staff", "ENABLE Active Directory", "NOTIFY manager, identity"]


def test_no_change_triggers_nothing(cfg):
    r = run(cfg, ev(prev="active", status="active", start_date="2020-01-01"))
    assert r.outcome == "NO_CHANGE" and r.actions == [] and r.flags == []


def test_unknown_state_technical_name_mismatch(cfg):
    r = run(cfg, ev(profile="Contractors", status="leave", start_date="2026-01-01"))
    assert r.outcome == "UNKNOWN_STATE" and r.actions == [] and any("'leave'" in x for x in r.reasons)


def test_unknown_profile_is_deny_by_default(cfg):
    r = run(cfg, ev(profile="Ghost Profile", status="active", start_date="2020-01-01"))
    assert r.outcome == "UNKNOWN_STATE" and r.actions == []


def test_leaver_keeps_access_no_disable_and_partial_disable(cfg):
    none = run(cfg, ev(profile="Contractors", status="terminated", end_date="2026-11-05"))
    assert none.outcome == "LEAVER_KEEPS_ACCESS" and none.actions == ["NOTIFY manager"]
    partial = run(cfg, ev(accounts=["Active Directory", "Salesforce"], status="??"))
    assert partial.outcome == "LEAVER_KEEPS_ACCESS" and "Salesforce" in partial.reasons[-1]
    clean = run(cfg, ev(accounts=["Active Directory", "Salesforce"], status="terminated", end_date="2026-11-05"))
    assert clean.outcome == "TRANSITIONED" and "DISABLE Salesforce" in clean.actions


def test_prehire_access_too_early(cfg):
    bad = run(cfg, ev(profile="Contractors", prev=None, status="hired", start_date="2026-12-01"))
    assert bad.outcome == "PREHIRE_ACCESS_TOO_EARLY" and "ENABLE Active Directory" in bad.actions
    ok = run(cfg, ev(prev=None, status="active", start_date="2026-12-01"))
    assert ok.outcome == "TRANSITIONED"


def test_severity_unknown_beats_everything(cfg):
    profiles = base_profiles()
    for st in profiles["Employees"]["lifecycle_states"]:
        if st["technical_name"] == "terminated":
            st["technical_name"] = "Terminated"            # display-style value: no longer matches
    r = run(cfg, ev(status="terminated", end_date="2026-11-05"), profiles)
    assert r.outcome == "UNKNOWN_STATE"


def test_disable_all_with_no_account_list(cfg):
    st = next(s for s in base_profiles()["Employees"]["lifecycle_states"] if s["technical_name"] == "terminated")
    assert "DISABLE all sources" in state_actions(st)


def test_policy_change_moves_answers(policies):
    strict = copy.deepcopy(policies)
    strict["isc_lifecycle_states"]["prehire_allowed_access_profiles"] = []
    r = process_event(ev(prev=None, status="active", start_date="2026-12-01"), base_profiles(), TODAY,
                      strict["isc_lifecycle_states"])
    assert r.outcome == "PREHIRE_ACCESS_TOO_EARLY"


# --- Sample data, briefing, generator, challenges -----------------------------
EXPECTED = {"EV-01": "TRANSITIONED", "EV-02": "TRANSITIONED", "EV-03": "TRANSITIONED", "EV-04": "TRANSITIONED",
            "EV-05": "TRANSITIONED", "EV-06": "TRANSITIONED", "EV-07": "LEAVER_KEEPS_ACCESS", "EV-08": "NO_CHANGE",
            "EV-09": "TRANSITIONED", "EV-10": "NO_CHANGE", "EV-11": "PREHIRE_ACCESS_TOO_EARLY",
            "EV-12": "UNKNOWN_STATE", "EV-13": "LEAVER_KEEPS_ACCESS", "EV-14": "UNKNOWN_STATE"}


def test_sample_outcomes(policies, quiet_ui, sample):
    out = run_demo(quiet_ui, policies, sample)
    json.dumps(out)
    assert out["events"] == EXPECTED
    assert set(out["events"].values()) == set(OUTCOMES)
    assert out["metrics"]["actions"] == 36


def test_briefing_matches_demo(policies, quiet_ui, sample):
    path = Path(__file__).resolve().parent.parent / "data" / "briefings" / "lab44.json"
    tp = json.loads(path.read_text())["talking_point"]
    m = run_demo(quiet_ui, policies, sample)["metrics"]
    c = m["outcome_counts"]
    assert f"Processed {m['events']} joiner" in tp
    assert f"{c['TRANSITIONED']} moved cleanly" in tp and f"{c['NO_CHANGE']} needed no change" in tp
    assert f"{m['flagged']} were flagged ({c['UNKNOWN_STATE']} unknown" in tp
    assert f"{c['LEAVER_KEEPS_ACCESS']} leavers keeping access and {c['PREHIRE_ACCESS_TOO_EARLY']} pre-hire" in tp
    assert f"{m['actions']} provisioning actions" in tp


def test_generator_is_deterministic_and_covers_outcomes(policies, quiet_ui):
    for seed in (1, 7, 42):
        g = generate_scenario(random.Random(seed), policies)
        assert g == generate_scenario(random.Random(seed), policies)
        out = run_demo(quiet_ui, policies, g)
        assert set(out["events"].values()) == set(OUTCOMES)
        assert len(build_challenges(policies, g)) >= 12
    assert generate_scenario(random.Random(1), policies) != generate_scenario(random.Random(2), policies)


def test_challenges_valid_and_full_score(policies, quiet_ui, sample):
    qs = build_challenges(policies, sample)
    assert len(qs) >= 12
    for q in qs:
        assert q.objective in ("3.3", "4.1") and q.answer in q.choices
        assert len(set(q.choices)) == len(q.choices)
        assert "lab" not in (q.prompt + " ".join(q.choices)).lower()
    assert {q.objective for q in qs} == {"3.3", "4.1"}
    answers = iter([q.answer for q in qs])
    res = run_challenge(quiet_ui, 44, qs, ask=lambda _: next(answers), progress=None, shuffle=False)
    assert res.correct == res.total == len(qs)
