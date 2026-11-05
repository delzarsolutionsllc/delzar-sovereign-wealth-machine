"""Lab 41 — Okta password policies, self-service recovery and sign-in troubleshooting tests."""

from __future__ import annotations

import copy
import random

import pytest

from labs.lab41_okta_password_recovery import (CAUSES, CHANGE_OUTCOMES, COURSES, FIXES, RECOVERY_OUTCOMES,
                                               _policy, build_challenges, evaluate_change, evaluate_recovery,
                                               generate_scenario, password_hash, policy_for, run_demo, triage_ticket)
from utils.challenge import run_challenge
from utils.loader import load_policies

D = "@corp.example"


@pytest.fixture
def cfg(policies):
    return policies["okta_password_recovery"]


@pytest.fixture
def sample(data):
    return data("sample_okta_password_recovery.json")


def org(*users, policies=None):
    pols = policies if policies is not None else [
        _policy("p-admin", "Admins", 1, ["Admins"], 15, 1, 10, 1440, 60, 5, None, ["push"], False),
        _policy("p-work", "Workforce", 2, ["Staff"], 12, 0, 5, 60, 180, 10, 30, ["email", "sms"], True),
        _policy("p-def", "Default Policy", 3, ["Everyone"], 8, 0, 4, 0, 0, 10, None, ["email"], False, common=False),
    ]
    return {"password_policies": pols, "users": list(users)}


def user(name="ann.lee", groups=("Staff",), status="Active", enrolled=("email",), age=30, history=()):
    return {"login": name + D, "groups": list(groups), "status": status, "enrolled": list(enrolled),
            "password_age_days": age, "password_history": [password_hash(p) for p in history]}


def change(data, cfg, pw, who="ann.lee", **kw):
    return evaluate_change({"id": "C1", "user": who + D, "new_password": pw, **kw}, data, cfg)


def test_loader_merges_section_and_course_scope():
    assert "okta_password_recovery" in load_policies() and COURSES == ("okta",)


def test_policy_priority_inactive_skip_and_fallback(cfg):
    d = org(user(groups=["Admins", "Staff"]))
    assert policy_for(d["users"][0], d, cfg)[0]["id"] == "p-admin"
    d["password_policies"][0]["status"] = "INACTIVE"
    pol, why = policy_for(d["users"][0], d, cfg)
    assert pol["id"] == "p-work" and "inactive" in why[0]
    assert policy_for(user(groups=[]), d, cfg)[0]["id"] == "p-def"
    pol, why = policy_for(user(), {"password_policies": []}, cfg)
    assert pol["id"] == cfg["fallback_policy"]["id"] and "fallback" in why[-1]


def test_accepted_and_too_short_and_missing_password(cfg):
    d = org(user())
    assert change(d, cfg, "Tundra-Lantern-42").outcome == "ACCEPTED"
    assert change(d, cfg, "Short1A").outcome == "REJECTED_TOO_SHORT"
    r = evaluate_change({"id": "C9", "user": "ann.lee" + D}, d, cfg)
    assert r.outcome == "REJECTED_TOO_SHORT" and "empty" in r.reasons[1]


def test_missing_class_names_the_class(cfg):
    r = change(org(user()), cfg, "copperkettle7781")
    assert r.outcome == "REJECTED_MISSING_CLASS" and "uppercase" in r.reasons[-1]
    admin = change(org(user(groups=["Admins"], age=5)), cfg, "CopperxKettlex778Z1")
    assert admin.outcome == "REJECTED_MISSING_CLASS" and "symbol" in admin.reasons[-1]


def test_contains_username_part_case_insensitive(cfg):
    d = org(user())
    assert change(d, cfg, "Winter-LEE-20261").outcome == "REJECTED_CONTAINS_USERNAME"
    d2 = org(user(name="jo.li"))   # parts shorter than 3 characters are not checked
    assert change(d2, cfg, "Joyful-Lima-2026", who="jo.li").outcome == "ACCEPTED"


def test_common_password_only_when_policy_checks(cfg):
    assert change(org(user()), cfg, "Password1234").outcome == "REJECTED_COMMON_PASSWORD"
    # the Default Policy in this org has the common-password check off
    assert change(org(user(groups=[])), cfg, "Password1234").outcome == "ACCEPTED"


def test_history_window(cfg):
    old = [f"Old-Password-{i}X" for i in range(1, 8)]
    d = org(user(history=old))
    assert change(d, cfg, old[4]).outcome == "REJECTED_IN_HISTORY"
    r = change(d, cfg, old[5])
    assert r.outcome == "ACCEPTED" and any("outside the history window" in x for x in r.reasons)


def test_minimum_age_and_unknown_age(cfg):
    d = org(user(age=None))
    assert change(d, cfg, "Tundra-Lantern-42", minutes_since_last_change=30).outcome == "REJECTED_TOO_SOON"
    assert change(d, cfg, "Tundra-Lantern-42", minutes_since_last_change=60).outcome == "ACCEPTED"
    r = change(d, cfg, "Tundra-Lantern-42")
    assert r.outcome == "REJECTED_TOO_SOON" and any("unknown" in x for x in r.reasons)


def test_first_failure_wins_in_check_order(cfg):
    r = change(org(user(age=0)), cfg, "ann")
    assert r.outcome == "REJECTED_TOO_SHORT" and r.failures[0] == "TOO_SHORT" and "TOO_SOON" in r.failures
    assert r.failures == [x for x in cfg["check_order"] if x in r.failures]


def test_unknown_user_rejected(cfg):
    r = change(org(user()), cfg, "Tundra-Lantern-42", who="ghost")
    assert r.outcome == "REJECTED_UNKNOWN_USER" and "deny by default" in r.reasons[0]


def rec(d, cfg, method, purpose="reset", who="ann.lee"):
    return evaluate_recovery({"id": "R1", "user": who + D, "method": method, "purpose": purpose}, d, cfg)


def test_recovery_allowed_and_blocked_rules(cfg):
    d = org(user(enrolled=["email", "phone"]), user("bo.kay", status="Locked out"),
            user("cy.ng", groups=["Admins"], status="Locked out", enrolled=["okta_verify"]),
            user("di.ott", status="Suspended"), user("ed.fox", status="Mystery"))
    assert rec(d, cfg, "sms").outcome == "RECOVERY_ALLOWED"
    assert "not allowed" in rec(d, cfg, "voice").reasons[-1]              # same phone, method not allowed
    assert "not enrolled" in rec(d, cfg, "sms", who="bo.kay").reasons[-1]
    assert rec(d, cfg, "email", "unlock", who="bo.kay").outcome == "RECOVERY_ALLOWED"
    assert "self-service unlock" in rec(d, cfg, "push", "unlock", who="cy.ng").reasons[-1]
    assert "not Locked out" in rec(d, cfg, "email", "unlock").reasons[-1]
    for who in ("di.ott", "ed.fox", "ghost"):
        assert rec(d, cfg, "email", who=who).outcome == "RECOVERY_BLOCKED"
    assert rec(d, cfg, "carrier-pigeon").outcome == "RECOVERY_BLOCKED"


def tk(d, cfg, **kw):
    return triage_ticket({"id": "T1", "user": "ann.lee" + D, **kw}, d, cfg)


def test_ticket_status_fixes(cfg):
    d = org(user(enrolled=["email", "phone"]))
    expect = {"Suspended": "UNSUSPEND", "Staged": "ACTIVATE_USER", "Pending user action": "ACTIVATE_USER",
              "Deactivated": "REACTIVATE", "Password expired": "RESET_PASSWORD"}
    for status, fix in expect.items():
        assert tk(d, cfg, status=status).fix == fix
    assert tk(d, cfg, status="Deactivated", offboarded=True).cause == "OFFBOARDED"
    r = tk(d, cfg, status="Pending deletion")
    assert (r.cause, r.fix, r.can_sign_in) == ("UNKNOWN_STATUS", "ESCALATE", False)
    assert tk(d, cfg).can_sign_in is True


def test_lockout_paths(cfg):
    d = org(user(enrolled=["email"]), user("cy.ng", groups=["Admins"], enrolled=["okta_verify"]))
    assert tk(d, cfg, status="Locked out", minutes_since_lockout=31).fix == "NONE"            # auto-unlock passed
    assert "self-service unlock" in tk(d, cfg, status="Locked out", minutes_since_lockout=5).reasons[-1]
    assert tk(d, cfg, status="Locked out", enrolled=[]).fix == "UNLOCK"                         # no self path
    admin = triage_ticket({"id": "T2", "user": "cy.ng" + D, "status": "Locked out", "minutes_since_lockout": 999},
                          d, cfg)
    assert admin.fix == "UNLOCK"


def test_compromise_beats_suspend_and_active_rules(cfg):
    d = org(user(enrolled=["email", "okta_verify"], age=400))
    assert tk(d, cfg, status="Suspended", suspected_compromise=True).fix == "EXPIRE_PASSWORD_AND_CLEAR_SESSIONS"
    assert tk(d, cfg, status="Active", lost_device=True).fix == "RESET_AUTHENTICATORS"
    assert tk(d, cfg, status="Active", failed_attempts=2).fix == "NONE"
    assert tk(d, cfg, status="Active", failed_attempts=2, enrolled=[]).fix == "RESET_PASSWORD"
    assert tk(d, cfg, status="Active").cause == "PASSWORD_PAST_MAX_AGE"
    assert tk(org(user(age=1)), cfg, status="Active").cause == "NO_ACCOUNT_ISSUE"
    # lost phone but nothing phone-based enrolled: falls through to the other rules
    assert tk(org(user(age=1)), cfg, status="Active", lost_device=True).cause == "NO_ACCOUNT_ISSUE"


def test_deactivated_is_never_treated_as_compromise_fix(cfg):
    d = org(user())
    assert tk(d, cfg, status="Deactivated", offboarded=True, suspected_compromise=True).fix == "NONE"


def test_sample_outcomes(policies, quiet_ui, sample):
    out = run_demo(quiet_ui, policies, sample)
    assert out["changes"] == {"C01": "ACCEPTED", "C02": "REJECTED_TOO_SHORT", "C03": "REJECTED_MISSING_CLASS",
                              "C04": "REJECTED_CONTAINS_USERNAME", "C05": "REJECTED_COMMON_PASSWORD",
                              "C06": "REJECTED_IN_HISTORY", "C07": "ACCEPTED", "C08": "REJECTED_TOO_SOON",
                              "C09": "REJECTED_CONTAINS_USERNAME", "C10": "ACCEPTED", "C11": "REJECTED_UNKNOWN_USER"}
    assert [k for k, v in out["recovery"].items() if v == "RECOVERY_ALLOWED"] == ["R01", "R04", "R08"]
    assert out["tickets"] == {"T01": "NONE", "T02": "UNLOCK", "T03": "NONE", "T04": "RESET_PASSWORD",
                              "T05": "UNSUSPEND", "T06": "REACTIVATE", "T07": "NONE", "T08": "ACTIVATE_USER",
                              "T09": "ACTIVATE_USER", "T10": "EXPIRE_PASSWORD_AND_CLEAR_SESSIONS",
                              "T11": "RESET_AUTHENTICATORS", "T12": "RESET_PASSWORD", "T13": "NONE", "T14": "NONE",
                              "T15": "ESCALATE", "T16": "EXPIRE_PASSWORD_AND_CLEAR_SESSIONS"}
    assert set(out["changes"].values()) == set(CHANGE_OUTCOMES)
    assert set(out["recovery"].values()) == set(RECOVERY_OUTCOMES)
    assert set(out["tickets"].values()) == set(FIXES)
    assert out["policy_for"]["maria.okafor@larkspur.example"] == "pol-admins"
    assert out["policy_for"]["dev.patel@larkspur.example"] == "pol-workforce"


def test_briefing_talking_point_matches_demo(policies, quiet_ui, sample, data):
    tp = data("briefings/lab41.json")["talking_point"]
    m = run_demo(quiet_ui, policies, sample)["metrics"]
    assert f"Mapped {m['users']} users to {len(sample['password_policies'])} Okta" in tp
    assert f"checked {m['changes']} password changes ({m['accepted']} accepted, {m['changes'] - m['accepted']} rejected" in tp
    rc = m["recovery_counts"]
    assert f"{m['recoveries']} self-service recovery attempts ({rc['RECOVERY_ALLOWED']} allowed, " \
           f"{rc['RECOVERY_BLOCKED']} blocked)" in tp
    assert f"triaged {m['tickets']} " in tp and f"{m['admin_actions']} needed an admin action" in tp
    assert f"{m['fix_counts']['NONE']} needed none" in tp and f"{m['fix_counts']['ESCALATE']} unknown status" in tp


def test_challenges_valid_and_full_score(policies, quiet_ui, sample):
    qs = build_challenges(policies, sample)
    assert len(qs) >= 12
    for q in qs:
        assert q.objective in ("4.4", "5.1") and q.answer in q.choices
        assert len(set(q.choices)) == len(q.choices)
        assert "lab" not in (q.prompt + " ".join(q.choices)).lower()
    assert {q.objective for q in qs} == {"4.4", "5.1"}
    answers = iter([q.answer for q in qs])
    res = run_challenge(quiet_ui, 41, qs, ask=lambda _: next(answers), progress=None, shuffle=False)
    assert res.correct == res.total == len(qs)


def test_challenge_answers_follow_policy(policies, sample):
    pol = copy.deepcopy(policies)
    pol["okta_password_recovery"]["common_passwords"] = []
    before = {q.prompt: q.answer for q in build_challenges(policies, sample)}
    after = {q.prompt: q.answer for q in build_challenges(pol, sample)}
    key = next(p for p in before if p.startswith("C05:"))
    assert before[key] == "REJECTED_COMMON_PASSWORD" and after[key] == "ACCEPTED"


def test_generator_is_deterministic_and_covers_outcomes(policies, quiet_ui):
    for seed in (1, 7, 42):
        g = generate_scenario(random.Random(seed), policies)
        assert g == generate_scenario(random.Random(seed), policies)
        out = run_demo(quiet_ui, policies, g)
        assert set(out["changes"].values()) == set(CHANGE_OUTCOMES)
        assert set(out["recovery"].values()) == set(RECOVERY_OUTCOMES)
        assert set(out["tickets"].values()) == set(FIXES) and set(out["causes"].values()) == set(CAUSES)
        assert len(build_challenges(policies, g)) >= 12
    assert generate_scenario(random.Random(1), policies) != generate_scenario(random.Random(2), policies)
