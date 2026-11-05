"""Lab 31 — identity monitoring (sign-in logs, ID Protection risk & detections) tests."""

from __future__ import annotations

import copy
import json
import random
import re

import pytest

from labs.lab31_identity_monitoring import (DETECTIONS, RESPONSES, build_challenges, check_records, detect_all,
                                            generate_scenario, respond, run_demo)
from utils.challenge import check


@pytest.fixture
def cfg(policies):
    return policies["identity_monitoring"]


def rec(id="S1", user="u1", minute=0, ip="192.0.2.10", country="NL", result="0", client="Browser",
        ur="low", sr="low", **kw):
    r = {"id": id, "user": user, "time": f"2026-10-14T{10 + minute // 60:02d}:{minute % 60:02d}:00Z", "ip": ip,
         "country": country, "app": "Office 365 Exchange Online", "client_app": client, "result": result,
         "mfa_detail": None, "user_risk": ur, "signin_risk": sr}
    r.update(kw)
    return r


def types(data, cfg):
    return sorted(d.type for d in detect_all(data, cfg)[0])


def responses(data, cfg):
    return {r.user: r.response for r in respond(data, cfg)}


def test_password_spray_needs_distinct_users_in_window(cfg):
    n = cfg["password_spray"]["min_distinct_users"]
    fails = [rec(f"S{i}", f"u{i}", i, ip="203.0.113.5", result="50126") for i in range(n)]
    assert "PASSWORD_SPRAY" in types({"signins": fails}, cfg)
    assert "PASSWORD_SPRAY" not in types({"signins": fails[:-1]}, cfg)
    spread = [rec(f"S{i}", f"u{i}", i * (cfg["password_spray"]["window_minutes"] + 1), ip="203.0.113.5",
                  result="50126") for i in range(n)]
    assert "PASSWORD_SPRAY" not in types({"signins": spread}, cfg)


def test_brute_force_threshold_and_window(cfg):
    n = cfg["brute_force"]["min_failures"]
    burst = [rec(f"S{i}", "u1", i, result="50126") for i in range(n)]
    assert types({"signins": burst}, cfg) == ["BRUTE_FORCE"]
    assert types({"signins": burst[:-1]}, cfg) == []
    slow = [rec(f"S{i}", "u1", i * 40, result="50126") for i in range(n)]
    assert types({"signins": slow}, cfg) == []


def test_mfa_fatigue_requires_success_after_prompts(cfg):
    n = cfg["mfa_fatigue"]["min_failed_prompts"]
    prompts = [rec(f"S{i}", "u1", i, result="500121") for i in range(n)]
    assert "MFA_FATIGUE" not in types({"signins": prompts}, cfg)
    win = prompts + [rec("SX", "u1", n + 1, result="0")]
    assert "MFA_FATIGUE" in types({"signins": win}, cfg)
    assert responses({"signins": win}, cfg) == {"u1": "BLOCK_AND_REVOKE_SESSIONS"}
    assert "MFA_FATIGUE" not in types({"signins": prompts[:-1] + [rec("SX", "u1", n + 1, result="0")]}, cfg)


def test_legacy_auth_any_attempt_and_unknown_client(cfg):
    data = {"signins": [rec("S1", "u1", client="IMAP4", result="50126"), rec("S2", "u2", client="Browser"),
                        rec("S3", "u3", client=None)]}
    dets = [d for d in detect_all(data, cfg)[0] if d.type == "LEGACY_AUTH_USE"]
    assert sorted(d.subject for d in dets) == ["u1", "u3"]
    assert any("treated as legacy" in r for r in next(d for d in dets if d.subject == "u3").reasons)


def test_impossible_travel_speed_and_failures_ignored(cfg):
    far = {"signins": [rec("S1", "u1", 0, country="JP"), rec("S2", "u1", 60, country="BR")]}
    assert types(far, cfg) == ["IMPOSSIBLE_TRAVEL"]
    near = {"signins": [rec("S1", "u1", 0, country="NL"), rec("S2", "u1", 60, country="BE")]}
    assert types(near, cfg) == []
    failed = {"signins": [rec("S1", "u1", 0, country="JP"), rec("S2", "u1", 60, country="BR", result="50126")]}
    assert "IMPOSSIBLE_TRAVEL" not in types(failed, cfg)


def test_impossible_travel_unknown_country_is_reported(cfg):
    data = {"signins": [rec("S1", "u1", 0, country="NL"), rec("S2", "u1", 10, country="ZZ")]}
    dets, _, notes = detect_all(data, cfg)
    assert not dets and any("cannot be checked" in n for n in notes)


def test_privileged_role_added_and_missing_role(cfg):
    audits = [{"id": "A1", "activity": "Add member to role", "role": "Global Administrator", "target": "u1",
               "actor": "u2", "time": "2026-10-14T10:00:00Z"},
              {"id": "A2", "activity": "Add member to role", "role": "Reports Reader", "target": "u1"},
              {"id": "A3", "activity": "Add eligible member to role", "role": None, "target": "u3"},
              {"id": "A4", "activity": "Update user", "role": None, "target": "u4"}]
    dets = detect_all({"signins": [], "audit_logs": audits}, cfg)[0]
    assert [(d.type, d.subject) for d in dets] == [("PRIVILEGED_ROLE_ADDED", "A1"), ("PRIVILEGED_ROLE_ADDED", "A3")]
    assert "deny by default" in dets[1].reasons[0]


def test_missing_timestamp_or_ip_is_reported_not_trusted(cfg):
    data = {"signins": [rec("S1", "u1", ip=None), rec("S2", "u2", time=None), rec("S3", "u3", time="yesterday")]}
    good, bad = check_records(data["signins"])
    assert not good and sorted(bad) == ["S1", "S2", "S3"]
    assert "no IP address" in bad["S1"][0] and "no timestamp" in bad["S2"][0] and "cannot be parsed" in bad["S3"][0]
    assert set(responses(data, cfg).values()) == {"REQUIRE_MFA"}


def test_unverifiable_records_are_kept_out_of_windows(cfg):
    n = cfg["brute_force"]["min_failures"]
    fails = [rec(f"S{i}", "u1", i, result="50126") for i in range(n)]
    fails[0]["time"] = None
    assert "BRUTE_FORCE" not in types({"signins": fails}, cfg)


def test_response_rule_order(cfg):
    data = {"signins": [rec("S1", "a", ur="high", sr="high"), rec("S2", "b", ur="medium", sr="high"),
                        rec("S3", "c", ur="low", sr="medium"), rec("S4", "d", ur="none", sr="low"),
                        rec("S5", "e", ur="high", sr="none")],
            "confirmed_compromised": ["e"]}
    assert responses(data, cfg) == {"a": "REQUIRE_SECURE_PASSWORD_CHANGE", "b": "REQUIRE_MFA", "c": "REQUIRE_MFA",
                                    "d": "NO_ACTION", "e": "BLOCK_AND_REVOKE_SESSIONS"}


def test_unknown_risk_is_treated_as_high(cfg):
    data = {"signins": [rec("S1", "a", ur=None, sr="low"), rec("S2", "b", ur="low", sr="hidden")]}
    out = {r.user: r for r in respond(data, cfg)}
    assert out["a"].response == "REQUIRE_SECURE_PASSWORD_CHANGE" and out["b"].response == "REQUIRE_MFA"
    assert any("missing or unknown" in x for x in out["a"].reasons)


def test_confirmed_user_without_signins_is_blocked(cfg):
    assert responses({"signins": [], "confirmed_compromised": ["ghost"]}, cfg) == {
        "ghost": "BLOCK_AND_REVOKE_SESSIONS"}


def test_policy_drives_thresholds(cfg):
    strict = copy.deepcopy(cfg)
    strict["brute_force"]["min_failures"] = 2
    data = {"signins": [rec("S1", "u1", 0, result="50126"), rec("S2", "u1", 1, result="50126")]}
    assert types(data, cfg) == [] and types(data, strict) == ["BRUTE_FORCE"]


def test_sample_expected_outcomes(policies, quiet_ui, data):
    sample = data("sample_identity_monitoring.json")
    out = run_demo(quiet_ui, policies, sample)
    json.dumps(out)
    d = "@kestrelridge.example"
    assert out["responses"] == {
        f"ava.lindqvist{d}": "NO_ACTION", f"ben.okafor{d}": "NO_ACTION", f"chloe.ramos{d}": "REQUIRE_MFA",
        f"dev.patel{d}": "REQUIRE_SECURE_PASSWORD_CHANGE", f"emma.novak{d}": "NO_ACTION",
        f"farid.haddad{d}": "BLOCK_AND_REVOKE_SESSIONS", f"gina.morales{d}": "NO_ACTION",
        f"hiro.tanaka{d}": "REQUIRE_MFA", f"ines.costa{d}": "NO_ACTION", f"jonas.weber{d}": "REQUIRE_MFA",
        f"kai.brandt{d}": "BLOCK_AND_REVOKE_SESSIONS", f"lena.fischer{d}": "NO_ACTION"}
    assert set(out["responses"].values()) == set(RESPONSES)
    assert out["metrics"]["detection_counts"] == {"PASSWORD_SPRAY": 1, "BRUTE_FORCE": 1, "MFA_FATIGUE": 1,
                                                  "LEGACY_AUTH_USE": 2, "IMPOSSIBLE_TRAVEL": 1,
                                                  "PRIVILEGED_ROLE_ADDED": 2}
    assert out["unverifiable"] == ["S19", "S38"]
    assert out["metrics"]["records"] == 38 and out["metrics"]["audit_records"] == 4
    spray = [x for x in out["detections"] if x["type"] == "PASSWORD_SPRAY"]
    assert [x["subject"] for x in spray] == ["203.0.113.50"]          # 198.51.100.77 stays under threshold


def test_briefing_talking_point_matches_demo(policies, quiet_ui, data):
    out = run_demo(quiet_ui, policies, data("sample_identity_monitoring.json"))
    tp = data("briefings/lab31.json")["talking_point"]
    m = out["metrics"]
    c = m["response_counts"]
    for phrase in (f"{m['records']} sign-in records", f"{m['audit_records']} audit entries", f"{m['users']} users",
                   f"{m['unverifiable']} records", f"{m['detections']} detections",
                   f"sessions for {c['BLOCK_AND_REVOKE_SESSIONS']} users",
                   f"password change for {c['REQUIRE_SECURE_PASSWORD_CHANGE']}",
                   f"MFA for {c['REQUIRE_MFA']}", f"closed {c['NO_ACTION']}"):
        assert phrase in tp, phrase


def test_challenges_valid_and_full_score(policies, data):
    qs = build_challenges(policies, data("sample_identity_monitoring.json"))
    assert len(qs) >= 12
    assert all(q.objective in ("4.4", "2.3") for q in qs)
    assert all(len(set(q.choices)) == len(q.choices) for q in qs)
    assert not any(re.search(r"\blabs?\b", (q.prompt + " ".join(q.choices)).lower()) for q in qs)
    assert sum(check(q, q.answer) for q in qs) == len(qs)
    prompts = " ".join(q.prompt for q in qs)
    assert "SigninLogs column" in prompts and "diagnostic setting" in prompts
    assert {q.answer for q in qs} >= {"AuditLogs", "ResultType", "Log Analytics workspace"}


def test_generate_scenario_deterministic_and_complete(policies, quiet_ui):
    a, b = generate_scenario(random.Random(7), policies), generate_scenario(random.Random(7), policies)
    assert a == b and a != generate_scenario(random.Random(8), policies)
    out = run_demo(quiet_ui, policies, a)
    json.dumps(out)
    assert set(out["responses"].values()) == set(RESPONSES)
    assert {x["type"] for x in out["detections"]} == set(DETECTIONS)
    assert out["unverifiable"]
    assert len(build_challenges(policies, a)) >= 12


@pytest.mark.parametrize("seed", range(5))
def test_generated_scenarios_always_cover_every_outcome(policies, quiet_ui, seed):
    out = run_demo(quiet_ui, policies, generate_scenario(random.Random(seed), policies))
    assert set(out["responses"].values()) == set(RESPONSES)
    assert {x["type"] for x in out["detections"]} == set(DETECTIONS)
