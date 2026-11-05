"""Lab 42 — Okta System Log investigation and support escalation tests."""

from __future__ import annotations

import copy
import random

import pytest

from labs.lab42_okta_system_log import (FINDINGS, QUERY_OUTCOMES, RESOURCES, build_challenges, generate_scenario,
                                        investigate, run_demo, run_filter, triage)
from utils.challenge import run_challenge

D = "@corp.example"


@pytest.fixture
def cfg(policies):
    return policies["okta_system_log"]


def user(n):
    return {"id": "00u" + n, "type": "User", "alternateId": n + D, "displayName": n.title()}


def app(a):
    return {"id": "0oa" + a, "type": "AppInstance", "alternateId": a.lower(), "displayName": a}


def grp(g):
    return {"id": "00g" + g, "type": "UserGroup", "alternateId": g, "displayName": g}


def ev(uuid, minute, etype, actor, targets=(), result="SUCCESS", reason=None, ip="192.0.2.1", country="Netherlands"):
    return {"uuid": uuid, "published": f"2026-10-28T09:{minute:02d}:00.000Z", "eventType": etype,
            "actor": user(actor), "target": list(targets), "outcome": {"result": result, "reason": reason},
            "client": {"ipAddress": ip, "geographicalContext": {"city": "X", "country": country}}}


def assigned(n, a, minute=1):
    return [ev(f"a-{n}", minute, "application.user_membership.add", "admin", [user(n), app(a)]),
            ev(f"p-{n}", minute + 1, "app.user_management.push_new_user_success", "admin", [user(n), app(a)])]


def access(cfg, events, n="dana", a="Workday"):
    return investigate({"id": "T", "kind": "app_access", "user": n + D, "app": a}, events, cfg)


# ----------------------------------------------------------------- filters
def test_filter_eq_and_or_parentheses_precedence(cfg):
    events = [ev("e1", 1, "user.account.lock", "lee"), ev("e2", 2, "group.user_membership.add", "admin",
              [user("sam"), grp("Admins")], "FAILURE"), ev("e3", 3, "group.user_membership.add", "admin",
              [user("sam"), grp("Admins")])]
    r = run_filter('eventType eq "user.account.lock" or (eventType sw "group." and outcome.result eq "SUCCESS")',
                   events, cfg)
    assert r.status == "MATCHES" and r.matches == ["e1", "e3"]
    # Without parentheses "and" still binds tighter than "or": same result.
    r2 = run_filter('eventType eq "user.account.lock" or eventType sw "group." and outcome.result eq "SUCCESS"',
                    events, cfg)
    assert r2.matches == ["e1", "e3"]
    r3 = run_filter('(eventType eq "user.account.lock" or eventType sw "group.") and outcome.result eq "SUCCESS"',
                    events, cfg)
    assert r3.matches == ["e1", "e3"]
    r4 = run_filter('(eventType eq "user.account.lock" or eventType sw "group.") and outcome.result eq "FAILURE"',
                    events, cfg)
    assert r4.matches == ["e2"]


def test_filter_target_list_and_contains(cfg):
    events = [ev("e1", 1, "group.user_membership.add", "admin", [user("sam"), grp("Admins")])]
    assert run_filter('target.displayName co "admin"', events, cfg).matches == ["e1"]
    assert run_filter(f'target.alternateId eq "sam{D}"', events, cfg).matches == ["e1"]
    assert run_filter('target.displayName eq "Finance"', events, cfg).status == "NO_MATCH"


@pytest.mark.parametrize("expr", ["", "   ", 'outcome.result eq FAILURE', 'eventType eq "x" and',
                                  '(eventType eq "x"', 'nosuch.field eq "x"', 'eventType gt "x"',
                                  'eventType eq "unterminated', 'eventType eq "a" eventType eq "b"'])
def test_invalid_expressions_return_error_never_all_events(cfg, expr):
    events = [ev("e1", 1, "user.session.start", "lee")]
    r = run_filter(expr, events, cfg)
    assert r.status == "INVALID_EXPRESSION" and r.matches == [] and r.error


# ----------------------------------------------------------------- tickets
def test_not_assigned_when_group_not_assigned_to_app(cfg):
    r = access(cfg, [ev("g", 1, "group.user_membership.add", "admin", [user("dana"), grp("Finance")])])
    assert r.finding == "NOT_ASSIGNED_TO_APP" and "Finance" in r.reasons[0]


def test_unassigned_after_assignment_is_not_assigned(cfg):
    events = assigned("dana", "Workday") + [ev("r", 5, "application.user_membership.remove", "admin",
                                                [user("dana"), app("Workday")])]
    assert access(cfg, events).finding == "NOT_ASSIGNED_TO_APP"


def test_failed_assignment_does_not_count(cfg):
    events = [ev("a", 1, "application.user_membership.add", "admin", [user("dana"), app("Workday")], "FAILURE")]
    assert access(cfg, events).finding == "NOT_ASSIGNED_TO_APP"


def test_provisioning_failed_and_missing_outcome_is_failure(cfg):
    events = assigned("dana", "Workday")[:1] + [ev("p", 2, "application.provision.user.push", "admin",
                                                     [user("dana"), app("Workday")], "FAILURE", "user exists")]
    r = access(cfg, events)
    assert r.finding == "PROVISIONING_FAILED" and r.evidence == ["p"]
    events[-1]["outcome"] = None
    assert access(cfg, events).finding == "PROVISIONING_FAILED"


def test_denied_by_policy_uses_latest_evaluation(cfg):
    events = assigned("dana", "Workday") + [
        ev("ok", 5, "policy.evaluate_sign_on", "dana", [app("Workday")], "ALLOW"),
        ev("no", 9, "policy.evaluate_sign_on", "dana", [app("Workday")], "DENY", "Device is not managed")]
    r = access(cfg, events)
    assert r.finding == "DENIED_BY_POLICY" and r.evidence == ["no"]
    events[-1]["outcome"] = {"result": "CHALLENGE"}
    assert access(cfg, events).finding == "NO_EVIDENCE"
    events[-1]["outcome"] = {}
    assert access(cfg, events).finding == "DENIED_BY_POLICY"


def test_deactivated_beats_everything_and_reactivation_clears_it(cfg):
    events = assigned("dana", "Workday") + [ev("d", 5, "user.lifecycle.deactivate", "admin", [user("dana")])]
    assert access(cfg, events).finding == "USER_DEACTIVATED"
    events.append(ev("re", 6, "user.lifecycle.reactivate", "admin", [user("dana")]))
    assert access(cfg, events).finding == "NO_EVIDENCE"


def test_locked_out_unless_unlocked_later(cfg):
    events = assigned("dana", "Workday") + [ev("l", 5, "user.account.lock", "dana", [user("dana")])]
    assert access(cfg, events).finding == "LOCKED_OUT"
    events.append(ev("u", 7, "user.account.unlock_by_admin", "admin", [user("dana")]))
    assert access(cfg, events).finding == "NO_EVIDENCE"


def test_check_order_is_policy_driven(cfg):
    events = [ev("l", 5, "user.account.lock", "dana", [user("dana")])]
    assert access(cfg, events).finding == "LOCKED_OUT"
    alt = copy.deepcopy(cfg)
    alt["app_access_checks"] = ["NOT_ASSIGNED_TO_APP", "LOCKED_OUT"]
    assert access(alt, events).finding == "NOT_ASSIGNED_TO_APP"


def test_who_changed_ignores_failed_attempt(cfg):
    events = [ev("f", 1, "group.user_membership.add", "ana", [user("sam"), grp("Admins")], "FAILURE", "no rights"),
              ev("s", 3, "group.user_membership.add", "alex", [user("sam"), grp("Admins")])]
    t = {"id": "T", "kind": "who_changed", "change": "group_add", "user": "sam" + D, "object": "Admins"}
    r = investigate(t, events, cfg)
    assert r.finding == "CHANGE_BY_ADMIN" and r.actor == "alex" + D and r.evidence == ["s"]
    assert any("ana" in x and "FAILURE" in x for x in r.reasons)
    assert investigate(t, events[:1], cfg).finding == "NO_EVIDENCE"


def test_api_token_creator(cfg):
    events = [ev("t", 1, "system.api_token.create", "alex", [{"id": "t1", "type": "Token", "displayName": "ci"}])]
    r = investigate({"id": "T", "kind": "who_changed", "change": "api_token", "object": "ci"}, events, cfg)
    assert r.finding == "CHANGE_BY_ADMIN" and r.actor == "alex" + D


def test_when_locked_counts_failures_in_window(cfg):
    events = [ev("old", 1, "user.session.start", "lee", result="FAILURE", reason="INVALID_CREDENTIALS")]
    events += [ev(f"f{i}", 40 + i, "user.session.start", "lee", result="FAILURE", reason="INVALID_CREDENTIALS",
                  country="Romania") for i in range(5)]
    events.append(ev("lock", 45, "user.account.lock", "lee", [user("lee")]))
    r = investigate({"id": "T", "kind": "when_locked", "user": "lee" + D}, events, cfg)
    assert r.finding == "LOCKED_OUT" and r.when == "2026-10-28T09:45:00.000Z"
    assert r.evidence == ["f0", "f1", "f2", "f3", "f4", "lock"] and "still locked" in r.reasons[-1]


def test_missing_input_and_unknown_kind_are_no_evidence(cfg):
    events = [ev("l", 5, "user.account.lock", "dana", [user("dana")])]
    for t in ({"id": "T", "kind": "app_access", "app": "Workday"}, {"id": "T", "kind": "when_locked"},
              {"id": "T", "kind": "who_changed", "change": "group_add"},
              {"id": "T", "kind": "who_changed", "change": "rename_org", "user": "dana" + D},
              {"id": "T", "kind": "reset_everything", "user": "dana" + D}):
        r = investigate(t, events, cfg)
        assert r.finding == "NO_EVIDENCE" and r.reasons


# ----------------------------------------------------------------- triage
@pytest.mark.parametrize("desc,listed,resource", [
    ("Okta sign-in is timing out for everyone", True, "OKTA_STATUS_PAGE"),
    ("Okta sign-in is timing out for everyone", False, "SUPPORT_CASE"),
    ("Okta sign-in is timing out for everyone", None, "SUPPORT_CASE"),
    ("How do I configure a password policy for contractors?", None, "OKTA_HELP_CENTER"),
    ("It would be great if Okta could export reports as PDF", None, "OKTA_COMMUNITY"),
    ("What is best practice for naming groups?", None, "OKTA_COMMUNITY"),
    ("The Profile Editor drops a mapping, reproducible in our org", None, "SUPPORT_CASE"),
    ("Suspicious admin sign-in from an unknown country; we suspect a compromise", None, "SUPPORT_CASE"),
    ("Hello there", None, "SUPPORT_CASE"),
])
def test_triage_resources(cfg, desc, listed, resource):
    issue = {"id": "S", "description": desc}
    if listed is not None:
        issue["status_page_incident"] = listed
    assert triage(issue, cfg).resource == resource


def test_security_beats_outage_and_case_completeness(cfg):
    r = triage({"id": "S", "description": "Suspicious token while Okta is timing out", "status_page_incident": True,
                "provided": ["org_id"]}, cfg)
    assert r.category == "security_incident" and r.resource == "SUPPORT_CASE" and r.severity == "critical"
    assert r.case_status == "INCOMPLETE" and {"system_log_evidence", "containment_done"} <= set(r.missing)
    full = cfg["case_fields"]["base"] + cfg["case_fields"]["bug"]
    ok = triage({"id": "S", "description": "reproducible bug", "provided": full}, cfg)
    assert ok.case_status == "READY" and ok.missing == []
    assert triage({"id": "S", "description": "How do I set up SSO?"}, cfg).case_status is None


# ----------------------------------------------------------------- sample, generator, challenges
def test_sample_expected_outcomes(policies, quiet_ui, data):
    out = run_demo(quiet_ui, policies, data("sample_okta_system_log.json"))
    assert out["queries"] == {"Q1": "MATCHES", "Q2": "NO_MATCH", "Q3": "INVALID_EXPRESSION"}
    assert out["query_matches"]["Q1"] == ["evt-022", "evt-024"]
    assert out["tickets"] == {"T1": "NOT_ASSIGNED_TO_APP", "T2": "PROVISIONING_FAILED", "T3": "DENIED_BY_POLICY",
                              "T4": "LOCKED_OUT", "T5": "CHANGE_BY_ADMIN", "T6": "USER_DEACTIVATED",
                              "T7": "NO_EVIDENCE"}
    assert out["actors"]["T5"] == "alex.kim@larkspur.example"
    assert out["support"] == {"S1": "OKTA_STATUS_PAGE", "S2": "SUPPORT_CASE", "S3": "OKTA_HELP_CENTER",
                              "S4": "SUPPORT_CASE", "S5": "OKTA_COMMUNITY", "S6": "SUPPORT_CASE"}
    assert out["cases"] == {"S2": "READY", "S4": "INCOMPLETE", "S6": "READY"}
    assert out["metrics"] == {"events": 29, "failed_or_denied_events": 8, "queries_invalid": 1,
                              "tickets_explained": 6, "cases_ready": 2, "cases_incomplete": 1}
    assert set(out["queries"].values()) == set(QUERY_OUTCOMES)
    assert set(out["tickets"].values()) == set(FINDINGS)
    assert set(out["support"].values()) == set(RESOURCES)


def test_generator_is_deterministic_and_covers_every_outcome(policies, quiet_ui):
    a, b = generate_scenario(random.Random(11), policies), generate_scenario(random.Random(11), policies)
    assert a == b and a != generate_scenario(random.Random(12), policies)
    out = run_demo(quiet_ui, policies, a)
    assert set(out["queries"].values()) == set(QUERY_OUTCOMES)
    assert set(out["tickets"].values()) == set(FINDINGS)
    assert set(out["support"].values()) == set(RESOURCES)
    assert len(build_challenges(policies, a)) >= 12


def test_challenges_are_valid_and_self_answering_scores_100(policies, quiet_ui, data):
    qs = build_challenges(policies, data("sample_okta_system_log.json"))
    assert len(qs) >= 12
    assert all(q.objective in ("6.1", "6.2", "5.2") for q in qs)
    assert all(len(set(q.choices)) == len(q.choices) for q in qs)
    assert not any("lab" in (q.prompt + " ".join(q.choices)).lower().split() for q in qs)
    answers = iter([q.answer for q in qs])
    res = run_challenge(quiet_ui, 42, qs, ask=lambda _: next(answers), shuffle=False)
    assert res.correct == res.total == len(qs)
