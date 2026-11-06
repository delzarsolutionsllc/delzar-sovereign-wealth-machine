"""Lab 45 — ISC source aggregation, correlation and account deletion safety tests."""

from __future__ import annotations

import random

import pytest

from labs.lab45_isc_aggregation import (ACCOUNT_STATUSES, CORRELATION, SOURCE_OUTCOMES, aggregate,
                                        build_challenges, correlate, generate_scenario, run_demo)
from utils.challenge import run_challenge

IDS = [
    {"id": "ID-1", "attributes": {"employeeId": "E1", "email": "ava@x.example"}},
    {"id": "ID-2", "attributes": {"employeeId": "E2", "email": "ben@x.example"}},
    {"id": "ID-3", "attributes": {"employeeId": "E3", "email": "kai@x.example"}},
    {"id": "ID-4", "attributes": {"employeeId": "E4", "email": "kai@x.example"}},
]
PAIRS = [{"account_attribute": "employeeID", "identity_attribute": "employeeId"},
         {"account_attribute": "mail", "identity_attribute": "email"}]


@pytest.fixture
def cfg(policies):
    return policies["isc_aggregation"]


def acct(i, emp="", mail="", **extra):
    return {"id": i, "attributes": {"employeeID": emp, "mail": mail, **extra}, "entitlements": []}


def src(prev, cur, **kw):
    s = {"id": "S", "connector": "saas", "aggregation": {"mode": "full"}, "delete_threshold_percent": 10,
         "correlation": PAIRS, "previous_accounts": prev, "result": {"status": "ok", "accounts": cur}}
    s.update(kw)
    return s


def by_id(r):
    return {a.id: a for a in r.accounts}


# ----------------------------------------------------------------- correlation
def test_correlation_pairs_in_order_first_unique_match_wins():
    r = correlate(acct("a", emp="E1", mail="ben@x.example"), src([], []), IDS)
    assert (r.correlation, r.identity, r.matched_on) == ("CORRELATED", "ID-1", "employeeID->employeeId")


def test_correlation_falls_through_to_second_pair_and_is_case_insensitive():
    r = correlate(acct("a", emp="E99", mail="  BEN@X.example "), src([], []), IDS)
    assert (r.correlation, r.identity, r.matched_on) == ("CORRELATED", "ID-2", "mail->email")


def test_ambiguous_when_several_identities_match():
    r = correlate(acct("a", mail="kai@x.example"), src([], []), IDS)
    assert r.correlation == "AMBIGUOUS" and r.identity is None
    assert "ID-3" in r.reasons[-1] and "ID-4" in r.reasons[-1]


def test_empty_value_never_matches_and_no_config_is_uncorrelated():
    blank = [{"id": "ID-9", "attributes": {"employeeId": "", "email": ""}}]
    r = correlate(acct("a"), src([], []), IDS + blank)
    assert r.correlation == "UNCORRELATED" and all("skipped" in x for x in r.reasons[:2])
    r2 = correlate(acct("a", emp="E1"), src([], [], correlation=[]), IDS)
    assert r2.correlation == "UNCORRELATED"


def test_manual_correlation_overrides_pairs_and_unknown_target_is_uncorrelated():
    s = src([], [], manual_correlations={"a": "ID-2"})
    r = correlate(acct("a", emp="E1"), s, IDS)
    assert (r.correlation, r.identity, r.matched_on) == ("CORRELATED", "ID-2", "manual")
    r2 = correlate(acct("a", emp="E1"), src([], [], manual_correlations={"a": "ID-404"}), IDS)
    assert r2.correlation == "UNCORRELATED"
    r3 = correlate(acct("a", emp="E1"), src([], []), IDS, {"id": "a", "identity": "ID-3", "manually_correlated": True})
    assert (r3.identity, r3.matched_on) == ("ID-3", "manual")


def test_existing_correlation_is_kept():
    r = correlate(acct("a", emp="E1"), src([], []), IDS, {"id": "a", "identity": "ID-2"})
    assert (r.correlation, r.identity, r.matched_on) == ("CORRELATED", "ID-2", "existing")


# ----------------------------------------------------------------- diff and modes
def test_diff_new_changed_unchanged_removed(cfg):
    prev = [acct(f"u{i}", emp=f"E{i}") for i in range(1, 11)]
    cur = [dict(a) for a in prev[:9]]
    cur[0] = acct("u1", emp="E1", dept="Sales")
    cur.append(acct("new", emp="E2"))
    r = aggregate(src(prev, cur), IDS, cfg)
    a = by_id(r)
    assert r.outcome == "COMPLETED"
    assert (a["u1"].status, a["u2"].status, a["u10"].status, a["new"].status) == \
        ("CHANGED", "UNCHANGED", "REMOVED", "NEW")
    assert r.deleted == 1 and a["new"].correlation == "CORRELATED"


def test_entitlement_change_makes_account_changed(cfg):
    prev = [acct("u1", emp="E1")]
    cur = [dict(acct("u1", emp="E1"), entitlements=["Admins"])]
    r = aggregate(src(prev, cur), IDS, cfg)
    assert by_id(r)["u1"].status == "CHANGED" and "entitlements" in by_id(r)["u1"].reasons[0]


def test_optimized_skips_unchanged_and_unknown_mode_runs_full(cfg):
    prev = [acct("u1", emp="E1"), acct("u2", emp="E2")]
    cur = [acct("u1", emp="E1"), acct("u2", emp="E2", dept="IT")]
    r = aggregate(src(prev, cur, aggregation={"mode": "optimized"}), IDS, cfg)
    assert not by_id(r)["u1"].processed and by_id(r)["u1"].correlation is None
    assert by_id(r)["u2"].processed and by_id(r)["u2"].correlation == "CORRELATED"
    d = aggregate(src(prev, cur, aggregation={"mode": "delta"}), IDS, cfg)
    assert d.mode == "optimized"
    f = aggregate(src(prev, cur, aggregation={"mode": "turbo"}), IDS, cfg)
    assert f.mode == "full" and by_id(f)["u1"].processed and "unknown aggregation mode" in f.reasons[0]


# ----------------------------------------------------------------- delete threshold
def test_exactly_at_threshold_completes_above_it_aborts(cfg):
    prev = [acct(f"u{i}") for i in range(10)]
    at = aggregate(src(prev, prev[1:]), IDS, cfg)
    assert at.outcome == "COMPLETED" and at.deleted == 1 and at.removed_percent == 10
    over = aggregate(src(prev, prev[2:]), IDS, cfg)
    assert over.outcome == "ABORTED_DELETE_THRESHOLD" and over.deleted == 0 and over.deletions_prevented == 2
    assert all(not a.processed and a.correlation is None for a in over.accounts)


def test_empty_result_never_deletes_even_with_100_percent_threshold(cfg):
    prev = [acct(f"u{i}") for i in range(4)]
    r = aggregate(src(prev, [], connector="delimited_file", delete_threshold_percent=100), IDS, cfg)
    assert r.outcome == "ABORTED_DELETE_THRESHOLD" and r.deleted == 0 and r.deletions_prevented == 4


def test_missing_or_invalid_threshold_uses_default(cfg):
    prev = [acct(f"u{i}") for i in range(5)]
    s = src(prev, prev[1:])
    s.pop("delete_threshold_percent")
    r = aggregate(s, IDS, cfg)
    assert r.threshold == cfg["default_delete_threshold_percent"] and r.outcome == "ABORTED_DELETE_THRESHOLD"
    r2 = aggregate(src(prev, prev[1:], delete_threshold_percent="lots"), IDS, cfg)
    assert r2.threshold == cfg["default_delete_threshold_percent"] and r2.outcome == "ABORTED_DELETE_THRESHOLD"


# ----------------------------------------------------------------- source errors
@pytest.mark.parametrize("override,error", [
    ({"connector": "active_directory", "cluster": {"name": "C", "status": "UNREACHABLE"}}, "va_unreachable"),
    ({"connector": "jdbc"}, "va_unreachable"),
    ({"result": {"status": "error", "error": "auth_failure", "message": "401"}}, "auth_failure"),
    ({"result": {"status": "error", "error": "connection_failure"}}, "connection_failure"),
    ({"result": {"status": "error", "error": "weird"}}, "unknown_error"),
    ({"result": None}, "unknown_error"),
    ({"connector": "mainframe_magic"}, "unknown_error"),
    ({"connector": "delimited_file", "result": {"status": "ok", "accounts": [{"id": ""}]}}, "file_invalid"),
])
def test_failures_never_delete_and_say_where_to_look(cfg, override, error):
    prev = [acct(f"u{i}") for i in range(3)]
    r = aggregate(src(prev, prev, **override), IDS, cfg)
    assert r.outcome == "AGGREGATION_FAILED" and r.error == error
    assert r.deleted == 0 and r.accounts == [] and r.where == cfg["error_types"][error]["where"]


def test_saas_connector_ignores_cluster_and_va_needs_healthy_cluster(cfg):
    prev = [acct("u1")]
    assert aggregate(src(prev, prev, cluster={"status": "UNREACHABLE"}), IDS, cfg).outcome == "COMPLETED"
    ok = aggregate(src(prev, prev, connector="ldap", cluster={"name": "C", "status": "HEALTHY"}), IDS, cfg)
    assert ok.outcome == "COMPLETED" and ok.kind == "va"


# ----------------------------------------------------------------- entitlements
def test_entitlement_aggregation_new_removed_and_empty_is_safe(cfg):
    prev = [acct("u1")]
    s = src(prev, prev, previous_entitlements=["A", "B"], entitlement_result={"status": "ok", "entitlements": ["A", "C"]})
    r = aggregate(s, IDS, cfg)
    assert r.entitlement_run and r.new_entitlements == ["C"] and r.removed_entitlements == ["B"]
    s2 = src(prev, prev, previous_entitlements=["A", "B"], entitlement_result={"status": "ok", "entitlements": []})
    r2 = aggregate(s2, IDS, cfg)
    assert r2.entitlement_run and r2.removed_entitlements == []
    r3 = aggregate(src(prev, prev, previous_entitlements=["A"]), IDS, cfg)
    assert not r3.entitlement_run


# ----------------------------------------------------------------- sample data
def test_sample_outcomes(policies, quiet_ui, data):
    out = run_demo(quiet_ui, policies, data("sample_isc_aggregation.json"))
    assert out["sources"] == {"SRC-AD": "COMPLETED", "SRC-CHAT": "COMPLETED", "SRC-FINDB": "AGGREGATION_FAILED",
                              "SRC-BADGE": "ABORTED_DELETE_THRESHOLD", "SRC-LDAP": "ABORTED_DELETE_THRESHOLD",
                              "SRC-VIDEO": "AGGREGATION_FAILED", "SRC-PORTAL": "AGGREGATION_FAILED",
                              "SRC-TRAIN": "COMPLETED"}
    assert out["errors"] == {"SRC-FINDB": "va_unreachable", "SRC-VIDEO": "auth_failure",
                             "SRC-PORTAL": "connection_failure"}
    assert out["accounts"]["SRC-AD"]["fbyrne"] == "REMOVED"
    assert out["correlation"]["SRC-AD"]["lvogel"] == "CORRELATED"
    assert out["correlation"]["SRC-AD"]["test-admin"] == "UNCORRELATED"
    assert out["correlation"]["SRC-CHAT"]["kai.nakamura@halden.example"] == "AMBIGUOUS"
    assert out["entitlements"]["SRC-AD"] == {"new": ["CN=Payroll Readers"], "removed": ["CN=Old Print Ops"]}
    assert out["metrics"] == {"sources": 8, "completed": 3, "aborted": 2, "failed": 3, "new": 4, "changed": 5,
                              "unchanged": 14, "skipped": 4, "deleted": 1, "deletions_prevented": 9,
                              "correlated": 15, "uncorrelated": 3, "ambiguous": 1, "new_entitlements": 2,
                              "removed_entitlements": 1}
    assert set(out["sources"].values()) == set(SOURCE_OUTCOMES)
    assert {v for d in out["accounts"].values() for v in d.values()} == set(ACCOUNT_STATUSES)
    assert {v for d in out["correlation"].values() for v in d.values()} == set(CORRELATION)


def test_generator_is_deterministic_and_covers_every_outcome(policies, quiet_ui):
    a, b = generate_scenario(random.Random(11), policies), generate_scenario(random.Random(11), policies)
    assert a == b and a != generate_scenario(random.Random(12), policies)
    for seed in range(10):
        g = generate_scenario(random.Random(seed), policies)
        out = run_demo(quiet_ui, policies, g)
        assert set(out["sources"].values()) == set(SOURCE_OUTCOMES)
        assert {v for d in out["correlation"].values() for v in d.values()} == set(CORRELATION)
        assert {v for d in out["accounts"].values() for v in d.values()} == set(ACCOUNT_STATUSES)
        assert len(build_challenges(policies, g)) >= 12


def test_challenges_are_valid_and_self_answering_scores_100(policies, quiet_ui, data):
    qs = build_challenges(policies, data("sample_isc_aggregation.json"))
    assert len(qs) >= 12
    assert all(q.objective in ("7.1", "7.2", "7.3") for q in qs)
    assert all(len(set(q.choices)) == len(q.choices) for q in qs)
    assert not any("lab" in (q.prompt + " ".join(q.choices)).lower().split() for q in qs)
    answers = iter([q.answer for q in qs])
    res = run_challenge(quiet_ui, 45, qs, ask=lambda _: next(answers), shuffle=False)
    assert res.correct == res.total == len(qs)
