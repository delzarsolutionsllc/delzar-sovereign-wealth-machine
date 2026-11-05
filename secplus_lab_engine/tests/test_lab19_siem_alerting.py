"""Lab 19 — SIEM correlation & alert tuning tests."""

from __future__ import annotations

import copy

import pytest

from labs.lab19_siem_alerting import build_challenges, evaluate, parse_ts, run_demo, score

T0 = 1791936000  # 2026-10-14T00:00:00Z, a Wednesday


@pytest.fixture
def pol(policies):
    return copy.deepcopy(policies)


def feed(*events, window=(T0, T0 + 3600)):
    evs = [{"id": f"E{i}", "scenario": "S", **e} for i, e in enumerate(events, 1)]
    return {"window": {"start": window[0], "end": window[1]}, "scenarios": {"S": {"label": "actionable"}}, "events": evs}


def fails(n, user="u1", ip="203.0.113.9", step=10, start=T0 + 60):
    return [{"ts": start + i * step, "source": "auth", "action": "login", "outcome": "failure", "user": user,
             "src_ip": ip, "host": "VPN-1"} for i in range(n)]


def R(pol, rid):
    return next(r for r in pol["siem"]["rules"] if r["id"] == rid)


def rules(alerts):
    return sorted(a.rule_id for a in alerts if a.rule_id != "SIEM-005")


def test_parse_ts_is_deterministic_and_strict():
    assert parse_ts(T0) == T0 and parse_ts("2026-10-14T00:00:00Z") == T0
    assert parse_ts("2026-10-14T02:00:00+02:00") == T0
    assert parse_ts("2026-10-14T00:00:00") is None          # no timezone: do not guess
    assert parse_ts("14/10/2026 25:61") is None and parse_ts(None) is None and parse_ts(True) is None


def test_bad_event_raises_parse_alert_not_dropped(pol):
    a = evaluate(feed({"ts": "yesterday", "source": "auth"}, {"ts": T0, "source": "printer"}, {"source": "app"}), pol)
    parse = [x for x in a if x.rule_id == "SIEM-000"]
    text = " ".join(r for x in parse for r in x.reasons)
    assert len(parse) == 3 and "unparseable" in text and "unknown log source" in text and "missing" in text


def test_brute_force_threshold_boundary(pol):
    n = R(pol, "SIEM-001")["params"]["count"]
    assert "SIEM-001" not in rules(evaluate(feed(*fails(n - 1)), pol))
    a = [x for x in evaluate(feed(*fails(n)), pol) if x.rule_id == "SIEM-001"]
    assert len(a) == 1 and a[0].severity == "high" and len(a[0].evidence) == n


def test_failures_outside_window_do_not_correlate(pol):
    w = R(pol, "SIEM-001")["params"]["window_seconds"]
    assert "SIEM-001" not in rules(evaluate(feed(*fails(6, step=w)), pol))


def test_brute_force_then_success_escalates_to_critical(pol):
    ok = {"ts": T0 + 200, "source": "auth", "action": "login", "outcome": "success", "user": "u1",
          "src_ip": "203.0.113.9", "geo": "London"}
    a = next(x for x in evaluate(feed(*fails(5), ok), pol) if x.rule_id == "SIEM-001")
    assert a.severity == "critical" and "compromise" in a.reasons[-1] and "disable the account" in a.response


def test_password_spraying_distinct_users(pol):
    evs = [f for i in range(4) for f in fails(1, user=f"user{i}", start=T0 + 60 + i)]
    assert rules(evaluate(feed(*evs), pol)) == ["SIEM-002"]


def test_impossible_travel_and_unknown_geo(pol):
    def ok(t, geo):
        return {"ts": t, "source": "auth", "action": "login", "outcome": "success", "user": "u2", "geo": geo}
    fast = evaluate(feed(ok(T0 + 60, "London"), ok(T0 + 3000, "New York")), pol)
    slow = evaluate(feed(ok(T0 + 60, "London"), ok(T0 + 3000 + 9 * 3600, "New York"), window=(T0, T0 + 10 * 3600)), pol)
    unknown = evaluate(feed(ok(T0 + 60, "London"), ok(T0 + 120, "Atlantis")), pol)
    assert "SIEM-003" in rules(fast) and "SIEM-003" not in rules(slow)
    assert "cannot be verified" in next(x for x in unknown if x.rule_id == "SIEM-003").reasons[0]


def test_after_hours_privileged_action(pol):
    act = {"source": "app", "action": "add_admin", "user": "adm", "host": "ERP-1"}
    assert rules(evaluate(feed({**act, "ts": T0 + 2 * 3600}, window=(T0, T0 + 3 * 3600)), pol)) == ["SIEM-004"]
    day = T0 + 10 * 3600
    assert rules(evaluate(feed({**act, "ts": day}, window=(day - 60, day + 60)), pol)) == []


def test_source_silence_is_a_blind_spot(pol):
    gaps = R(pol, "SIEM-005")["params"]["max_gap_seconds"]
    evs = [{"ts": T0 + 10, "source": s} for s in gaps]
    a = evaluate(feed(*evs, window=(T0, T0 + gaps["dns"] + 60)), pol)
    assert [x.entities["source"] for x in a if x.rule_id == "SIEM-005"] == ["dns"]


def test_suppression_owner_expiry_and_critical(pol):
    scan = [{"ts": T0 + 10 + i, "source": "firewall", "src_ip": "10.0.5.20", "dst_port": p} for i, p in enumerate(range(20, 25))]
    a = next(x for x in evaluate(feed(*scan), pol) if x.rule_id == "SIEM-007")
    assert a.disposition == "SUPPRESSED" and "SUP-1" in a.tuning[0]
    pol["siem"]["suppressions"][0]["expires"] = "2026-10-01T00:00:00Z"
    a = next(x for x in evaluate(feed(*scan), pol) if x.rule_id == "SIEM-007")
    assert a.disposition == "ALERT" and "expired" in a.tuning[0]
    pol["siem"]["suppressions"][0].update(expires="2027-01-01T00:00:00Z", owner="")
    assert next(x for x in evaluate(feed(*scan), pol) if x.rule_id == "SIEM-007").disposition == "ALERT"
    pol["siem"]["suppressions"][0].update(owner="vm", match={})
    assert next(x for x in evaluate(feed(*scan), pol) if x.rule_id == "SIEM-007").disposition == "ALERT"
    R(pol, "SIEM-007")["severity"] = "critical"
    pol["siem"]["suppressions"][0]["match"] = {"src_ip": "10.0.5.20"}
    a = next(x for x in evaluate(feed(*scan), pol) if x.rule_id == "SIEM-007")
    assert a.disposition == "ALERT" and "never suppressed" in a.tuning[0]


def test_threshold_comes_from_policy(pol):
    R(pol, "SIEM-001")["params"]["count"] = 3
    assert "SIEM-001" in rules(evaluate(feed(*fails(3)), pol))


def test_sample_outcomes_and_metrics(policies, data, quiet_ui):
    d = data("sample_security_events.json")
    alerts = evaluate(d, policies)
    assert sorted({a.rule_id for a in alerts}) == [f"SIEM-00{i}" for i in range(9)]
    summary = run_demo(quiet_ui, policies, d)
    assert list(summary.values()).count("SUPPRESSED") == 1 and len(summary) == 12
    by = {(a.rule_id, a.entities.get("src_ip")): a for a in alerts}
    assert by[("SIEM-007", "10.0.5.20")].disposition == "SUPPRESSED"
    assert by[("SIEM-007", "10.0.5.99")].disposition == "ALERT"
    assert by[("SIEM-001", "203.0.113.50")].severity == "critical"
    raw, tuned = score(alerts, d, tuned=False), score(alerts, d)
    assert (raw.tp, raw.fp, tuned.fp, tuned.fn, tuned.missed) == (10, 2, 1, 1, ["S10"])
    assert tuned.precision > raw.precision and tuned.recall == raw.recall
    assert len(build_challenges(policies, d)) >= 8
