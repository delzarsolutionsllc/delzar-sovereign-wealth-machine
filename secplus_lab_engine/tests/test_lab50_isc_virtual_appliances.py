"""Lab 50 — ISC virtual appliance clusters: health, networking and troubleshooting tests."""

from __future__ import annotations

import copy
import random

import pytest

from labs.lab50_isc_virtual_appliances import (CAUSES, CHANGES, CLUSTER, HEALTH, PLACEMENT, build_challenges,
                                               check_placement, cluster_status, diagnose, generate_scenario,
                                               review_change, run_demo, va_health)
from utils.challenge import run_challenge

SAMPLE = "sample_isc_virtual_appliances.json"


@pytest.fixture
def cfg(policies):
    return policies["isc_virtual_appliances"]


CL = {"id": "CL-A", "environment": "production", "site": "Amsterdam", "dmz": False,
      "key_passphrase_fingerprint": "kp-a"}


def good(cfg, vid="VA-1", host="esx-1", dc="DC1", **over):
    v = {"id": vid, "cluster": "CL-A", "host": host, "datacenter": dc, "last_heartbeat_minutes_ago": 1,
         "outbound_443": {e: True for e in cfg["required_endpoints"]}, "dns": "ok",
         "ntp": {"synced": True, "skew_seconds": 0.5}, "proxy": {"required": False, "configured": False},
         "disk_used_pct": 40, "memory_used_pct": 50, "services": {"ccg": "running", "charon": "running"},
         "ccg_restarts_30min": 0, "keys": {"config_yaml": True, "key_passphrase_fingerprint": "kp-a"},
         "cert_min_days_left": None, "release": cfg["current_release"], "os_reboot_pending": False}
    v.update(over)
    return v


def estate(cfg, *vas, clusters=None):
    return {"clusters": clusters or [dict(CL)], "vas": list(vas)}


# ------------------------------------------------------------------ health
def test_healthy_va(cfg):
    r = va_health(good(cfg), CL, cfg)
    assert r.health == "HEALTHY" and r.failed == []


@pytest.mark.parametrize("over, check", [
    ({"last_heartbeat_minutes_ago": 45}, "heartbeat"),
    ({"services": {"ccg": "running", "charon": "stopped"}}, "charon"),
    ({"services": {"ccg": "stopped", "charon": "running"}}, "ccg"),
    ({"proxy": {"required": True, "configured": False}}, "proxy"),
    ({"proxy": {"required": False, "configured": True}}, "proxy"),
    ({"dns": "failing"}, "dns"),
    ({"outbound_443": {"tenant": True}}, "outbound_443"),
    ({"ntp": {"synced": True, "skew_seconds": 300}}, "ntp"),
    ({"ntp": {"synced": False, "skew_seconds": 1}}, "ntp"),
    ({"disk_used_pct": 90}, "disk_error"),
    ({"memory_used_pct": 95}, "memory_error"),
    ({"keys": {"config_yaml": True, "key_passphrase_fingerprint": "kp-other"}}, "keys"),
    ({"keys": {"config_yaml": False}}, "keys"),
])
def test_each_unhealthy_check(cfg, over, check):
    r = va_health(good(cfg, **over), CL, cfg)
    assert r.health == "UNHEALTHY" and r.failed[0] == check


@pytest.mark.parametrize("over, check", [
    ({"disk_used_pct": 80}, "disk_warning"),
    ({"memory_used_pct": 85}, "memory_warning"),
    ({"ccg_restarts_30min": 11}, "ccg_restarts"),
    ({"cert_min_days_left": 30}, "certificate"),
    ({"cert_min_days_left": -2}, "certificate"),
    ({"release": "2026.07"}, "release"),
    ({"os_reboot_pending": True}, "reboot_pending"),
])
def test_each_degraded_check(cfg, over, check):
    r = va_health(good(cfg, **over), CL, cfg)
    assert r.health == "DEGRADED" and r.failed == [check]


def test_thresholds_are_inclusive_and_boundaries(cfg):
    assert va_health(good(cfg, disk_used_pct=79, cert_min_days_left=31, ccg_restarts_30min=10,
                          last_heartbeat_minutes_ago=10), CL, cfg).health == "HEALTHY"


def test_missing_values_deny_by_default(cfg):
    bare = {"id": "VA-X", "cluster": "CL-A"}
    r = va_health(bare, CL, cfg)
    assert r.health == "UNHEALTHY"
    assert {"heartbeat", "charon", "ccg", "proxy", "dns", "outbound_443", "ntp", "disk_error", "memory_error",
            "keys"} <= set(r.failed)
    # A VA whose cluster is unknown cannot prove its keyPassphrase.
    assert va_health(good(cfg, cluster="CL-NOPE"), None, cfg).failed == ["keys"]


# ------------------------------------------------------------------ clusters
def test_cluster_redundant_spof_down(cfg):
    a, b = good(cfg, "VA-1", "esx-1"), good(cfg, "VA-2", "esx-2")
    d = estate(cfg, a, b)
    res = [va_health(v, CL, cfg) for v in d["vas"]]
    assert cluster_status(CL, d["vas"], res, cfg).status == "REDUNDANT"
    # Same host: not redundant.
    b2 = good(cfg, "VA-2", "esx-1")
    res = [va_health(v, CL, cfg) for v in (a, b2)]
    assert cluster_status(CL, [a, b2], res, cfg).status == "SINGLE_POINT_OF_FAILURE"
    # One working VA plus one unhealthy.
    bad = good(cfg, "VA-2", "esx-2", dns="failing")
    res = [va_health(v, CL, cfg) for v in (a, bad)]
    c = cluster_status(CL, [a, bad], res, cfg)
    assert c.status == "SINGLE_POINT_OF_FAILURE" and any("pauses updates" in r for r in c.reasons)
    # Degraded still counts as working.
    deg = good(cfg, "VA-2", "esx-2", disk_used_pct=85)
    res = [va_health(v, CL, cfg) for v in (a, deg)]
    assert cluster_status(CL, [a, deg], res, cfg).status == "REDUNDANT"
    # No working VA, and an empty cluster.
    res = [va_health(bad, CL, cfg)]
    assert cluster_status(CL, [bad], res, cfg).status == "DOWN"
    assert cluster_status(CL, [], [], cfg).status == "DOWN"


def test_missing_host_is_not_redundant(cfg):
    a, b = good(cfg, "VA-1", "esx-1"), good(cfg, "VA-2", None)
    res = [va_health(v, CL, cfg) for v in (a, b)]
    assert cluster_status(CL, [a, b], res, cfg).status == "SINGLE_POINT_OF_FAILURE"


# ------------------------------------------------------------------ tickets
def test_diagnosis_order_dns_beats_443(cfg):
    v = good(cfg, dns="failing", outbound_443={})
    t = diagnose({"id": "T", "symptom": "va_disconnected", "va": "VA-1"}, estate(cfg, v), cfg)
    assert t.cause == "DNS_FAILURE" and t.command == cfg["va_knowledge"]["commands"]["dns_lookup"]
    v = good(cfg, proxy={"required": True, "configured": False}, dns="failing")
    assert diagnose({"id": "T", "symptom": "va_disconnected", "va": "VA-1"}, estate(cfg, v), cfg).cause == \
        "PROXY_MISCONFIGURED"


@pytest.mark.parametrize("over, cause", [
    ({"outbound_443": {"tenant": True}}, "OUTBOUND_443_BLOCKED"),
    ({"ntp": {"synced": True, "skew_seconds": 400}}, "NTP_TIME_SKEW"),
    ({"services": {"ccg": "stopped", "charon": "running"}}, "CCG_SERVICE_DOWN"),
    ({"memory_used_pct": 88}, "RESOURCE_EXHAUSTION"),
    ({"cert_min_days_left": -1}, "CERTIFICATE_TRUST"),
])
def test_ticket_causes(cfg, over, cause):
    t = diagnose({"id": "T", "symptom": "aggregation_timeout", "va": "VA-1"}, estate(cfg, good(cfg, **over)), cfg)
    assert t.cause == cause and t.next_step and t.log
    assert cfg["do_not"] in t.reasons


def test_cluster_ticket_scans_every_va_and_certificate_error_text(cfg):
    d = estate(cfg, good(cfg, "VA-1", "esx-1", disk_used_pct=85),
               good(cfg, "VA-2", "esx-2", outbound_443={"tenant": True}))
    t = diagnose({"id": "T", "symptom": "after_network_change", "cluster": "CL-A"}, d, cfg)
    assert t.cause == "OUTBOUND_443_BLOCKED" and t.checked == ["VA-1", "VA-2"]
    t = diagnose({"id": "T", "symptom": "test_connection_fails", "va": "VA-1", "error": "PKIX path building failed"},
                 estate(cfg, good(cfg)), cfg)
    assert t.cause == "CERTIFICATE_TRUST" and t.command == "sudo systemctl restart ccg"


def test_source_side_versus_needs_evidence(cfg):
    d = estate(cfg, good(cfg))
    assert diagnose({"id": "T", "symptom": "test_connection_fails", "va": "VA-1"}, d, cfg).cause == \
        "SOURCE_CONNECTIVITY"
    # A healthy VA "showing disconnected" has no evidence: never guessed.
    assert diagnose({"id": "T", "symptom": "va_disconnected", "va": "VA-1"}, d, cfg).cause == "NEEDS_EVIDENCE"
    # A heartbeat-only failure is not blamed on the source.
    d2 = estate(cfg, good(cfg, last_heartbeat_minutes_ago=None))
    assert diagnose({"id": "T", "symptom": "aggregation_timeout", "va": "VA-1"}, d2, cfg).cause == "NEEDS_EVIDENCE"


@pytest.mark.parametrize("ticket", [
    {"id": "T"}, {"id": "T", "symptom": "printer_jam", "va": "VA-1"},
    {"id": "T", "symptom": "va_disconnected", "va": "VA-99"},
    {"id": "T", "symptom": "va_disconnected", "cluster": "CL-NOPE"},
    {"id": "T", "symptom": "va_disconnected"},
])
def test_unknown_ticket_input_needs_evidence(cfg, ticket):
    t = diagnose(ticket, estate(cfg, good(cfg)), cfg)
    assert t.cause == "NEEDS_EVIDENCE" and "STUNT" in t.next_step


# ------------------------------------------------------------------ deployment
def test_placement_rules(cfg):
    ok = estate(cfg, good(cfg, "VA-1", "esx-1", "DC1"), good(cfg, "VA-2", "esx-2", "DC2"),
                clusters=[dict(CL), {"id": "CL-S", "environment": "sandbox", "key_passphrase_fingerprint": "kp-s"}])
    ok["vas"] += [good(cfg, "VA-3", "esx-3", "DC1", cluster="CL-S"), good(cfg, "VA-4", "esx-4", "DC1", cluster="CL-S")]
    res, tenant = check_placement(ok, cfg)
    assert [r.outcome for r in res] == ["COMPLIANT", "COMPLIANT"] and tenant == []
    for mutate, text in [(lambda d: d["vas"][1].update(host="esx-1"), "1 VA per host"),
                         (lambda d: d["vas"][1].update(datacenter="DC1"), "HA/DR"),
                         (lambda d: d["clusters"][0].update(dmz=True), "DMZ"),
                         (lambda d: d["vas"][1].pop("datacenter"), "no host or datacenter"),
                         (lambda d: d["vas"].pop(1), "at least 2")]:
        d = copy.deepcopy(ok)
        mutate(d)
        r = check_placement(d, cfg)[0][0]
        assert r.outcome == "NON_COMPLIANT" and any(text in g for g in r.reasons), text
    d = copy.deepcopy(ok)
    d["clusters"] = d["clusters"][:1]
    assert any("no sandbox cluster" in t for t in check_placement(d, cfg)[1])


@pytest.mark.parametrize("change, outcome", [
    ({"id": "C", "va": "VA-1", "action": "configure_proxy"}, "VALID"),
    ({"id": "C", "cluster": "CL-A", "action": "add_va_to_cluster"}, "VALID"),
    ({"id": "C", "va": "VA-1", "action": "install_antivirus"}, "NOT_SUPPORTED"),
    ({"id": "C", "va": "VA-1", "action": "install_packages"}, "NOT_SUPPORTED"),
    ({"id": "C", "va": "VA-1", "action": "migrate_va"}, "NOT_SUPPORTED"),
    ({"id": "C", "va": "VA-1", "action": "make_it_faster"}, "NOT_SUPPORTED"),
    ({"id": "C", "va": "VA-1"}, "NOT_SUPPORTED"),
    ({"id": "C", "va": "VA-99", "action": "restart_ccg"}, "NOT_SUPPORTED"),
])
def test_change_requests(cfg, change, outcome):
    assert review_change(change, estate(cfg, good(cfg)), cfg).outcome == outcome


# ------------------------------------------------------------------ sample, generator, challenges
def test_sample_expected_outcomes(policies, quiet_ui, data):
    out = run_demo(quiet_ui, policies, data(SAMPLE))
    assert out["health"] == {"VA-01": "HEALTHY", "VA-02": "DEGRADED", "VA-03": "UNHEALTHY", "VA-04": "HEALTHY",
                             "VA-05": "HEALTHY", "VA-06": "UNHEALTHY", "VA-07": "UNHEALTHY", "VA-08": "UNHEALTHY",
                             "VA-09": "UNHEALTHY", "VA-10": "UNHEALTHY", "VA-11": "DEGRADED", "VA-12": "UNHEALTHY",
                             "VA-13": "DEGRADED", "VA-14": "HEALTHY"}
    assert out["clusters"] == {"CL-AMS-PROD": "REDUNDANT", "CL-CHI-PROD": "SINGLE_POINT_OF_FAILURE",
                               "CL-SGP-PROD": "DOWN", "CL-LON-PROD": "REDUNDANT",
                               "CL-AMS-SBX": "SINGLE_POINT_OF_FAILURE"}
    assert out["tickets"] == {"T1": "PROXY_MISCONFIGURED", "T2": "DNS_FAILURE", "T3": "NTP_TIME_SKEW",
                              "T4": "OUTBOUND_443_BLOCKED", "T5": "CCG_SERVICE_DOWN", "T6": "RESOURCE_EXHAUSTION",
                              "T7": "CERTIFICATE_TRUST", "T8": "SOURCE_CONNECTIVITY", "T9": "NEEDS_EVIDENCE",
                              "T10": "NEEDS_EVIDENCE"}
    assert out["placement"] == {"CL-AMS-PROD": "COMPLIANT", "CL-CHI-PROD": "NON_COMPLIANT",
                                "CL-SGP-PROD": "COMPLIANT", "CL-LON-PROD": "NON_COMPLIANT",
                                "CL-AMS-SBX": "NON_COMPLIANT"}
    m = out["metrics"]
    assert m["health"] == {"HEALTHY": 4, "DEGRADED": 3, "UNHEALTHY": 7}
    assert m["tickets_explained"] == 8 and m["changes"] == {"VALID": 5, "NOT_SUPPORTED": 6}
    for vocab, key in ((HEALTH, "health"), (CLUSTER, "clusters"), (CAUSES, "tickets"), (PLACEMENT, "placement"),
                       (CHANGES, "changes")):
        assert set(out[key].values()) == set(vocab)


def test_generator_is_deterministic_and_covers_every_outcome(policies, quiet_ui):
    a, b = generate_scenario(random.Random(11), policies), generate_scenario(random.Random(11), policies)
    assert a == b and a != generate_scenario(random.Random(12), policies)
    out = run_demo(quiet_ui, policies, a)
    for vocab, key in ((HEALTH, "health"), (CLUSTER, "clusters"), (CAUSES, "tickets"), (PLACEMENT, "placement"),
                       (CHANGES, "changes")):
        assert set(out[key].values()) == set(vocab), key
    assert len(build_challenges(policies, a)) >= 12


def test_challenges_are_valid_and_self_answering_scores_100(policies, quiet_ui, data):
    qs = build_challenges(policies, data(SAMPLE))
    assert len(qs) >= 12
    assert all(q.objective in ("2.1", "2.2") for q in qs)
    assert all(len(set(q.choices)) == len(q.choices) for q in qs)
    assert not any("lab" in (q.prompt + " " + " ".join(q.choices)).lower().split() for q in qs)
    answers = iter([q.answer for q in qs])
    res = run_challenge(quiet_ui, 50, qs, ask=lambda _: next(answers), shuffle=False)
    assert res.correct == res.total == len(qs)
