"""Lab 26 — identity governance (account reconciliation & access certification) tests."""

from __future__ import annotations

import copy

import pytest

from labs.lab26_identity_governance import build_challenges, certify, reconcile, run_demo


@pytest.fixture
def cfg(policies):
    return policies["identity_governance_iga"]


IDS = [
    {"employee_id": "E1", "email": "a@example.com", "status": "active", "manager": "E9"},
    {"employee_id": "E2", "email": "b@example.com", "status": "terminated", "manager": "E9"},
    {"employee_id": "E9", "email": "m@example.com", "status": "active", "manager": None},
]


def acct(**kw):
    base = {"id": "A1", "app": "ERP", "account": "x", "last_login_days_ago": 1}
    base.update(kw)
    return base


def recon(cfg, *accounts, identities=IDS):
    return reconcile({"identities": identities, "accounts": list(accounts)}, cfg)


def test_correlation_by_employee_id_then_email(cfg):
    r = recon(cfg, acct(employee_id="E1"), acct(id="A2", app="CRM", email="A@EXAMPLE.COM"))
    assert [(x.finding, x.identity, x.rule) for x in r] == [("CORRELATED", "E1", "employee_id"),
                                                          ("CORRELATED", "E1", "email")]


def test_orphan_and_privileged_unowned(cfg):
    orphan, priv = recon(cfg, acct(employee_id="E404"), acct(id="A2", privileged=True))
    assert orphan.finding == "ORPHAN" and orphan.action == "DISABLE"
    assert priv.finding == "PRIVILEGED_UNOWNED" and "ORPHAN" in priv.findings


def test_terminated_with_access_but_disabled_is_done(cfg):
    on, off = recon(cfg, acct(employee_id="E2"), acct(id="A2", app="CRM", employee_id="E2", enabled=False))
    assert on.finding == "TERMINATED_WITH_ACCESS" and on.action == "REVOKE"
    assert off.finding == "CORRELATED" and any("already disabled" in r for r in off.reasons)


def test_unknown_hr_status_treated_as_terminated(cfg):
    ids = [{"employee_id": "E1", "status": "contractor?"}]
    assert recon(cfg, acct(employee_id="E1"), identities=ids)[0].finding == "TERMINATED_WITH_ACCESS"


def test_service_account_needs_active_owner(cfg):
    ok, none, gone = recon(cfg, acct(type="service", owner="E1"), acct(id="A2", type="service"),
                           acct(id="A3", type="service", owner="E2"))
    assert ok.finding == "CORRELATED" and ok.rule == "owner"
    assert none.finding == gone.finding == "PRIVILEGED_UNOWNED"


def test_dormant_boundary_and_missing_login(cfg):
    limit = cfg["dormant_after_days"]
    at, over, missing = recon(cfg, acct(employee_id="E1", last_login_days_ago=limit),
                              acct(id="A2", app="CRM", employee_id="E1", last_login_days_ago=limit + 1),
                              acct(id="A3", app="X", employee_id="E1", last_login_days_ago=None))
    assert at.finding == "CORRELATED" and over.finding == "DORMANT" and missing.finding == "DORMANT"


def test_duplicate_second_account_same_app(cfg):
    first, second = recon(cfg, acct(employee_id="E1"), acct(id="A2", account="x2", employee_id="E1"))
    assert first.finding == "CORRELATED" and second.finding == "DUPLICATE"


def camp(items, entitlements=None):
    ents = entitlements or {"ERP:LOW": {"risk": "low", "owner": "E9"}, "ERP:HI": {"risk": "high", "owner": "E9"}}
    return {"identities": IDS, "entitlements": ents, "campaign": {"items": items}}


def item(**kw):
    base = {"id": "C1", "identity": "E1", "app": "ERP", "entitlement": "LOW", "reviewer": "E9",
            "decision": "approve", "decided_at_seconds": 100, "comment": ""}
    base.update(kw)
    return base


def test_certification_keep_revoke_self_review_and_no_decision(cfg):
    res, metrics = certify(camp([item(), item(id="C2", identity="E2"), item(id="C3", reviewer="E1"),
                                 item(id="C4", decision="none", decided_at_seconds=None),
                                 item(id="C5", reviewer="E2")]), cfg)
    assert [r.outcome for r in res] == ["KEEP", "REVOKE", "ESCALATE", "REVOKE", "ESCALATE"]
    assert "self-review" in res[2].reasons[0] and metrics["completion_pct"] == 80.0


def test_high_risk_needs_comment_and_unknown_entitlement_is_high(cfg):
    res, _ = certify(camp([item(entitlement="HI"), item(id="C2", entitlement="HI", comment="needed"),
                           item(id="C3", entitlement="NOT_IN_CATALOG")]), cfg)
    assert [r.outcome for r in res] == ["ESCALATE", "KEEP", "ESCALATE"]


def test_sod_conflict_flags_both_approvals(cfg):
    a, b = cfg["sod_conflicts"][0]["pair"]
    ents = {e: {"risk": "low", "owner": "E9"} for e in (a, b)}
    res, _ = certify(camp([item(app=a.split(":")[0], entitlement=a.split(":")[1]),
                           item(id="C2", app=b.split(":")[0], entitlement=b.split(":")[1])], ents), cfg)
    assert all(r.outcome == "ESCALATE" and "SoD" in r.reasons[0] for r in res)


def test_rubber_stamp_threshold_is_policy_driven(cfg):
    rs = cfg["campaign"]["rubber_stamp"]
    n = rs["min_approvals"]
    fast = [item(id=f"C{i}", decided_at_seconds=i * (rs["max_median_seconds"] - 1)) for i in range(1, n + 1)]
    res, metrics = certify(camp(fast), cfg)
    assert metrics["rubber_stamp_reviewers"] == ["E9"] and all(r.outcome == "ESCALATE" for r in res)
    _, m2 = certify(camp(fast[:-1]), cfg)
    assert m2["rubber_stamp_reviewers"] == []


def test_allowed_reviewers_is_policy_driven(cfg):
    owner_review = camp([item(reviewer="E7")], {"ERP:LOW": {"risk": "low", "owner": "E7"}})
    assert certify(owner_review, cfg)[0][0].outcome == "KEEP"
    strict = copy.deepcopy(cfg)
    strict["campaign"]["allowed_reviewers"] = ["manager"]
    assert certify(owner_review, strict)[0][0].outcome == "ESCALATE"


def test_sample_demo_and_challenges(policies, quiet_ui, data):
    sample = data("sample_governance.json")
    out = run_demo(quiet_ui, policies, sample)
    assert set(out["accounts"].values()) == {"CORRELATED", "ORPHAN", "TERMINATED_WITH_ACCESS", "DORMANT",
                                             "PRIVILEGED_UNOWNED", "DUPLICATE"}
    assert out["items"] == {"C01": "KEEP", "C02": "ESCALATE", "C03": "ESCALATE", "C04": "ESCALATE",
                            "C05": "ESCALATE", "C06": "ESCALATE", "C07": "REVOKE", "C08": "ESCALATE",
                            "C09": "ESCALATE", "C10": "ESCALATE", "C11": "KEEP", "C12": "REVOKE", "C13": "KEEP",
                            "C14": "REVOKE", "C15": "ESCALATE", "C16": "REVOKE"}
    assert out["metrics"]["rubber_stamp_reviewers"] == ["E1008"] and out["metrics"]["completion_pct"] == 93.8
    qs = build_challenges(policies, sample)
    assert len(qs) >= 10 and all(q.answer in q.choices for q in qs)
