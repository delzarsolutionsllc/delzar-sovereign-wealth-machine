"""Lab 25 — Conditional Access & just-in-time privileged access tests."""

from __future__ import annotations

import pytest

from labs.lab25_conditional_access import (assess_assignments, build_challenges, decide_activation, evaluate_signin,
                                           policy_applies, resolve_location, run_demo)


@pytest.fixture
def cfg(policies):
    return policies["conditional_access"]


def S(**kw):
    base = {"id": "X", "user": "u1", "groups": ["Staff"], "app": "Wiki", "ip": "10.20.0.5", "risk": "low",
            "client_app": "browser", "device": {"platform": "windows", "compliant": True}, "mfa_satisfied": False}
    base.update(kw)
    return base


ELIG = [{"user": "heidi", "role": "Global Administrator", "type": "eligible"},
        {"user": "oscar", "role": "Helpdesk Administrator", "type": "eligible"}]


def R(**kw):
    base = {"id": "R", "user": "oscar", "role": "Helpdesk Administrator", "duration_hours": 4,
            "justification": "queue", "mfa_done": True}
    base.update(kw)
    return base


def test_named_locations(cfg):
    assert resolve_location("10.20.9.9", cfg) == "HQ-Tulsa"
    assert resolve_location("203.0.113.5", cfg) == "untrusted"
    assert resolve_location(None, cfg) == "unknown"


def test_no_policy_allows_and_deny_by_default_app(cfg):
    assert evaluate_signin(S(), cfg).outcome == "ALLOW"
    gap = evaluate_signin(S(app="Payroll"), cfg)
    assert gap.outcome == "ALLOW" and any("COVERAGE GAP" in f for f in gap.flags)
    assert evaluate_signin(S(app="Finance-ERP"), cfg).outcome == "BLOCK"


def test_legacy_auth_blocked_and_unknown_client_is_legacy(cfg):
    assert evaluate_signin(S(client_app="legacy_imap", mfa_satisfied=True), cfg).outcome == "BLOCK"
    assert evaluate_signin(S(client_app="weird_proto"), cfg).outcome == "BLOCK"


def test_risky_signin_mfa(cfg):
    assert evaluate_signin(S(risk="medium", mfa_satisfied=True), cfg).outcome == "ALLOW_AFTER_MFA"
    assert evaluate_signin(S(risk="medium"), cfg).outcome == "INTERRUPTED_MFA_REQUIRED"
    missing = S()
    del missing["risk"]
    r = evaluate_signin(missing, cfg)
    assert r.outcome == "INTERRUPTED_MFA_REQUIRED" and "treated as high" in r.reasons[0]


def test_require_all_across_controls_blocks_without_compliant_device(cfg):
    s = S(app="Payroll", ip="203.0.113.9", mfa_satisfied=True, device={"platform": "windows", "compliant": False})
    r = evaluate_signin(s, cfg)
    assert r.outcome == "BLOCK" and "missing compliant_device" in r.reasons[0]
    s["device"]["compliant"] = True
    assert evaluate_signin(s, cfg).outcome == "ALLOW_AFTER_MFA"
    assert evaluate_signin({**s, "ip": "10.20.1.1"}, cfg).applied == []        # trusted location excluded


def test_require_one_of(cfg):
    s = S(app="Mail", device={"platform": "ios", "compliant": False}, client_app="mobile_app")
    assert evaluate_signin(s, cfg).outcome == "BLOCK"
    assert evaluate_signin({**s, "approved_app": True}, cfg).outcome == "ALLOW"


def test_report_only_logged_not_enforced_and_exclusion_beats_inclusion(cfg):
    r = evaluate_signin(S(risk="high", mfa_satisfied=True), cfg)
    assert r.outcome == "ALLOW_AFTER_MFA" and list(r.report_only.values()) == ["BLOCK"]
    bg = S(user="bg", groups=["BreakGlass", "Admins"], client_app="legacy_imap")
    assert policy_applies(cfg["policies"][0], bg, cfg) == (False, "excluded (BreakGlass)")
    assert evaluate_signin(bg, cfg).outcome == "ALLOW"


def test_any_block_wins_policy_driven(cfg):
    pols = [{**p, "state": "on"} if p["name"].startswith("CA06") else p for p in cfg["policies"]]
    r = evaluate_signin(S(risk="high", mfa_satisfied=True), {**cfg, "policies": pols})
    assert r.outcome == "BLOCK" and len(r.applied) == 2


def test_missing_user_denied(cfg):
    assert evaluate_signin({"id": "X", "app": "Wiki"}, cfg).outcome == "BLOCK"


def test_activation_decisions(cfg):
    assert decide_activation(R(), cfg, ELIG).decision == "APPROVE"
    assert decide_activation(R(duration_hours=8), cfg, ELIG).decision == "APPROVE"          # boundary = max
    assert decide_activation(R(duration_hours=9), cfg, ELIG).decision == "DENY"
    assert decide_activation(R(user="victor"), cfg, ELIG).decision == "DENY"
    assert decide_activation(R(role="Made-up Role"), cfg, ELIG).decision == "DENY"
    assert decide_activation(R(mfa_done=None), cfg, ELIG).decision == "DENY"


def test_high_privilege_approval(cfg):
    ga = dict(user="heidi", role="Global Administrator", duration_hours=1, ticket="CHG-1")
    assert decide_activation(R(**ga), cfg, ELIG).decision == "PENDING_APPROVAL"
    assert decide_activation(R(**ga, approver="ciso"), cfg, ELIG).decision == "APPROVE"
    r = decide_activation(R(**ga, approver="heidi"), cfg, ELIG)
    assert r.decision == "DENY" and "own activation" in r.reasons[0]
    assert decide_activation(R(**{**ga, "ticket": ""}, approver="ciso"), cfg, ELIG).decision == "DENY"


def test_standing_and_break_glass(policies):
    d = {"break_glass_accounts": [{"user": "bg1", "groups": ["BreakGlass"], "alert_on_signin": True},
                                  {"user": "bg2", "groups": [], "alert_on_signin": True}],
         "assignments": [{"user": u, "role": "Global Administrator", "type": "active", "permanent": True}
                         for u in ("bg1", "bg2", "mallory")]}
    v = {f.user: f.verdict for f in assess_assignments(d, policies)}
    assert v == {"bg1": "BREAK_GLASS_OK", "bg2": "BREAK_GLASS_FINDING", "mallory": "STANDING_PRIVILEGE"}


def test_run_demo_and_challenges(policies, quiet_ui, data):
    d = data("sample_signins.json")
    out = run_demo(quiet_ui, policies, d)
    assert out["signins"] == {"S01": "BLOCK", "S02": "ALLOW_AFTER_MFA", "S03": "ALLOW",
                              "S04": "INTERRUPTED_MFA_REQUIRED", "S05": "BLOCK", "S06": "ALLOW_AFTER_MFA",
                              "S07": "ALLOW", "S08": "ALLOW", "S09": "ALLOW", "S10": "ALLOW_AFTER_MFA",
                              "S11": "BLOCK", "S12": "BLOCK", "S13": "INTERRUPTED_MFA_REQUIRED"}
    assert out["activations"] == {"R1": "APPROVE", "R2": "PENDING_APPROVAL", "R3": "DENY", "R4": "DENY",
                                  "R5": "DENY", "R6": "APPROVE", "R7": "DENY"}
    assert sorted(out["report_only"]) == ["S06", "S13"]
    assert list(out["assignments"].values()).count("STANDING_PRIVILEGE") == 2
    qs = build_challenges(policies, d)
    assert len(qs) >= 10 and all(q.answer in q.choices for q in qs)
