"""
Tests for challenge mode, the Lab 2 step-up flow, and Labs 6–8.
"""

from __future__ import annotations

import copy

import pytest

from labs import LABS
from labs.lab1_jml_governance import IdentityGovernance
from labs.lab2_zero_trust_evaluator import AccessRequest, PolicyDecision, ZeroTrustGateway
from labs.lab5_ai_agent_governor import HITL, AgentAction, AgentGovernor
from labs.lab6_risk_management import ale, assess, availability, band, check_bia, sle, SLE_BANDS
from labs.lab7_incident_response import grade_playbook
from labs.lab8_soc_pipeline import run_pipeline
from utils.challenge import Progress, Question, run_challenge


# =========================================================================== #
# Challenge framework
# =========================================================================== #
def _scripted(answers):
    it = iter(answers)
    return lambda _prompt: next(it)


class TestChallengeFramework:
    def test_question_rejects_bad_answer(self):
        with pytest.raises(ValueError):
            Question("q", ["a", "b"], "c", "x", "1.1")

    def test_scoring_by_number_and_text(self, quiet_ui, tmp_path):
        qs = [Question("q1", ["yes", "no"], "yes", "e", "1.1"),
              Question("q2", ["yes", "no"], "no", "e", "1.1"),
              Question("q3", ["A", "B", "C"], "C", "e", "2.2")]
        prog = Progress(tmp_path / "p.json")
        res = run_challenge(quiet_ui, 1, qs, ask=_scripted(["1", "NO", "1"]), progress=prog, shuffle=False)
        assert (res.correct, res.total) == (2, 3) and res.missed[0].prompt == "q3"
        reloaded = Progress(tmp_path / "p.json")
        assert reloaded.data["objectives"]["1.1"] == {"attempted": 2, "correct": 2}
        assert reloaded.data["objectives"]["2.2"] == {"attempted": 1, "correct": 0}
        assert reloaded.rows()[0][0] == "2.2"   # weakest first
        assert len(reloaded.data["sessions"]) == 1

    def test_eof_stops_gracefully(self, quiet_ui):
        def ask(_):
            raise EOFError
        res = run_challenge(quiet_ui, 1, [Question("q", ["a"], "a", "e", "1.1")], ask=ask)
        assert res.total == 0 and res.correct == 0

    def test_corrupt_progress_file_is_tolerated(self, tmp_path):
        f = tmp_path / "p.json"
        f.write_text("{not json")
        assert Progress(f).rows() == []

    @pytest.mark.parametrize("num", sorted(LABS))
    def test_every_lab_builds_valid_questions(self, num, policies, data, quiet_ui):
        module, data_file = LABS[num]
        qs = module.build_challenges(policies, data(data_file))
        assert len(qs) >= 5
        for q in qs:
            assert q.answer in q.choices and len(q.choices) >= 2 and len(set(q.choices)) == len(q.choices)
            assert q.objective and q.explanation
        # answering with the engine's own answers must score 100%
        res = run_challenge(quiet_ui, num, qs, ask=_scripted([q.answer for q in qs]), shuffle=False)
        assert res.correct == res.total == len(qs)


# =========================================================================== #
# Lab 1 / 2 / 5 extensions
# =========================================================================== #
def _req(**kw):
    base = {"id": "R", "subject": "carol", "resource": "source-repo", "action": "write", "hour": 20, "mfa": True,
            "device": {"id": "D", "managed": True, "health_score": 92}, "ip": "1.1.1.1", "ip_reputation": "good",
            "geo": "Austin, US", "usual_geo": "Tulsa, US"}
    base.update(kw)
    return AccessRequest.from_dict(base)


class TestStepUp:
    @pytest.fixture
    def gw(self, policies):
        return ZeroTrustGateway(policies["zero_trust"], clock=lambda: 1_800_000_000.0)

    def test_step_up_success_issues_short_token(self, gw, policies):
        req = _req()
        d, tok = gw.request_access(req)
        assert d.verdict == "STEP_UP" and tok is None
        final, tok = gw.complete_step_up(req, d, mfa_passed=True)
        assert final.verdict == "ALLOW" and tok
        claims = gw.pa.decode_unverified(tok)
        assert claims["exp"] - claims["iat"] < policies["zero_trust"]["token_ttl_seconds"]
        assert gw.pep.handle(tok, "source-repo", "write").allowed

    def test_step_up_cannot_fix_unhealthy_device(self, gw):
        req = _req(subject="carol", resource="prod-db", action="read", hour=14, geo="Tulsa, US",
                   device={"id": "D", "managed": True, "health_score": 65})
        d, _ = gw.request_access(req)
        assert d.verdict == "STEP_UP"
        final, tok = gw.complete_step_up(req, d, mfa_passed=True)
        assert final.verdict == "DENY" and tok is None

    def test_failed_mfa_denies_and_raises_risk(self, gw):
        req = _req()
        d, _ = gw.request_access(req)
        final, tok = gw.complete_step_up(req, d, mfa_passed=False)
        assert final.verdict == "DENY" and tok is None and "carol" in gw.risky_subjects

    def test_step_up_only_for_step_up_verdicts(self, gw):
        req = _req(hour=10, geo="Tulsa, US")
        d, _ = gw.request_access(req)
        with pytest.raises(ValueError):
            gw.complete_step_up(req, d, True)

    def test_revoke_subject(self, gw):
        r = _req(hour=10, geo="Tulsa, US")
        toks = [gw.pa.issue(r, PolicyDecision("x", "ALLOW", 100, 75)) for _ in range(3)]
        assert gw.pa.revoke_subject("carol") == 3
        assert all(not gw.pep.handle(t, "source-repo", "write").allowed for t in toks)
        assert gw.pa.revoke_subject("carol") == 0


def test_suspend_keeps_entitlements(policies):
    iga = IdentityGovernance(policies["identity_governance"])
    iga.joiner({"user_id": "u", "name": "U", "department": "HR", "role": "hr_specialist", "clearance": "confidential"})
    iga.suspend("u", "IR-1")
    ident = iga.get("u")
    assert ident.status == "disabled" and ident.permissions
    d = iga.evaluate_access("u", "hr_records:read", {"name": "r", "classification": "internal"})
    assert not d.allowed and d.gate == "STATUS"


def test_always_hitl_action_class(policies):
    gov = AgentGovernor(policies["ai_governance"])
    d = gov.evaluate(AgentAction("1", "soc-triage-03", "disable_account", "jdoe", {}, "compromised", confidence=0.99))
    assert d.verdict == HITL and "HUMAN_REQUIRED_CLASS" in d.codes


def test_key_separation(policies):
    assert policies["log_inspection"]["manifest_hmac_key"] != policies["zero_trust"]["signing_key"]


# =========================================================================== #
# Lab 6 — risk
# =========================================================================== #
class TestLab6:
    def test_formulas(self):
        assert sle(100_000, 0.25) == 25_000
        assert ale(25_000, 2) == 50_000
        assert availability(999, 1) == pytest.approx(0.999)
        with pytest.raises(ValueError):
            sle(1, 1.5)
        with pytest.raises(ValueError):
            ale(1, -1)

    def test_bands(self):
        assert band(5_000, SLE_BANDS) == 1 and band(3_000_000, SLE_BANDS) == 5

    def test_sample_treatments(self, data):
        d = data("sample_risks.json")
        got = {r["id"]: assess(r, d["risk_appetite_ale"]).treatment for r in d["risks"]}
        assert got == {"R-01": "MITIGATE", "R-02": "MITIGATE", "R-03": "TRANSFER", "R-04": "ACCEPT", "R-05": "AVOID"}

    def test_exception_when_nothing_is_cost_effective(self):
        r = {"id": "X", "title": "t", "asset_value": 100_000, "exposure_factor": 1.0, "aro": 0.5,
             "controls": [{"name": "too expensive", "annual_cost": 1_000_000, "new_aro": 0.0}]}
        assert assess(r, 10_000).treatment == "EXCEPTION"

    def test_bia(self, data):
        res = {b["system"]: check_bia(b) for b in data("sample_risks.json")["bia"]}
        assert not res["payroll-app"].rpo_ok and res["payroll-app"].rto_ok
        assert res["erp-legacy"].rpo_ok and not res["erp-legacy"].rto_ok
        assert not res["web-frontend"].issues


# =========================================================================== #
# Lab 7 — incident response
# =========================================================================== #
class TestLab7:
    @pytest.fixture
    def inc(self, data):
        return data("sample_incident.json")

    def test_expert_is_perfect(self, inc):
        g = grade_playbook("expert", inc["playbooks"]["expert"], inc["actions"])
        assert g.score == 100 and g.grade == "A"
        assert all(c.status == "INTACT" for c in g.custody) and len(g.custody) == 5

    def test_rookie_mistakes_are_caught(self, inc):
        g = grade_playbook("rookie", inc["playbooks"]["rookie"], inc["actions"])
        codes = {i.code for i in g.issues}
        assert {"EVIDENCE_DESTROYED", "CHAIN_OF_CUSTODY", "MISSING_PREREQ", "PHASE_ORDER", "NO_LESSONS_LEARNED"} <= codes
        assert g.grade == "F"

    def test_order_of_volatility(self, inc):
        g = grade_playbook("x", ["image_disk", "capture_memory", "isolate_host", "lessons"], inc["actions"])
        assert any(i.code == "ORDER_OF_VOLATILITY" for i in g.issues)

    def test_recovery_before_eradication(self, inc):
        g = grade_playbook("x", ["isolate_host", "restore_service", "lessons"], inc["actions"])
        assert any("before eradication" in i.message for i in g.issues)

    def test_unknown_action(self, inc):
        g = grade_playbook("x", ["isolate_host", "do_magic", "lessons"], inc["actions"])
        assert any(i.code == "UNKNOWN_ACTION" for i in g.issues)


# =========================================================================== #
# Lab 8 — pipeline
# =========================================================================== #
class TestLab8:
    @pytest.fixture
    def run(self, policies, data):
        def _run(pipeline=None):
            p = pipeline or data("sample_pipeline.json")
            return run_pipeline(policies, p, data("sample_logs.json"), data("sample_incident.json"))
        return _run

    def test_end_to_end(self, run):
        res = run()
        assert res.suspended == ["jdoe"] and res.sessions_revoked == 2
        assert res.rfc_decision == "APPROVE_WITH_CONDITIONS"
        assert res.isolated == ["ws-0142"] and res.custody_records == 2
        overreach = [r for r in res.rows if "firewall_rule_modify" in r.proposal]
        assert overreach and overreach[0].verdict == "BLOCK"

    def test_human_rejection_prevents_execution(self, run):
        res = run()
        asmith = next(r for r in res.rows if r.proposal.endswith("asmith"))
        assert asmith.human.startswith("REJECT") and "asmith" not in res.suspended

    def test_no_review_leaves_action_pending(self, run, data):
        p = copy.deepcopy(data("sample_pipeline.json"))
        p["human_reviews"] = {}
        res = run(p)
        assert res.suspended == [] and all(r.human == "PENDING" for r in res.rows if r.verdict == HITL)

    def test_cab_without_quorum_rejects_auto_rfc(self, run, data):
        p = copy.deepcopy(data("sample_pipeline.json"))
        p["emergency_cab_approvals"] = ["cab_chair"]
        assert run(p).rfc_decision == "REJECT"


# =========================================================================== #
# CLI
# =========================================================================== #
def test_cli_challenge_and_progress(tmp_path, monkeypatch, capsys):
    import main
    from utils import challenge as ch

    monkeypatch.setattr(ch, "DEFAULT_PROGRESS_PATH", tmp_path / "progress.json")
    monkeypatch.setattr(main, "Progress", lambda path=None: ch.Progress(path or tmp_path / "progress.json"))
    answers = iter(["1"] * 100)
    monkeypatch.setattr("builtins.input", lambda *_: next(answers))
    assert main.main(["--plain", "challenge", "2", "--seed", "1"]) == 0
    assert main.main(["--plain", "progress"]) == 0
    out = capsys.readouterr().out
    assert "Challenge score" in out and "1.2" in out
