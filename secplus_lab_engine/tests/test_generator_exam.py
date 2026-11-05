"""Random scenario generator + exam simulator tests."""

from __future__ import annotations

import itertools

import pytest

from labs import LABS
from utils.challenge import Question, run_challenge
from utils.exam import DOMAIN_WEIGHTS, ExamResult, allocate, build_exam, collect_questions, run_exam
from utils.scenario_generator import GENERATORS, generate


# =========================================================================== #
# Generator
# =========================================================================== #
@pytest.mark.parametrize("lab", sorted(GENERATORS))
def test_generator_is_deterministic_per_seed(policies, lab):
    assert generate(lab, policies, 7) == generate(lab, policies, 7)
    assert generate(lab, policies, 7) != generate(lab, policies, 8)


@pytest.mark.parametrize("lab,seed", list(itertools.product(sorted(GENERATORS), range(25))))
def test_generated_scenarios_are_valid_and_answerable(policies, quiet_ui, lab, seed):
    module = LABS[lab][0]
    data = generate(lab, policies, seed)
    assert isinstance(module.run_demo(quiet_ui, policies, data), dict)
    qs = module.build_challenges(policies, data)
    assert qs
    answers = iter([q.answer for q in qs])
    res = run_challenge(quiet_ui, lab, qs, ask=lambda _: next(answers), shuffle=False)
    assert res.correct == res.total


def test_unsupported_lab(policies):
    with pytest.raises(KeyError):
        generate(3, policies, 1)


# =========================================================================== #
# Exam allocation & assembly
# =========================================================================== #
def test_allocate_matches_official_weights():
    alloc, short = allocate(90, {d: 500 for d in DOMAIN_WEIGHTS})
    assert sum(alloc.values()) == 90 and not short
    assert alloc == {"1": 11, "2": 20, "3": 16, "4": 25, "5": 18}
    alloc, _ = allocate(100, {d: 500 for d in DOMAIN_WEIGHTS})
    assert alloc == {"1": 12, "2": 22, "3": 18, "4": 28, "5": 20}


def test_allocate_redistributes_shortfall():
    alloc, short = allocate(90, {"1": 3, "2": 500, "3": 500, "4": 500, "5": 500})
    assert alloc["1"] == 3 and short == {"1": 8} and sum(alloc.values()) == 90


def test_allocate_when_pool_too_small():
    alloc, _ = allocate(90, {d: 2 for d in DOMAIN_WEIGHTS})
    assert sum(alloc.values()) == 10


def test_build_exam(policies):
    qs, alloc, short = build_exam(policies, 90, seed=3)
    assert len(qs) == 90 and not short
    counts = {d: sum(q.objective.split(".")[0] == d for q in qs) for d in DOMAIN_WEIGHTS}
    assert counts == alloc
    assert len({(q.prompt, q.context) for q in qs}) == 90                    # no duplicates
    again, _, _ = build_exam(policies, 90, seed=3)
    assert [q.prompt for q in again] == [q.prompt for q in qs]               # reproducible


def test_fixed_mode_has_enough_questions(policies):
    pool = collect_questions(policies, randomize=False)
    _, short = allocate(90, {d: len(v) for d, v in pool.items()})
    assert not short


# =========================================================================== #
# Exam runner
# =========================================================================== #
def _qs(n=5):
    doms = list(DOMAIN_WEIGHTS)
    return [Question(f"q{i}", ["right", "wrong"], "right", "because", f"{doms[i % 5]}.1") for i in range(n)]


def test_perfect_exam_passes(quiet_ui):
    res = run_exam(quiet_ui, _qs(), minutes=10, ask=lambda _: "right")
    assert res.correct == 5 and res.scaled == 900 and res.passed and not res.missed


def test_failing_exam(quiet_ui):
    answers = iter(["right", "wrong", "2", "nonsense", "1"])
    res = run_exam(quiet_ui, _qs(), minutes=10, ask=lambda _: next(answers))
    assert res.correct == 2 and res.scaled == 420 and not res.passed and len(res.missed) == 3


def test_time_runs_out(quiet_ui):
    t = itertools.count(0, 40)                      # every clock read advances 40 s
    res = run_exam(quiet_ui, _qs(), minutes=1, ask=lambda _: "right", clock=lambda: next(t))
    assert res.timed_out and res.answered < 5 and res.correct == res.answered
    assert len(res.missed) == 5 - res.answered      # unanswered count as wrong


def test_exam_records_progress(quiet_ui, tmp_path):
    from utils.challenge import Progress
    prog = Progress(tmp_path / "p.json")
    run_exam(quiet_ui, _qs(), minutes=10, ask=lambda _: "right", progress=prog)
    reloaded = Progress(tmp_path / "p.json")
    assert sum(v["attempted"] for v in reloaded.data["objectives"].values()) == 5
    assert reloaded.data["sessions"][-1]["lab"] == "exam"


def test_scaled_score_bounds():
    assert ExamResult(10, 0, 10, False).scaled == 100 and ExamResult(10, 10, 10, False).scaled == 900


# =========================================================================== #
# CLI
# =========================================================================== #
def test_cli_random_challenge_and_exam(tmp_path, monkeypatch, capsys):
    import main
    from utils import challenge as ch

    monkeypatch.setattr(main, "Progress", lambda path=None: ch.Progress(path or tmp_path / "progress.json"))
    answers = iter(["1"] * 500)
    monkeypatch.setattr("builtins.input", lambda *_: next(answers))
    assert main.main(["--plain", "challenge", "9", "--random", "--seed", "4"]) == 0
    assert main.main(["--plain", "lab", "13", "--random", "--seed", "4"]) == 0
    assert main.main(["--plain", "exam", "--count", "10", "--minutes", "5", "--seed", "1"]) == 0
    out = capsys.readouterr().out
    assert "generated scenario" in out.lower() and "Practice exam result" in out
    with pytest.raises(SystemExit):
        main.main(["--plain", "lab", "3", "--random"])


# =========================================================================== #
# Domain tests
# =========================================================================== #
@pytest.mark.parametrize("domain", sorted(DOMAIN_WEIGHTS))
def test_domain_test_draws_only_that_domain_and_every_objective(policies, domain):
    from utils.exam import build_domain_test
    qs, per_obj = build_domain_test(policies, domain, 30, seed=3)
    assert len(qs) == 30 and all(q.objective.split(".")[0] == domain for q in qs)
    objectives = {q.objective for qs_ in collect_questions(policies, 3).values() for q in qs_ if q.objective.startswith(domain + ".")}
    assert set(per_obj) == objectives                                  # every objective in the domain is represented
    assert max(per_obj.values()) - min(per_obj.values()) <= 1 or sum(per_obj.values()) < 30  # round-robin spread
    assert len({(q.prompt, q.context, *q.choices) for q in qs}) == 30  # no repeats


def test_domain_test_is_seeded_and_validated(policies):
    from utils.exam import build_domain_test
    a, _ = build_domain_test(policies, "4", 20, seed=9)
    b, _ = build_domain_test(policies, "4", 20, seed=9)
    assert [q.prompt for q in a] == [q.prompt for q in b]
    with pytest.raises(ValueError):
        build_domain_test(policies, "6", 10, seed=1)


def test_domain_test_scoring_uses_target(quiet_ui, tmp_path):
    from utils.challenge import Progress
    from utils.exam import DOMAIN_TEST_TARGET
    qs = [Question("p%d" % i, ["yes", "no"], "yes", "e", f"3.{1 + i % 4}") for i in range(10)]
    answers = iter(["yes"] * 8 + ["no"] * 2)
    prog = Progress(tmp_path / "p.json")
    res = run_exam(quiet_ui, qs, 10, ask=lambda _: next(answers), progress=prog, domain="3")
    assert res.percent == 80.0 and res.passed == (80.0 >= DOMAIN_TEST_TARGET)
    assert sum(t for _, t in res.by_objective.values()) == 10 and set(res.by_objective) == {"3.1", "3.2", "3.3", "3.4"}
    assert prog.data["sessions"][-1]["lab"] == "domain 3 test" and prog.data["sessions"][-1]["score"] == "8/10 (80%)"
    answers = iter(["yes"] * 7 + ["no"] * 3)
    assert not run_exam(quiet_ui, qs, 10, ask=lambda _: next(answers), domain="3").passed


def test_domain_test_via_api_and_cli(policies, capsys, tmp_path):
    import main
    import webapi
    from utils.terminal_ui import UI
    out = webapi.exam(policies, 12, seed=4, domain="5")
    assert out["domain"] == "5" and len(out["questions"]) == 12 and all(q["objective"][0] == "5" for q in out["questions"])
    assert webapi.dispatch("exam", {"count": 6, "seed": 1, "domain": "2"}, policies)["domain"] == "2"
    assert "domain_test_target" in webapi.catalog(policies)
    answers = iter(["1"] * 6)
    res = main.domain_test(UI(plain=True), policies, "1", 6, 6, seed=2, ask=lambda _: next(answers),
                           progress_path=str(tmp_path / "p.json"))
    assert res.domain == "1" and res.total == 6
    assert "Domain 1 test result" in capsys.readouterr().out
