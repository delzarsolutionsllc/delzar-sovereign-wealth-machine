"""Exam-style question bank: format, coverage and how the practice exam uses it."""

from __future__ import annotations

import json
from collections import Counter

import pytest

from utils import exam_bank
from utils.exam import DOMAIN_WEIGHTS, build_domain_test, build_exam

BANK = list(exam_bank.load_bank())


def test_every_domain_file_is_valid():
    for d in sorted(exam_bank.OBJECTIVES):
        data = json.loads((exam_bank.BANK_DIR / f"domain{d}.json").read_text(encoding="utf-8"))
        assert data["domain"] == d and "Not real exam questions" in data["note"]
        assert exam_bank.validate(data["questions"], d) == [], f"domain {d}"


def test_every_objective_is_covered():
    per_obj = Counter(q["objective"] for q in BANK)
    assert set(per_obj) == exam_bank.VALID_OBJECTIVES
    assert min(per_obj.values()) >= 8


def test_bank_size_tracks_exam_weights():
    per_dom = Counter(q["objective"][0] for q in BANK)
    assert sum(per_dom.values()) >= 300
    share = {d: per_dom[d] / len(BANK) for d in per_dom}
    for d, w in DOMAIN_WEIGHTS.items():
        assert abs(share[d] - w) < 0.05, f"domain {d}: {share[d]:.2f} of the bank vs {w} of the exam"


def test_answer_positions_are_balanced():
    spread = exam_bank.answer_position_spread(BANK)
    assert min(spread.values()) / len(BANK) >= 0.18          # roughly 25 % each, no favourite letter


def test_ids_unique_across_bank():
    ids = [q["id"] for q in BANK]
    assert len(ids) == len(set(ids))


def test_validator_catches_lab_jargon_and_bad_options():
    good = {"id": "X-1", "objective": "3.3", "stem": "A hospital must let analysts study records without seeing names. "
            "Which of the following BEST meets this?", "choices": ["Tokenization", "Hashing", "Data masking", "Encryption"],
            "answer": "Data masking", "explanation": "Masking hides identifying values on display while keeping the format usable."}
    assert exam_bank.validate([good]) == []
    assert any("jargon" in p for p in exam_bank.validate([dict(good, stem="DF-5: what does the gate decide here?")]))
    assert exam_bank.validate([dict(good, stem="Which hash is SHA-256 compared with AES-256 keys here today?")]) == []
    assert any("4 distinct" in p for p in exam_bank.validate([dict(good, choices=["A x", "A x", "B", "C"])]))
    assert any("above" in p for p in exam_bank.validate([dict(good, choices=["Tokenization", "Hashing", "Data masking", "All of the above"])]))
    assert any("not in domain" in p for p in exam_bank.validate([good], "1"))


def test_practice_exam_uses_the_bank_by_default(policies):
    stems = {q["stem"] for q in BANK}
    qs, alloc, short = build_exam(policies, 90, seed=5)
    assert len(qs) == 90 and not short and all(q.prompt in stems and q.context == "" for q in qs)
    assert alloc == {"1": 11, "2": 20, "3": 16, "4": 25, "5": 18}
    lab_qs, _, _ = build_exam(policies, 20, seed=5, source="labs")
    assert not any(q.prompt in stems for q in lab_qs)
    with pytest.raises(ValueError):
        build_exam(policies, 10, seed=1, source="nope")


def test_options_are_shuffled_but_answer_kept(policies):
    a, _, _ = build_exam(policies, 60, seed=1)
    b, _, _ = build_exam(policies, 60, seed=2)
    by_stem = {q["stem"]: q for q in BANK}
    for q in a:
        assert sorted(q.choices) == sorted(by_stem[q.prompt]["choices"]) and q.answer in q.choices
    common = {q.prompt for q in a} & {q.prompt for q in b}
    orders = [(next(x.choices for x in a if x.prompt == s), next(x.choices for x in b if x.prompt == s)) for s in common]
    assert any(x != y for x, y in orders)                      # same question, different option order


@pytest.mark.parametrize("domain", sorted(DOMAIN_WEIGHTS))
def test_domain_tests_use_the_bank(policies, domain):
    qs, per_obj = build_domain_test(policies, domain, 30, seed=4)
    assert len(qs) == 30 and all(q.objective.startswith(domain + ".") and q.context == "" for q in qs)
    assert set(per_obj) == {o for o in exam_bank.VALID_OBJECTIVES if o.startswith(domain + ".")}


def test_web_bundle_carries_the_bank():
    from tools.build_web_bundle import build
    b = build(variants=0)
    assert len(b["exam_bank"]) == len(BANK) and {"id", "objective", "stem", "choices", "answer", "explanation"} <= set(b["exam_bank"][0])
