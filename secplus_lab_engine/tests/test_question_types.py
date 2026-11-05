"""Select-TWO (multi) and performance-based (order / match) questions: data, scoring, CLI, exam mix, exports."""

from __future__ import annotations

import json
import random
from collections import Counter

import pytest

from utils import exam_bank
from utils.challenge import Question, _resolve, check, option_index
from utils.exam import (DOMAIN_WEIGHTS, PBQ_SHARE, _shuffled_choices, build_domain_test, build_exam, parse_answer,
                        run_exam)

PBQ = json.loads(exam_bank.PBQ_FILE.read_text(encoding="utf-8"))
RECORDS = PBQ["questions"]
BY_ID = {r["id"]: r for r in RECORDS}


def _q(kind):
    return next(q for q in exam_bank.as_questions(RECORDS) if q.kind == kind)


# --------------------------------------------------------------------------- data
def test_pbq_file_is_valid_and_original():
    assert "Not real exam questions" in PBQ["note"] and "Original practice questions" in PBQ["note"]
    assert exam_bank.validate(RECORDS) == []


def test_pbq_counts_and_domain_spread():
    kinds = Counter(r["type"] for r in RECORDS)
    assert kinds["multi"] >= 20 and kinds["order"] >= 6 and kinds["match"] >= 6
    assert {r["objective"][0] for r in RECORDS if r["type"] == "multi"} == set(DOMAIN_WEIGHTS)
    assert all(r["id"].startswith("PBQ-") for r in RECORDS)


def test_load_bank_includes_pbq_and_domain_files():
    bank = exam_bank.load_bank()
    ids = {r["id"] for r in bank}
    assert set(BY_ID) <= ids and any(i.startswith("D1-") for i in ids)
    assert len(ids) == len(bank)
    kinds = Counter(q.kind for q in exam_bank.as_questions())
    assert kinds["single"] >= 300 and kinds["multi"] and kinds["order"] and kinds["match"]


GOOD = {
    "multi": {"id": "X-1", "type": "multi", "objective": "3.3", "select": 2,
              "stem": "A company needs to protect data while it moves across networks. Which TWO controls apply?",
              "choices": ["TLS", "IPsec", "Full-disk encryption", "File permissions", "Data masking"],
              "answers": ["TLS", "IPsec"], "explanation": "TLS and IPsec encrypt traffic in transit; the rest protect stored data."},
    "order": {"id": "X-2", "type": "order", "objective": "4.8",
              "stem": "Put the incident response phases in the order they occur after detection.",
              "items": ["Analysis", "Containment", "Eradication", "Recovery"],
              "explanation": "Analyze first, then contain, eradicate the cause and recover systems to normal."},
    "match": {"id": "X-3", "type": "match", "objective": "4.5",
              "stem": "Match each insecure protocol to its secure replacement on the network.",
              "pairs": [{"item": "Telnet", "match": "SSH"}, {"item": "HTTP", "match": "HTTPS"},
                        {"item": "FTP", "match": "SFTP"}, {"item": "LDAP", "match": "LDAPS"}],
              "targets_extra": ["IMAPS"], "explanation": "Each secure protocol encrypts what the older one sent in clear text."},
}


@pytest.mark.parametrize("kind", sorted(GOOD))
def test_validator_accepts_good_records(kind):
    assert exam_bank.validate([GOOD[kind]]) == []


@pytest.mark.parametrize("kind, change, problem", [
    ("multi", {"answers": ["TLS"]}, "exactly 2"),
    ("multi", {"answers": ["TLS", "SSH"]}, "not among the choices"),
    ("multi", {"choices": ["TLS", "IPsec", "A", "B"]}, "5-6"),
    ("multi", {"select": 3}, "select"),
    ("multi", {"stem": "A company needs to protect data while it moves. Which two controls apply here?"}, "TWO"),
    ("multi", {"stem": "Pick the controls that protect data while it moves across the network."}, "stem should end"),
    ("order", {"items": ["Analysis", "Containment", "Recovery"]}, "4-6"),
    ("order", {"items": ["Analysis", "Analysis", "Eradication", "Recovery"]}, "4-6 distinct"),
    ("match", {"pairs": [{"item": "Telnet", "match": "SSH"}]}, "4-6 pairs"),
    ("match", {"targets_extra": ["SSH"]}, "targets_extra"),
    ("match", {"pairs": GOOD["match"]["pairs"][:3] + [{"item": "Telnet", "match": "LDAPS"}]}, "items must be distinct"),
    ("match", {"targets_extra": ["3"]}, "bare number"),
    ("order", {"items": ["DF-5 review", "Containment", "Eradication", "Recovery"]}, "jargon"),
])
def test_validator_rejects_bad_records(kind, change, problem):
    probs = exam_bank.validate([dict(GOOD[kind], **change)])
    assert any(problem in p for p in probs), probs


def test_validator_rejects_unknown_type_and_keeps_single_rules():
    assert any("unknown type" in p for p in exam_bank.validate([dict(GOOD["order"], type="essay")]))
    single = {"id": "S-1", "objective": "1.1", "stem": "Put the following in the right order for the change board.",
              "choices": ["A x", "B y", "C z", "D w"], "answer": "A x", "explanation": "A single question must still end with a question mark."}
    assert any("stem should end with a question" in p for p in exam_bank.validate([single]))


# --------------------------------------------------------------------------- Question + check()
def test_question_defaults_keep_single_behaviour():
    q = Question("Which one?", ["right", "wrong"], "right", "because", "1.1")
    assert q.kind == "single" and q.answers == () and q.items == () and q.pairs == ()
    assert check(q, "right") and q.check("right") and not check(q, "wrong") and not check(q, None)
    with pytest.raises(ValueError):
        Question("Which one?", ["2", "3"], "2", "because", "1.1")           # bare-number rule kept
    with pytest.raises(ValueError):
        Question("Which one?", ["a b", "c d"], "zz", "because", "1.1")


def test_question_validates_each_kind():
    with pytest.raises(ValueError):
        Question("p", ["a x", "b x", "c x"], "", "e", "1.1", kind="multi", answers=("a x", "z"))
    with pytest.raises(ValueError):
        Question("p", ["a x", "b x"], "", "e", "1.1", kind="order", items=("a x", "c x"))
    with pytest.raises(ValueError):
        Question("p", ["t1"], "", "e", "1.1", kind="match", pairs=(("i1", "t1"), ("i2", "t2")))
    with pytest.raises(ValueError):
        Question("p", ["a x"], "a x", "e", "1.1", kind="essay")


def test_check_multi_needs_exactly_the_right_set():
    q = _q("multi")
    right = list(q.answers)
    wrong = next(c for c in q.choices if c not in right)
    assert check(q, right) and check(q, list(reversed(right))) and check(q, set(right))
    assert not check(q, right[:1])                                         # partial selection
    assert not check(q, right + [wrong])                                   # one too many
    assert not check(q, [right[0], wrong])
    assert not check(q, [right[0], right[0]])
    assert not check(q, right[0]) and not check(q, None)


def test_check_order_needs_the_exact_sequence():
    q = _q("order")
    assert check(q, list(q.items)) and check(q, q.items)
    swapped = list(q.items)
    swapped[0], swapped[1] = swapped[1], swapped[0]
    assert not check(q, swapped) and not check(q, list(q.items)[:-1]) and not check(q, list(reversed(q.items)))


def test_check_match_needs_every_pair():
    q = _q("match")
    right = dict(q.pairs)
    assert check(q, right)
    partial = dict(list(right.items())[:-1])
    assert not check(q, partial)
    first, second = list(right)[:2]
    assert not check(q, {**right, first: right[second]}) and not check(q, list(right.items()))


def test_answer_is_a_stable_string_for_every_kind():
    for q in exam_bank.as_questions(RECORDS):
        assert isinstance(q.answer, str) and q.answer
        if q.kind == "multi":
            assert all(a in q.answer for a in q.answers)
        if q.kind == "order":
            assert q.answer.startswith(q.items[0]) and q.answer.endswith(q.items[-1])
        if q.kind == "match":
            assert all(f"{i} = {m}" in q.answer for i, m in q.pairs)


# --------------------------------------------------------------------------- letters (A-D) as answers
def test_resolve_accepts_letters_numbers_and_text():
    ch = ["Tokenization", "Hashing", "Masking", "Encryption"]
    assert _resolve("c", ch) == "Masking" == _resolve("C", ch) == _resolve("3", ch) == _resolve("masking", ch)
    assert _resolve("e", ch) is None and _resolve("5", ch) is None and _resolve("zz", ch) is None


def test_letter_never_overrides_a_choice_whose_text_is_that_letter():
    ch = ["B", "A", "Neither", "Both"]
    assert _resolve("a", ch) == "A" and _resolve("b", ch) == "B"           # exact text wins
    assert option_index("a", ch) is None and option_index("c", ch) is None  # letters off for this question
    assert option_index("2", ch) == 1


def test_cli_exam_scores_letter_answers(quiet_ui):
    """Regression: answers c,c,c,c,d used to score 0/5 although four were right by position."""
    qs = [Question(f"Which option is right for case {i}?", ["Alpha", "Bravo", "Charlie", "Delta"], "Charlie", "why", f"{d}.1")
          for i, d in enumerate("1234")]
    qs.append(Question("Which option is right for the last case?", ["Alpha", "Bravo", "Charlie", "Delta"], "Charlie", "why", "5.1"))
    answers = iter(["c", "C", "c", "3", "d"])
    res = run_exam(quiet_ui, qs, minutes=10, ask=lambda _: next(answers))
    assert res.correct == 4 and res.missed[0][1] == "Delta"


# --------------------------------------------------------------------------- CLI parsing
def test_parse_multi():
    q = _q("multi")
    assert parse_answer(q, "1,3") == [q.choices[0], q.choices[2]]
    assert parse_answer(q, "1 3") == parse_answer(q, " 1 , 3 ") == parse_answer(q, "A C") == parse_answer(q, "a,c")
    assert parse_answer(q, "1 1") is None and parse_answer(q, "1 9") is None and parse_answer(q, "") is None
    assert parse_answer(q, "1") == [q.choices[0]]                          # read fine, but scored wrong
    assert not check(q, parse_answer(q, "1"))


def test_parse_order():
    q = _q("order")
    n = len(q.choices)
    seq = list(range(n, 0, -1))
    assert parse_answer(q, " ".join(map(str, seq))) == [q.choices[k - 1] for k in seq]
    assert parse_answer(q, ",".join("abcdef"[k - 1] for k in seq)) == [q.choices[k - 1] for k in seq]
    assert parse_answer(q, "1 2") is None                                  # not every step
    assert parse_answer(q, " ".join(["1"] * n)) is None                    # repeats


def test_parse_match():
    q = _q("match")
    letters = "".join(chr(97 + k) for k in range(len(q.choices)))
    raw = " ".join(f"{n}{letters[q.choices.index(t)]}" for n, (_, t) in enumerate(q.pairs, 1))
    resp = parse_answer(q, raw)
    assert resp == dict(q.pairs) and check(q, resp)
    assert parse_answer(q, raw.upper()) == resp
    assert parse_answer(q, "1-a, 2:b 3=c") == {q.pairs[0][0]: q.choices[0], q.pairs[1][0]: q.choices[1], q.pairs[2][0]: q.choices[2]}
    assert parse_answer(q, "1a 1b") is None and parse_answer(q, "9a") is None and parse_answer(q, "1z") is None
    assert parse_answer(q, "hello") is None


def _cli_answer(q, good: bool) -> str:
    if q.kind == "single":
        return str(q.choices.index(q.answer) + 1) if good else str(next(k for k, c in enumerate(q.choices, 1) if c != q.answer))
    if q.kind == "multi":
        picks = [q.choices.index(a) + 1 for a in q.answers]
        if not good:
            picks[-1] = next(k for k, c in enumerate(q.choices, 1) if c not in q.answers)
        return ",".join(map(str, picks))
    if q.kind == "order":
        seq = [q.choices.index(i) + 1 for i in q.items]
        return " ".join(map(str, seq if good else seq[::-1]))
    tgt = [chr(97 + q.choices.index(m)) for _, m in q.pairs]
    if not good:
        tgt[0], tgt[1] = tgt[1], tgt[0]
    return " ".join(f"{n}{t}" for n, t in enumerate(tgt, 1))


def test_run_exam_scores_every_kind(capsys):
    from utils.terminal_ui import UI
    quiet_ui = UI(plain=True)
    rng = random.Random(3)
    qs = [_shuffled_choices(q, rng) for q in exam_bank.as_questions(RECORDS)[:12]]
    good = [k % 3 != 0 for k in range(len(qs))]
    answers = iter(_cli_answer(q, g) for q, g in zip(qs, good))
    res = run_exam(quiet_ui, qs, minutes=30, ask=lambda _: next(answers))
    assert res.correct == sum(good) and len(res.missed) == len(qs) - sum(good)
    out = capsys.readouterr().out
    assert "Select TWO" in out and "Put these in order" in out and "Match each numbered item" in out


# --------------------------------------------------------------------------- exam mix
def test_practice_exam_includes_about_ten_percent_pbqs(policies):
    for seed in (1, 2, 3):
        qs, alloc, short = build_exam(policies, 90, seed=seed)
        kinds = Counter(q.kind for q in qs)
        others = len(qs) - kinds["single"]
        assert len(qs) == 90 and not short and 6 <= others <= 12, kinds
        assert alloc == {d: sum(q.objective[0] == d for q in qs) for d in DOMAIN_WEIGHTS}
    assert PBQ_SHARE == 0.10


def test_exam_shuffles_display_only(policies):
    qs, _, _ = build_exam(policies, 90, seed=11)
    for q in qs:
        r = BY_ID.get(q.qid)
        if not r:
            continue
        if q.kind == "multi":
            assert sorted(q.choices) == sorted(r["choices"]) and set(q.answers) == set(r["answers"])
        elif q.kind == "order":
            assert q.items == tuple(r["items"]) and sorted(q.choices) == sorted(r["items"])
            assert list(q.choices) != list(q.items)                         # never shown already solved
        elif q.kind == "match":
            assert dict(q.pairs) == {p["item"]: p["match"] for p in r["pairs"]}


def test_order_question_is_never_shown_solved():
    q = _q("order")
    for seed in range(40):
        assert list(_shuffled_choices(q, random.Random(seed)).choices) != list(q.items)


@pytest.mark.parametrize("domain", sorted(DOMAIN_WEIGHTS))
def test_domain_test_includes_pbqs_and_stays_balanced(policies, domain):
    qs, per_obj = build_domain_test(policies, domain, 30, seed=4)
    kinds = Counter(q.kind for q in qs)
    assert len(qs) == 30 and 1 <= 30 - kinds["single"] <= 3
    assert max(per_obj.values()) - min(per_obj.values()) <= 1


def test_lab_source_has_only_single_questions(policies):
    qs, _, _ = build_exam(policies, 20, seed=5, source="labs")
    assert {q.kind for q in qs} == {"single"}


# --------------------------------------------------------------------------- web API, bundle, exports
def test_webapi_serialises_new_fields(policies):
    import webapi
    out = webapi.exam(policies, 90, seed=2)
    kinds = Counter(q["kind"] for q in out["questions"])
    assert kinds["single"] and len(out["questions"]) - kinds["single"] >= 6
    for q in out["questions"]:
        if q["kind"] == "multi":
            assert q["select"] == 2 and set(q["answers"]) <= set(q["choices"])
        elif q["kind"] == "order":
            assert sorted(q["items"]) == sorted(q["choices"])
        elif q["kind"] == "match":
            assert all(len(p) == 2 and p[1] in q["choices"] for p in q["pairs"])
        else:
            assert q["answer"] in q["choices"] and "items" not in q
    json.dumps(out)


def test_web_bundle_carries_pbq_records():
    from tools.build_web_bundle import build
    bank = build(variants=0)["exam_bank"]
    assert {r["id"] for r in bank} >= set(BY_ID)
    assert next(r for r in bank if r["id"] == "PBQ-001")["type"] in ("multi", "order", "match")


def test_exports_skip_non_single_kinds():
    from tools.export_anki import collect
    from tools.export_ctfd import build_challenges
    pbq_stems = {r["stem"] for r in RECORDS}
    qs = collect(0)
    assert not any(q["prompt"] in pbq_stems for q in qs)
    assert any(q["lab"] == 0 for q in qs)                                   # single bank questions still exported
    assert not any(c["_question"]["prompt"] in pbq_stems for c in build_challenges(0))
