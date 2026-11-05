"""Lab-backed PBQs (tools/build_lab_pbqs.py -> data/exam_bank/pbq-labs.json): answers come from the engines."""

from __future__ import annotations

import json
from collections import Counter

import pytest

from labs import LABS
from tools import build_lab_pbqs as gen
from utils import exam_bank
from utils.loader import load_data, load_policies

POLICIES = load_policies()
BUILT = gen.build(POLICIES)
RECORDS = [r for r, _ in BUILT]
BY_LAB: dict[int, list] = {}
for _rec, _truth in BUILT:
    BY_LAB.setdefault(_rec["lab"], []).append((_rec, _truth))
FILE = json.loads(gen.OUT.read_text(encoding="utf-8"))


def _targets(rec: dict) -> list[str]:
    return [p["match"] for p in rec["pairs"]]


def _answers(rec: dict) -> list:
    return {"match": lambda r: _targets(r), "order": lambda r: r["items"], "multi": lambda r: r["choices"]}[rec["type"]](rec)


def test_file_is_up_to_date_and_deterministic():
    text = gen.render(POLICIES)
    assert gen.OUT.read_text(encoding="utf-8") == text, "run: python tools/build_lab_pbqs.py"
    assert gen.render(POLICIES) == text
    assert text.endswith("\n") and FILE["title"] == gen.TITLE and FILE["note"] == gen.NOTE
    assert gen.main(["--check"]) == 0


def test_records_validate():
    assert exam_bank.validate(FILE["questions"]) == []
    assert exam_bank.main([str(gen.OUT)]) == 0


def test_coverage_targets():
    qs = FILE["questions"]
    assert len(qs) >= 20
    assert len({q["lab"] for q in qs}) >= 10
    per_obj = Counter(q["objective"] for q in qs)
    assert len(per_obj) >= 12
    assert per_obj["4.2"] >= 2 and per_obj["4.7"] >= 2
    kinds = Counter(q["type"] for q in qs)
    assert kinds["order"] >= 3 and kinds["match"] >= 10
    assert [q["id"] for q in qs] == [f"LPBQ-{i:03d}" for i in range(1, len(qs) + 1)]


def test_topics_valid_and_ids_unique_across_bank():
    topics, _ = exam_bank.load_topics()
    for q in FILE["questions"]:
        assert q["topic"] in topics[q["objective"]], q["id"]
        assert isinstance(q["lab"], int) and q["lab"] in LABS
    bank = exam_bank.load_bank()
    ids = [q["id"] for q in bank]
    assert len(ids) == len(set(ids))
    assert {q["id"] for q in FILE["questions"]} <= set(ids)


def test_items_are_distinct_and_truth_lines_up():
    for rec, truth in BUILT:
        shown = _answers(rec) if rec["type"] != "match" else [p["item"] for p in rec["pairs"]]
        assert len(set(shown)) == len(shown), rec["id"]
        n = len(rec["pairs"]) if rec["type"] == "match" else len(rec["items"]) if rec["type"] == "order" else len(rec["choices"])
        assert len(truth["source"]) == len(truth["engine"]) == n, rec["id"]
        assert truth["lab"] == rec["lab"] and truth["id"] == rec["id"]


def test_match_targets_follow_the_engine_codes():
    """Same engine verdict -> same target; different verdicts -> different targets (no swappable items)."""
    for rec, truth in BUILT:
        if rec["type"] != "match":
            continue
        code_to_target: dict = {}
        for code, target in zip(truth["engine"], _targets(rec)):
            assert code_to_target.setdefault(code, target) == target, rec["id"]
        assert len(set(code_to_target.values())) == len(code_to_target), rec["id"]
        assert not set(rec.get("targets_extra", [])) & set(code_to_target.values()), rec["id"]


# --------------------------------------------------------------------------- #
# Re-derive answers from the engines directly
# --------------------------------------------------------------------------- #
def test_disposal_and_inventory_answers_match_lab21():
    mod, data = LABS[21][0], load_data(LABS[21][1])
    cfg = POLICIES["asset_mgmt"]
    reqs = {r["id"]: r for r in data["disposals"]}
    disposal, inventory = BY_LAB[21]
    for src, target in zip(disposal[1]["source"], _targets(disposal[0])):
        d = mod.evaluate_disposal(reqs[src], cfg, data["today"])
        key = "APPROVE" if d.decision == "APPROVE" else d.rules[0]
        assert gen.DISPOSAL_OUTCOME[key] == target
    assert "Approve the disposal" in _targets(disposal[0])
    found = {r.key: r.primary for r in mod.reconcile(data, cfg)}
    for src, target in zip(inventory[1]["source"], _targets(inventory[0])):
        assert gen.INVENTORY_OUTCOME[found[src]] == target


def test_governor_answers_match_lab5():
    mod, data = LABS[5][0], load_data(LABS[5][1])
    pol = POLICIES["ai_governance"]
    acts = {a["id"]: a for a in data["actions"]}
    verdict_q = next(r for r, _ in BY_LAB[5] if r["type"] == "match" and "decision" in r["stem"])
    truth = next(t for r, t in BY_LAB[5] if r is verdict_q)
    for src, target in zip(truth["source"], _targets(verdict_q)):
        v = mod.AgentGovernor(pol).evaluate(mod.AgentAction.from_dict(acts[src])).verdict
        assert gen.GOVERNOR[v] == target
    multi, mt = next((r, t) for r, t in BY_LAB[5] if r["type"] == "multi")
    allowed = [c for c, src in zip(multi["choices"], mt["source"])
               if mod.AgentGovernor(pol).evaluate(mod.AgentAction.from_dict(acts[src])).verdict == "ALLOW"]
    assert sorted(allowed) == sorted(multi["answers"]) and multi["select"] == 2


def test_volatility_order_matches_lab7_ranks():
    data = load_data(LABS[7][1])
    rec, truth = next((r, t) for r, t in BY_LAB[7] if r["topic"] == "Digital forensics")
    ranks = [data["actions"][a]["evidence"]["volatility_rank"] for a in truth["source"]]
    assert ranks == sorted(ranks) and len(set(ranks)) == len(ranks)
    phases_rec, phases_truth = next((r, t) for r, t in BY_LAB[7] if r["topic"] == "Incident response process")
    idx = [LABS[7][0].PHASE_IDX[data["actions"][a]["phase"]] for a in phases_truth["source"]]
    assert idx == sorted(idx) and len(set(idx)) == len(idx)


def test_ale_order_recomputed_from_data():
    data = load_data(LABS[6][1])
    risks = {r["id"]: r for r in data["risks"]}
    rec, truth = next((r, t) for r, t in BY_LAB[6] if r["type"] == "order")
    ales = [risks[i]["asset_value"] * risks[i]["exposure_factor"] * risks[i]["aro"] for i in truth["source"]]
    assert ales == sorted(ales, reverse=True) and len(set(ales)) == len(ales)
    for item, i in zip(rec["items"], truth["source"]):
        assert item.startswith(risks[i]["title"])


def test_vulnerability_order_recomputed_from_data():
    data, cfg = load_data(LABS[9][1]), POLICIES["vulnerability_management"]
    cmdb = POLICIES["change_management"]["systems"]
    finds = {f["id"]: f for f in data["findings"]}
    rec, truth = next((r, t) for r, t in BY_LAB[9] if r["type"] == "order")

    def score(f):
        s = cmdb[f["asset"]]
        return (f["cvss"] * cfg["criticality_multiplier"][str(s["criticality"])]
                * (cfg["kev_multiplier"] if f["kev"] else 1.0) * cfg["exposure_multiplier"][s["exposure"]])

    scores = [score(finds[i]) for i in truth["source"]]
    assert scores == sorted(scores, reverse=True)
    assert all(a - b >= 1 for a, b in zip(scores, scores[1:]))


def test_conditional_access_and_dlp_answers():
    mod25, data25 = LABS[25][0], load_data(LABS[25][1])
    outcomes = {r.id: r.outcome for r in mod25.evaluate_all(data25, POLICIES)}
    rec, truth = next((r, t) for r, t in BY_LAB[25] if r["topic"] == "Multifactor authentication")
    for src, target in zip(truth["source"], _targets(rec)):
        assert gen.CA_OUTCOME[outcomes[src]] == target
    mod18, data18 = LABS[18][0], load_data(LABS[18][1])
    dec = {d.id: d for d in mod18.evaluate_all(data18, POLICIES)}
    rec, truth = BY_LAB[18][0]
    for src, target in zip(truth["source"], _targets(rec)):
        d = dec[src]
        assert target.startswith({"ALLOW": "Allow as", "ALLOW_WITH_PROTECTION": "Allow only after", "BLOCK": "Block"}[d.decision])


def test_resilience_options_are_the_cheapest():
    cfg = POLICIES["resilience"]
    rec, _ = BY_LAB[14][0]
    sites = {p["match"].split()[0].lower(): p["item"] for p in rec["pairs"] if p["match"].endswith(" site")}
    by_cost = sorted(cfg["site_types"], key=lambda k: cfg["site_types"][k]["annual_cost"])
    by_speed = sorted(cfg["site_types"], key=lambda k: cfg["site_types"][k]["rto_hours"])
    assert by_cost == list(reversed(by_speed)) and set(sites) == set(cfg["site_types"])


# --------------------------------------------------------------------------- #
# Playable as exam questions
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("rec", RECORDS, ids=[r["id"] for r in RECORDS])
def test_turns_into_a_question_and_check_accepts_the_answer(rec):
    q = exam_bank.as_question(rec)
    assert q.kind == rec["type"] and q.qid == rec["id"] and q.objective == rec["objective"]
    if rec["type"] == "match":
        good = {p["item"]: p["match"] for p in rec["pairs"]}
        assert q.check(good)
        items = list(good)
        swap = next(((a, b) for a in items for b in items if good[a] != good[b]), None)
        if swap:
            bad = dict(good)
            bad[swap[0]], bad[swap[1]] = good[swap[1]], good[swap[0]]
            assert not q.check(bad)
    elif rec["type"] == "order":
        assert q.check(list(rec["items"]))
        assert not q.check(list(reversed(rec["items"])))
    else:
        assert q.check(list(rec["answers"]))
        assert not q.check([c for c in rec["choices"] if c not in rec["answers"]][:2])
