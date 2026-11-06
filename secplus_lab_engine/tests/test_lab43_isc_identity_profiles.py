"""Lab 43 — ISC identity profiles, attribute mappings and transforms tests."""

from __future__ import annotations

import copy
import random

import pytest

from labs.lab43_isc_identity_profiles import (ERROR_CHOICE, OUTCOMES, Ctx, TransformError, build_challenges,
                                              evaluate, evaluate_people, generate_scenario, review_profiles,
                                              run_demo, standard_profiles)
from utils.challenge import run_challenge
from utils.loader import load_json

SAMPLE = "sample_isc_identity_profiles.json"
ROOT = __import__("pathlib").Path(__file__).resolve().parent.parent


@pytest.fixture
def cfg(policies):
    return policies["isc_identity_profiles"]


def ev(cfg, t, implicit=None, accounts=None, identity=None):
    return evaluate(t, Ctx(accounts or {}, identity or {}, cfg), implicit)


def acct(src, attr):
    return {"type": "accountAttribute", "attributes": {"sourceName": src, "attributeName": attr}}


def scenario(accounts):
    sources, profiles = standard_profiles("t.example")
    return {"sources": sources, "identity_profiles": profiles, "accounts": accounts}


def emp(i, f="Ada", l="Byron", status="Active", **over):
    a = {"FIRST_NAME": f, "LAST_NAME": l, "PREFERRED_NAME": "", "WORK_EMAIL": f"{f}.{l}@t.example".lower(),
         "DEPT_CODE": "ENG", "HIRE_DATE": "01/02/2024", "WORK_PHONE": "(312) 555-0142", "WORKER_STATUS": status}
    a.update(over)
    return {"id": i, "source": "Workday HR", "attributes": a}


def con(i, f="Cy", l="Dahl", status="A", **over):
    a = {"contractor_id": "C-7", "first_name": f, "last_name": l, "email": f"{f}.{l}@t.example".lower(),
         "vendor": "V", "end_date": "2027-01-31", "status": status}
    a.update(over)
    return {"id": i, "source": "Contractor CSV", "attributes": a}


def outcomes(cfg, accounts):
    return {r.id: r for r in evaluate_people(scenario(accounts), cfg)}


# ----------------------------------------------------------------- transforms
def test_string_transforms_use_implicit_input_and_explicit_input(cfg):
    assert ev(cfg, {"type": "lower"}, "MiXeD") == "mixed"
    assert ev(cfg, {"type": "upper", "attributes": {"input": {"type": "trim"}}}, "  osaka ") == "OSAKA"
    assert ev(cfg, {"type": "upper", "attributes": {"input": "explicit"}}, "ignored") == "EXPLICIT"
    assert ev(cfg, {"type": "lower"}, None) is None


def test_substring_begin_minus_one_offsets_and_out_of_range(cfg):
    assert ev(cfg, {"type": "substring", "attributes": {"begin": 4}}, "EMP-00731") == "00731"
    assert ev(cfg, {"type": "substring", "attributes": {"begin": -1, "end": 3}}, "abcdef") == "abc"
    assert ev(cfg, {"type": "substring", "attributes": {"begin": 1, "beginOffset": 1, "end": 4, "endOffset": 1}},
              "abcdefg") == "cde"
    with pytest.raises(TransformError):
        ev(cfg, {"type": "substring", "attributes": {"begin": 0, "end": 9}}, "abc")


def test_concat_replace_static_variables(cfg):
    a = {"HR": {"fn": "Ada", "ln": "Byron"}}
    t = {"type": "concat", "attributes": {"values": [acct("HR", "fn"), ".", acct("HR", "ln")]}}
    assert ev(cfg, t, accounts=a) == "Ada.Byron"
    assert ev(cfg, {"type": "concat", "attributes": {"values": [acct("HR", "missing"), "@x"]}}, accounts=a) is None
    assert ev(cfg, {"type": "replace", "attributes": {"regex": "(\\w+)-(\\d+)", "replacement": "$2-$1"}},
              "EMP-42") == "42-EMP"
    assert ev(cfg, {"type": "static", "attributes": {"value": "Hi $who", "who": acct("HR", "fn")}},
              accounts=a) == "Hi Ada"
    with pytest.raises(TransformError):
        ev(cfg, {"type": "static", "attributes": {"value": "Hi $nobody"}})


def test_lookup_default_and_no_default_errors(cfg):
    t = {"type": "lookup", "attributes": {"table": {"A": "active", "default": "inactive"}}}
    assert ev(cfg, t, "A") == "active" and ev(cfg, t, "Z") == "inactive"
    with pytest.raises(TransformError, match="no default"):
        ev(cfg, {"type": "lookup", "attributes": {"table": {"A": "active"}}}, "a")   # keys are case-sensitive


def test_conditional_eq_only_case_sensitive_and_null_operand(cfg):
    t = {"type": "conditional", "attributes": {"expression": "$s eq A", "positiveCondition": "yes",
                                               "negativeCondition": "no", "s": acct("HR", "s")}}
    assert ev(cfg, t, accounts={"HR": {"s": "A"}}) == "yes"
    assert ev(cfg, t, accounts={"HR": {"s": "a"}}) == "no"
    with pytest.raises(TransformError, match="null"):
        ev(cfg, t, accounts={"HR": {}})
    ne = copy.deepcopy(t)
    ne["attributes"]["expression"] = "$s ne A"
    with pytest.raises(TransformError, match="only valid comparison"):
        ev(cfg, ne, accounts={"HR": {"s": "A"}})


def test_first_valid_skips_nulls_and_errors_only_with_ignore_errors(cfg):
    bad = {"type": "lookup", "attributes": {"table": {}}}
    t = {"type": "firstValid", "attributes": {"values": [acct("HR", "nope"), bad, "fallback"]}}
    with pytest.raises(TransformError):
        ev(cfg, t, "x", accounts={"HR": {}})
    t["attributes"]["ignoreErrors"] = True
    assert ev(cfg, t, "x", accounts={"HR": {}}) == "fallback"


def test_identity_attribute_only_when_computed_earlier(cfg):
    t = {"type": "identityAttribute", "attributes": {"name": "uid"}}
    assert ev(cfg, t, identity={"uid": "ada"}) == "ada"
    with pytest.raises(TransformError, match="not computed yet"):
        ev(cfg, t, identity={})


def test_date_format_and_e164(cfg):
    assert ev(cfg, {"type": "dateFormat", "attributes": {"inputFormat": "PEOPLE_SOFT"}}, "03/14/2019") == \
        "2019-03-14T00:00:00.000Z"
    assert ev(cfg, {"type": "dateFormat", "attributes": {"inputFormat": "yyyy-MM-dd", "outputFormat": "dd.MM.yyyy"}},
              "2027-01-31") == "31.01.2027"
    with pytest.raises(TransformError):
        ev(cfg, {"type": "dateFormat", "attributes": {"inputFormat": "PEOPLE_SOFT"}}, "31/31/2020")
    assert ev(cfg, {"type": "e164phone"}, "1-312-555-0142") == "+13125550142"
    assert ev(cfg, {"type": "e164phone", "attributes": {"defaultRegion": "GB"}}, "020 7946 0018") == "+442079460018"
    assert ev(cfg, {"type": "e164phone"}, "ext. 22") is None                 # invalid number -> null (ISC docs)


def test_unknown_and_unsimulated_types_are_refused(cfg):
    with pytest.raises(TransformError, match="unknown transform type"):
        ev(cfg, {"type": "titleCase"}, "ada")
    with pytest.raises(TransformError, match="not simulated"):
        ev(cfg, {"type": "dateMath", "attributes": {"expression": "now"}})
    with pytest.raises(TransformError, match="no type"):
        ev(cfg, {"attributes": {}}, "x")


# ----------------------------------------------------------------- profiles and outcomes
def test_profile_review_flags_sign_in_and_mapping_problems(cfg, data):
    d = data(SAMPLE)
    res = {p.name: p for p in review_profiles(d, cfg)}
    assert res["Employees"].status == "READY"
    assert res["Contractors"].status == "MISCONFIGURED" and "every user is blocked" in res["Contractors"].reasons[0]
    assert res["Interns"].status == "MISCONFIGURED" and "Campus LDAP" in res["Interns"].reasons[0]
    d2 = copy.deepcopy(d)
    emp_p = next(p for p in d2["identity_profiles"] if p["name"] == "Employees")
    del emp_p["sign_in"]["method"]
    del emp_p["mappings"]["email"]
    emp_p["priority"] = 20                                    # same as Contractors
    r = {p.name: p for p in review_profiles(d2, cfg)}["Employees"]
    assert r.status == "MISCONFIGURED"
    text = " ".join(r.reasons)
    assert "sign-in method" in text and "'email' has no mapping" in text and "shared with Contractors" in text


def test_higher_priority_profile_wins_for_person_on_two_sources(cfg):
    out = outcomes(cfg, [con("C1", "Pat", "Ng"), emp("W1", "Pat", "Ng", WORK_EMAIL="PAT.NG@t.example")])
    (r,) = out.values()
    assert r.profile == "Employees" and sorted(r.accounts) == ["C1", "W1"] and r.outcome == "OK"


def test_no_profile_for_non_authoritative_source(cfg):
    out = outcomes(cfg, [{"id": "L1", "source": "Legacy Payroll", "attributes": {"email": "x@t.example"}}])
    assert out["L1"].outcome == "NO_PROFILE" and out["L1"].profile is None


def test_mapping_errors_for_empty_required_and_unknown_lifecycle_state(cfg):
    out = outcomes(cfg, [emp("W1", l="   "), emp("W2", "Bo", "Cole", status="Leave"), con("C1", l="")])
    assert out["W1"].outcome == "MAPPING_ERROR" and "lastname" in " ".join(out["W1"].reasons)
    assert out["W2"].outcome == "MAPPING_ERROR" and "'leave' is not a lifecycle state" in " ".join(out["W2"].reasons)
    assert out["C1"].outcome == "MAPPING_ERROR"


def test_transform_error_wins_and_stores_no_value(cfg):
    out = outcomes(cfg, [emp("W1", status="Pending", LAST_NAME="")])
    r = out["W1"]
    assert r.outcome == "TRANSFORM_ERROR" and "MAPPING_ERROR" in r.findings       # precedence
    assert "cloudLifecycleState" not in r.attributes


def test_missing_input_is_never_ok(cfg):
    out = outcomes(cfg, [{"id": "W1", "source": "Workday HR", "attributes": {}},
                         {"id": "C1", "source": "Contractor CSV", "attributes": {}}])
    assert out["W1"].outcome == "TRANSFORM_ERROR"            # lookup on a null status has no default
    assert out["C1"].outcome == "TRANSFORM_ERROR"            # conditional on a null status
    assert all(r.outcome != "OK" for r in out.values())


def test_duplicate_uid_later_identity_loses(cfg):
    out = outcomes(cfg, [emp("W1", "Jordan", "Park"), emp("W2", "Jamie", "Park")])
    assert out["W1"].outcome == "OK" and out["W2"].outcome == "DUPLICATE_UID"
    assert "already belongs to W1" in out["W2"].reasons[-1]


def test_email_falls_back_to_uid_via_identity_attribute(cfg):
    out = outcomes(cfg, [emp("W1", "Mei", "Tanaka", WORK_EMAIL="")])
    assert out["W1"].attributes["email"] == "mtanaka@t.example" and out["W1"].outcome == "OK"


# ----------------------------------------------------------------- sample, generator, challenges
def test_sample_expected_outcomes(policies, quiet_ui, data):
    out = run_demo(quiet_ui, policies, data(SAMPLE))
    assert out["people"] == {"W01": "OK", "W02": "OK", "W03": "DUPLICATE_UID", "W04": "TRANSFORM_ERROR",
                             "W05": "OK", "W06": "MAPPING_ERROR", "W07": "OK", "W08": "OK", "W09": "MAPPING_ERROR",
                             "C02": "OK", "C03": "OK", "C04": "MAPPING_ERROR", "C05": "TRANSFORM_ERROR",
                             "I01": "TRANSFORM_ERROR", "L01": "NO_PROFILE"}
    assert out["profiles"] == {"Contractors": "MISCONFIGURED", "Employees": "READY", "Interns": "MISCONFIGURED"}
    assert out["assigned"]["W07"] == "Employees"
    assert out["transform_tests"] == {"X1": '"731"', "X2": '"ROTTERDAM"', "X3": ERROR_CHOICE,
                                      "X4": '"Unknown country"', "X5": '"03/02/2026"', "X6": ERROR_CHOICE,
                                      "X7": '"+13125550142"'}
    m = out["metrics"]
    assert (m["accounts"], m["people"], m["OK"], m["MAPPING_ERROR"], m["TRANSFORM_ERROR"], m["DUPLICATE_UID"],
            m["NO_PROFILE"], m["profiles_misconfigured"]) == (16, 15, 7, 3, 3, 1, 1, 2)
    assert set(out["people"].values()) == set(OUTCOMES)


def test_briefing_talking_point_matches_demo(policies, quiet_ui, data):
    m = run_demo(quiet_ui, policies, data(SAMPLE))["metrics"]
    tp = load_json(ROOT / "data" / "briefings" / "lab43.json")["talking_point"]
    for phrase in (f"{m['accounts']} HR accounts", f"{m['people']} people", f"built {m['OK']} identities",
                   f"{m['TRANSFORM_ERROR']} transform errors", f"{m['MAPPING_ERROR']} mapping errors",
                   f"{m['DUPLICATE_UID']} duplicate uid", f"{m['profiles_misconfigured']} of 3"):
        assert phrase in tp


def test_generator_is_deterministic_and_covers_every_outcome(policies, quiet_ui):
    a, b = generate_scenario(random.Random(11), policies), generate_scenario(random.Random(11), policies)
    assert a == b and a != generate_scenario(random.Random(12), policies)
    for seed in (1, 7, 11):
        out = run_demo(quiet_ui, policies, generate_scenario(random.Random(seed), policies))
        assert set(out["people"].values()) == set(OUTCOMES)
    assert len(build_challenges(policies, a)) >= 12


def test_challenges_are_valid_and_self_answering_scores_100(policies, quiet_ui, data):
    qs = build_challenges(policies, data(SAMPLE))
    assert len(qs) >= 12
    assert all(q.objective in ("3.1", "3.2") for q in qs)
    assert all(len(set(q.choices)) == len(q.choices) >= 2 for q in qs)
    assert not any("lab" in (q.prompt + " ".join(q.choices)).lower().split() for q in qs)
    assert any("what value does this transform produce" in q.prompt for q in qs)
    answers = iter([q.answer for q in qs])
    res = run_challenge(quiet_ui, 43, qs, ask=lambda _: next(answers), shuffle=False)
    assert res.correct == res.total == len(qs)
