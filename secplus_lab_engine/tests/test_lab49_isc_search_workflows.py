"""Lab 49 — ISC search queries, scheduled reports, workflow validation and event trigger subscriptions."""

from __future__ import annotations

import json
import random

import pytest

from labs.lab49_isc_search_workflows import (build_challenges, deliver, generate_scenario, parse_filter, run_demo,
                                             run_search, schedule_report, validate_workflow, var_name)
from utils.challenge import check


@pytest.fixture
def cfg(policies):
    return policies["isc_search_workflows"]


PEOPLE = [
    {"name": "amy.lee", "email": "amy@x.example", "status": "ACTIVE", "inactive": False, "created": "2026-01-01T08:00:00Z",
     "manager": {"name": "bo.chan"}, "attributes": {"department": "Finance", "location": "Sao Paulo",
                                                    "cloudLifecycleState": "terminated"},
     "accounts": [{"source": {"name": "Active Directory"}, "disabled": True},
                  {"source": {"name": "ServiceNow"}, "disabled": False}],
     "access": [{"type": "ENTITLEMENT", "name": "Domain Admins", "privileged": True}]},
    {"name": "bo.chan", "email": "bo@x.example", "status": "ACTIVE", "inactive": False, "created": "2026-06-30T08:00:00Z",
     "manager": None, "attributes": {"department": "IT", "location": "London", "cloudLifecycleState": "active"},
     "accounts": [{"source": {"name": "Active Directory"}, "disabled": False}], "access": []},
]


def hits(q, cfg, people=PEOPLE, as_of="2026-07-10"):
    r = run_search(q, people, cfg, as_of)
    return r.outcome, r.matches


def test_field_term_case_insensitive_and_phrase(cfg):
    assert hits("attributes.department:finance", cfg) == ("MATCHES", ["amy.lee"])
    assert hits('attributes.location:"sao paulo"', cfg) == ("MATCHES", ["amy.lee"])
    assert hits("attributes.location:paulo", cfg) == ("MATCHES", ["amy.lee"])          # one word of the value
    assert hits("attributes.location.exact:\"sao paulo\"", cfg)[0] == "NO_MATCH"      # .exact is case sensitive


def test_and_or_not_parentheses_and_implicit_or(cfg):
    assert hits("attributes.department:Finance AND attributes.location:London", cfg)[0] == "NO_MATCH"
    assert hits("attributes.department:Finance OR attributes.location:London", cfg)[1] == ["amy.lee", "bo.chan"]
    implicit = run_search("attributes.department:Finance attributes.location:London", PEOPLE, cfg)
    assert implicit.matches == ["amy.lee", "bo.chan"] and "OR" in implicit.reasons[0]
    assert hits("NOT attributes.department:IT", cfg)[1] == ["amy.lee"]
    assert hits("!attributes.department:IT", cfg)[1] == ["amy.lee"]
    assert hits("attributes.department:(Finance OR IT) AND NOT (status:ACTIVE AND manager.name:bo.chan)",
                cfg)[1] == ["bo.chan"]


def test_wildcards_exists_and_counts(cfg):
    assert hits("name:a*", cfg)[1] == ["amy.lee"] and hits("name:b?.chan", cfg)[1] == ["bo.chan"]
    assert hits("NOT _exists_:manager.name", cfg)[1] == ["bo.chan"]
    assert hits("_exists_:manager.name", cfg)[1] == ["amy.lee"]
    assert hits("accountCount:>1", cfg)[1] == ["amy.lee"]


def test_ranges_inclusive_exclusive_and_relative(cfg):
    assert hits("created:[2026-01-01 TO 2026-06-30]", cfg)[1] == ["amy.lee", "bo.chan"]
    assert hits("created:{2026-01-01 TO 2026-06-30}", cfg)[0] == "NO_MATCH"
    assert hits("created:[2026-01-01 TO 2026-06-30}", cfg)[1] == ["amy.lee"]
    assert hits("created:>=now-30d", cfg)[1] == ["bo.chan"]                            # as_of 2026-07-10
    assert hits("created:<=2026-01-01", cfg)[1] == ["amy.lee"]


def test_nested_query_needs_one_matching_item(cfg):
    # amy has a disabled AD account and an enabled ServiceNow account: the nested query must not mix them.
    assert hits('@accounts(source.name:"Active Directory" AND disabled:false)', cfg)[1] == ["bo.chan"]
    assert hits('@accounts(source.name:"Active Directory") AND @accounts(disabled:false)', cfg)[1] == \
        ["amy.lee", "bo.chan"]
    assert hits("@access(privileged:true)", cfg)[1] == ["amy.lee"]


@pytest.mark.parametrize("query, fragment", [
    ("", "empty query"),
    ("   ", "empty query"),
    ("attributes.department:Finance and status:ACTIVE", "capitals"),
    ("attributes.costCenter:4410", "unknown field"),
    ("nickname:amy", "unknown field"),
    ('attributes.location:"sao paulo', "unterminated"),
    ("(attributes.department:Finance", "closing parenthesis"),
    ("attributes.department:Finance)", "without a matching"),
    ("created:[2026-01-01 2026-06-30]", "TO"),
    ("accountCount:many", "not a number"),
    ("created:2026*", "wildcards work only on text"),
    ("inactive:maybe", "true or false"),
    ("@groups(name:x)", "unknown nested object"),
    ("@accounts(attributes.department:IT)", "unknown field"),
    ("attributes.department:", "no value"),
    ("attributes.department:Finance AND", "query ends"),
])
def test_invalid_queries_return_nothing(cfg, query, fragment):
    r = run_search(query, PEOPLE, cfg, "2026-07-10")
    assert r.outcome == "INVALID_QUERY" and r.matches == [] and fragment in r.error


def test_relative_date_without_as_of_is_invalid(cfg):
    assert run_search("created:>=now-30d", PEOPLE, cfg, None).outcome == "INVALID_QUERY"


def test_missing_values_never_match(cfg):
    ghost = [{"name": "ghost"}]
    assert hits("attributes.department:IT", cfg, ghost)[0] == "NO_MATCH"
    assert hits("NOT attributes.department:IT", cfg, ghost)[1] == ["ghost"]


def report(cfg, **kw):
    base = {"id": "S1", "name": "r", "query": "attributes.department:Finance", "schedule": {"type": "DAILY"},
            "recipients": ["bo.chan"], "emailEmptyResults": False}
    base.update(kw)
    return schedule_report(base, {"identities": PEOPLE, "as_of": "2026-07-10"}, cfg)


def test_scheduled_report_rules_in_order(cfg):
    assert report(cfg).outcome == "SEND_REPORT"
    assert report(cfg, query="attributes.department:finance and x:y").outcome == "NOT_SENT"
    assert report(cfg, schedule=None).outcome == "NOT_SENT"
    assert report(cfg, recipients=["nobody"]).outcome == "NOT_SENT"
    assert report(cfg, recipients=[]).outcome == "NOT_SENT"
    gone = [dict(PEOPLE[1], inactive=True)]
    assert schedule_report({"id": "S", "name": "r", "query": "status:ACTIVE", "schedule": {"t": 1},
                            "recipients": ["bo.chan"]}, {"identities": gone}, cfg).outcome == "NOT_SENT"
    assert report(cfg, query="attributes.department:Legal").outcome == "SKIP_EMPTY"
    assert report(cfg, query="attributes.department:Legal", emailEmptyResults=True).outcome == "SEND_REPORT"


def S(name, stype, nxt=None, uses=None, **kw):
    s = {"name": name, "type": stype, **kw}
    if nxt:
        s["next"] = nxt
    if uses:
        s["uses"] = uses
    return s


T = S("Identity Created", "Event Trigger", "Get Identity", trigger="Identity Created")
END = S("End Step - Success", "End Step - Success")


def wf(*steps):
    return validate_workflow({"id": "W", "name": "w", "steps": list(steps)}, cfg_global())


def cfg_global():
    from utils.loader import load_policies
    return load_policies()["isc_search_workflows"]


def test_valid_linear_workflow_gives_order_even_when_scrambled():
    r = wf(END, S("Send Email", "Send Email", END["name"], ["$.getIdentity.email"]),
           S("Get Identity", "Get Identity", "Send Email", ["$.trigger.identity.id"]), T)
    assert r.code == "VALID" and r.order == ["Identity Created", "Get Identity", "Send Email", "End Step - Success"]


def test_workflow_trigger_rules():
    assert wf().code == "NO_TRIGGER"
    assert wf(S("Get Identity", "Get Identity", END["name"]), END).code == "NO_TRIGGER"
    assert wf(T, S("Scheduled Trigger", "Scheduled Trigger", "Get Identity"),
              S("Get Identity", "Get Identity", END["name"]), END).code == "MULTIPLE_TRIGGERS"
    assert wf(T, S("Get Identity", "Get Identity", "Identity Created"), END).code == "TRIGGER_NOT_FIRST"
    bad = dict(T, trigger="Identity Teleported")
    assert wf(bad, S("Get Identity", "Get Identity", END["name"]), END).code == "UNKNOWN_STEP"
    assert wf(T, S("Get Identity", "Teleport Identity", END["name"]), END).code == "UNKNOWN_STEP"
    assert wf(T, S("Get Identity", "Get Identity", END["name"]), S("Get Identity", "Wait", END["name"]),
              END).code == "DUPLICATE_STEP_NAME"


def test_workflow_structure_rules():
    assert wf(T, S("Get Identity", "Get Identity", "Nowhere"), END).code == "BROKEN_LINK"
    assert wf(T, S("Get Identity", "Get Identity", "Compare Strings"),
              S("Compare Strings", "Compare Strings", true=END["name"]), END).code == "MISSING_BRANCH"
    assert wf(T, S("Get Identity", "Get Identity", END["name"]),
              S(END["name"], END["type"], "Get Identity")).code == "END_STEP_HAS_NEXT"
    assert wf(T, S("Get Identity", "Get Identity"), END).code == "PATH_NOT_ENDED"
    assert wf(T, S("Get Identity", "Get Identity", "Wait"), S("Wait", "Wait", "Get Identity"), END).code == \
        "LOOP_DETECTED"
    assert wf(T, S("Get Identity", "Get Identity", END["name"]), S("Send Email", "Send Email", END["name"]),
              END).code == "UNREACHABLE_STEP"


def test_variables_must_come_from_an_earlier_step_on_every_path():
    early = wf(S("Identity Created", "Event Trigger", "Send Email", trigger="Identity Created"),
               S("Send Email", "Send Email", "Get Identity", ["$.getIdentity.email"]),
               S("Get Identity", "Get Identity", END["name"]), END)
    assert early.code == "VARIABLE_NOT_AVAILABLE"
    one_branch = wf(T, S("Get Identity", "Get Identity", "Compare Strings", ["$.trigger.identity.id"]),
                    S("Compare Strings", "Compare Strings", true="Get Access", false="Send Email",
                      uses=["$.getIdentity.attributes.department"]),
                    S("Get Access", "Get Access", "Send Email"),
                    S("Send Email", "Send Email", END["name"], ["$.getAccess.accessItems"]), END)
    assert one_branch.code == "VARIABLE_NOT_AVAILABLE"
    both = wf(T, S("Get Identity", "Get Identity", "Compare Strings"),
              S("Compare Strings", "Compare Strings", true="Send Email", false=END["name"],
                uses=["$.getIdentity.email"]),
              S("Send Email", "Send Email", END["name"], ["$.getIdentity.email"]), END)
    assert both.code == "VALID" and both.order is None
    assert var_name("Get Identity 2") == "getIdentity2" and var_name("HTTP Request") == "httpRequest"


def test_jsonpath_filters(cfg):
    ev = {"identity": {"name": "john.doe"}, "status": "Error", "errors": ["x"],
          "changes": [{"attribute": "department", "newValue": "US Tier 2 Support"}]}
    yes = ['$[?($.identity.name == "john.doe")]', '$.changes[?(@.attribute == "department")]',
           "$.changes[?(@.newValue =~ /us.*support/i)]", "$.changes[?(@.newValue in ['US Tier 2 Support'])]",
           '$[?($.identity.name contains "john")]', "$[?($.errors.length() >= 1)]", "$.changes",
           "$[?($.errors anyof ['x','y'])]", '$[?(!($.status == "Success"))]']
    no = ['$[?($.status == "error")]', "$.changes[?(@.newValue =~ /Support/)]", "$.missing",
          '$[?($.nothere != "x")]', '$[?($.identity.name contains "JOHN")]']
    from labs.lab49_isc_search_workflows import filter_matches
    assert all(filter_matches(parse_filter(f), ev) for f in yes)
    assert not any(filter_matches(parse_filter(f), ev) for f in no)
    for broken in ('$.changes[?(@.attribute = "x")]', "", "changes[0]", "$[?($.a == )]", "$[?(@.a == 'x')"):
        with pytest.raises(ValueError):
            parse_filter(broken)


def test_subscription_outcomes_and_deny_by_default(cfg):
    data = {"events": [{"id": "E1", "trigger": "Identity Created", "payload": {"attributes": {"department": "IT"}}},
                       {"id": "E2", "trigger": "Identity Teleported", "payload": {}}],
            "subscriptions": [
                {"id": "A", "trigger": "Identity Created", "enabled": True, "filter": None},
                {"id": "B", "trigger": "Identity Created", "enabled": True,
                 "filter": "$.attributes[?(@.department == 'Sales')]"},
                {"id": "C", "trigger": "Identity Created", "enabled": False, "filter": None},
                {"id": "D", "trigger": "Identity Created", "filter": None},
                {"id": "E", "trigger": "Identity Created", "enabled": True, "filter": "$.attributes[?(@.x = 1)]"},
                {"id": "F", "trigger": "Identity Teleported", "enabled": True, "filter": None}]}
    pairs, fired, notes = deliver(data, cfg)
    out = {(p.event, p.subscription): p.outcome for p in pairs}
    assert out[("E1", "A")] == "FIRED" and out[("E1", "B")] == "FILTERED_OUT"
    assert out[("E1", "C")] == out[("E1", "D")] == "DISABLED" and out[("E1", "E")] == "INVALID_FILTER"
    assert out[("-", "F")] == "UNKNOWN_TRIGGER" and fired == {"E1": ["A"], "E2": []} and "E2" in notes


def test_request_response_trigger_is_noted(cfg):
    data = {"events": [{"id": "E", "trigger": "Access Request Submitted", "payload": {}}],
            "subscriptions": [{"id": "S", "trigger": "Access Request Submitted", "enabled": True, "filter": None}]}
    pairs, _, _ = deliver(data, cfg)
    assert cfg["event_triggers"]["Access Request Submitted"]["type"] == "REQUEST_RESPONSE"
    assert any("REQUEST_RESPONSE" in r for r in pairs[0].reasons)


def test_sample_outcomes(policies, quiet_ui, data):
    out = run_demo(quiet_ui, policies, data("sample_isc_search_workflows.json"))
    json.dumps(out)
    assert out["queries"] == {"Q01": "MATCHES", "Q02": "MATCHES", "Q03": "MATCHES", "Q04": "MATCHES",
                              "Q05": "MATCHES", "Q06": "MATCHES", "Q07": "INVALID_QUERY", "Q08": "INVALID_QUERY",
                              "Q09": "NO_MATCH", "Q10": "MATCHES", "Q11": "INVALID_QUERY", "Q12": "MATCHES"}
    assert out["matches"]["Q02"] == ["chloe.martin"] and out["matches"]["Q04"] == ["ava.reyes"]
    assert out["matches"]["Q03"] == ["ava.reyes", "elena.novak", "grace.lindqvist"]
    assert len(out["matches"]["Q10"]) == 4
    assert out["reports"] == {"S01": "SEND_REPORT", "S02": "NOT_SENT", "S03": "SKIP_EMPTY", "S04": "NOT_SENT",
                              "S05": "SEND_REPORT"}
    assert out["workflows"] == {"W01": "VALID", "W02": "VALID", "W03": "MISSING_BRANCH", "W04": "PATH_NOT_ENDED",
                                "W05": "VARIABLE_NOT_AVAILABLE", "W06": "MULTIPLE_TRIGGERS",
                                "W07": "VARIABLE_NOT_AVAILABLE", "W08": "VALID"}
    assert out["events"] == {"E01": ["SUB03"], "E02": ["SUB01", "SUB10"], "E03": ["SUB02", "SUB10"],
                             "E04": ["SUB04"], "E05": ["SUB05"], "E06": ["SUB06"], "E07": []}
    assert {"FIRED", "FILTERED_OUT", "DISABLED", "INVALID_FILTER"} <= set(out["deliveries"].values())
    assert out["metrics"]["deliveries"] == 8 and out["metrics"]["workflows_valid"] == 3


def answer_for(q):
    if q.kind == "multi":
        return list(q.answers)
    if q.kind == "order":
        return list(q.items)
    return q.answer


def test_challenges_score_full_marks_and_follow_rules(policies, data):
    qs = build_challenges(policies, data("sample_isc_search_workflows.json"))
    assert len(qs) >= 12
    assert all(check(q, answer_for(q)) for q in qs)
    assert {q.objective for q in qs} <= {"1.1", "1.3"}
    assert {"order", "multi", "single"} <= {q.kind for q in qs}
    for q in qs:
        assert len(set(q.choices)) == len(q.choices)
        text = (q.prompt + " " + " ".join(q.choices)).lower()
        assert " lab " not in f" {text} " and "lab." not in text


def test_generated_scenario_is_deterministic_and_runs(policies, quiet_ui):
    a = generate_scenario(random.Random(11), policies)
    assert a == generate_scenario(random.Random(11), policies) != generate_scenario(random.Random(12), policies)
    out = run_demo(quiet_ui, policies, a)
    assert set(out["queries"].values()) == {"MATCHES", "NO_MATCH", "INVALID_QUERY"}
    assert set(out["reports"].values()) == {"SEND_REPORT", "SKIP_EMPTY", "NOT_SENT"}
    assert "VALID" in out["workflows"].values() and len(set(out["workflows"].values())) >= 4
    assert {"FIRED", "FILTERED_OUT", "DISABLED", "INVALID_FILTER"} <= set(out["deliveries"].values())
    qs = build_challenges(policies, a)
    assert len(qs) >= 12 and all(check(q, answer_for(q)) for q in qs)
