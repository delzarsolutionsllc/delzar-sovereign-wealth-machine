"""
Lab 42 — Okta System Log Investigation & Support Escalation
===========================================================

Okta Professional objectives
----------------------------
* 6.1  System Log and reports: reading an event (eventType, actor, target,
       outcome, client), filter expressions, answering "who, what, when".
* 6.2  Okta help, status and support resources: status.okta.com, the Okta
       Help Center and product documentation, the Okta Community and Okta
       Ideas, and opening a support case with the right evidence.
* 5.2  App access and group assignment troubleshooting: "why can't this
       user open this app?" answered from the log.

How it works
------------
You are the Okta administrator on ticket duty. The engine works on a set of
System Log events in a simplified Okta event shape (uuid, published,
eventType, actor, target list, outcome.result / outcome.reason, client
ipAddress and geographicalContext). Three parts, each deny by default:

1. **Filter expressions.** An Okta-style expression is parsed and evaluated:
   ``attribute op "value"`` with the operators ``eq`` (equals), ``sw``
   (starts with) and ``co`` (contains), joined by ``and`` / ``or`` with
   parentheses; ``and`` binds tighter than ``or``. A ``target.*`` attribute
   matches when ANY target matches. Result: MATCHES (with the events),
   NO_MATCH, or INVALID_EXPRESSION. An empty, malformed or unknown-attribute
   expression is an error and returns NO events, never all of them.
2. **Investigation tickets** (only events with the right outcome count as
   evidence; a missing outcome is never treated as success):
   * app access ("why can't Dana open Workday?"), checks in this order,
     first hit wins: USER_DEACTIVATED (last lifecycle event is a
     deactivate or suspend), LOCKED_OUT (last lock event has no unlock
     after it), NOT_ASSIGNED_TO_APP (no successful
     application.user_membership.add, or a remove after it),
     PROVISIONING_FAILED (last provisioning event for the app did not
     succeed), DENIED_BY_POLICY (last policy.evaluate_sign_on for the app is
     DENY, or has no allow result); otherwise NO_EVIDENCE.
   * who changed it ("who added Sam to Admins?"): the latest SUCCESSFUL
     change event for that user / object gives CHANGE_BY_ADMIN with the
     actor; failed attempts are listed but not blamed.
   * when was it locked: the latest user.account.lock gives LOCKED_OUT, with
     the failed sign-ins in the lookback window before it and any unlock.
   * A ticket with a missing user or object, or an unknown kind, is
     NO_EVIDENCE: it is never closed as solved.
3. **Support triage.** Keyword rules from the policy (in order: security
   incident, outage, bug, how-to, feature idea, discussion) classify an
   issue description and pick the resource: OKTA_STATUS_PAGE (outage listed
   on status.okta.com), OKTA_HELP_CENTER (how-to and configuration),
   OKTA_COMMUNITY (feature ideas and peer discussion) or SUPPORT_CASE (bug,
   security incident, outage NOT on the status page or not yet checked,
   anything unclassified). Each case is checked for the fields Okta
   Support needs (org ID, time window, System Log evidence, impact, plus
   per-category fields) and marked READY or INCOMPLETE.

Simplifications: the real System Log has many more fields (transaction,
authenticationContext, debugContext, securityContext), more operators
(for example ``ne``, ``gt``, ``lt``, ``pr``) and separate ``since`` /
``until`` / ``q`` parameters; matching here is case-insensitive.

Run it
------
    python main.py --course okta lab 42
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

TITLE = "Lab 42 — Okta System Log Investigation & Support Escalation"
OBJECTIVES = ("Okta Professional 6.1 System Log and reports · 6.2 Okta help, status and support · "
              "5.2 App access and group assignment troubleshooting")
COURSES = ("okta",)

QUERY_OUTCOMES = ["MATCHES", "NO_MATCH", "INVALID_EXPRESSION"]
FINDINGS = ["USER_DEACTIVATED", "LOCKED_OUT", "NOT_ASSIGNED_TO_APP", "PROVISIONING_FAILED", "DENIED_BY_POLICY",
            "CHANGE_BY_ADMIN", "NO_EVIDENCE"]
RESOURCES = ["OKTA_STATUS_PAGE", "OKTA_HELP_CENTER", "OKTA_COMMUNITY", "SUPPORT_CASE"]
DECISIONS = QUERY_OUTCOMES + FINDINGS + RESOURCES


class FilterError(ValueError):
    """Raised for an expression that cannot be parsed or uses an unknown attribute or operator."""


@dataclass
class QueryResult:
    id: str
    expression: str
    status: str
    matches: list[str] = field(default_factory=list)
    error: str = ""
    reasons: list[str] = field(default_factory=list)


@dataclass
class TicketResult:
    id: str
    question: str
    kind: str
    finding: str
    actor: str | None = None
    when: str | None = None
    evidence: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


@dataclass
class TriageResult:
    id: str
    category: str
    resource: str
    where: str
    severity: str | None = None
    case_status: str | None = None          # READY / INCOMPLETE for a SUPPORT_CASE, else None
    missing: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Part 1 — filter expressions
# --------------------------------------------------------------------------- #
_TOKEN = re.compile(r'\s*(?:(\()|(\))|("(?:[^"\\]|\\.)*")|([A-Za-z_][A-Za-z0-9_.]*)|(\S))')


def tokenize(expression: str) -> list[tuple[str, str]]:
    tokens, pos, text = [], 0, expression or ""
    while pos < len(text):
        if text[pos:].strip() == "":
            break
        m = _TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise FilterError(f"cannot read the expression at position {pos}")
        lp, rp, string, word, other = m.groups()
        if lp:
            tokens.append(("(", lp))
        elif rp:
            tokens.append((")", rp))
        elif string is not None:
            tokens.append(("STR", string[1:-1].replace('\\"', '"').replace("\\\\", "\\")))
        elif word:
            tokens.append(("WORD", word))
        else:
            if other == '"':
                raise FilterError("unterminated string: a value is missing its closing double quote")
            raise FilterError(f"unexpected character '{other}'")
        pos = m.end()
    return tokens


def parse(expression: str, cfg: dict):
    """Parse into a tree: ('or', a, b) / ('and', a, b) / ('cmp', attr, op, value). Raises FilterError."""
    fcfg = cfg["filter"]
    ops, attrs = set(fcfg["operators"]), set(fcfg["attributes"])
    tokens = tokenize(expression)
    if not tokens:
        raise FilterError("empty filter: refusing to return every event (deny by default)")
    i = 0

    def peek():
        return tokens[i] if i < len(tokens) else (None, None)

    def keyword(word):
        kind, val = peek()
        return kind == "WORD" and val.lower() == word

    def expr():
        nonlocal i
        node = term()
        while keyword("or"):
            i += 1
            node = ("or", node, term())
        return node

    def term():
        nonlocal i
        node = factor()
        while keyword("and"):
            i += 1
            node = ("and", node, factor())
        return node

    def factor():
        nonlocal i
        kind, val = peek()
        if kind == "(":
            i += 1
            node = expr()
            if peek()[0] != ")":
                raise FilterError("missing closing parenthesis")
            i += 1
            return node
        if kind != "WORD":
            raise FilterError("expected an attribute such as eventType" + (f", found '{val}'" if val else
                                                                          " at the end of the expression"))
        if val not in attrs:
            raise FilterError(f"unknown attribute '{val}'")
        i += 1
        okind, op = peek()
        if okind != "WORD" or op.lower() not in ops:
            raise FilterError(f"expected an operator ({', '.join(sorted(ops))}) after '{val}'"
                              + (f", found '{op}'" if op else ""))
        i += 1
        vkind, value = peek()
        if vkind != "STR":
            raise FilterError(f"the value after '{val} {op}' must be in double quotes")
        i += 1
        return ("cmp", val, op.lower(), value)

    tree = expr()
    if i != len(tokens):
        raise FilterError(f"unexpected '{tokens[i][1]}' after a complete expression (missing and/or?)")
    return tree


def values_at(event: dict, path: str) -> list:
    """Every value at a dotted path; target is a list and yields one value per target."""
    head, _, rest = path.partition(".")
    node = event.get(head)
    items = node if isinstance(node, list) else [node]
    out = []
    for item in items:
        cur = item
        for part in rest.split(".") if rest else []:
            cur = cur.get(part) if isinstance(cur, dict) else None
        if cur is not None and not isinstance(cur, (dict, list)):
            out.append(str(cur))
    return out


def evaluate(tree, event: dict, cfg: dict) -> bool:
    if tree[0] == "or":
        return evaluate(tree[1], event, cfg) or evaluate(tree[2], event, cfg)
    if tree[0] == "and":
        return evaluate(tree[1], event, cfg) and evaluate(tree[2], event, cfg)
    _, attr, op, value = tree
    fold = (lambda s: s.lower()) if cfg["filter"].get("case_insensitive", True) else (lambda s: s)
    want = fold(value)
    for v in values_at(event, attr):
        v = fold(v)
        if (op == "eq" and v == want) or (op == "sw" and v.startswith(want)) or (op == "co" and want in v):
            return True
    return False


def run_filter(expression: str, events: list[dict], cfg: dict, qid: str = "") -> QueryResult:
    try:
        tree = parse(expression, cfg)
    except FilterError as exc:
        return QueryResult(qid, expression or "", "INVALID_EXPRESSION", [], str(exc),
                           [f"invalid expression: {exc}; no events returned"])
    hits = [e.get("uuid", "?") for e in sorted(events, key=lambda e: e.get("published") or "")
            if evaluate(tree, e, cfg)]
    if not hits:
        return QueryResult(qid, expression, "NO_MATCH", [], "",
                           [f"valid expression, 0 of {len(events)} events match"])
    return QueryResult(qid, expression, "MATCHES", hits, "", [f"{len(hits)} of {len(events)} events match"])


# --------------------------------------------------------------------------- #
# Part 2 — investigation tickets
# --------------------------------------------------------------------------- #
def _lower(s) -> str:
    return str(s or "").lower()


def result_of(ev: dict) -> str:
    return str((ev.get("outcome") or {}).get("result") or "UNKNOWN").upper()


def reason_of(ev: dict) -> str:
    return (ev.get("outcome") or {}).get("reason") or "no reason given"


def involves(ev: dict, login: str) -> bool:
    login = _lower(login)
    if _lower((ev.get("actor") or {}).get("alternateId")) == login:
        return True
    return any(_lower(t.get("alternateId")) == login for t in ev.get("target") or [])


def targets_user(ev: dict, login: str) -> bool:
    return any(_lower(t.get("alternateId")) == _lower(login) for t in ev.get("target") or [])


def names_object(ev: dict, name: str) -> bool:
    return any(_lower(t.get("displayName")) == _lower(name) for t in ev.get("target") or [])


def _sorted(events):
    return sorted(events, key=lambda e: e.get("published") or "")


def _when(ev: dict) -> str:
    return ev.get("published") or "unknown time"


def _parse_time(s: str | None):
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc) if s else None
    except ValueError:
        try:
            return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            return None


def _actor(ev: dict) -> str:
    a = ev.get("actor") or {}
    return a.get("alternateId") or a.get("displayName") or a.get("id") or "unknown actor"


def _geo(ev: dict) -> str:
    c = ev.get("client") or {}
    g = c.get("geographicalContext") or {}
    return f"{c.get('ipAddress') or 'no IP'} ({', '.join(x for x in (g.get('city'), g.get('country')) if x) or 'no location'})"


def app_access(ticket: dict, events: list[dict], cfg: dict) -> TicketResult:
    et, user, app = cfg["event_types"], ticket.get("user"), ticket.get("app")
    res = TicketResult(ticket.get("id", "?"), ticket.get("question", ""), "app_access", "NO_EVIDENCE")
    mine = _sorted(e for e in events if involves(e, user))
    ok = set(cfg["success_results"])

    def last(types, pred=lambda e: True):
        hits = [e for e in mine if e.get("eventType") in types and pred(e)]
        return hits[-1] if hits else None

    def check_deactivated():
        ev = last(et["deactivate"] + et["reactivate"], lambda e: targets_user(e, user) and result_of(e) in ok)
        if ev and ev["eventType"] in et["deactivate"]:
            return ev, [f"{ev['eventType']} at {_when(ev)} by {_actor(ev)} and no reactivation after it: "
                        "a deactivated or suspended user cannot open any app"]
        return None

    def check_locked():
        ev = last(et["lock"] + et["unlock"])
        if ev and ev["eventType"] in et["lock"]:
            return ev, [f"account locked at {_when(ev)} with no unlock after it: unlock or reset before "
                        "looking at the app"]
        return None

    def on_app(e):
        return targets_user(e, user) or _lower((e.get("actor") or {}).get("alternateId")) == _lower(user)

    def check_assigned():
        ev = last(et["app_assign"] + et["app_unassign"],
                  lambda e: names_object(e, app) and on_app(e) and result_of(e) in ok)
        if ev is None:
            groups = sorted({t.get("displayName") for e in mine if e.get("eventType") in et["group_add"]
                             and result_of(e) in ok for t in e.get("target") or []
                             if t.get("type") == "UserGroup"})
            note = (f"; the user was added to {', '.join(groups)}, but no assignment to {app} followed, so that "
                    f"group is probably not assigned to {app}") if groups else ""
            return {"uuid": None}, [f"no successful application.user_membership.add for {app}{note}"]
        if ev["eventType"] in et["app_unassign"]:
            return ev, [f"{app} was unassigned at {_when(ev)} by {_actor(ev)} (application.user_membership.remove)"]
        return None

    def check_provisioning():
        ev = last(et["provisioning"], lambda e: names_object(e, app))
        if ev and result_of(ev) not in ok:
            return ev, [f"{ev['eventType']} for {app} at {_when(ev)} is {result_of(ev)}: {reason_of(ev)}; fix the "
                        "cause, then retry the task (Admin Console Dashboard, Tasks)"]
        return None

    def check_policy():
        ev = last(et["policy_evaluation"], lambda e: names_object(e, app))
        if ev and result_of(ev) not in cfg["policy_allow_results"]:
            extra = "" if result_of(ev) == "DENY" else " (no allow result recorded: treated as denied)"
            return ev, [f"policy.evaluate_sign_on for {app} at {_when(ev)} is {result_of(ev)}{extra}: "
                        f"{reason_of(ev)}"]
        return None

    if not user or not app:
        res.reasons = ["ticket is missing the user or the app: nothing can be searched, ticket stays open "
                       "(deny by default)"]
        return res
    checks = {"USER_DEACTIVATED": check_deactivated, "LOCKED_OUT": check_locked,
              "NOT_ASSIGNED_TO_APP": check_assigned, "PROVISIONING_FAILED": check_provisioning,
              "DENIED_BY_POLICY": check_policy}
    for finding in cfg["app_access_checks"]:
        hit = checks[finding]()
        if hit:
            ev, reasons = hit
            res.finding, res.reasons = finding, reasons
            if ev.get("uuid"):
                res.evidence, res.when, res.actor = [ev["uuid"]], ev.get("published"), _actor(ev)
            return res
    res.reasons = [f"{user} is active, assigned to {app}, provisioned and allowed by policy in the log: no event "
                   "explains the problem; collect the time, a screenshot and the app's own logs, or open a case"]
    res.evidence = [e.get("uuid") for e in mine if names_object(e, app)]
    return res


def who_changed(ticket: dict, events: list[dict], cfg: dict) -> TicketResult:
    res = TicketResult(ticket.get("id", "?"), ticket.get("question", ""), "who_changed", "NO_EVIDENCE")
    change = cfg["changes"].get(ticket.get("change"))
    user, obj = ticket.get("user"), ticket.get("object")
    if change is None or not (user or obj):
        res.reasons = [f"unknown change type '{ticket.get('change')}' or no user/object named: cannot attribute "
                       "the change (deny by default)"]
        return res
    cands = _sorted(e for e in events if e.get("eventType") in change["event_types"]
                    and (not user or targets_user(e, user)) and (not obj or names_object(e, obj)))
    good = [e for e in cands if result_of(e) in cfg["success_results"]]
    failed = [f"{_actor(e)} tried at {_when(e)} but the outcome was {result_of(e)} ({reason_of(e)}): not the change"
              for e in cands if result_of(e) not in cfg["success_results"]]
    if not good:
        res.reasons = [f"no successful {' / '.join(change['event_types'])} event for "
                       f"{' '.join(x for x in (user, obj) if x)}"] + failed
        return res
    ev = good[-1]
    res.finding, res.actor, res.when, res.evidence = "CHANGE_BY_ADMIN", _actor(ev), ev.get("published"), [ev["uuid"]]
    res.reasons = [f"{_actor(ev)} {change['label']} at {_when(ev)} from {_geo(ev)} ({ev['eventType']}, "
                   f"{result_of(ev)})"] + failed
    return res


def when_locked(ticket: dict, events: list[dict], cfg: dict) -> TicketResult:
    et, user = cfg["event_types"], ticket.get("user")
    res = TicketResult(ticket.get("id", "?"), ticket.get("question", ""), "when_locked", "NO_EVIDENCE")
    if not user:
        res.reasons = ["ticket names no user: nothing to search (deny by default)"]
        return res
    mine = _sorted(e for e in events if involves(e, user))
    locks = [e for e in mine if e.get("eventType") in et["lock"]]
    if not locks:
        res.reasons = [f"no user.account.lock event for {user} in the log window"]
        return res
    ev = locks[-1]
    t = _parse_time(ev.get("published"))
    window = timedelta(minutes=cfg["lock_lookback_minutes"])
    fails = [e for e in mine if e.get("eventType") in et["failed_sign_in"] and result_of(e) == "FAILURE"
             and t is not None and (pt := _parse_time(e.get("published"))) is not None and t - window <= pt <= t]
    res.finding, res.when, res.actor = "LOCKED_OUT", ev.get("published"), _actor(ev)
    res.evidence = [e["uuid"] for e in fails] + [ev["uuid"]]
    res.reasons = [f"user.account.lock at {_when(ev)}"]
    if fails:
        places = sorted({_geo(e) for e in fails})
        res.reasons.append(f"{len(fails)} failed sign-in(s) in the {cfg['lock_lookback_minutes']} minutes before, "
                           f"from {'; '.join(places)} ({', '.join(sorted({reason_of(e) for e in fails}))})")
    unlock = [e for e in mine if e.get("eventType") in et["unlock"] and (e.get("published") or "") > _when(ev)]
    if unlock:
        res.reasons.append(f"unlocked at {_when(unlock[0])} by {_actor(unlock[0])} ({unlock[0]['eventType']})")
    else:
        res.reasons.append("no unlock since: the account is still locked")
    return res


def investigate(ticket: dict, events: list[dict], cfg: dict) -> TicketResult:
    handler = {"app_access": app_access, "who_changed": who_changed, "when_locked": when_locked}.get(ticket.get("kind"))
    if handler is None:
        return TicketResult(ticket.get("id", "?"), ticket.get("question", ""), str(ticket.get("kind")),
                            "NO_EVIDENCE", reasons=[f"unknown ticket kind '{ticket.get('kind')}': not investigated, "
                                                    "ticket stays open (deny by default)"])
    return handler(ticket, events, cfg)


# --------------------------------------------------------------------------- #
# Part 3 — support triage
# --------------------------------------------------------------------------- #
def classify(description: str, cfg: dict) -> tuple[str, str | None]:
    text = _lower(description)
    for rule in cfg["triage_rules"]:
        for kw in rule["keywords"]:
            if kw in text:
                return rule["category"], kw
    return "unclassified", None


def triage(issue: dict, cfg: dict) -> TriageResult:
    category, kw = classify(issue.get("description", ""), cfg)
    reasons = [f"classified as {category} (keyword '{kw}')" if kw else
               "no rule matched the description: unclassified, so a support case is opened rather than "
               "dropping it (deny by default)"]
    if category == "outage":
        listed = issue.get("status_page_incident")
        key = "listed_on_status_page" if listed is True else "not_listed" if listed is False else "not_checked"
        resource = cfg["outage_rule"][key]
        reasons.append({"listed_on_status_page": "status.okta.com lists an incident: a service-wide problem, so "
                        "subscribe and follow it there instead of opening a duplicate case",
                        "not_listed": "status.okta.com shows no incident: the problem is specific to your org, "
                        "open a support case",
                        "not_checked": "status page not checked yet: check status.okta.com, and treat it as "
                        "org-specific (open a case) until an incident is listed"}[key])
    else:
        resource = cfg["category_resources"].get(category, cfg["unclassified_resource"])
    out = TriageResult(issue.get("id", "?"), category, resource, cfg["resources"][resource]["where"],
                       reasons=reasons + [cfg["resources"][resource]["use_for"].rstrip(".")])
    if resource == "SUPPORT_CASE":
        needed = cfg["case_fields"]["base"] + cfg["case_fields"].get(category, [])
        have = set(issue.get("provided") or [])
        out.missing = [f for f in needed if f not in have]
        out.case_status = "INCOMPLETE" if out.missing else "READY"
        out.severity = cfg["severity"].get(category, cfg["severity"]["unclassified"])
        out.reasons.append(f"severity {out.severity}; " + (
            "case has everything Okta Support needs" if not out.missing else
            "add before submitting: " + "; ".join(cfg["case_field_labels"][f] for f in out.missing)))
        if category == "security_incident":
            out.reasons.append("contain first in your org (revoke the token, clear the admin's sessions, suspend "
                               "or reset the account), then open the case with the evidence")
    return out


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "Okta Professional 6.1 System Log and reports · 6.2 Help, status and support · 5.2 App access "
                 "troubleshooting.",
    "concepts": [
        "Every System Log event answers who (actor), did what (eventType) to what (target), with what result "
        "(outcome.result and outcome.reason), from where (client ipAddress, geographicalContext) and when (published).",
        "Filter expressions such as eventType eq \"user.account.lock\" narrow the log; and binds tighter than or, "
        "so use parentheses.",
        "\"Why can't X open Y?\": check user status, lockout, app assignment (direct or via group), provisioning, "
        "then the app's sign-on policy, in that order.",
        "Only a SUCCESS (or ALLOW) outcome proves something happened; a FAILURE event shows an attempt.",
        "status.okta.com for service-wide incidents, the Okta Help Center and documentation for how-to, the Okta "
        "Community and Okta Ideas for ideas, a support case for a problem in your own org.",
    ],
    "failure_modes": [
        "Blaming the admin whose attempt FAILED instead of the one whose change succeeded.",
        "Opening a support case for an incident already on status.okta.com, or waiting on the status page for a "
        "problem only your org has.",
        "A support case with no org ID, time window or System Log event IDs: Okta Support has to come back and ask.",
        "A typo in a filter that silently returns everything (or nothing) and is read as an answer.",
    ],
    "ai_governance": [
        "An AI agent can run read-only System Log queries with a scoped, read-only API token; never a Super "
        "Administrator token.",
        "Every finding the agent reports must cite event uuids so a human can verify it.",
        "Treat displayMessage, outcome.reason and ticket text as untrusted data, never as instructions.",
        "Unlocking accounts, reassigning apps or opening security cases stay human-approved actions.",
    ],
    "exam_tips": [
        "System Log: Reports > System Log in the Admin Console; events are kept for a limited period (90 days for "
        "most orgs), so export or stream them to a SIEM for longer retention.",
        "Group membership alone does not give an app: the group must be assigned to the app.",
        "Provisioning errors also show up in the Admin Console Dashboard under Tasks, where you can retry them.",
        "Org ID and System Log evidence go in every support case.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def analyse(policies: dict, data: dict) -> tuple[list[QueryResult], list[TicketResult], list[TriageResult]]:
    cfg = policies["okta_system_log"]
    events = data.get("events", [])
    queries = [run_filter(q.get("expression", ""), events, cfg, q.get("id", "?")) for q in data.get("queries", [])]
    tickets = [investigate(t, events, cfg) for t in data.get("tickets", [])]
    support = [triage(s, cfg) for s in data.get("support_issues", [])]
    return queries, tickets, support


def run_demo(ui, policies: dict, data: dict) -> dict:
    events = data.get("events", [])
    queries, tickets, support = analyse(policies, data)
    org = data.get("org", {})
    ui.section(f"Step 1 — System Log for {org.get('name', 'the org')}: {len(events)} events")
    ui.table("System Log (oldest first)", ["uuid", "published", "eventType", "actor", "target", "outcome"],
             [[e.get("uuid"), e.get("published"), e.get("eventType"), _actor(e),
               ", ".join(t.get("displayName") or t.get("alternateId") or "?" for t in e.get("target") or []) or "-",
               result_of(e)] for e in _sorted(events)])
    ui.section("Step 2 — Filter expressions")
    ui.table("Queries", ["ID", "Expression", "Result", "Events"],
             [[q.id, q.expression or "(empty)", q.status, ", ".join(q.matches) or "-"] for q in queries])
    for q in queries:
        ui.bullet(f"{q.id}: " + "; ".join(q.reasons), style="red" if q.status == "INVALID_EXPRESSION" else "dim")
    ui.section("Step 3 — Investigation tickets")
    ui.table("Tickets", ["ID", "Question", "Finding", "Actor", "When", "Evidence"],
             [[t.id, t.question, t.finding, t.actor or "-", t.when or "-", ", ".join(t.evidence) or "-"]
              for t in tickets])
    for t in tickets:
        ui.bullet(f"{t.id} → {t.finding}: " + "; ".join(t.reasons),
                  style="yellow" if t.finding == "NO_EVIDENCE" else None)
    ui.section("Step 4 — Support triage")
    ui.table("Issues", ["ID", "Category", "Resource", "Where", "Case"],
             [[s.id, s.category, s.resource, s.where, (f"{s.case_status} ({s.severity})" if s.case_status else "-")]
              for s in support])
    for s in support:
        ui.bullet(f"{s.id} → {s.resource}: " + "; ".join(s.reasons),
                  style="yellow" if s.case_status == "INCOMPLETE" else None)
    metrics = {"events": len(events),
               "failed_or_denied_events": sum(result_of(e) in ("FAILURE", "DENY") for e in events),
               "queries_invalid": sum(q.status == "INVALID_EXPRESSION" for q in queries),
               "tickets_explained": sum(t.finding != "NO_EVIDENCE" for t in tickets),
               "cases_ready": sum(s.case_status == "READY" for s in support),
               "cases_incomplete": sum(s.case_status == "INCOMPLETE" for s in support)}
    ui.print(f"{metrics['events']} events, {metrics['failed_or_denied_events']} failed or denied · "
             f"{metrics['tickets_explained']}/{len(tickets)} tickets explained · support cases: "
             f"{metrics['cases_ready']} ready, {metrics['cases_incomplete']} incomplete")
    ui.insight(INSIGHT)
    return {"queries": {q.id: q.status for q in queries}, "query_matches": {q.id: q.matches for q in queries},
            "tickets": {t.id: t.finding for t in tickets}, "actors": {t.id: t.actor for t in tickets if t.actor},
            "support": {s.id: s.resource for s in support},
            "cases": {s.id: s.case_status for s in support if s.case_status}, "metrics": metrics}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["okta_system_log"]
    events = data.get("events", [])
    queries, tickets, support = analyse(policies, data)
    raw_t = {t.get("id"): t for t in data.get("tickets", [])}
    raw_s = {s.get("id"): s for s in data.get("support_issues", [])}
    qs: list = []
    for q in queries:
        qs.append(Question(prompt=f"{q.id}: what does this System Log filter return?",
                           context=f"filter: {q.expression or '(empty)'}\n{len(events)} events in the log",
                           choices=QUERY_OUTCOMES, answer=q.status, explanation="; ".join(q.reasons),
                           objective="6.1"))
        if q.status == "MATCHES":
            n = len(q.matches)
            pool = [f"{k} event{'s' if k != 1 else ''}" for k in range(0, max(n + 3, 5))]
            ans = f"{n} event{'s' if n != 1 else ''}"
            qs.append(Question(prompt=f"{q.id}: how many events match?", context=f"filter: {q.expression}",
                               choices=choices_with(ans, pool, key=q.id), answer=ans,
                               explanation=f"matching events: {', '.join(q.matches)}", objective="6.1"))
    for t in tickets:
        src = raw_t.get(t.id, {})
        obj = "5.2" if t.kind == "app_access" else "6.1"
        qs.append(Question(prompt=f"{t.id}: \"{t.question}\" What is the finding?",
                           context=f"ticket={ {k: v for k, v in src.items() if k not in ('id', 'question')} }",
                           choices=choices_with(t.finding, FINDINGS, key=t.id), answer=t.finding,
                           explanation="; ".join(t.reasons), objective=obj))
        if t.finding == "CHANGE_BY_ADMIN":
            pool = sorted({_actor(e) for e in events if (e.get("actor") or {}).get("type") == "User"})
            if len(pool) >= 2:
                qs.append(Question(prompt=f"{t.id}: who made the change?",
                                   choices=choices_with(t.actor, pool, key=t.id), answer=t.actor,
                                   explanation="; ".join(t.reasons), objective="6.1"))
    for s in support:
        src = raw_s.get(s.id, {})
        ctx = f"issue: {src.get('description', '')}"
        if "status_page_incident" in src:
            ctx += f"\nstatus.okta.com shows an incident: {src['status_page_incident']}"
        qs.append(Question(prompt=f"{s.id}: where should this go?", context=ctx, choices=RESOURCES,
                           answer=s.resource, explanation="; ".join(s.reasons), objective="6.2"))
        if s.case_status == "INCOMPLETE":
            ans = cfg["case_field_labels"][s.missing[0]]
            present = [cfg["case_field_labels"][f] for f in (src.get("provided") or []) if f in cfg["case_field_labels"]]
            others = [cfg["case_field_labels"][f] for f in s.missing[1:]]
            pool = present or [v for k, v in cfg["case_field_labels"].items() if k not in s.missing]
            qs.append(Question(prompt=f"{s.id}: the case is incomplete. Which of these still has to be added?",
                               context=ctx + f"\nalready provided: {', '.join(src.get('provided') or []) or 'nothing'}",
                               choices=choices_with(ans, pool, exclude=others, key=s.id), answer=ans,
                               explanation="; ".join(s.reasons), objective="6.2"))
    # Concept and rule questions.
    order = cfg["app_access_checks"]
    qs.append(Question(prompt="For \"why can't this user open this app?\", which check comes first?",
                       choices=sorted(order), answer=order[0],
                       explanation="order: " + " → ".join(order) + "; a deactivated user cannot open any app, so "
                       "nothing else matters until that is fixed", objective="5.2"))
    qs.append(Question(prompt="A user was added to the Finance group but still has no Workday tile. What is the "
                              "most likely cause?",
                       choices=["the Finance group is not assigned to Workday",
                                "the System Log is missing events",
                                "the user must be added to the Everyone group again",
                                "the Workday tile only appears after 90 days"],
                       answer="the Finance group is not assigned to Workday",
                       explanation=cfg["finding_definitions"]["NOT_ASSIGNED_TO_APP"], objective="5.2"))
    bad = run_filter('eventType eq "user.account.lock" and', events, cfg)
    qs.append(Question(prompt="What happens to a malformed filter such as eventType eq \"user.account.lock\" and ?",
                       choices=["it is rejected with an error and no events are returned",
                                "every event is returned", "only the first event is returned",
                                "the trailing and is ignored and the filter runs"],
                       answer="it is rejected with an error and no events are returned" if
                       bad.status == "INVALID_EXPRESSION" else "every event is returned",
                       explanation="; ".join(bad.reasons), objective="6.1"))
    qs.append(Question(prompt="Two group.user_membership.add events name Sam and Admins: one FAILURE by Ana, one "
                              "SUCCESS by Alex. Who made the change?",
                       choices=["Alex, whose event succeeded", "Ana, whose event came first",
                                "both of them equally", "Okta itself"],
                       answer="Alex, whose event succeeded",
                       explanation="only a SUCCESS outcome proves the change; a FAILURE event is an attempt",
                       objective="6.1"))
    for term in ("actor", "target", "outcome", "eventType", "status.okta.com", "org ID"):
        if term in cfg["concepts"]:
            qs.append(Question(prompt=f"Which term is this? \"{cfg['concepts'][term]}\"",
                               choices=choices_with(term, cfg["concepts"], key=term), answer=term,
                               explanation=cfg["concepts"][term],
                               objective="6.2" if term in ("status.okta.com", "org ID") else "6.1"))
    return qs


# --------------------------------------------------------------------------- #
# Scenario generator
# --------------------------------------------------------------------------- #
FIRST = ["Dana", "Priya", "Omar", "Lee", "Sam", "Jordan", "Riley", "Mina", "Tariq", "Elena", "Hugo", "Ines",
         "Kofi", "Yuki", "Marta", "Noor"]
LAST = ["Reyes", "Shah", "Haddad", "Park", "Okafor", "Lind", "Moreau", "Novak", "Silva", "Brandt"]
APPS = ["Workday", "Salesforce", "Zoom", "Slack", "Box", "ServiceNow", "Jira", "Tableau"]
CITIES = [("Amsterdam", "Netherlands"), ("Toronto", "Canada"), ("Austin", "United States"), ("Dublin", "Ireland")]
FOREIGN = [("Lagos", "Nigeria"), ("Sao Paulo", "Brazil"), ("Bucharest", "Romania"), ("Hanoi", "Vietnam")]


def generate_scenario(rng, policies: dict) -> dict:
    domain = rng.choice(["fernhill-example", "quarry-example", "lumen-example"])
    mail = f"{domain}.example"
    names = rng.sample(FIRST, 9)
    users = [f"{n.lower()}.{rng.choice(LAST).lower()}@{mail}" for n in names]
    admins = [f"admin.{rng.choice(LAST).lower()}{i}@{mail}" for i in range(2)]
    apps = rng.sample(APPS, 5)
    base = datetime(2026, 10, rng.randint(1, 27), 7, 0, tzinfo=timezone.utc)
    home = rng.choice(CITIES)
    events: list[dict] = []
    n = [0]

    def user_obj(login):
        kind = "SystemPrincipal" if login.startswith("system@") else "User"
        return {"id": f"00u{sum(map(ord, login)) * 7919 % 10**8:08d}", "type": kind, "alternateId": login,
                "displayName": login.split("@")[0].replace(".", " ").title()}

    def add(minute, etype, actor, targets, result, reason=None, city=None, ip=None):
        n[0] += 1
        c = city or home
        events.append({"uuid": f"evt-{n[0]:03d}",
                       "published": (base + timedelta(minutes=minute, seconds=rng.randint(0, 59)))
                       .strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                       "eventType": etype, "actor": user_obj(actor), "target": targets,
                       "outcome": {"result": result, "reason": reason},
                       "client": {"ipAddress": ip or f"192.0.2.{rng.randint(10, 90)}",
                                  "geographicalContext": {"city": c[0], "country": c[1]}}})

    def app_t(a):
        return {"id": f"0oa{apps.index(a)}", "type": "AppInstance", "alternateId": a.lower(), "displayName": a}

    def grp(g):
        return {"id": f"00g{len(g)}", "type": "UserGroup", "alternateId": g, "displayName": g}

    def u(login):
        return user_obj(login)

    adm, adm2 = admins
    # Not assigned: added to a group that is not assigned to the app.
    add(10, "group.user_membership.add", adm, [u(users[0]), grp("Finance")], "SUCCESS")
    # Provisioning failed.
    add(20, "application.user_membership.add", adm, [u(users[1]), app_t(apps[1])], "SUCCESS")
    add(21, "application.provision.user.push", "system@okta.com", [u(users[1]), app_t(apps[1])], "FAILURE",
        rng.choice(["Matching user already exists in the app", "Required attribute 'department' is empty"]))
    # Denied by policy.
    add(30, "application.user_membership.add", adm, [u(users[2]), app_t(apps[2])], "SUCCESS")
    add(31, "app.user_management.push_new_user_success", "system@okta.com", [u(users[2]), app_t(apps[2])], "SUCCESS")
    add(40, "policy.evaluate_sign_on", users[2], [app_t(apps[2]), {"id": "rul1", "type": "Rule",
        "alternateId": "rul1", "displayName": "Managed devices only"}], "DENY",
        rng.choice(["Device is not managed", "Network zone not allowed"]))
    # Locked out after failures from abroad.
    foreign = rng.choice(FOREIGN)
    fip = f"203.0.113.{rng.randint(1, 250)}"
    k = rng.randint(4, 7)
    for i in range(k):
        add(60 + i, "user.session.start", users[3], [], "FAILURE", "INVALID_CREDENTIALS", foreign, fip)
    add(60 + k, "user.account.lock", users[3], [u(users[3])], "SUCCESS", "LOCKED_OUT", foreign, fip)
    # Change by admin: one failed attempt, one success.
    add(80, "group.user_membership.add", adm2, [u(users[4]), grp("Admins")], "FAILURE", "Insufficient permissions")
    add(85, "group.user_membership.add", adm, [u(users[4]), grp("Admins")], "SUCCESS")
    # Deactivated.
    add(90, "user.lifecycle.deactivate", adm, [u(users[5])], "SUCCESS")
    # Healthy user: nothing explains the ticket.
    add(100, "application.user_membership.add", adm, [u(users[6]), app_t(apps[4])], "SUCCESS")
    add(101, "app.user_management.push_new_user_success", "system@okta.com", [u(users[6]), app_t(apps[4])],
        "SUCCESS")
    add(110, "policy.evaluate_sign_on", users[6], [app_t(apps[4])], "ALLOW")
    add(111, "user.session.start", users[6], [], "SUCCESS")
    add(112, "user.authentication.auth_via_mfa", users[6], [], "SUCCESS")
    # API token.
    add(120, "system.api_token.create", adm2, [{"id": "tok1", "type": "Token", "alternateId": "tok1",
                                                "displayName": "ci-deploy"}], "SUCCESS")
    ev_sorted = sorted(events, key=lambda e: e["published"])

    def first(login):
        return login.split(".")[0].title()

    tickets = [
        {"id": "T1", "question": f"Why can't {first(users[0])} open {apps[0]}?", "kind": "app_access",
         "user": users[0], "app": apps[0]},
        {"id": "T2", "question": f"Why can't {first(users[1])} open {apps[1]}?", "kind": "app_access",
         "user": users[1], "app": apps[1]},
        {"id": "T3", "question": f"Why can't {first(users[2])} open {apps[2]}?", "kind": "app_access",
         "user": users[2], "app": apps[2]},
        {"id": "T4", "question": f"When was {first(users[3])}'s account locked?", "kind": "when_locked",
         "user": users[3]},
        {"id": "T5", "question": f"Who added {first(users[4])} to Admins?", "kind": "who_changed",
         "change": "group_add", "user": users[4], "object": "Admins"},
        {"id": "T6", "question": f"Why can't {first(users[5])} open {apps[3]}?", "kind": "app_access",
         "user": users[5], "app": apps[3]},
        {"id": "T7", "question": f"Why can't {first(users[6])} open {apps[4]}?", "kind": "app_access",
         "user": users[6], "app": apps[4]},
    ]
    rng.shuffle(tickets)
    support = [
        {"id": "S1", "description": "Sign-in pages are timing out for every user since 08:40 UTC.",
         "status_page_incident": True, "provided": []},
        {"id": "S2", "description": "All users get HTTP 500 at sign-in in our org only.",
         "status_page_incident": False, "provided": ["org_id", "time_window", "system_log_evidence", "impact",
                                                     "affected_users"]},
        {"id": "S3", "description": f"How do I configure a group rule that assigns {apps[0]} by department?",
         "provided": []},
        {"id": "S4", "description": "Saving a mapping in the Profile Editor drops our custom attribute; it is "
                                    "reproducible every time.",
         "provided": rng.sample(["org_id", "time_window", "impact"], 2)},
        {"id": "S5", "description": "It would be great if group rules could run on a schedule.", "provided": []},
        {"id": "S6", "description": f"Suspicious API token ci-deploy was created by {adm2}, who says they did not "
                                    "do it.",
         "provided": ["org_id", "time_window", "system_log_evidence", "impact", "affected_accounts"]},
    ]
    rng.shuffle(support)
    return {"_description": f"Generated System Log day for {domain}",
            "org": {"name": domain.replace("-", " ").title(), "org_id": f"00o{rng.randint(10**7, 10**8 - 1)}",
                    "url": f"{domain}.okta.com"},
            "events": ev_sorted,
            "queries": [
                {"id": "Q1", "expression": 'eventType eq "user.account.lock" or (eventType sw "group.user_membership" '
                                           'and outcome.result eq "SUCCESS")'},
                {"id": "Q2", "expression": f'eventType eq "user.account.lock" and actor.alternateId eq "{users[0]}"'},
                {"id": "Q3", "expression": 'outcome.result eq FAILURE'},
            ],
            "tickets": tickets, "support_issues": support}
