"""
Lab 49 — Search Queries, Event Triggers & Workflows
===================================================

SailPoint ISC objectives (Identity Security Administrator)
----------------------------------------------------------
* 1.1  Search queries and scheduled search reports: field:term queries,
       attributes.<name>, quoted phrases, wildcards, AND / OR / NOT,
       parentheses, _exists_, ranges, nested @accounts / @access queries,
       saved searches and their scheduled email reports.
* 1.3  Monitoring, event triggers, workflows and configuration backup:
       trigger subscriptions and their JSONPath filters, workflow steps
       (trigger, actions, operators, end steps) and what makes a workflow
       valid.

Engineer course mapping: the same skills sit under Identity Security
Engineer 7.2 (Search, email configuration, monitoring and activity records)
and 7.3 (Workflows, platform testing and troubleshooting).

How it works
------------
You are the Identity Security Cloud (ISC) administrator for a fictional
company. Three engines, each deny by default:

1. **Search queries** over identities (a documented subset of ISC Search,
   which uses an Elasticsearch / Lucene query string):
   1. An empty query, a syntax error (unclosed quote, bracket or
      parenthesis, a range without ``TO``), a lowercase ``and`` / ``or`` /
      ``not``, an unknown field or attribute, or a value of the wrong type
      (a word for a number field, a wildcard on a date) is INVALID_QUERY and
      returns NO identities, never all of them.
   2. ``field:term`` matches a whole value or one word of it, case
      insensitively; ``"a phrase"`` must appear as consecutive words;
      ``*`` and ``?`` are wildcards (text fields only); ``.exact`` makes a
      text match case sensitive and whole-value.
   3. ``AND`` / ``&&`` binds tighter than ``OR`` / ``||``. Two clauses with
      NO operator between them are joined by OR (the ISC default), which
      widens the results. ``NOT`` / ``!`` before a clause negates it;
      ``a NOT b`` means a AND NOT b.
   4. ``_exists_:field`` is true when the field has a non-empty value.
      ``[a TO b]`` is inclusive, ``{a TO b}`` exclusive, ``>``, ``>=``,
      ``<``, ``<=`` compare numbers and dates; dates compare by day and
      ``now-30d`` is relative to the scenario's ``as_of`` date.
   5. ``@accounts(...)`` / ``@access(...)`` is true when ONE account or
      access item satisfies everything inside the parentheses.
   Result: MATCHES (with the identities), NO_MATCH, or INVALID_QUERY.
2. **Scheduled search reports**, checked in order: an invalid query, no
   schedule, or no recipient who is a known, active identity with an email
   address gives NOT_SENT; a run with no results and ``emailEmptyResults``
   false gives SKIP_EMPTY; otherwise SEND_REPORT.
3. **Workflows** given as a scrambled list of steps. Checks in order, the
   first failure is the verdict: DUPLICATE_STEP_NAME, UNKNOWN_STEP (type
   or event trigger not in the catalog), NO_TRIGGER / MULTIPLE_TRIGGERS,
   BROKEN_LINK (a next step that does not exist), TRIGGER_NOT_FIRST
   (something links back to the trigger), MISSING_BRANCH (a choice
   operator without both a true and a false path), END_STEP_HAS_NEXT,
   PATH_NOT_ENDED (a step with nowhere to go that is not an end step),
   LOOP_DETECTED, UNREACHABLE_STEP, VARIABLE_NOT_AVAILABLE (a ``$.step``
   reference to a step that does not run before it on EVERY path; the
   trigger is ``$.trigger``, a step called "Get Identity" is
   ``$.getIdentity``). Otherwise VALID.
4. **Event triggers**: each event is checked against every subscription to
   its trigger, in order: DISABLED (or no enabled flag), UNKNOWN_TRIGGER,
   INVALID_FILTER (the subscription can never fire), FIRED (no filter, or
   the JSONPath filter selects something), else FILTERED_OUT. An event of
   an unknown trigger fires nothing.

Simplifications (marked so you can tell the model from the product): field
types come from the policy file; an unknown field is rejected here, while
real ISC silently returns no results; text is split into words on spaces
and punctuation rather than by Elasticsearch analyzers; relative dates use
30-day months and 365-day years; ``a OR b NOT c`` groups as
a OR (b AND NOT c), so write explicit parentheses. JSONPath filters support
paths, ``[?()]`` filters, ``==`` ``!=`` ``<`` ``<=`` ``>`` ``>=`` ``=~``
``in`` ``nin`` ``contains`` ``anyof`` ``noneof`` ``subsetof`` ``size``,
``&&`` ``||`` ``!`` and ``.length()``; real ISC rejects an invalid filter
when you save it, here the subscription is kept but never fires. Workflow
loops (Loop / Serial Loop), forms and approvals are not modelled.

Run it
------
    python main.py --course spadmin lab 49
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from datetime import date, timedelta

TITLE = "Lab 49 — Search Queries, Event Triggers & Workflows"
OBJECTIVES = ("SailPoint ISC 1.1 Search queries and scheduled search reports · "
              "1.3 Monitoring, event triggers, workflows and configuration backup")
COURSES = ("spadmin", "speng")

QUERY_OUTCOMES = ["MATCHES", "NO_MATCH", "INVALID_QUERY"]
REPORT_OUTCOMES = ["SEND_REPORT", "SKIP_EMPTY", "NOT_SENT"]
WORKFLOW_CODES = ["VALID", "DUPLICATE_STEP_NAME", "UNKNOWN_STEP", "NO_TRIGGER", "MULTIPLE_TRIGGERS", "BROKEN_LINK",
                  "TRIGGER_NOT_FIRST", "MISSING_BRANCH", "END_STEP_HAS_NEXT", "PATH_NOT_ENDED", "LOOP_DETECTED",
                  "UNREACHABLE_STEP", "VARIABLE_NOT_AVAILABLE"]
DELIVERY_OUTCOMES = ["FIRED", "FILTERED_OUT", "DISABLED", "INVALID_FILTER", "UNKNOWN_TRIGGER"]
DECISIONS = QUERY_OUTCOMES + REPORT_OUTCOMES + WORKFLOW_CODES + DELIVERY_OUTCOMES


class QueryError(ValueError):
    """A search query that cannot be parsed or uses an unknown field or a wrong-typed value."""


class FilterError(ValueError):
    """A trigger subscription filter that is not valid JSONPath (in the supported subset)."""


@dataclass
class SearchResult:
    id: str
    query: str
    outcome: str
    matches: list[str] = field(default_factory=list)
    error: str = ""
    reasons: list[str] = field(default_factory=list)


@dataclass
class ReportResult:
    id: str
    name: str
    outcome: str
    rows: int = 0
    recipients: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


@dataclass
class WorkflowResult:
    id: str
    name: str
    verdict: str                     # VALID or INVALID
    code: str                        # VALID or the first error code
    order: list[str] | None = None   # step order for a valid, linear workflow
    reasons: list[str] = field(default_factory=list)


@dataclass
class DeliveryResult:
    event: str
    subscription: str
    outcome: str
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Part 1 — search query parser and evaluator
# --------------------------------------------------------------------------- #
_STOP = set(" \t\r\n()\"[]{}")


def tokenize_query(query: str, cfg: dict) -> list[tuple[str, object]]:
    q, i, out = query or "", 0, []
    lower_ops = cfg["search"].get("lowercase_operators", "invalid") == "invalid"
    while i < len(q):
        c = q[i]
        if c.isspace():
            i += 1
        elif c in "()":
            out.append((c, c))
            i += 1
        elif q.startswith("&&", i):
            out.append(("AND", "&&"))
            i += 2
        elif q.startswith("||", i):
            out.append(("OR", "||"))
            i += 2
        elif c == "!":
            out.append(("NOT", "!"))
            i += 1
        elif c == '"':
            j = q.find('"', i + 1)
            if j < 0:
                raise QueryError("unterminated phrase: a double quote is not closed")
            out.append(("PHRASE", q[i + 1:j]))
            i = j + 1
        elif c in "[{":
            ends = [k for k in (q.find("]", i), q.find("}", i)) if k >= 0]
            if not ends:
                raise QueryError("range is missing its closing ] or }")
            j = min(ends)
            parts = q[i + 1:j].split(" TO ")
            if len(parts) != 2 or not all(p.strip() for p in parts):
                raise QueryError(f"range '{q[i:j + 1]}' must be 'low TO high' (TO in capitals)")
            out.append(("RANGE", (c == "[", parts[0].strip(), parts[1].strip(), q[j] == "]")))
            i = j + 1
        elif c in "]}":
            raise QueryError(f"unexpected '{c}' without an opening bracket")
        else:
            j = i
            while j < len(q) and q[j] not in _STOP:
                j += 1
            word, i = q[i:j], j
            if ":" in word:
                name, _, value = word.partition(":")
                if not name:
                    raise QueryError(f"'{word}' has no field name before the colon")
                out.append(("FIELD", name))
                if value:
                    out.append(("TERM", value))
            elif word.startswith("@"):
                out.append(("NESTED", word[1:]))
            elif word in ("AND", "OR", "NOT"):
                out.append((word, word))
            elif lower_ops and word in ("and", "or", "not"):
                raise QueryError(f"operator '{word}' must be in capitals ({word.upper()}): lowercase it is "
                                 "searched as a word and OR-ed in, which widens the results")
            else:
                out.append(("TERM", word))
    return out


def resolve_field(name: str, scope: str | None, cfg: dict) -> tuple[str, str, bool]:
    """(path, type, exact) for a field in the top-level or nested scope; QueryError if unknown."""
    scfg = cfg["search"]
    exact = name.endswith(".exact")
    base = name[:-len(".exact")] if exact else name
    if scope:
        ftype = scfg["nested"][scope].get(base)
    else:
        ftype = scfg["fields"].get(base)
        if ftype is None and base.startswith("attributes."):
            ftype = scfg["identity_attributes"].get(base[len("attributes."):])
    if ftype is None:
        where = f"inside @{scope}(...)" if scope else "for identities"
        raise QueryError(f"unknown field '{base}' {where}")
    if exact and ftype != "text":
        raise QueryError(f".exact works only on text fields, not on {ftype} field '{base}'")
    return base, ftype, exact


def parse_date(text: str, as_of: str | None, cfg: dict) -> str:
    """'YYYY-MM-DD' (or a full timestamp) or now[+-N(d|w|M|y)] -> 'YYYY-MM-DD'."""
    t = text.strip()
    m = re.fullmatch(r"now(?:([+-])(\d+)([dwMy]))?", t)
    if m:
        if not as_of:
            raise QueryError("relative date 'now' needs the scenario as_of date (deny by default)")
        base = date.fromisoformat(as_of[:10])
        if m.group(1):
            days = int(m.group(2)) * cfg["search"]["relative_date_units_days"][m.group(3)]
            base = base + timedelta(days=days if m.group(1) == "+" else -days)
        return base.isoformat()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}(T[0-9:.]+Z?)?", t):
        try:
            return date.fromisoformat(t[:10]).isoformat()
        except ValueError:
            pass
    raise QueryError(f"'{text}' is not a date (use YYYY-MM-DD or now-30d)")


def _typed(value: str, ftype: str, path: str, as_of, cfg):
    if value == "*":
        return None                                    # open-ended range bound
    if ftype == "number":
        try:
            return float(value)
        except ValueError:
            raise QueryError(f"'{value}' is not a number for numeric field '{path}'") from None
    if ftype == "date":
        return parse_date(value, as_of, cfg)
    raise QueryError(f"ranges and >, < work on number and date fields, not on {ftype} field '{path}'")


def make_clause(path: str, ftype: str, exact: bool, kind: str, value, as_of, cfg):
    """Validate one field:value against the field type -> ('clause', path, type, op, value, exact)."""
    if kind == "RANGE":
        lo_inc, lo, hi, hi_inc = value
        return ("clause", path, ftype, "range",
                (lo_inc, _typed(lo, ftype, path, as_of, cfg), _typed(hi, ftype, path, as_of, cfg), hi_inc), exact)
    if kind == "PHRASE":
        if ftype in ("number", "date", "boolean"):
            kind, value = "TERM", value
        else:
            return ("clause", path, ftype, "phrase", value, exact)
    m = re.fullmatch(r"(>=|<=|>|<)(.+)", value)
    if m:
        return ("clause", path, ftype, m.group(1), _typed(m.group(2), ftype, path, as_of, cfg), exact)
    wild = "*" in value or "?" in value
    if ftype == "boolean":
        if value.lower() not in ("true", "false"):
            raise QueryError(f"boolean field '{path}' takes true or false, not '{value}'")
        return ("clause", path, ftype, "eq", value.lower() == "true", exact)
    if ftype in ("number", "date"):
        if wild:
            raise QueryError(f"wildcards work only on text fields, not on {ftype} field '{path}'")
        return ("clause", path, ftype, "eq", _typed(value, ftype, path, as_of, cfg), exact)
    return ("clause", path, ftype, "wild" if wild else "term", value, exact)


def parse_query(query: str, cfg: dict, as_of: str | None = None) -> tuple[tuple, list[str]]:
    """Parse into a tree; returns (tree, notes). Raises QueryError (deny by default)."""
    tokens = tokenize_query(query, cfg)
    if not tokens:
        raise QueryError("empty query: refusing to return every identity (deny by default)")
    notes: list[str] = []
    i = 0
    starts = {"FIELD", "NESTED", "TERM", "PHRASE", "("}

    def peek(k=0):
        return tokens[i + k] if i + k < len(tokens) else (None, None)

    def take():
        nonlocal i
        i += 1
        return tokens[i - 1]

    def expr(scope):
        node = and_expr(scope)
        while True:
            kind = peek()[0]
            if kind == "OR":
                take()
            elif kind in starts:
                if "implicit OR" not in notes:
                    notes.append("implicit OR")
            else:
                return node
            node = ("or", node, and_expr(scope))

    def and_expr(scope):
        node = unary(scope)
        while peek()[0] in ("AND", "NOT"):
            if take()[0] == "AND":
                node = ("and", node, unary(scope))
            else:
                node = ("and", node, ("not", unary(scope)))
        return node

    def unary(scope):
        if peek()[0] == "NOT":
            take()
            return ("not", unary(scope))
        return primary(scope)

    def primary(scope):
        kind, val = peek()
        if kind == "(":
            take()
            node = expr(scope)
            if peek()[0] != ")":
                raise QueryError("missing closing parenthesis")
            take()
            return node
        if kind == "NESTED":
            take()
            if scope:
                raise QueryError("nested queries cannot be put inside another nested query")
            if val not in cfg["search"]["nested"]:
                raise QueryError(f"unknown nested object '@{val}' (use "
                                 + ", ".join("@" + n for n in sorted(cfg["search"]["nested"])) + ")")
            if peek()[0] != "(":
                raise QueryError(f"@{val} must be followed by '(' and a query")
            take()
            inner = expr(val)
            if peek()[0] != ")":
                raise QueryError(f"missing closing parenthesis after @{val}(")
            take()
            return ("nested", val, inner)
        if kind == "FIELD":
            take()
            if val == "_exists_":
                fk, fname = peek()
                if fk != "TERM":
                    raise QueryError("_exists_ must be followed by a field name, e.g. _exists_:manager.name")
                take()
                path, _, _ = resolve_field(fname, scope, cfg)
                return ("exists", path)
            path, ftype, exact = resolve_field(val, scope, cfg)
            vk, vv = peek()
            if vk in ("TERM", "PHRASE", "RANGE"):
                take()
                return make_clause(path, ftype, exact, vk, vv, as_of, cfg)
            if vk == "(":
                take()
                node = values(path, ftype, exact)
                if peek()[0] != ")":
                    raise QueryError(f"missing closing parenthesis in {val}:( ... )")
                take()
                return node
            raise QueryError(f"field '{val}' has no value after the colon (no space allowed after ':')")
        if kind in ("TERM", "PHRASE"):
            take()
            return ("any", kind == "PHRASE", val)
        if kind is None:
            raise QueryError("query ends where a field or term was expected")
        raise QueryError(f"unexpected '{val}' where a field or term was expected")

    def values(path, ftype, exact):
        def one():
            vk, vv = peek()
            if vk not in ("TERM", "PHRASE", "RANGE"):
                raise QueryError(f"expected a value inside {path}:( ... )")
            take()
            return make_clause(path, ftype, exact, vk, vv, as_of, cfg)
        node = one()
        while peek()[0] in ("AND", "OR") or peek()[0] in ("TERM", "PHRASE", "RANGE"):
            op = "or"
            if peek()[0] in ("AND", "OR"):
                op = take()[0].lower()
            node = (op, node, one())
        return node

    tree = expr(None)
    if i != len(tokens):
        extra = tokens[i][1]
        raise QueryError(f"unexpected '{extra}'" + (" without a matching '('" if extra == ")" else ""))
    return tree, notes


def enrich(identity: dict) -> dict:
    """Identity document with the count fields ISC Search derives (when not given)."""
    doc = dict(identity)
    access = doc.get("access") or []
    doc.setdefault("accountCount", len(doc.get("accounts") or []))
    doc.setdefault("accessCount", len(access))
    doc.setdefault("entitlementCount", sum(a.get("type") == "ENTITLEMENT" for a in access))
    doc.setdefault("roleCount", sum(a.get("type") == "ROLE" for a in access))
    return doc


def get_path(doc, path: str):
    cur = doc
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _words(text: str) -> list[str]:
    return [w for w in re.split(r"[\s,/()\-]+", str(text).lower()) if w]


def _match_text(val, op: str, term: str, exact: bool, keyword: bool = False) -> bool:
    v = str(val)
    if exact:
        return fnmatch.fnmatchcase(v, term) if op == "wild" else v == term
    if op == "phrase":
        want, have = _words(term), _words(v)
        return bool(want) and any(have[k:k + len(want)] == want for k in range(len(have) - len(want) + 1))
    cands = [v.lower()] + ([] if keyword else _words(v))
    if op == "wild":
        return any(fnmatch.fnmatchcase(c, term.lower()) for c in cands)
    return term.lower() in cands


def _strings(node):
    if isinstance(node, dict):
        for v in node.values():
            yield from _strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _strings(v)
    elif isinstance(node, str):
        yield node


def evaluate_query(tree, doc: dict) -> bool:
    op = tree[0]
    if op == "or":
        return evaluate_query(tree[1], doc) or evaluate_query(tree[2], doc)
    if op == "and":
        return evaluate_query(tree[1], doc) and evaluate_query(tree[2], doc)
    if op == "not":
        return not evaluate_query(tree[1], doc)
    if op == "nested":
        return any(evaluate_query(tree[2], item) for item in (doc.get(tree[1]) or []) if isinstance(item, dict))
    if op == "exists":
        v = get_path(doc, tree[1])
        return v not in (None, "", [], {})
    if op == "any":
        _, phrase, term = tree
        wild = not phrase and ("*" in term or "?" in term)
        return any(_match_text(s, "phrase" if phrase else "wild" if wild else "term", term, False)
                   for s in _strings(doc))
    _, path, ftype, cop, value, exact = tree
    v = get_path(doc, path)
    if v is None or v == "":
        return False                                   # missing value never matches (NOT makes it match)
    if ftype in ("text", "keyword"):
        return _match_text(v, cop, value, exact, keyword=ftype == "keyword")
    if ftype == "boolean":
        return isinstance(v, bool) and v == value
    if ftype == "date":
        try:
            v = date.fromisoformat(str(v)[:10]).isoformat()
        except ValueError:
            return False                               # not in date format: ISC does not match it either
    else:
        try:
            v = float(v)
        except (TypeError, ValueError):
            return False
    if cop == "eq":
        return v == value
    if cop == "range":
        lo_inc, lo, hi, hi_inc = value
        ok_lo = lo is None or (v >= lo if lo_inc else v > lo)
        ok_hi = hi is None or (v <= hi if hi_inc else v < hi)
        return ok_lo and ok_hi
    return {">": v > value, ">=": v >= value, "<": v < value, "<=": v <= value}[cop]


def run_search(query: str, identities: list[dict], cfg: dict, as_of: str | None = None, qid: str = "") -> SearchResult:
    try:
        tree, notes = parse_query(query, cfg, as_of)
    except QueryError as exc:
        return SearchResult(qid, query or "", "INVALID_QUERY", [], str(exc),
                            [f"invalid query: {exc}; no identities returned (deny by default)"])
    hits = [i.get("name", i.get("id", "?")) for i in identities if evaluate_query(tree, enrich(i))]
    reasons = []
    if "implicit OR" in notes:
        reasons.append("no operator between two clauses: ISC joins them with OR, which widens the results")
    if not hits:
        return SearchResult(qid, query, "NO_MATCH", [], "", reasons + [f"valid query, 0 of {len(identities)} "
                                                                      "identities match"])
    return SearchResult(qid, query, "MATCHES", hits, "", reasons + [f"{len(hits)} of {len(identities)} identities "
                                                                    "match: " + ", ".join(hits)])


def search_all(data: dict, cfg: dict) -> list[SearchResult]:
    ids = data.get("identities", [])
    return [run_search(q.get("query", ""), ids, cfg, data.get("as_of"), q.get("id", "?")) for q in data.get("queries", [])]


# --------------------------------------------------------------------------- #
# Part 2 — scheduled search reports
# --------------------------------------------------------------------------- #
def schedule_report(saved: dict, data: dict, cfg: dict) -> ReportResult:
    sid, name = saved.get("id", "?"), saved.get("name", "?")
    res = run_search(saved.get("query", ""), data.get("identities", []), cfg, data.get("as_of"), sid)
    if res.outcome == "INVALID_QUERY":
        return ReportResult(sid, name, "NOT_SENT", 0, [], [f"saved search query is invalid: {res.error}"])
    if cfg["scheduled_search"].get("require_schedule", True) and not saved.get("schedule"):
        return ReportResult(sid, name, "NOT_SENT", 0, [], ["saved search has no schedule, so it never runs by itself"])
    people = {i.get("name"): i for i in data.get("identities", [])}
    ok, dropped = [], []
    for r in saved.get("recipients") or []:
        p = people.get(r)
        if p is None:
            dropped.append(f"{r} is not a known identity")
        elif p.get("inactive", True) or not p.get("email"):
            dropped.append(f"{r} is inactive or has no email address")
        else:
            ok.append(r)
    if not ok:
        return ReportResult(sid, name, "NOT_SENT", len(res.matches), [],
                            ["no valid recipient: " + ("; ".join(dropped) if dropped else "the recipient list is empty")])
    notes = [f"dropped recipient: {d}" for d in dropped]
    if not res.matches and not saved.get("emailEmptyResults", False):
        return ReportResult(sid, name, "SKIP_EMPTY", 0, ok, notes + ["0 results and emailEmptyResults is false: "
                                                                     "no email is sent this run"])
    return ReportResult(sid, name, "SEND_REPORT", len(res.matches), ok,
                        notes + [f"{len(res.matches)} result(s) emailed to " + ", ".join(ok)
                                 + (" (empty results are emailed because emailEmptyResults is true)"
                                    if not res.matches else "")])


def reports_all(data: dict, cfg: dict) -> list[ReportResult]:
    return [schedule_report(s, data, cfg) for s in data.get("saved_searches", [])]


# --------------------------------------------------------------------------- #
# Part 3 — workflow validator
# --------------------------------------------------------------------------- #
def var_name(step_name: str) -> str:
    """ISC-style variable for a step's output: 'Get Identity' -> 'getIdentity', 'Get Identity 2' -> 'getIdentity2'."""
    parts = re.findall(r"[A-Za-z0-9]+", step_name or "")
    if not parts:
        return ""
    return parts[0].lower() + "".join(p[:1].upper() + p[1:] for p in parts[1:])


def _kind(step: dict, cfg: dict) -> str | None:
    return cfg["workflow"]["step_types"].get(step.get("type"))


def _links(step: dict, cfg: dict) -> list[str]:
    if _kind(step, cfg) == "choice":
        return [t for t in (step.get("true"), step.get("false")) if t]
    return [step["next"]] if step.get("next") else []


def validate_workflow(wf: dict, cfg: dict) -> WorkflowResult:
    wid, wname = wf.get("id", "?"), wf.get("name", "?")
    steps = wf.get("steps") or []

    def bad(code, msg):
        return WorkflowResult(wid, wname, "INVALID", code, None, [msg])

    if not steps:
        return bad("NO_TRIGGER", "the workflow has no steps, so no trigger")
    names = [s.get("name") for s in steps]
    for n in names:
        if not n or names.count(n) > 1:
            return bad("DUPLICATE_STEP_NAME", f"step name '{n}' is missing or used twice: steps link by name")
    by = {s["name"]: s for s in steps}
    for s in steps:
        k = _kind(s, cfg)
        if k is None:
            return bad("UNKNOWN_STEP", f"'{s['name']}' has unknown step type '{s.get('type')}' (deny by default)")
        if s.get("type") == "Event Trigger" and s.get("trigger") not in cfg["event_triggers"]:
            return bad("UNKNOWN_STEP", f"event trigger '{s.get('trigger')}' is not an available ISC event trigger")
    triggers = [s for s in steps if _kind(s, cfg) == "trigger"]
    if not triggers:
        return bad("NO_TRIGGER", "a workflow needs exactly one trigger and has none")
    if len(triggers) > 1:
        return bad("MULTIPLE_TRIGGERS", "a workflow has exactly one trigger; found "
                   + ", ".join(t["name"] for t in triggers))
    trig = triggers[0]
    for s in steps:
        for t in _links(s, cfg):
            if t not in by:
                return bad("BROKEN_LINK", f"'{s['name']}' points to '{t}', which is not a step in this workflow")
    for s in steps:
        if trig["name"] in _links(s, cfg):
            return bad("TRIGGER_NOT_FIRST", f"'{s['name']}' links back to the trigger: the trigger must be first")
    for s in steps:
        if _kind(s, cfg) == "choice":
            missing = [b for b in ("true", "false") if not s.get(b)]
            if missing:
                return bad("MISSING_BRANCH", f"choice operator '{s['name']}' has no {' or '.join(missing)} path: "
                           "both outcomes must lead somewhere")
    for s in steps:
        k = _kind(s, cfg)
        if k == "end" and s.get("next"):
            return bad("END_STEP_HAS_NEXT", f"end step '{s['name']}' has a next step: an end step stops the run")
        if k in ("trigger", "action", "operator") and not s.get("next"):
            return bad("PATH_NOT_ENDED", f"'{s['name']}' has no next step and is not an end step: every path "
                       "must finish in End Step - Success or End Step - Failure")
    color: dict[str, int] = {}
    order: list[str] = []

    def dfs(n):
        color[n] = 1
        for t in _links(by[n], cfg):
            if color.get(t) == 1:
                return f"'{n}' leads back to '{t}'"
            if t not in color:
                found = dfs(t)
                if found:
                    return found
        color[n] = 2
        order.append(n)
        return None

    loop = dfs(trig["name"])
    if loop:
        return bad("LOOP_DETECTED", f"cycle: {loop}; this model allows no backward links (loops need a Loop operator)")
    unreachable = [n for n in names if n not in color]
    if unreachable:
        return bad("UNREACHABLE_STEP", "not connected to the trigger: " + ", ".join(unreachable))
    # Every path from the trigger: a reference must point to a step that ran earlier on EVERY path.
    paths, limit = [], cfg["workflow"].get("max_paths", 200)

    def walk(n, path):
        if len(paths) >= limit:
            return
        path = path + [n]
        nxt = _links(by[n], cfg)
        if not nxt:
            paths.append(path)
        for t in nxt:
            walk(t, path)

    walk(trig["name"], [])
    for path in paths:
        seen = {"trigger"}
        for n in path:
            for ref in by[n].get("uses") or []:
                m = re.match(r"\$\.([A-Za-z0-9_]+)", ref or "")
                root = m.group(1) if m else None
                if root not in seen:
                    return bad("VARIABLE_NOT_AVAILABLE",
                               f"'{n}' uses {ref}, but " + (f"no step named like '{root}' runs before it on the path "
                                                             + " → ".join(path[:path.index(n) + 1])
                                                             if root else "it is not a $.step JSONPath reference"))
            if by[n] is not trig:
                seen.add(var_name(n))
    linear = all(len(_links(by[n], cfg)) <= 1 for n in names)
    ordered = None
    if linear:
        ordered, cur = [], trig["name"]
        while cur:
            ordered.append(cur)
            cur = (_links(by[cur], cfg) or [None])[0]
    return WorkflowResult(wid, wname, "VALID", "VALID", ordered,
                          [f"one trigger ({trig['name']}), {len(paths)} path(s), every path ends in an end step, "
                           "every choice has both branches and every variable comes from an earlier step"])


def workflows_all(data: dict, cfg: dict) -> list[WorkflowResult]:
    return [validate_workflow(w, cfg) for w in data.get("workflows", [])]


# --------------------------------------------------------------------------- #
# Part 4 — event trigger subscriptions (Jayway JSONPath filter subset)
# --------------------------------------------------------------------------- #
_JTOK = re.compile(r"""\s*(?:
    (?P<str>'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")
  | (?P<num>-?\d+(?:\.\d+)?)
  | (?P<op>==|!=|>=|<=|=~|&&|\|\||[<>!$@.\[\]?(),*])
  | (?P<name>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<regex>/(?:[^/\\]|\\.)*/[a-z]*)
  | (?P<bad>\S)
)""", re.X)
_WORD_OPS = {"in", "nin", "contains", "anyof", "noneof", "subsetof", "size"}
_MISSING = object()


def tokenize_filter(text: str) -> list[tuple[str, object]]:
    out, pos = [], 0
    text = text or ""
    while pos < len(text):
        if not text[pos:].strip():
            break
        prev = out[-1][1] if out else None
        if prev == "=~":
            m = re.compile(r"\s*(/(?:[^/\\]|\\.)*/[a-z]*)").match(text, pos)
            if not m:
                raise FilterError("=~ must be followed by a /regular expression/")
            body, _, flags = m.group(1)[1:].rpartition("/")
            out.append(("regex", (body, flags)))
            pos = m.end()
            continue
        m = _JTOK.match(text, pos)
        if m.group("bad"):
            ch = m.group("bad")
            raise FilterError("single '=' is not an operator: use == for equality" if ch == "=" else
                              f"unexpected character '{ch}'")
        if m.group("str") is not None:
            out.append(("lit", m.group("str")[1:-1].replace("\\'", "'").replace('\\"', '"')))
        elif m.group("num") is not None:
            n = m.group("num")
            out.append(("lit", float(n) if "." in n else int(n)))
        elif m.group("op"):
            out.append(("op", m.group("op")))
        elif m.group("name"):
            w = m.group("name")
            if w in ("true", "false"):
                out.append(("lit", w == "true"))
            elif w == "null":
                out.append(("lit", None))
            elif w in _WORD_OPS:
                out.append(("op", w))
            else:
                out.append(("name", w))
        else:
            raise FilterError("a /regex/ is only allowed after =~")
        pos = m.end()
    return out


def parse_filter(text: str):
    """('select', path, cond_or_None). Raises FilterError."""
    toks = tokenize_filter(text)
    if not toks:
        raise FilterError("empty filter")
    i = 0

    def peek(k=0):
        return toks[i + k] if i + k < len(toks) else (None, None)

    def expect(val):
        nonlocal i
        if peek() != ("op", val):
            raise FilterError(f"expected '{val}'" + (f", found '{peek()[1]}'" if peek()[1] is not None else
                                                     " at the end"))
        i += 1

    def path(root):
        nonlocal i
        expect(root)
        parts, length = [], False
        while peek() == ("op", "."):
            i += 1
            k, v = peek()
            if k != "name":
                raise FilterError("expected a field name after '.'")
            i += 1
            if peek() == ("op", "("):
                if v != "length":
                    raise FilterError(f"function '{v}()' is not supported here (only length())")
                i += 1
                expect(")")
                length = True
                break
            parts.append(v)
        return ("path", root, parts, length)

    def operand():
        nonlocal i
        k, v = peek()
        if (k, v) in (("op", "@"), ("op", "$")):
            return path(v)
        if k == "lit":
            i += 1
            return ("lit", v)
        if k == "regex":
            i += 1
            return ("regex", v)
        if (k, v) == ("op", "["):
            i += 1
            items = []
            while peek() != ("op", "]"):
                lk, lv = peek()
                if lk != "lit":
                    raise FilterError("a list may contain only literal values")
                items.append(lv)
                i += 1
                if peek() == ("op", ","):
                    i += 1
                elif peek() != ("op", "]"):
                    raise FilterError("expected ',' or ']' in a list")
            i += 1
            return ("lit", items)
        raise FilterError("expected @.field, $.field or a value" + (f", found '{v}'" if v is not None else ""))

    def cond():
        nonlocal i
        node = conj()
        while peek() == ("op", "||"):
            i += 1
            node = ("or", node, conj())
        return node

    def conj():
        nonlocal i
        node = neg()
        while peek() == ("op", "&&"):
            i += 1
            node = ("and", node, neg())
        return node

    def neg():
        nonlocal i
        if peek() == ("op", "!"):
            i += 1
            return ("not", neg())
        if peek() == ("op", "("):
            i += 1
            node = cond()
            expect(")")
            return node
        left = operand()
        k, v = peek()
        if k == "op" and v in {"==", "!=", ">", ">=", "<", "<=", "=~"} | _WORD_OPS:
            i += 1
            right = operand()
            if (v == "=~") != (right[0] == "regex"):
                raise FilterError("=~ needs a /regex/ on the right, and a /regex/ needs =~")
            return ("cmp", v, left, right)
        return ("truthy", left)

    root = path("$")
    cnd = None
    if peek() == ("op", "["):
        i += 1
        expect("?")
        expect("(")
        cnd = cond()
        expect(")")
        expect("]")
    if i != len(toks):
        raise FilterError(f"unexpected '{toks[i][1]}' after the end of the filter")
    if root[3]:
        raise FilterError("length() can only be used inside a [?( )] filter")
    return ("select", root, cnd)


def _walk(node, parts):
    cur = node
    for p in parts:
        if isinstance(cur, list):
            cur = [x.get(p, _MISSING) if isinstance(x, dict) else _MISSING for x in cur]
            cur = [x for x in cur if x is not _MISSING]
        elif isinstance(cur, dict):
            cur = cur.get(p, _MISSING)
        else:
            return _MISSING
        if cur is _MISSING:
            return _MISSING
    return cur


def _value(opnd, current, root):
    if opnd[0] == "lit":
        return opnd[1]
    if opnd[0] == "regex":
        return opnd[1]
    _, which, parts, length = opnd
    v = _walk(current if which == "@" else root, parts)
    if length:
        return len(v) if isinstance(v, (list, str)) else _MISSING
    return v


def _num(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _cond(c, current, root) -> bool:
    k = c[0]
    if k == "or":
        return _cond(c[1], current, root) or _cond(c[2], current, root)
    if k == "and":
        return _cond(c[1], current, root) and _cond(c[2], current, root)
    if k == "not":
        return not _cond(c[1], current, root)
    if k == "truthy":
        v = _value(c[1], current, root)
        return v is not _MISSING and v is not None
    _, op, lo, ro = c
    left, right = _value(lo, current, root), _value(ro, current, root)
    if left is _MISSING or right is _MISSING:
        return False                                   # a missing path never matches, even with != (deny by default)
    if op in ("==", "!="):
        same = (left == right) and (type(left) is type(right) or (_num(left) and _num(right)))
        return same if op == "==" else not same
    if op in (">", ">=", "<", "<="):
        if not ((_num(left) and _num(right)) or (isinstance(left, str) and isinstance(right, str))):
            return False
        return {">": left > right, ">=": left >= right, "<": left < right, "<=": left <= right}[op]
    if op == "=~":
        body, flags = right
        if not isinstance(left, str):
            return False
        try:
            # Jayway =~ needs the WHOLE value to match the pattern (Java Matcher.matches()).
            return re.fullmatch(body, left, re.I if "i" in flags else 0) is not None
        except re.error:
            return False
    if op in ("in", "nin"):
        if not isinstance(right, list):
            return False
        return (left in right) if op == "in" else (left not in right)
    if op == "contains":
        if isinstance(left, str) and isinstance(right, str):
            return right in left                       # case sensitive, as in ISC
        return isinstance(left, list) and right in left
    if op in ("anyof", "noneof", "subsetof"):
        if not (isinstance(left, list) and isinstance(right, list)):
            return False
        inter = any(x in right for x in left)
        return {"anyof": inter, "noneof": not inter, "subsetof": all(x in right for x in left)}[op]
    if op == "size":
        return isinstance(left, (list, str)) and _num(right) and len(left) == right
    return False


def filter_matches(tree, payload) -> bool:
    _, root_path, cnd = tree
    node = _walk(payload, root_path[2])
    if node is _MISSING or node is None:
        return False
    if cnd is None:
        return node not in ([], {}, "")
    candidates = node if isinstance(node, list) else [node]
    return any(_cond(cnd, c, payload) for c in candidates)


def deliver(data: dict, cfg: dict) -> tuple[list[DeliveryResult], dict[str, list[str]], dict[str, str]]:
    """Every (event, subscription-to-its-trigger) pair -> outcome; plus fired subscriptions per event and event notes."""
    catalog = cfg["event_triggers"]
    subs = data.get("subscriptions", [])
    parsed: dict[str, object] = {}
    for s in subs:
        if s.get("filter"):
            try:
                parsed[s["id"]] = parse_filter(s["filter"])
            except FilterError as exc:
                parsed[s["id"]] = exc
    pairs, fired, notes = [], {}, {}
    for e in data.get("events", []):
        eid, trig = e.get("id", "?"), e.get("trigger")
        fired[eid] = []
        if trig not in catalog:
            notes[eid] = f"'{trig}' is not an available event trigger: nothing fires (deny by default)"
            continue
        for s in subs:
            if s.get("trigger") != trig:
                continue
            sid = s["id"]
            if s.get("enabled") is not True:
                pairs.append(DeliveryResult(eid, sid, "DISABLED", ["subscription is disabled" if s.get("enabled")
                                                                   is False else "no enabled flag: treated as "
                                                                   "disabled (deny by default)"]))
                continue
            f = parsed.get(sid)
            if isinstance(f, FilterError):
                pairs.append(DeliveryResult(eid, sid, "INVALID_FILTER", [f"filter is not valid JSONPath: {f}; the "
                                                                         "subscription never fires"]))
                continue
            rtype = catalog[trig]["type"]
            extra = ([f"{rtype}: the access request waits for this service to approve or deny it; no answer in "
                      "time and the request fails"] if rtype == "REQUEST_RESPONSE" else [])
            if f is None:
                pairs.append(DeliveryResult(eid, sid, "FIRED", ["no filter: every " + trig + " event is sent"] + extra))
                fired[eid].append(sid)
            elif filter_matches(f, e.get("payload") or {}):
                pairs.append(DeliveryResult(eid, sid, "FIRED", [f"filter {s['filter']} selects data in the event"]
                                            + extra))
                fired[eid].append(sid)
            else:
                pairs.append(DeliveryResult(eid, sid, "FILTERED_OUT", [f"filter {s['filter']} selects nothing in "
                                                                       "this event"]))
    for s in subs:
        if s.get("trigger") not in catalog:
            pairs.append(DeliveryResult("-", s.get("id", "?"), "UNKNOWN_TRIGGER",
                                        [f"'{s.get('trigger')}' is not an available event trigger"]))
    return pairs, fired, notes


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SailPoint ISC 1.1 Search queries and scheduled search reports · 1.3 Event triggers, workflows and "
                 "configuration backup (Engineer 7.2, 7.3).",
    "concepts": [
        "ISC Search takes field:term queries; identity attributes are attributes.<name>, related records are nested "
        "with @accounts(...) and @access(...).",
        "Operators must be in capitals; with no operator between two clauses ISC uses OR.",
        "A saved search can be scheduled to email a report; emailEmptyResults decides whether an empty run is sent.",
        "Event trigger subscriptions call an HTTP endpoint, EventBridge or a workflow; a Jayway JSONPath filter "
        "narrows which events are sent.",
        "Access Request Submitted is REQUEST_RESPONSE: the request waits for the subscriber's approve or deny.",
        "A workflow has one trigger, actions, operators (Compare Strings, Wait ...) and an end step on every path.",
        "Configuration Hub backups let you compare and restore tenant configuration after a bad change.",
    ],
    "failure_modes": [
        "Typing 'and' in lowercase: the word is searched and OR-ed in, so the report lists far too many people.",
        "Checking 'terminated' and 'AD account enabled' outside one @accounts(...) so they can match different accounts.",
        "A scheduled report addressed to a person who has left: nobody reads it.",
        "A filter that compares 'error' when the event says 'Error': JSONPath string compare is case sensitive.",
        "A Compare Strings step with only the true path wired, so half the runs have nowhere to go.",
    ],
    "ai_governance": [
        "An AI agent can draft search queries and filters, but test them against sample data before they drive "
        "reports or provisioning.",
        "Workflows that Manage Access are privileged automation: give them an owner, review them and back up "
        "the configuration before changes.",
        "Event payloads contain names and comments written by users: treat them as data, never as instructions.",
        "Prefer a filter that fails closed (fires on nothing) over one that fires on everything.",
    ],
    "exam_tips": [
        "Inclusive range [a TO b], exclusive {a TO b}; NOT _exists_:manager.name finds identities with no manager.",
        "Nested query = all conditions on the same account or access item.",
        "Identity Attributes Changed carries a changes[] list with attribute, oldValue and newValue.",
        "Every workflow branch must end in End Step - Success or End Step - Failure.",
        "Reference earlier step output with JSONPath such as $.trigger.identity.id or $.getIdentity.email.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def _esc(ui):
    return (lambda s: str(s).replace("[", r"\[")) if getattr(ui, "use_rich", False) else str


def run_demo(ui, policies: dict, data: dict) -> dict:
    cfg = policies["isc_search_workflows"]
    esc = _esc(ui)
    searches, reports = search_all(data, cfg), reports_all(data, cfg)
    flows = workflows_all(data, cfg)
    pairs, fired, notes = deliver(data, cfg)
    ui.section(f"Step 1 — Search queries over {len(data.get('identities', []))} identities (as of "
               f"{data.get('as_of', 'unknown')})")
    ui.table("Search", ["ID", "Query", "Outcome", "Identities"],
             [[r.id, esc(r.query), r.outcome, ", ".join(r.matches) or "-"] for r in searches])
    for r in searches:
        ui.bullet(f"{r.id}: " + esc("; ".join(r.reasons)),
                  style={"MATCHES": "green", "NO_MATCH": "dim"}.get(r.outcome, "red"))
    ui.section("Step 2 — Scheduled search reports")
    ui.table("Saved searches", ["ID", "Name", "Outcome", "Rows", "Recipients"],
             [[r.id, r.name, r.outcome, r.rows, ", ".join(r.recipients) or "-"] for r in reports])
    for r in reports:
        ui.bullet(f"{r.id}: " + esc("; ".join(r.reasons)),
                  style={"SEND_REPORT": "green", "SKIP_EMPTY": "dim"}.get(r.outcome, "yellow"))
    ui.section("Step 3 — Validate workflows (steps arrive scrambled)")
    ui.table("Workflows", ["ID", "Name", "Verdict", "First error"],
             [[w.id, w.name, w.verdict, "-" if w.code == "VALID" else w.code] for w in flows])
    for w in flows:
        line = "; ".join(w.reasons) + (f" · order: {' → '.join(w.order)}" if w.order else "")
        ui.bullet(f"{w.id}: " + esc(line), style="green" if w.verdict == "VALID" else "red")
    ui.section("Step 4 — Event triggers: which subscriptions fire")
    subs = {s["id"]: s for s in data.get("subscriptions", [])}
    ui.table("Events", ["Event", "Trigger", "Fired subscriptions"],
             [[e["id"], e.get("trigger", "?"), ", ".join(f"{x} ({subs[x].get('name', '')})" for x in fired[e["id"]])
               or "none"] for e in data.get("events", [])])
    for p in pairs:
        if p.outcome != "FIRED":
            ui.bullet(f"{p.event} × {p.subscription}: {p.outcome} — " + esc("; ".join(p.reasons)), style="yellow")
    for eid, n in notes.items():
        ui.bullet(f"{eid}: {n}", style="yellow")
    counts = {o: sum(r.outcome == o for r in searches) for o in QUERY_OUTCOMES}
    metrics = {"queries": len(searches), **{f"queries_{o.lower()}": n for o, n in counts.items()},
               "reports_sent": sum(r.outcome == "SEND_REPORT" for r in reports),
               "workflows_valid": sum(w.verdict == "VALID" for w in flows),
               "workflows_invalid": sum(w.verdict == "INVALID" for w in flows),
               "deliveries": sum(len(v) for v in fired.values())}
    ui.print(f"{counts['MATCHES']} queries matched, {counts['NO_MATCH']} matched nobody, {counts['INVALID_QUERY']} "
             f"were rejected · {metrics['workflows_valid']} of {len(flows)} workflows valid · "
             f"{metrics['deliveries']} subscription deliveries")
    ui.insight(INSIGHT)
    return {"queries": {r.id: r.outcome for r in searches},
            "matches": {r.id: r.matches for r in searches},
            "reports": {r.id: r.outcome for r in reports},
            "workflows": {w.id: w.code for w in flows},
            "events": fired,
            "deliveries": {f"{p.event}:{p.subscription}": p.outcome for p in pairs},
            "metrics": metrics}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def _id_line(i: dict) -> str:
    a = i.get("attributes") or {}
    accts = ", ".join(f"{x.get('source', {}).get('name', '?')}{' (disabled)' if x.get('disabled') else ''}"
                      for x in i.get("accounts") or []) or "none"
    acc = ", ".join(x.get("name", "?") + (" [privileged]" if x.get("privileged") else "") for x in i.get("access") or [])
    return (f"{i.get('name')}: dept={a.get('department')}, location={a.get('location')}, "
            f"lifecycle={a.get('cloudLifecycleState')}, created={str(i.get('created', ''))[:10]}, "
            f"manager={(i.get('manager') or {}).get('name')}, accounts={accts}, access={acc or 'none'}")


def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["isc_search_workflows"]
    searches, reports = search_all(data, cfg), reports_all(data, cfg)
    flows = workflows_all(data, cfg)
    pairs, fired, _ = deliver(data, cfg)
    people = "\n".join(_id_line(i) for i in data.get("identities", []))
    qs: list = []

    def label(r: SearchResult) -> str:
        if r.outcome == "MATCHES":
            return "returns " + ", ".join(r.matches)
        return {"NO_MATCH": "valid query, returns no identities", "INVALID_QUERY": "INVALID_QUERY: nothing returned"}[
            r.outcome]

    pool = sorted({label(r) for r in searches} | {"valid query, returns no identities",
                                                   "INVALID_QUERY: nothing returned"})
    for r in searches[:8]:
        qs.append(Question(prompt=f"{r.id}: what does this search return? Query: {r.query}",
                           context=f"as of {data.get('as_of')}\n{people}",
                           choices=choices_with(label(r), pool, key=r.id), answer=label(r),
                           explanation="; ".join(r.reasons), objective="1.1"))
    invalid = [r for r in searches if r.outcome == "INVALID_QUERY"]
    errs = sorted({r.error for r in invalid} | {
        "operator 'and' must be in capitals (AND): lowercase it is searched as a word and OR-ed in, which widens "
        "the results", "missing closing parenthesis", "unknown field 'attributes.costCenter' for identities",
        "wildcards work only on text fields, not on date field 'created'"})
    for r in invalid[:2]:
        qs.append(Question(prompt=f"{r.id}: why is the query rejected? Query: {r.query}",
                           choices=choices_with(r.error, errs, key=r.id), answer=r.error,
                           explanation=r.reasons[0], objective="1.1"))
    implicit = next((r for r in searches if any("joins them with OR" in x for x in r.reasons)), None)
    if implicit:
        qs.append(Question(prompt=f"{implicit.id}: there is no operator between the two clauses in "
                                  f"'{implicit.query}'. How does ISC combine them?",
                           choices=["with OR, so either clause is enough", "with AND, so both must be true",
                                    "the query is rejected", "only the first clause is used"],
                           answer="with OR, so either clause is enough",
                           explanation=implicit.reasons[0], objective="1.1"))
    saved = {s["id"]: s for s in data.get("saved_searches", [])}
    for r in reports:
        s = saved[r.id]
        ctx = (f"query={s.get('query')}\nschedule={s.get('schedule')}\nrecipients={s.get('recipients')}\n"
               f"emailEmptyResults={s.get('emailEmptyResults', False)}")
        qs.append(Question(prompt=f"{r.id} '{r.name}': what happens on the next scheduled run?", context=ctx,
                           choices=REPORT_OUTCOMES, answer=r.outcome, explanation="; ".join(r.reasons),
                           objective="1.1"))
    wfs = {w["id"]: w for w in data.get("workflows", [])}

    def wf_ctx(w):
        lines = []
        for s in w.get("steps", []):
            links = (f"true→{s.get('true')}, false→{s.get('false')}" if _kind(s, cfg) == "choice"
                     else f"next→{s.get('next')}")
            extra = f", trigger={s['trigger']}" if s.get("trigger") else ""
            uses = f", uses {', '.join(s['uses'])}" if s.get("uses") else ""
            lines.append(f"- {s.get('name')} [{s.get('type')}{extra}] {links}{uses}")
        return "\n".join(lines)

    for w in flows:
        qs.append(Question(prompt=f"{w.id} '{w.name}': what does workflow validation report first?",
                           context=wf_ctx(wfs[w.id]),
                           choices=choices_with(w.code, WORKFLOW_CODES, key=w.id), answer=w.code,
                           explanation="; ".join(w.reasons), objective="1.3"))
    for w in [w for w in flows if w.order and len(w.order) >= 3][:2]:
        shown = [s["name"] for s in wfs[w.id]["steps"]]
        qs.append(Question(prompt=f"{w.id} '{w.name}': put the steps in the order they run.",
                           choices=shown, answer=" → ".join(w.order), explanation="follow next from the trigger: "
                           + " → ".join(w.order), objective="1.3", kind="order", items=tuple(w.order)))
    subs = {s["id"]: s for s in data.get("subscriptions", [])}
    names = {sid: f"{sid} {s.get('name', '')}".strip() for sid, s in subs.items()}
    for e in data.get("events", []):
        cands = [names[sid] for sid, s in subs.items() if s.get("trigger") == e.get("trigger")]
        hit = [names[x] for x in fired.get(e["id"], [])]
        ctx = f"trigger={e.get('trigger')}\npayload={e.get('payload')}\n" + "\n".join(
            f"{names[sid]}: trigger={s.get('trigger')}, enabled={s.get('enabled')}, filter={s.get('filter')}"
            for sid, s in subs.items() if s.get("trigger") == e.get("trigger"))
        if len(hit) >= 2:
            qs.append(Question(prompt=f"{e['id']}: which subscriptions fire? (select {len(hit)})", context=ctx,
                               choices=sorted(cands), answer="; ".join(hit), explanation="each filter is checked "
                               "on its own; " + ", ".join(hit) + " match", objective="1.3", kind="multi",
                               answers=tuple(hit)))
        elif cands:
            ans = hit[0] if hit else "none of them"
            qs.append(Question(prompt=f"{e['id']}: which subscription fires?", context=ctx,
                               choices=sorted(set(cands) | {"none of them"}), answer=ans,
                               explanation="; ".join(f"{p.subscription}: {p.outcome} ({'; '.join(p.reasons)})"
                                                     for p in pairs if p.event == e["id"]), objective="1.3"))
    shown_kinds = set()
    for p in pairs:
        if p.outcome in ("DISABLED", "INVALID_FILTER", "FILTERED_OUT") and p.outcome not in shown_kinds:
            shown_kinds.add(p.outcome)
            s = subs[p.subscription]
            qs.append(Question(prompt=f"{p.event} × {names[p.subscription]}: what is the delivery outcome?",
                               context=f"enabled={s.get('enabled')}, filter={s.get('filter')}",
                               choices=DELIVERY_OUTCOMES[:4], answer=p.outcome, explanation="; ".join(p.reasons),
                               objective="1.3"))
    types = sorted({v["type"] for v in cfg["event_triggers"].values()})
    if "Access Request Submitted" in cfg["event_triggers"]:
        t = cfg["event_triggers"]["Access Request Submitted"]["type"]
        qs.append(Question(prompt="Which trigger type is Access Request Submitted?",
                           choices=types + ["SCHEDULED_ONLY"], answer=t,
                           explanation="the request waits for the subscriber's approve/deny response" if
                           t == "REQUEST_RESPONSE" else "the subscriber is notified and nothing waits for it",
                           objective="1.3"))
    qs.append(Question(prompt="Which query finds identities that have NO manager?",
                       choices=["NOT _exists_:manager.name", "manager.name:null", "_exists_:manager.name",
                                "manager.name:\"\""],
                       answer="NOT _exists_:manager.name",
                       explanation="_exists_ is true for a non-empty value; NOT inverts it", objective="1.1"))
    for term, obj in (("nested query", "1.1"), ("subscription filter", "1.3"), ("configuration backup", "1.3"),
                      ("choice operator", "1.3")):
        if term in cfg["concepts"]:
            qs.append(Question(prompt=f"Which term is this? \"{cfg['concepts'][term]}\"",
                               choices=sorted(cfg["concepts"]), answer=term, explanation=cfg["concepts"][term],
                               objective=obj))
    return qs


# --------------------------------------------------------------------------- #
# Seeded scenario generator
# --------------------------------------------------------------------------- #
FIRST = ["Aria", "Bram", "Cleo", "Dario", "Esme", "Felix", "Gia", "Hugo", "Ines", "Jules", "Kofi", "Lena", "Mateo",
         "Noor", "Otto", "Priya"]
LAST = ["Abara", "Brandt", "Castell", "Dimitrov", "Eklund", "Fontaine", "Garza", "Holm", "Iwata", "Jansen", "Kaur",
        "Lindgren", "Moreau", "Novak"]
DEPTS = ["Finance", "Engineering", "Sales", "IT", "Operations"]
CITIES = ["London", "Austin", "Berlin", "Tokyo", "Toronto"]


def generate_scenario(rng, policies: dict) -> dict:
    domain = rng.choice(["lantern-example", "brookfield-example", "ostrava-example"]) + ".example"
    as_of = date(2026, rng.randint(9, 11), rng.randint(1, 28))
    first = rng.sample(FIRST, 10)
    last = [rng.choice(LAST) for _ in first]
    states = ["active"] * 6 + ["terminated", "terminated", "prehire", "active"]
    ids = []
    for k, (f, l) in enumerate(zip(first, last)):
        name = f"{f.lower()}.{l.lower()}"
        dept, city = rng.choice(DEPTS), rng.choice(CITIES)
        created = (as_of - timedelta(days=rng.randint(40, 900))).isoformat()
        state = states[k]
        accounts = [{"source": {"name": "Active Directory"}, "name": name, "disabled": state == "terminated" and k == 7,
                     "created": created}]
        if rng.random() < 0.5:
            accounts.append({"source": {"name": "Workday"}, "name": name.upper(), "disabled": False,
                             "created": created})
        access = [{"type": "ENTITLEMENT", "name": f"{dept} Users", "displayName": f"{dept} Users",
                   "privileged": False, "source": {"name": "Active Directory"}}]
        if k in (1, 3):
            access.append({"type": "ENTITLEMENT", "name": "Domain Admins", "displayName": "Domain Admins",
                           "privileged": True, "source": {"name": "Active Directory"}})
        ids.append({"id": f"2c9180{k:02d}{rng.randint(1000, 9999)}", "name": name, "displayName": f"{f} {l}",
                    "email": f"{name}@{domain}", "status": "UNREGISTERED" if k == 9 else "ACTIVE",
                    "inactive": state == "terminated", "created": created + "T09:00:00Z",
                    "manager": None if k == 4 else {"name": ids[0]["name"] if ids else "board.chair"},
                    "source": {"name": "Workday"}, "attributes": {"department": dept, "location": city,
                    "cloudLifecycleState": state, "employeeType": "contractor" if k == 5 else "employee"},
                    "accounts": accounts, "access": access})
    ids[9]["created"] = (as_of - timedelta(days=rng.randint(2, 20))).isoformat() + "T09:00:00Z"
    ids[5]["attributes"]["endDate"] = (as_of + timedelta(days=rng.randint(10, 60))).isoformat()
    pick = ids[rng.randint(0, 3)]
    pa = pick["attributes"]
    lo = (date.fromisoformat(pick["created"][:10]) - timedelta(days=rng.randint(0, 30))).isoformat()
    hi = (date.fromisoformat(pick["created"][:10]) + timedelta(days=rng.randint(0, 30))).isoformat()
    queries = [
        {"id": "Q01", "query": f"attributes.department:{pa['department']} AND attributes.location:{pa['location']}"},
        {"id": "Q02", "query": "attributes.cloudLifecycleState:terminated AND @accounts(source.name:\"Active "
                               "Directory\" AND disabled:false)"},
        {"id": "Q03", "query": f"created:[{lo} TO {hi}]"},
        {"id": "Q04", "query": "NOT _exists_:manager.name"},
        {"id": "Q05", "query": "@access(privileged:true) AND NOT attributes.department:IT"},
        {"id": "Q06", "query": f"attributes.department:{pa['department'].lower()} and status:ACTIVE"},
        {"id": "Q07", "query": "attributes.department:Marketing"},
        {"id": "Q08", "query": f"attributes.costCenter:{rng.randint(1000, 9999)}"},
        {"id": "Q09", "query": f"name:{ids[2]['name'][:2]}*"},
        {"id": "Q10", "query": "created:>=now-30d"},
        {"id": "Q11", "query": f"attributes.department:{ids[6]['attributes']['department']} "
                               f"attributes.location:{ids[8]['attributes']['location']}"},
    ]
    active = [i["name"] for i in ids if not i["inactive"]]
    gone = [i["name"] for i in ids if i["inactive"]]
    saved = [
        {"id": "S01", "name": "Leavers with live AD accounts", "query": queries[1]["query"],
         "schedule": {"type": "WEEKLY", "days": ["MON"], "hours": ["08"]}, "recipients": [rng.choice(active)],
         "emailEmptyResults": False},
        {"id": "S02", "name": "Marketing joiners", "query": "attributes.department:Marketing",
         "schedule": {"type": "DAILY", "hours": ["07"]}, "recipients": [rng.choice(active)], "emailEmptyResults": False},
        {"id": "S03", "name": "Contractors ending soon", "query": "attributes.employeeType:contractor AND "
                                                                  "attributes.endDate:[now TO now+90d]",
         "schedule": {"type": "WEEKLY", "days": ["FRI"], "hours": ["09"]}, "recipients": [rng.choice(gone)],
         "emailEmptyResults": False},
        {"id": "S04", "name": "Unscheduled draft", "query": "status:UNREGISTERED", "schedule": None,
         "recipients": [rng.choice(active)]},
    ]
    trig = rng.choice(["Identity Attributes Changed", "Identity Created"])
    end_ok, end_bad = "End Step - Success", "End Step - Failure"

    def step(name, stype, nxt=None, uses=None, **kw):
        s = {"name": name, "type": stype}
        if nxt:
            s["next"] = nxt
        s.update(kw)
        if uses:
            s["uses"] = uses
        return s

    t = step(trig, "Event Trigger", "Get Identity", trigger=trig)
    flows = [
        ("Notify the manager", [t, step("Get Identity", "Get Identity", "Send Email", ["$.trigger.identity.id"]),
                                step("Send Email", "Send Email", end_ok, ["$.getIdentity.email"]),
                                step(end_ok, end_ok)]),
        ("Remove leaver access", [t, step("Get Identity", "Get Identity", "Compare Strings", ["$.trigger.identity.id"]),
                                  step("Compare Strings", "Compare Strings", None,
                                       ["$.getIdentity.attributes.cloudLifecycleState"], true="Get Access",
                                       false=end_ok),
                                  step("Get Access", "Get Access", "Manage Access", ["$.trigger.identity.id"]),
                                  step("Manage Access", "Manage Access", end_ok, ["$.getAccess.accessItems"]),
                                  step(end_ok, end_ok)]),
        ("Half-wired check", [t, step("Get Identity", "Get Identity", "Compare Strings", ["$.trigger.identity.id"]),
                              step("Compare Strings", "Compare Strings", None, ["$.getIdentity.attributes.department"],
                                   true="Send Email"),
                              step("Send Email", "Send Email", end_ok, ["$.getIdentity.email"]),
                              step(end_ok, end_ok)]),
        ("Dead end", [t, step("Get Identity", "Get Identity", "Send Email", ["$.trigger.identity.id"]),
                      step("Send Email", "Send Email", None, ["$.getIdentity.email"]), step(end_ok, end_ok)]),
        ("Variable too early", [step(trig, "Event Trigger", "Send Email", trigger=trig),
                                step("Send Email", "Send Email", "Get Identity", ["$.getIdentity.email"]),
                                step("Get Identity", "Get Identity", end_ok, ["$.trigger.identity.id"]),
                                step(end_ok, end_ok)]),
        ("Two starts", [t, step("Scheduled Trigger", "Scheduled Trigger", "Get Identity"),
                        step("Get Identity", "Get Identity", end_bad, ["$.trigger.identity.id"]), step(end_bad, end_bad)]),
    ]
    workflows = []
    for k, (name, steps) in enumerate(flows, 1):
        steps = [dict(s) for s in steps]
        rng.shuffle(steps)
        workflows.append({"id": f"W{k:02d}", "name": name, "steps": steps})
    leaver, mover = ids[6], ids[0]
    new_dept = rng.choice([d for d in DEPTS if d != mover["attributes"]["department"]])
    events = [
        {"id": "E01", "trigger": "Identity Created", "payload": {"identity": {"type": "IDENTITY", "id": "2c91new",
         "name": f"{rng.choice(FIRST).lower()}.new"}, "attributes": {"department": rng.choice(DEPTS),
                                                                     "cloudLifecycleState": "prehire"}}},
        {"id": "E02", "trigger": "Identity Attributes Changed", "payload": {"identity": {"type": "IDENTITY",
         "id": leaver["id"], "name": leaver["name"]}, "changes": [{"attribute": "cloudLifecycleState",
                                                                  "oldValue": "active", "newValue": "terminated"}]}},
        {"id": "E03", "trigger": "Identity Attributes Changed", "payload": {"identity": {"type": "IDENTITY",
         "id": mover["id"], "name": mover["name"]}, "changes": [{"attribute": "department", "oldValue":
                                                                 mover["attributes"]["department"],
                                                                 "newValue": new_dept}]}},
        {"id": "E04", "trigger": "Access Request Submitted", "payload": {"accessRequestId": "ar-1",
         "requestedFor": {"type": "IDENTITY", "name": ids[2]["name"]}, "requestedItems": [{"name": "Domain Admins",
                                                                                          "type": "ENTITLEMENT",
                                                                                          "operation": "Add"}],
         "requestedBy": {"type": "IDENTITY", "name": ids[2]["name"]}}},
        {"id": "E05", "trigger": "Account Aggregation Completed", "payload": {"source": {"type": "SOURCE",
         "name": "Workday"}, "status": "Error", "errors": ["Connection timed out"], "warnings": [],
         "stats": {"scanned": 0, "unchanged": 0, "changed": 0, "added": 0, "removed": 0}}},
        {"id": "E06", "trigger": "Provisioning Completed", "payload": {"trackingNumber": "t-1", "action": "Add",
         "errors": [] if rng.random() < 0.5 else ["Connector AD Failed"], "warnings": [],
         "recipient": {"type": "IDENTITY", "name": ids[1]["name"]}, "accountRequests": []}},
    ]
    subscriptions = [
        {"id": "SUB01", "name": "Leaver to ticketing", "trigger": "Identity Attributes Changed", "enabled": True,
         "type": "HTTP", "filter": "$.changes[?(@.attribute == \"cloudLifecycleState\" && @.newValue == "
                                   "\"terminated\")]"},
        {"id": "SUB02", "name": "Mover sync", "trigger": "Identity Attributes Changed", "enabled": True,
         "type": "HTTP", "filter": f"$.changes[?(@.attribute == 'department' && @.newValue in ['{new_dept}'])]"},
        {"id": "SUB03", "name": "All joiners", "trigger": "Identity Created", "enabled": True, "type": "WORKFLOW",
         "filter": None},
        {"id": "SUB04", "name": "Admin request check", "trigger": "Access Request Submitted", "enabled": True,
         "type": "HTTP", "filter": "$.requestedItems[?(@.name contains \"Admin\")]"},
        {"id": "SUB05", "name": "Aggregation failure pager", "trigger": "Account Aggregation Completed",
         "enabled": True, "type": "EVENTBRIDGE", "filter": "$[?($.status == \"Error\")]"},
        {"id": "SUB06", "name": "Old aggregation hook", "trigger": "Account Aggregation Completed", "enabled": False,
         "type": "HTTP", "filter": None},
        {"id": "SUB07", "name": "Broken leaver filter", "trigger": "Identity Attributes Changed", "enabled": True,
         "type": "HTTP", "filter": "$.changes[?(@.attribute = \"cloudLifecycleState\")]"},
        {"id": "SUB08", "name": "Provisioning errors", "trigger": "Provisioning Completed", "enabled": True,
         "type": "HTTP", "filter": "$[?($.errors.length() > 0)]"},
    ]
    return {"_description": f"Generated scenario for {domain} (seeded).", "as_of": as_of.isoformat(),
            "identities": ids, "queries": queries, "saved_searches": saved, "workflows": workflows,
            "events": events, "subscriptions": subscriptions}
