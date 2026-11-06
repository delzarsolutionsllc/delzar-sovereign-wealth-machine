"""
Lab 43 — Identity Profiles, Attribute Mappings & Transforms
===========================================================

SailPoint ISC objectives
------------------------
* 3.1  Identity profiles and their authentication options: one authoritative
       source per profile, profile priority, and the sign-in method
       (user name and password, directory connection / pass-through, MFA).
* 3.2  Identity attribute mappings: mapping source account attributes to
       identity attributes, with transforms, and the required attributes.

The SailPoint Identity Security Engineer course maps this same lab to its
objectives 1.1 (identity model and identity profiles), 1.2 (identity
attributes) and 10.1 (transforms).

How it works
------------
You are the Identity Security Cloud (ISC) administrator onboarding a new
tenant. HR sources (employees from a Workday-style HR system, contractors from
a CSV file, interns from a tracker) feed identity profiles. The engine works
like an identity refresh, deny by default, in this order:

1. **Profile review (3.1).** Each identity profile must name an existing
   authoritative source, have a numeric priority that no other profile shares,
   a known sign-in method (USERNAME_PASSWORD, DIRECTORY_CONNECTION, MFA; a
   directory connection needs an existing authentication source), must not
   block off-network access without a network definition (that blocks every
   user), and must map every required attribute. Otherwise MISCONFIGURED.
2. **Correlation and profile choice.** Accounts on the HR sources are joined
   into one person by each source's correlation attribute (here the work
   email, compared without case). A person goes to the identity profile whose
   authoritative source holds one of their accounts; when two do, the profile
   with the LOWER priority number (higher priority) wins. No such profile:
   NO_PROFILE (an account on a non-authoritative source never creates an
   identity).
3. **Attribute mappings and transforms (3.2).** Each mapping is evaluated in
   order. A mapping may name a source and account attribute (the transform's
   implicit input) and a transform in ISC's JSON form. Supported types:
   accountAttribute, identityAttribute (only for an attribute already
   computed earlier in this profile), static (with $variables), firstValid
   (ignoreErrors), lower, upper, trim, concat, substring (begin, end,
   beginOffset, endOffset), replace (regex), lookup (table with optional
   "default"), conditional (``$a eq b`` only), dateFormat (named formats and
   simple patterns) and e164phone. Any other or unknown type, an invalid
   argument, a lookup miss with no default, or a null conditional operand is a
   TRANSFORM_ERROR: no value is stored, never a guessed one.
4. **Required attributes.** uid, email and lastname are required by ISC; this
   company also requires firstname and cloudLifecycleState, and the lifecycle
   state must be one the profile defines. A missing, empty or whitespace-only
   value is a MAPPING_ERROR.
5. **Uniqueness.** uid must be unique across all identities from any profile.
   The first person (in processing order) keeps it; a later one is
   DUPLICATE_UID. Otherwise OK.

Outcome precedence: NO_PROFILE > TRANSFORM_ERROR > MAPPING_ERROR >
DUPLICATE_UID > OK.

Simplifications (see code comments): static supports $var / ${var}
substitution but no other Velocity syntax; replace uses Python regular
expressions (Java ``$1`` group references are converted); e164phone handles
only a few regions with a length check, not the full libphonenumber rules;
dateFormat supports ISO8601, PEOPLE_SOFT, EPOCH_TIME_JAVA and the pattern
letters y, M, d, H, m, s; accountAttribute ignores the account filter and
sort options; the real refresh is multi-threaded, here it is in order.

Run it
------
    python main.py --course spadmin lab 43
    python main.py --course speng lab 43
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

TITLE = "Lab 43 — Identity Profiles, Attribute Mappings & Transforms"
OBJECTIVES = "SailPoint ISC 3.1 Identity profiles & sign-in options · 3.2 Identity attribute mappings"
COURSES = ("spadmin", "speng")

OUTCOMES = ["OK", "MAPPING_ERROR", "TRANSFORM_ERROR", "DUPLICATE_UID", "NO_PROFILE"]
PROFILE_STATUSES = ["READY", "MISCONFIGURED"]
ERROR_CHOICE = "TRANSFORM_ERROR (no value is stored)"
NULL_CHOICE = "null (no value)"


class TransformError(ValueError):
    """A transform that cannot produce a trustworthy value."""


@dataclass
class ProfileResult:
    name: str
    source: str
    priority: object
    sign_in: str
    status: str
    reasons: list[str] = field(default_factory=list)


@dataclass
class PersonResult:
    id: str
    accounts: list[str]
    sources: list[str]
    profile: str | None
    outcome: str
    attributes: dict = field(default_factory=dict)
    errors: dict = field(default_factory=dict)       # attribute -> transform error message
    traces: dict = field(default_factory=dict)       # attribute -> how the transform reached its value
    findings: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


@dataclass
class Ctx:
    accounts: dict                      # source name -> account attributes
    identity: dict                      # identity attributes computed so far
    cfg: dict
    trace: list = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Transform engine
# --------------------------------------------------------------------------- #
_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def show(value, error: str | None = None) -> str:
    """How a transform result is displayed (and offered as a choice)."""
    if error is not None:
        return ERROR_CHOICE
    if value is None:
        return NULL_CHOICE
    return json.dumps(value)


def _need(attrs: dict, key: str, ttype: str):
    if key not in attrs or attrs[key] is None:
        raise TransformError(f"{ttype}: required attribute '{key}' is missing")
    return attrs[key]


def _str(v):
    return None if v is None else str(v)


def evaluate(node, ctx: Ctx, implicit=None):
    """Evaluate one transform node (dict), a literal string, or None. Raises TransformError."""
    if node is None:
        return None
    if isinstance(node, bool) or not isinstance(node, (dict, str, int, float)):
        raise TransformError(f"cannot evaluate a value of type {type(node).__name__}")
    if not isinstance(node, dict):
        return str(node)
    ttype = node.get("type")
    cfg = ctx.cfg
    if not ttype:
        raise TransformError("transform has no type (deny by default)")
    if ttype not in cfg["supported_transforms"]:
        if ttype in cfg["known_unsimulated_transforms"]:
            raise TransformError(f"'{ttype}' is a real ISC transform but is not simulated here: refused, "
                                 "no value stored")
        raise TransformError(f"unknown transform type '{ttype}': refused, no value stored")
    attrs = node.get("attributes") or {}
    if not isinstance(attrs, dict):
        raise TransformError(f"{ttype}: attributes must be an object")

    def inp():
        # Explicit "input" wins; otherwise the implicit input from the mapping's source and attribute.
        return _str(evaluate(attrs["input"], ctx, implicit)) if "input" in attrs else _str(implicit)

    def var(name: str):
        if name not in attrs or name in ("expression", "positiveCondition", "negativeCondition", "value"):
            raise TransformError(f"{ttype}: variable '${name}' is not defined in attributes")
        return _str(evaluate(attrs[name], ctx, implicit))

    if ttype == "accountAttribute":
        src = attrs.get("sourceName") or attrs.get("applicationName")
        name = attrs.get("attributeName")
        if not src or not name:
            raise TransformError("accountAttribute: sourceName and attributeName are required")
        acct = ctx.accounts.get(src)
        if acct is None:
            return None                                   # no account on that source: null, as in ISC
        v = acct.get(name)
        return None if v is None or v == "" else str(v)   # an empty value aggregates as null
    if ttype == "identityAttribute":
        name = _need(attrs, "name", ttype)
        if cfg.get("identity_attribute_policy") != "computed_earlier_only":
            raise TransformError("identityAttribute is not allowed inside identity profile mappings")
        if name not in ctx.identity:
            # ISC docs: not intended inside another identity attribute's calculation; calculations are
            # multi-threaded, so the attribute may not exist yet. Only an attribute computed earlier in
            # this (sequential) simulation is treated as safe.
            raise TransformError(f"identityAttribute '{name}' is not computed yet in this profile: "
                                 "referencing it could read stale or missing data")
        ctx.trace.append(f"identityAttribute '{name}' read from an attribute computed earlier")
        return ctx.identity[name]
    if ttype == "static":
        value = str(_need(attrs, "value", ttype))
        if re.search(r"#(if|set|foreach|else|end)\b", value):
            raise TransformError("static: Velocity directives are not simulated here")

        def sub(m):
            v = var(m.group(1) or m.group(2))
            if v is None:
                raise TransformError(f"static: variable '${m.group(1) or m.group(2)}' is null")
            return v
        return _VAR.sub(sub, value)
    if ttype == "firstValid":
        values = _need(attrs, "values", ttype)
        if not isinstance(values, list) or not values:
            raise TransformError("firstValid: values must be a non-empty list")
        ignore = attrs.get("ignoreErrors") is True
        for i, v in enumerate(values):
            try:
                out = _str(evaluate(v, ctx, implicit))
            except TransformError as e:
                if not ignore:
                    raise
                ctx.trace.append(f"firstValid: value {i + 1} errored and was skipped (ignoreErrors): {e}")
                continue
            if out is not None:
                if i:
                    ctx.trace.append(f"firstValid: value {i + 1} is the first non-null (earlier values are null)")
                return out
        return None
    if ttype in ("lower", "upper", "trim"):
        v = inp()
        if v is None:
            return None
        return v.lower() if ttype == "lower" else v.upper() if ttype == "upper" else v.strip()
    if ttype == "concat":
        values = _need(attrs, "values", ttype)
        if not isinstance(values, list):
            raise TransformError("concat: values must be a list")
        parts = [_str(evaluate(v, ctx, implicit)) for v in values]
        if any(p is None for p in parts):
            # The ISC docs do not state how a null part is joined. Deny by default: the result is null, so a
            # half-built value (for example only "@example.com") is never stored.
            ctx.trace.append("concat: a part is null, so the result is null")
            return None
        return "".join(parts)
    if ttype == "substring":
        begin = _need(attrs, "begin", ttype)
        end = attrs.get("end")
        try:
            begin, b_off = int(begin), int(attrs.get("beginOffset", 0))
            end = None if end is None else int(end)
            e_off = int(attrs.get("endOffset", 0))
        except (TypeError, ValueError):
            raise TransformError("substring: begin, end and offsets must be integers") from None
        v = inp()
        if v is None:
            return None
        b = 0 if begin == -1 else begin + b_off          # beginOffset only used when begin is not -1
        e = len(v) if end in (None, -1) else end + e_off  # endOffset only used when end is given and not -1
        if b < 0 or e > len(v) or b > e:
            raise TransformError(f"substring: index out of range for \"{v}\" (begin {b}, end {e})")
        return v[b:e]
    if ttype == "replace":
        regex = _need(attrs, "regex", ttype)
        repl = str(_need(attrs, "replacement", ttype))
        v = inp()
        if v is None:
            return None
        # ISC uses Java regular expressions; Python's are close for simple patterns. $1 -> \1.
        repl = re.sub(r"\$(\d)", r"\\\1", repl.replace("\\", "\\\\"))
        try:
            return re.sub(regex, repl, v)
        except re.error as e:
            raise TransformError(f"replace: invalid regex '{regex}': {e}") from None
    if ttype == "lookup":
        table = _need(attrs, "table", ttype)
        if not isinstance(table, dict):
            raise TransformError("lookup: table must be an object")
        v = inp()
        if v is not None and v in table:                  # keys match exactly (case-sensitive)
            return _str(table[v])
        if "default" in table:
            ctx.trace.append(f"lookup: {json.dumps(v)} is not a key, so the table's default is used")
            return _str(table["default"])
        raise TransformError(f"lookup: {json.dumps(v)} matches no key and the table has no default")
    if ttype == "conditional":
        expr = str(_need(attrs, "expression", ttype))
        pos, neg = _need(attrs, "positiveCondition", ttype), _need(attrs, "negativeCondition", ttype)
        m = re.match(r"^\s*(\S+)\s+(\S+)\s+(.+?)\s*$", expr)
        if not m:
            raise TransformError(f"conditional: expression '{expr}' is not 'ValueA eq ValueB'")
        if m.group(2) != "eq":
            raise TransformError(f"conditional: operator '{m.group(2)}' is not allowed; 'eq' is the only "
                                 "valid comparison")

        def operand(tok: str):
            return var(tok[1:]) if tok.startswith("$") else tok
        a, b = operand(m.group(1)), operand(m.group(3))
        if a is None or b is None:
            raise TransformError("conditional: an operand is null (ISC throws IllegalArgumentException)")
        hit = a == b                                       # case-sensitive, as in ISC
        ctx.trace.append(f"conditional: {json.dumps(a)} eq {json.dumps(b)} is {str(hit).lower()}")
        out = str(pos if hit else neg)
        return operand(out) if out.startswith("$") else out
    if ttype == "dateFormat":
        v = inp()
        if v is None:
            return None
        named = cfg["date_named_formats"]
        fin, fout = attrs.get("inputFormat", "ISO8601"), attrs.get("outputFormat", "ISO8601")
        return _format_date(_parse_date(v, named.get(fin, fin)), named.get(fout, fout))
    if ttype == "e164phone":
        v = inp()
        if v is None:
            return None
        region = str(attrs.get("defaultRegion", "US"))
        out = _e164(v, region, cfg)
        if out is None:
            ctx.trace.append(f"e164phone: \"{v}\" is not a valid {region} phone number, so the result is null")
        return out
    raise TransformError(f"'{ttype}' is listed as supported but has no implementation")  # pragma: no cover


# ----------------------------------------------------------------- dates and phones
_DATE_TOKENS = {"yyyy": "%Y", "yy": "%y", "MM": "%m", "dd": "%d", "HH": "%H", "mm": "%M", "ss": "%S"}


def _java_pattern(p: str) -> str:
    """Convert a simple Java SimpleDateFormat pattern to a strftime format (subset)."""
    out, i = [], 0
    while i < len(p):
        c = p[i]
        if c == "'":
            j = p.find("'", i + 1)
            if j < 0:
                raise TransformError(f"dateFormat: unterminated quote in pattern '{p}'")
            out.append(p[i + 1:j].replace("%", "%%"))
            i = j + 1
        elif c.isalpha():
            j = i
            while j < len(p) and p[j] == c:
                j += 1
            tok = p[i:j]
            if tok not in _DATE_TOKENS:
                raise TransformError(f"dateFormat: pattern letters '{tok}' are not simulated here")
            out.append(_DATE_TOKENS[tok])
            i = j
        else:
            out.append("%%" if c == "%" else c)
            i += 1
    return "".join(out)


def _parse_date(v: str, fmt: str) -> datetime:
    try:
        if fmt == "ISO8601":
            dt = datetime.fromisoformat(v.strip().replace("Z", "+00:00"))
        elif fmt == "EPOCH_TIME_JAVA":
            dt = datetime.fromtimestamp(int(v) / 1000, tz=timezone.utc)
        else:
            dt = datetime.strptime(v.strip(), _java_pattern(fmt))
    except (ValueError, OverflowError):
        raise TransformError(f"dateFormat: \"{v}\" does not match input format {fmt}") from None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _format_date(dt: datetime, fmt: str) -> str:
    dt = dt.astimezone(timezone.utc)
    if fmt == "ISO8601":
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"
    if fmt == "EPOCH_TIME_JAVA":
        return str(int(dt.timestamp() * 1000))
    return dt.strftime(_java_pattern(fmt))


def _e164(v: str, region: str, cfg: dict):
    """Simplified E.164: an invalid number returns null (as the ISC docs say); an unknown region is an error."""
    regions = cfg["phone_regions"]
    s = v.strip()
    digits = re.sub(r"\D", "", s)
    if s.startswith("+"):
        return "+" + digits if 8 <= len(digits) <= 15 else None
    if region not in regions:
        raise TransformError(f"e164phone: defaultRegion '{region}' is not simulated here")
    r = regions[region]
    trunk = r.get("trunk_prefix", "")
    if trunk and digits.startswith(trunk) and len(digits) == r["national_length"] + len(trunk):
        digits = digits[len(trunk):]
    if len(digits) != r["national_length"]:
        return None
    if region in ("US", "CA") and (digits[0] in "01" or digits[3] in "01"):
        return None                                        # NANP area code and exchange cannot start 0/1
    return f"+{r['country_code']}{digits}"


# --------------------------------------------------------------------------- #
# Part 1 — profile review (3.1)
# --------------------------------------------------------------------------- #
def review_profiles(data: dict, cfg: dict) -> list[ProfileResult]:
    sources = {s.get("name") for s in data.get("sources", [])}
    profiles = data.get("identity_profiles", [])
    out = []
    for p in profiles:
        bad, notes = [], []
        src = p.get("authoritative_source")
        if not src or src not in sources:
            bad.append(f"authoritative source '{src}' does not exist: no identities can be built")
        else:
            notes.append(f"authoritative source {src}")
        prio = p.get("priority")
        if not isinstance(prio, int) or isinstance(prio, bool):
            bad.append("no numeric priority: it is treated as the lowest priority")
        else:
            twins = [q.get("name") for q in profiles if q is not p and q.get("priority") == prio]
            if twins:
                bad.append(f"priority {prio} is shared with {', '.join(twins)}: a person on both sources "
                           "has no clear profile")
            else:
                notes.append(f"priority {prio}")
        sign = p.get("sign_in") or {}
        method = sign.get("method")
        if method not in cfg["sign_in_methods"]:
            bad.append(f"sign-in method '{method}' is missing or unknown: nobody can sign in (deny by default)")
        elif method == "DIRECTORY_CONNECTION":
            auth = sign.get("authentication_source")
            if not auth or auth not in sources:
                bad.append(f"directory connection (pass-through) needs an existing authentication source; "
                           f"'{auth}' is not a source")
            else:
                notes.append(f"pass-through sign-in against {auth}")
        else:
            notes.append(f"sign-in: {cfg['sign_in_methods'][method]}")
        if "off_network" in (sign.get("block_access_from") or []) and not sign.get("network_ranges"):
            bad.append("blocks off-network access with no network definition: every user is blocked")
        mapped = p.get("mappings") or {}
        for attr in cfg["required_attributes"]:
            if attr not in mapped:
                bad.append(f"required attribute '{attr}' has no mapping")
        out.append(ProfileResult(p.get("name", "?"), src or "-", prio if prio is not None else "-",
                                 method or "-", "MISCONFIGURED" if bad else "READY", bad or notes))
    return out


# --------------------------------------------------------------------------- #
# Part 2 — correlation and profile choice
# --------------------------------------------------------------------------- #
def correlate(data: dict) -> list[list[dict]]:
    """Group accounts into people by each source's correlation attribute (compared without case)."""
    corr = {s.get("name"): s.get("correlation_attribute") for s in data.get("sources", [])}
    groups: list[list[dict]] = []
    by_key: dict[str, list[dict]] = {}
    for a in data.get("accounts", []):
        attr = corr.get(a.get("source"))
        raw = (a.get("attributes") or {}).get(attr) if attr else None
        key = str(raw).strip().lower() if raw not in (None, "") else None
        if key and key in by_key:
            by_key[key].append(a)
            continue
        g = [a]
        groups.append(g)
        if key:
            by_key[key] = g
    return groups


def _prio(p: dict) -> float:
    v = p.get("priority")
    return v if isinstance(v, int) and not isinstance(v, bool) else float("inf")


def choose_profile(group: list[dict], profiles: list[dict]) -> tuple[dict | None, list[str]]:
    srcs = [a.get("source") for a in group]
    cands = [p for p in profiles if p.get("authoritative_source") in srcs]
    if not cands:
        return None, [f"accounts only on {', '.join(dict.fromkeys(srcs))}: no identity profile uses that "
                      "source as authoritative, so no identity is created"]
    cands = sorted(cands, key=lambda p: (_prio(p), profiles.index(p)))
    win = cands[0]
    if len(cands) == 1:
        return win, [f"authoritative source {win['authoritative_source']} -> profile {win.get('name')}"]
    loser = ", ".join(f"{p.get('name')} (priority {p.get('priority', 'none')})" for p in cands[1:])
    return win, [f"on {len(cands)} authoritative sources: {win.get('name')} (priority {win.get('priority')}) "
                 f"beats {loser}; a lower number is a higher priority"]


# --------------------------------------------------------------------------- #
# Part 3 — mappings, required attributes, uniqueness (3.2)
# --------------------------------------------------------------------------- #
def compute_attributes(group: list[dict], profile: dict, cfg: dict) -> tuple[dict, dict, dict]:
    """Evaluate the profile's mappings in order. Returns (attributes, errors, traces per attribute)."""
    ctx = Ctx({a.get("source"): (a.get("attributes") or {}) for a in group}, {}, cfg)
    errors: dict[str, str] = {}
    traces: dict[str, list[str]] = {}
    for attr, m in (profile.get("mappings") or {}).items():
        m = m or {}
        ctx.trace = []
        implicit = None
        if m.get("source"):
            acct = ctx.accounts.get(m["source"]) or {}
            v = acct.get(m.get("attribute"))
            implicit = None if v in (None, "") else str(v)
        try:
            ctx.identity[attr] = _str(evaluate(m["transform"], ctx, implicit)) if m.get("transform") else implicit
        except TransformError as e:
            errors[attr] = str(e)
        if ctx.trace:
            traces[attr] = list(ctx.trace)
    return ctx.identity, errors, traces


def _blank(v) -> bool:
    return v is None or str(v).strip() == ""


def evaluate_people(data: dict, cfg: dict) -> list[PersonResult]:
    profiles = data.get("identity_profiles", [])
    prec = cfg["outcome_precedence"]
    results: list[PersonResult] = []
    for g in correlate(data):
        prof, reasons = choose_profile(g, profiles)
        ids, srcs = [a.get("id", "?") for a in g], [a.get("source", "?") for a in g]
        if prof is None:
            results.append(PersonResult(ids[0], ids, srcs, None, "NO_PROFILE", findings=["NO_PROFILE"],
                                        reasons=reasons))
            continue
        main = next(a for a in g if a.get("source") == prof["authoritative_source"])
        attrs, errors, traces = compute_attributes(g, prof, cfg)
        found: list[tuple[str, str]] = [("TRANSFORM_ERROR", f"{k}: {v}") for k, v in errors.items()]
        mapped = prof.get("mappings") or {}
        for attr, why in cfg["required_attributes"].items():
            if attr in errors:
                continue
            if attr not in mapped:
                found.append(("MAPPING_ERROR", f"required attribute {attr} has no mapping ({why})"))
            elif _blank(attrs.get(attr)):
                found.append(("MAPPING_ERROR", f"required attribute {attr} is empty ({why})"))
        state = attrs.get("cloudLifecycleState")
        states = prof.get("lifecycle_states") or []
        if not _blank(state) and "cloudLifecycleState" not in errors and state not in states:
            found.append(("MAPPING_ERROR", f"cloudLifecycleState '{state}' is not a lifecycle state of "
                          f"{prof.get('name')} ({', '.join(states) or 'none defined'})"))
        found.sort(key=lambda f: prec.index(f[0]))
        outcome = found[0][0] if found else "OK"
        notes = [f"{k}: {t}" for k, ts in traces.items() for t in ts if k not in errors]
        results.append(PersonResult(main.get("id", ids[0]), ids, srcs, prof.get("name"), outcome, attrs, errors,
                                    traces, [f for f, _ in found], reasons + [r for _, r in found] + notes))
    # Uniqueness: uid must be unique across all identities from any identity profile.
    seen: dict[str, str] = {}
    for r in results:
        if r.outcome != "OK":
            continue
        for attr in cfg["unique_attributes"]:
            v = str(r.attributes.get(attr))
            key = v.lower() if cfg.get("unique_case_insensitive") else v
            if key in seen:
                r.outcome = "DUPLICATE_UID"
                r.findings.append("DUPLICATE_UID")
                r.reasons.append(f"{attr} '{v}' already belongs to {seen[key]}: it must be unique across all "
                                 "identities from any identity profile")
            else:
                seen[key] = r.id
    for r in results:
        if r.outcome == "OK":
            r.reasons.append("all required attributes set, uid unique: identity created")
    return results


def run_transform_tests(data: dict, cfg: dict) -> list[dict]:
    out = []
    for t in data.get("transform_tests", []):
        ctx = Ctx(t.get("accounts") or {}, dict(t.get("identity") or {}), cfg)
        try:
            value, err = _str(evaluate(t.get("transform"), ctx, t.get("input"))), None
        except TransformError as e:
            value, err = None, str(e)
        out.append({"id": t.get("id", "?"), "type": (t.get("transform") or {}).get("type", "?"),
                    "value": value, "error": err, "display": show(value, err),
                    "reasons": [err] if err else (ctx.trace or [f"result {show(value)}"])})
    return out


def analyse(policies: dict, data: dict):
    cfg = policies["isc_identity_profiles"]
    people = evaluate_people(data, cfg)
    profiles = review_profiles(data, cfg)
    tests = run_transform_tests(data, cfg)
    counts = {o: sum(p.outcome == o for p in people) for o in OUTCOMES}
    metrics = {"accounts": len(data.get("accounts", [])), "people": len(people), **counts,
               "multi_source_people": sum(len(set(p.sources)) > 1 for p in people),
               "profiles_misconfigured": sum(p.status == "MISCONFIGURED" for p in profiles),
               "transform_tests": len(tests)}
    return profiles, people, tests, metrics


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SailPoint ISC 3.1 Identity profiles and sign-in options · 3.2 Identity attribute mappings "
                 "(Engineer course: 1.1, 1.2, 10.1 Transforms).",
    "concepts": [
        "An identity profile turns the accounts of ONE authoritative source into identities and sets their sign-in "
        "and security settings.",
        "When a person is on two authoritative sources, the profile with the lower priority number wins.",
        "Mappings fill identity attributes from account attributes, optionally through a transform; a transform "
        "with no input uses the mapped source attribute as its implicit input.",
        "uid, email and lastname are required on every profile; uid must be unique across all identities.",
        "cloudLifecycleState is calculated like any other attribute and must match a lifecycle state of the profile.",
    ],
    "failure_modes": [
        "A lookup without a default: one unexpected HR status value breaks the identity.",
        "Case-sensitive conditionals: 'a' is not 'A', so a contractor silently becomes inactive.",
        "uid built from first initial + last name collides for two people with the same pattern.",
        "identityAttribute used inside another identity attribute: refresh order is not guaranteed.",
        "Blocking off-network access with no network defined locks every user out.",
    ],
    "ai_governance": [
        "An AI assistant can draft transform JSON, but test it against real sample accounts before it reaches a "
        "profile: one wrong lookup can change thousands of lifecycle states.",
        "Changing a profile's mappings or priority is a reviewed change; preview the identities it affects first.",
        "Treat HR field values as untrusted data, never as instructions to an agent.",
    ],
    "exam_tips": [
        "One identity profile = one authoritative source.",
        "Priority: lower number = higher priority (new profiles default to 10, 20, 30 ...).",
        "Required identity attributes: User Name (uid), Work Email (email), Last Name (lastname).",
        "Directory Connection sign-in = pass-through authentication against a source.",
        "conditional supports only 'eq'; lookup with no match and no default returns an error.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    profiles, people, tests, metrics = analyse(policies, data)
    ui.section("Step 1 — Review the identity profiles (source, priority, sign-in)")
    ui.table("Identity profiles", ["Profile", "Priority", "Authoritative source", "Sign-in", "Status"],
             [[p.name, p.priority, p.source, p.sign_in, p.status] for p in profiles])
    for p in profiles:
        ui.bullet(f"{p.name}: " + "; ".join(p.reasons), style="green" if p.status == "READY" else "yellow")
    ui.section("Step 2 — Correlate HR accounts and choose each person's identity profile")
    ui.table("People", ["ID", "Accounts", "Sources", "Identity profile"],
             [[r.id, ", ".join(r.accounts), ", ".join(r.sources), r.profile or "-"] for r in people])
    for r in people:
        if r.profile is None or len(r.accounts) > 1:
            ui.bullet(f"{r.id}: {r.reasons[0]}", style="red" if r.profile is None else "dim")
    ui.section("Step 3 — Calculate identity attributes through the mappings and transforms")
    ui.table("Identity attributes", ["ID", "Profile", "uid", "email", "firstname", "lastname",
                                     "cloudLifecycleState", "Outcome"],
             [[r.id, r.profile or "-", *[r.attributes.get(a) or ("ERROR" if a in r.errors else "-") for a in
               ("uid", "email", "firstname", "lastname", "cloudLifecycleState")], r.outcome] for r in people])
    for r in people:
        ui.bullet(f"{r.id} → {r.outcome}: " + "; ".join(r.reasons[1:] or r.reasons),
                  style={"OK": "green", "DUPLICATE_UID": "yellow"}.get(r.outcome, "red"))
    ui.section("Step 4 — Test transforms before they go into a profile")
    ui.table("Transform tests", ["ID", "Type", "Result"], [[t["id"], t["type"], t["display"]] for t in tests])
    for t in tests:
        ui.bullet(f"{t['id']}: " + "; ".join(t["reasons"]), style="red" if t["error"] else "dim")
    ui.print(f"{metrics['people']} people from {metrics['accounts']} accounts: {metrics['OK']} OK, "
             f"{metrics['MAPPING_ERROR']} mapping error, {metrics['TRANSFORM_ERROR']} transform error, "
             f"{metrics['DUPLICATE_UID']} duplicate uid, {metrics['NO_PROFILE']} no profile · "
             f"{metrics['profiles_misconfigured']} of {len(profiles)} profiles misconfigured")
    ui.insight(INSIGHT)
    return {"people": {r.id: r.outcome for r in people}, "profiles": {p.name: p.status for p in profiles},
            "assigned": {r.id: r.profile for r in people},
            "uids": {r.id: r.attributes.get("uid") for r in people if r.profile},
            "transform_tests": {t["id"]: t["display"] for t in tests}, "metrics": metrics}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
_SKIP_KEYS = {"type", "name", "sourceName", "applicationName", "attributeName", "regex", "expression",
              "inputFormat", "outputFormat", "defaultRegion"}


def _leaves(node) -> list[str]:
    """String values inside a transform (conditions, table values, statics): plausible wrong answers."""
    out: list[str] = []
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, list):
        for v in node:
            out += _leaves(v)
    elif isinstance(node, dict):
        for k, v in node.items():
            if k not in _SKIP_KEYS:
                out += _leaves(v)
    return out


def _value_choices(answer: str, inputs, transform, key: str) -> list[str]:
    """The answer plus three plausible wrong values: the raw inputs and transform constants first, then the
    error and null outcomes, then case and whitespace variants."""
    plain = json.loads(answer) if answer.startswith('"') else None
    raw = [v for v in [*inputs, *_leaves(transform)] if isinstance(v, str) and v.strip()]
    ordered = [json.dumps(v) for v in raw] + [ERROR_CHOICE, NULL_CHOICE]
    for v in [*raw, plain]:
        if isinstance(v, str) and v.strip():
            ordered += [json.dumps(v.strip()), json.dumps(v.lower()), json.dumps(v.upper())]
    ordered.append(json.dumps(""))
    # Answers typed as text are matched without case, so keep one option per case-folded spelling.
    picked: dict[str, str] = {answer.casefold(): answer}
    for c in ordered:
        if len(picked) == 4:
            break
        picked.setdefault(c.casefold(), c)
    return sorted(picked.values())


def _interesting(r: PersonResult, attr: str) -> str | None:
    """Why this attribute's value is worth a question (None = routine)."""
    if attr in r.errors:
        return "error"
    t = " ".join(r.traces.get(attr, []))
    if "earlier values are null" in t or "default is used" in t or "read from an attribute" in t:
        return "fallback"
    if " is false" in t:
        return "negative"
    if r.attributes.get(attr) is None:
        return "null"
    return None


def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["isc_identity_profiles"]
    profiles, people, tests, _ = analyse(policies, data)
    raw = {a.get("id"): a for a in data.get("accounts", [])}
    prof_by_name = {p.get("name"): p for p in data.get("identity_profiles", [])}
    qs: list = []

    def acct_ctx(r: PersonResult) -> str:
        return "\n".join(f"{i} on {raw[i].get('source')}: {raw[i].get('attributes')}" for i in r.accounts)

    for r in people:
        qs.append(Question(prompt=f"{r.id}: what is the result of the identity refresh for this person?",
                           context=acct_ctx(r) + (f"\nidentity profile: {r.profile}" if r.profile else ""),
                           choices=OUTCOMES, answer=r.outcome, explanation="; ".join(r.reasons),
                           objective="3.1" if r.outcome == "NO_PROFILE" else "3.2"))
    names = [p.get("name") for p in data.get("identity_profiles", [])] + ["no identity profile"]
    for r in people:
        if len(set(r.sources)) > 1:
            qs.append(Question(prompt=f"{r.id} has accounts on {' and '.join(dict.fromkeys(r.sources))}. Which "
                                      "identity profile does the identity belong to?",
                               context="profiles: " + "; ".join(f"{p.get('name')} (source "
                                       f"{p.get('authoritative_source')}, priority {p.get('priority')})"
                                       for p in data.get("identity_profiles", [])),
                               choices=choices_with(r.profile, names, key=r.id), answer=r.profile,
                               explanation=r.reasons[0], objective="3.1"))
    # "What value does this mapping produce?" — computed by the engine, one per kind of tricky case.
    seen_kinds: set = set()
    for r in people:
        if not r.profile:
            continue
        prof = prof_by_name[r.profile]
        main = next(a for a in r.accounts if raw[a].get("source") == prof["authoritative_source"])
        acct = raw[main].get("attributes") or {}
        for attr, m in (prof.get("mappings") or {}).items():
            m = m or {}
            kind = _interesting(r, attr)
            if not m.get("transform") or kind is None or (attr, kind) in seen_kinds or len(seen_kinds) >= 6:
                continue
            seen_kinds.add((attr, kind))
            ans = show(r.attributes.get(attr), r.errors.get(attr))
            why = [r.errors[attr]] if attr in r.errors else r.traces.get(attr) or [f"{attr} = {ans}"]
            qs.append(Question(prompt=f"{r.id}: what value does the {attr} mapping produce?",
                               context=f"account {main}: {acct}\nmapping: {json.dumps(m)}",
                               choices=_value_choices(ans, [acct.get(m.get("attribute"))] if m.get("source") else [],
                                                      m["transform"], r.id + attr),
                               answer=ans, explanation="; ".join(why), objective="3.2"))
    by_test = {t.get("id"): t for t in data.get("transform_tests", [])}
    for t in tests:
        src = by_test[t["id"]]
        ctx = f"transform: {json.dumps(src.get('transform'))}"
        if src.get("input") is not None:
            ctx += f"\nimplicit input: {json.dumps(src['input'])}"
        if src.get("accounts"):
            ctx += f"\naccounts: {json.dumps(src['accounts'])}"
        if src.get("identity") is not None:
            ctx += f"\nidentity attributes already computed: {json.dumps(src['identity'])}"
        qs.append(Question(prompt=f"{t['id']}: what value does this transform produce?", context=ctx,
                           choices=_value_choices(t["display"], [src.get("input"),
                                                                   *(src.get("identity") or {}).values()],
                                                  src.get("transform"), t["id"]),
                           answer=t["display"], explanation="; ".join(t["reasons"]), objective="3.2"))
    for p in profiles:
        qs.append(Question(prompt=f"Identity profile {p.name}: is it ready, or misconfigured?",
                           context=f"settings: {json.dumps({k: v for k, v in prof_by_name[p.name].items() if k != 'mappings'})}"
                                   f"\nmapped attributes: {', '.join(prof_by_name[p.name].get('mappings') or {})}",
                           choices=PROFILE_STATUSES, answer=p.status, explanation="; ".join(p.reasons),
                           objective="3.1"))
    # Concept and rule questions.
    qs.append(Question(prompt="Two identity profiles have priority 10 and 20. A person has an account on both "
                              "authoritative sources. Where does the identity go?",
                       choices=["the profile with priority 10", "the profile with priority 20",
                                "both profiles, one identity each", "neither until an admin chooses"],
                       answer="the profile with priority 10",
                       explanation="identities join the highest-priority profile; a lower number is a higher priority",
                       objective="3.1"))
    qs.append(Question(prompt="Which identity attributes does ISC require on every identity profile?",
                       choices=["uid, email and lastname", "uid, email and manager", "email, phone and department",
                                "firstname, lastname and displayName"],
                       answer="uid, email and lastname",
                       explanation="User Name (uid), Work Email (email) and Last Name (lastname) must be mapped and "
                                   "not null; uid must be unique", objective="3.2"))
    qs.append(Question(prompt="Users must sign in to ISC with their Active Directory password. Which sign-in "
                              "method does the identity profile use?",
                       choices=sorted(cfg["sign_in_methods"]), answer="DIRECTORY_CONNECTION",
                       explanation=cfg["sign_in_methods"]["DIRECTORY_CONNECTION"], objective="3.1"))
    qs.append(Question(prompt="A conditional transform uses the expression \"$status ne T\". What happens?",
                       choices=["it errors: eq is the only valid comparison", "it returns the negative condition",
                                "it returns the positive condition", "ne is treated as eq"],
                       answer="it errors: eq is the only valid comparison",
                       explanation="the ISC conditional transform accepts only 'ValueA eq ValueB'", objective="3.2"))
    for term in ("identity profile", "authoritative source", "transform", "implicit input",
                 "pass-through authentication", "cloudLifecycleState"):
        if term in cfg["concepts"]:
            qs.append(Question(prompt=f"Which term is this? \"{cfg['concepts'][term]}\"",
                               choices=choices_with(term, cfg["concepts"], key=term), answer=term,
                               explanation=cfg["concepts"][term],
                               objective="3.1" if term in ("identity profile", "authoritative source",
                                                           "pass-through authentication") else "3.2"))
    return qs


# --------------------------------------------------------------------------- #
# Scenario builder (shared by the sample data and the generator)
# --------------------------------------------------------------------------- #
def _acct(source, attr):
    return {"type": "accountAttribute", "attributes": {"sourceName": source, "attributeName": attr}}


def standard_profiles(domain: str, prio=(10, 20, 30)) -> tuple[list[dict], list[dict]]:
    """The sources and identity profiles used by the sample data and the generator."""
    hr, csv, interns = "Workday HR", "Contractor CSV", "Intern Tracker"
    sources = [{"name": hr, "type": "HR (Workday-style)", "correlation_attribute": "WORK_EMAIL"},
               {"name": csv, "type": "Delimited file", "correlation_attribute": "email"},
               {"name": interns, "type": "Delimited file", "correlation_attribute": "email"},
               {"name": "Legacy Payroll", "type": "JDBC (not authoritative)", "correlation_attribute": "email"},
               {"name": "Corp AD", "type": "Active Directory", "correlation_attribute": "mail"}]
    contractors = {
        "name": "Contractors", "authoritative_source": csv, "priority": prio[1],
        "sign_in": {"method": "USERNAME_PASSWORD", "block_access_from": ["off_network"], "network_ranges": []},
        "lifecycle_states": ["active", "inactive"],
        "mappings": {
            "uid": {"source": csv, "attribute": "contractor_id",
                    "transform": {"type": "lower", "attributes": {"input": {"type": "replace", "attributes": {
                        "regex": "[^A-Za-z0-9]", "replacement": ""}}}}},
            "email": {"source": csv, "attribute": "email", "transform": {"type": "lower"}},
            "firstname": {"source": csv, "attribute": "first_name"},
            "lastname": {"source": csv, "attribute": "last_name"},
            "department": {"transform": {"type": "static", "attributes": {
                "value": "Contractor ($vendor)", "vendor": _acct(csv, "vendor")}}},
            "endDate": {"source": csv, "attribute": "end_date", "transform": {"type": "dateFormat", "attributes": {
                "inputFormat": "yyyy-MM-dd", "outputFormat": "ISO8601"}}},
            "cloudLifecycleState": {"transform": {"type": "conditional", "attributes": {
                "expression": "$status eq A", "positiveCondition": "active", "negativeCondition": "inactive",
                "status": _acct(csv, "status")}}}}}
    employees = {
        "name": "Employees", "authoritative_source": hr, "priority": prio[0],
        "sign_in": {"method": "DIRECTORY_CONNECTION", "authentication_source": "Corp AD"},
        "lifecycle_states": ["prehire", "active", "inactive"],
        "mappings": {
            "uid": {"transform": {"type": "lower", "attributes": {"input": {"type": "concat", "attributes": {
                "values": [{"type": "substring", "attributes": {"begin": 0, "end": 1,
                                                                "input": _acct(hr, "FIRST_NAME")}},
                           {"type": "trim", "attributes": {"input": _acct(hr, "LAST_NAME")}}]}}}}},
            "email": {"transform": {"type": "firstValid", "attributes": {"values": [
                _acct(hr, "WORK_EMAIL"),
                {"type": "concat", "attributes": {"values": [{"type": "identityAttribute",
                                                              "attributes": {"name": "uid"}}, "@" + domain]}}]}}},
            "firstname": {"transform": {"type": "firstValid", "attributes": {"values": [
                _acct(hr, "PREFERRED_NAME"), _acct(hr, "FIRST_NAME")]}}},
            "lastname": {"source": hr, "attribute": "LAST_NAME", "transform": {"type": "trim"}},
            "department": {"source": hr, "attribute": "DEPT_CODE", "transform": {"type": "lookup", "attributes": {
                "table": {"FIN": "Finance", "ENG": "Engineering", "OPS": "Operations", "default": "Unassigned"}}}},
            "startDate": {"source": hr, "attribute": "HIRE_DATE", "transform": {"type": "dateFormat", "attributes": {
                "inputFormat": "PEOPLE_SOFT", "outputFormat": "ISO8601"}}},
            "phone": {"source": hr, "attribute": "WORK_PHONE", "transform": {"type": "e164phone",
                                                                             "attributes": {"defaultRegion": "US"}}},
            "cloudLifecycleState": {"source": hr, "attribute": "WORKER_STATUS", "transform": {
                "type": "lookup", "attributes": {"table": {"Active": "active", "Pre-hire": "prehire",
                                                           "Terminated": "inactive", "Leave": "leave"}}}}}}
    intern = {
        "name": "Interns", "authoritative_source": interns, "priority": prio[2],
        "sign_in": {"method": "DIRECTORY_CONNECTION", "authentication_source": "Campus LDAP"},
        "lifecycle_states": ["active", "inactive"],
        "mappings": {
            "uid": {"source": interns, "attribute": "intern_id", "transform": {"type": "lower"}},
            "email": {"source": interns, "attribute": "email"},
            "firstname": {"source": interns, "attribute": "first_name", "transform": {"type": "titleCase"}},
            "lastname": {"source": interns, "attribute": "last_name"},
            "cloudLifecycleState": {"transform": {"type": "static", "attributes": {"value": "active"}}}}}
    return sources, [contractors, employees, intern]


def standard_transform_tests(rng=None) -> list[dict]:
    pick = (lambda xs: rng.choice(xs)) if rng else (lambda xs: xs[0])
    emp = pick(["EMP-00731", "EMP-04410", "EMP-00092"])
    city = pick(["  Rotterdam ", " Lisbon  ", "  Osaka "])
    date = pick(["2026-03-02", "2025-11-17", "2026-07-30"])
    phone = pick(["(312) 555-0142", "212.555.0187", "1-415-555-0123"])
    return [
        {"id": "X1", "description": "employee number without prefix and leading zeros",
         "transform": {"type": "replace", "attributes": {"regex": "^0+", "replacement": "", "input": {
             "type": "substring", "attributes": {"begin": 4}}}}, "input": emp},
        {"id": "X2", "description": "office city, cleaned and upper-case",
         "transform": {"type": "upper", "attributes": {"input": {"type": "trim"}}}, "input": city},
        {"id": "X3", "description": "termination check written with ne",
         "transform": {"type": "conditional", "attributes": {"expression": "$s ne T", "positiveCondition": "active",
                                                             "negativeCondition": "inactive",
                                                             "s": {"type": "static", "attributes": {"value": "A"}}}}},
        {"id": "X4", "description": "first valid of a failing lookup and a static fallback",
         "transform": {"type": "firstValid", "attributes": {"ignoreErrors": True, "values": [
             {"type": "lookup", "attributes": {"table": {"NL": "Netherlands"}}},
             {"type": "static", "attributes": {"value": "Unknown country"}}]}}, "input": pick(["PT", "JP", "BR"])},
        {"id": "X5", "description": "contract end date to PeopleSoft format",
         "transform": {"type": "dateFormat", "attributes": {"inputFormat": "yyyy-MM-dd",
                                                            "outputFormat": "PEOPLE_SOFT"}}, "input": date},
        {"id": "X6", "description": "manager uid read before it is calculated",
         "transform": {"type": "identityAttribute", "attributes": {"name": "managerUid"}},
         "identity": {"uid": "jdoe"}},
        {"id": "X7", "description": "work phone to E.164",
         "transform": {"type": "e164phone"}, "input": phone},
    ]


# --------------------------------------------------------------------------- #
# Scenario generator
# --------------------------------------------------------------------------- #
FIRST = ["Amara", "Jordan", "Jamie", "Luis", "Mei", "Noor", "Priya", "Robert", "Kai", "Diego", "Elif", "Tomas",
         "Sven", "Ana", "Hugo", "Ingrid", "Rafael", "Zara", "Owen", "Leila"]
LAST = ["Okoye", "Park", "Ferreira", "Tanaka", "Haddad", "Raman", "Lind", "Moreau", "Santos", "Kaya", "Novak",
        "Berg", "Lopes", "Brandt", "Achebe", "Iversen", "Costa", "Quinn"]
VENDORS = ["Northwind Staffing", "Bluebird Talent", "Granite Partners"]


def generate_scenario(rng, policies: dict) -> dict:
    domain = rng.choice(["fjordline.example", "copperleaf.example", "tidewater.example"])
    p_emp, p_con = rng.choice([(10, 20), (5, 15), (10, 30)])
    sources, profiles = standard_profiles(domain, (p_emp, p_con, p_con + 10))
    rng.shuffle(profiles)
    firsts = rng.sample([f for f in FIRST if f[0] != "J"], 13)
    lasts = rng.sample(LAST, 14)
    twin_last = lasts.pop()                       # unique, so only the planned pair collides on uid
    n = [0]

    def mail(f, l):
        return f"{f.lower()}.{l.lower()}@{domain}"

    def phone():
        return f"({rng.randint(2, 9)}{rng.randint(0, 9)}{rng.randint(0, 9)}) 555-01{rng.randint(10, 99)}"

    def hire():
        return f"{rng.randint(1, 12):02d}/{rng.randint(1, 28):02d}/{rng.randint(2015, 2026)}"

    accounts: list[dict] = []

    def emp(f, l, status="Active", **over):
        n[0] += 1
        a = {"WORKER_ID": f"W{rng.randint(10000, 99999)}", "FIRST_NAME": f, "LAST_NAME": l,
             "PREFERRED_NAME": "", "WORK_EMAIL": mail(f, l), "DEPT_CODE": rng.choice(["FIN", "ENG", "OPS", "LEG"]),
             "HIRE_DATE": hire(), "WORK_PHONE": phone(), "WORKER_STATUS": status}
        a.update(over)
        accounts.append({"id": f"W{n[0]:02d}", "source": "Workday HR", "attributes": a})

    def con(f, l, status="A", **over):
        n[0] += 1
        a = {"contractor_id": f"C-{rng.randint(1000, 9999)}", "first_name": f, "last_name": l, "email": mail(f, l),
             "vendor": rng.choice(VENDORS), "end_date": f"2027-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}",
             "status": status}
        a.update(over)
        accounts.append({"id": f"C{n[0]:02d}", "source": "Contractor CSV", "attributes": a})

    f, l = firsts, lasts
    emp(f[0], l[0])                                                     # OK
    emp("Jordan", twin_last)                                            # OK, first holder of the uid
    emp("Jamie", twin_last)                                             # DUPLICATE_UID
    emp(f[1], l[1], status=rng.choice(["Pending", "Suspended", "On hold"]))   # TRANSFORM_ERROR: lookup miss
    emp(f[2], l[2], WORK_EMAIL="")                                      # OK via identityAttribute fallback
    emp(f[3], "   ")                                                    # MAPPING_ERROR: lastname empty after trim
    emp(f[4], l[4], status="Leave")                                     # MAPPING_ERROR: state not on profile
    emp(f[5], l[5], PREFERRED_NAME=rng.choice(["Bobby", "Sunny", "Max"]), WORK_PHONE="ext. 2201")   # OK
    emp(f[6], l[6])                                                     # converted contractor (also in CSV)
    con(f[6], l[6], status="T", email=mail(f[6], l[6]).upper())
    con(f[7], l[7])                                                     # OK
    con(f[8], l[8], status="a")                                         # OK, but inactive (case-sensitive)
    con(f[9], "")                                                       # MAPPING_ERROR: no last name
    con(f[10], l[10], status="")                                        # TRANSFORM_ERROR: null operand
    n[0] += 1
    accounts.append({"id": f"I{n[0]:02d}", "source": "Intern Tracker", "attributes": {
        "intern_id": f"INT-{rng.randint(100, 999)}", "first_name": f[11].lower(), "last_name": l[11],
        "email": mail(f[11], l[11])}})                                  # TRANSFORM_ERROR: unknown type
    n[0] += 1
    accounts.append({"id": f"L{n[0]:02d}", "source": "Legacy Payroll", "attributes": {
        "emp_no": str(rng.randint(1000, 9999)), "email": mail(f[12], l[12]), "name": f"{f[12]} {l[12]}"}})
    order = accounts[:]
    head, tail = order[:3], order[3:]
    rng.shuffle(tail)
    return {"_description": f"Generated identity profile scenario for {domain}.", "sources": sources,
            "identity_profiles": profiles, "accounts": head + tail,
            "transform_tests": standard_transform_tests(rng)}
