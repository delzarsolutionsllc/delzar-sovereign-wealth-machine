"""
Lab 46 — Provisioning Engine: Plans, Create Account Policies & Channels
=======================================================================

SailPoint ISC objectives
------------------------
* 4.1  How provisioning is triggered, its components and channels: role
       assignment through membership criteria or an access request, access
       profiles, lifecycle state changes and attribute sync; the create
       account provisioning policy; direct connector provisioning, service
       desk tickets and manual tasks.
* 4.2  Provisioning logging and troubleshooting: where to look when a
       transaction fails (account activities, events, connector logging).

Engineer course mapping: SailPoint Identity Security Engineer 2.1
(provisioning outcomes and role assignment behaviour), 2.2 (provisioning
policies, attribute sync and multiple accounts) and 2.3 (provisioning
testing, troubleshooting and best practices).

How it works
------------
You are the Identity Security Cloud (ISC) administrator. Each item is one
change to one identity. The engine compares the identity's access before
and after the change and writes the provisioning plan per source, then
picks the channel and says where to look for every failed transaction.
Each change is planned against the starting snapshot (changes do not build
on each other). Rules, in evaluation order:

1. **Validate the change (deny by default).** An unknown identity, change
   type, trigger, role, access profile or lifecycle state, a source that is
   not in the catalog, or an access request for something that is not
   requestable gives REJECTED and nothing is sent.
2. **Membership criteria.** A role assigned "via membership criteria" is
   only assigned when the identity matches the role's criteria (as on an
   identity refresh); otherwise NO_CHANGE.
3. **Additions.** For every entitlement the new assignment grants on a source:
   * no account on the source -> CREATE_ACCOUNT, with attributes built from
     the source's create account provisioning policy: ``identityAttribute``
     copies an identity attribute, ``static`` is a fixed value, and the
     ``unique_username`` generator fills a pattern such as
     ``$(firstname).$(lastname)$(uniqueCounter)`` (the counter is empty on
     the first try, then 1, 2 ...) until the value is not taken. A missing
     required value, an exhausted generator or an unknown field type gives
     PLAN_ERROR and the account is not created;
   * more than one account on the source and no account selected ->
     MULTIPLE_ACCOUNTS (someone must pick the account);
   * one account (or the selected one) -> ADD_ENTITLEMENT, or NO_CHANGE if
     the account already holds it.
4. **Removals.** REMOVE_ENTITLEMENT only when no other role, access profile
   or directly requested entitlement still grants it; otherwise NO_CHANGE,
   naming what still grants it.
5. **Lifecycle state.** Moving to a state that disables accounts gives
   DISABLE for each enabled account on the listed sources (already disabled
   -> NO_CHANGE).
6. **Attribute sync.** An identity attribute change gives MODIFY on each
   account whose source maps that attribute and holds a different value.
   Attribute sync needs a direct connector, so a ticket or read-only source
   gets NO_CHANGE with a reason.
7. **Channel** (first match wins): a service desk integration on the source
   -> SERVICE_DESK (a ticket); a connector that supports provisioning ->
   DIRECT; otherwise (read-only, flat file or unknown capability) ->
   MANUAL_TASK, a work item for the source owner.
8. **Transactions.** DIRECT is COMPLETED unless the connector reported an
   error (FAILED); SERVICE_DESK and MANUAL_TASK stay PENDING until a person
   completes them. Every FAILED line (PLAN_ERROR, MULTIPLE_ACCOUNTS,
   REJECTED, or a connector error) gets troubleshooting steps.

Simplifications: real ISC builds one plan per identity refresh across all
changes, re-evaluates role criteria after attribute changes, supports more
generator and transform types (rules, unique LDAP attributes), account
enable/unlock/delete operations, "before provisioning" rules and per-source
account selection rules. Statuses here are simplified labels for ISC
account activity states.

Run it
------
    python main.py --course spadmin lab 46
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

TITLE = "Lab 46 — Provisioning Engine: Plans, Create Account Policies & Channels"
OBJECTIVES = ("SailPoint ISC 4.1 Provisioning triggers, components and channels · "
              "4.2 Provisioning logging and troubleshooting")
COURSES = ("spadmin", "speng")

OPERATIONS = ["CREATE_ACCOUNT", "ADD_ENTITLEMENT", "REMOVE_ENTITLEMENT", "MODIFY", "DISABLE", "NO_CHANGE"]
FAILURES = ["PLAN_ERROR", "MULTIPLE_ACCOUNTS", "REJECTED"]
OUTCOMES = OPERATIONS + FAILURES
CHANNELS = ["DIRECT", "SERVICE_DESK", "MANUAL_TASK"]
STATUSES = ["COMPLETED", "PENDING", "FAILED", "NOT_SENT"]


@dataclass
class PlanLine:
    id: str
    change: str
    source: str
    operation: str
    target: str = ""                         # entitlement or attribute name
    account: str | None = None
    channel: str | None = None
    status: str = "NOT_SENT"
    attributes: dict = field(default_factory=dict)
    entitlements: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    troubleshooting: list[str] = field(default_factory=list)


@dataclass
class ChangeResult:
    id: str
    identity: str
    type: str
    lines: list[PlanLine] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Access model
# --------------------------------------------------------------------------- #
def grants(roles: list[str], profiles: list[str], direct: list[dict], data: dict) -> dict:
    """{source: {entitlement: [what grants it]}} for a set of assignments. Unknown names are skipped here;
    the change validator rejects them before this is used."""
    out: dict = {}
    aps = data.get("access_profiles", {})

    def add(source, ent, by):
        out.setdefault(source, {}).setdefault(ent, []).append(by)

    for r in roles:
        for ap in data.get("roles", {}).get(r, {}).get("access_profiles", []):
            for e in aps.get(ap, {}).get("entitlements", []):
                add(aps[ap].get("source"), e, f"role '{r}' (access profile {ap})")
    for ap in profiles:
        for e in aps.get(ap, {}).get("entitlements", []):
            add(aps[ap].get("source"), e, f"access profile {ap}")
    for d in direct:
        add(d.get("source"), d.get("entitlement"), "a directly requested entitlement")
    return out


def criteria_match(identity: dict, criteria: list[dict] | None) -> tuple[bool, str]:
    """All criteria must match (AND). No criteria on the role = no automatic assignment (deny by default)."""
    if not criteria:
        return False, "role has no membership criteria, so it is never assigned automatically"
    attrs = identity.get("attributes", {})
    for c in criteria:
        have = attrs.get(c.get("attribute"))
        if str(have or "").lower() != str(c.get("equals", "")).lower():
            return False, f"criteria not met: {c.get('attribute')} is '{have}', role needs '{c.get('equals')}'"
    return True, "membership criteria met: " + ", ".join(f"{c['attribute']} = {c['equals']}" for c in criteria)


def channel_for(source: dict, cfg: dict) -> tuple[str, str]:
    """First matching channel rule. A source without a clear provisioning capability gets a manual task."""
    rules = {r["channel"]: r["name"] for r in cfg["channel_rules"]}
    if source.get("service_desk"):
        return "SERVICE_DESK", f"{rules['SERVICE_DESK']} ({source['service_desk']}): a ticket is opened"
    if source.get("provisioning") is True and not source.get("read_only"):
        return "DIRECT", f"{rules['DIRECT']} ({source.get('connector', 'connector')})"
    why = "source is read-only" if source.get("read_only") or source.get("provisioning") is False else \
        "provisioning capability is not stated (deny by default)"
    return "MANUAL_TASK", f"{why}: work item for the source owner {source.get('owner') or '(no owner set)'}"


# --------------------------------------------------------------------------- #
# Create account provisioning policy
# --------------------------------------------------------------------------- #
_TOKEN = re.compile(r"\$\(([A-Za-z0-9_]+)\)")


def generate_unique(fld: dict, identity: dict, taken: list[str], cfg: dict) -> tuple[str | None, str]:
    gen = cfg["generators"]["unique_username"]
    pattern = fld.get("pattern") or ""
    counter_tok = gen["counter_token"]
    attrs = identity.get("attributes", {})
    missing = [t for t in _TOKEN.findall(pattern) if t != counter_tok[2:-1] and not attrs.get(t)]
    if not pattern or missing:
        return None, f"generator pattern '{pattern}' needs identity attribute(s) {missing or ['(no pattern)']}"
    base = _TOKEN.sub(lambda m: m.group(0) if m.group(0) == counter_tok else str(attrs[m.group(1)]), pattern)
    if counter_tok not in base:
        base += counter_tok                         # no counter in the pattern: ISC cannot make it unique
        checks = 1
    else:
        checks = int(fld.get("max_uniqueness_checks", gen["max_uniqueness_checks"]))
    taken_l = {t.lower() for t in taken}
    tried = []
    for n in range(checks):
        value = re.sub(r"[^a-z0-9._-]", "", base.replace(counter_tok, "" if n == 0 else str(n)).lower())
        tried.append(value)
        if value not in taken_l:
            return value, f"generated '{value}'" + (f" ({', '.join(tried[:-1])} already taken)" if n else "")
    return None, f"no unique value after {checks} check(s): {', '.join(tried)} all taken"


def render_create_policy(source: dict, identity: dict, cfg: dict) -> tuple[dict, list[str], list[str]]:
    """(attributes, errors, notes) for the source's create account provisioning policy."""
    attrs, errors, notes = {}, [], []
    policy = source.get("create_policy")
    if not policy:
        return {}, ["source has no create account provisioning policy"], []
    ident = identity.get("attributes", {})
    for fld in policy:
        name, kind, required = fld.get("name", "?"), fld.get("type"), fld.get("required", False)
        value, note = None, ""
        if kind == "identityAttribute":
            value = ident.get(fld.get("attribute"))
            note = f"{name} = identity attribute {fld.get('attribute')}"
        elif kind == "static":
            value = fld.get("value")
            note = f"{name} = static value"
        elif kind == "generator" and fld.get("generator") == "unique_username":
            value, note = generate_unique(fld, identity, source.get("existing_usernames", []), cfg)
            note = f"{name}: {note}"
        elif kind == "generator" and fld.get("generator") == "password":
            value, note = cfg["generators"]["password"]["masked_value"], f"{name} = generated password"
        else:
            errors.append(f"field {name}: unknown field type '{kind}' {fld.get('generator', '')}".strip()
                          + " (deny by default)")
            continue
        if value in (None, ""):
            if required:
                errors.append(f"required field {name} has no value ({note})")
            else:
                notes.append(f"optional field {name} left empty")
            continue
        attrs[name] = value
        notes.append(note)
    return attrs, errors, notes


# --------------------------------------------------------------------------- #
# Plan one change
# --------------------------------------------------------------------------- #
def _validate(change: dict, data: dict, cfg: dict) -> tuple[dict | None, list[str]]:
    ident = data.get("identities", {}).get(change.get("identity") or "")
    kind, via = change.get("type"), change.get("via")
    if ident is None:
        return None, [f"identity '{change.get('identity')}' is not in ISC (deny by default)"]
    if kind not in cfg["change_types"]:
        return None, [f"change type '{kind}' is not a provisioning trigger this engine knows (deny by default)"]
    if kind.startswith("role") or kind.startswith("access_profile"):
        if via not in cfg["via_values"]:
            return None, [f"trigger '{via}' is not a known way to assign access (deny by default)"]
        cat, name = ("roles", change.get("role")) if kind.startswith("role") else \
            ("access_profiles", change.get("access_profile"))
        obj = data.get(cat, {}).get(name or "")
        if obj is None:
            return None, [f"{cat[:-1].replace('_', ' ')} '{name}' does not exist (deny by default)"]
        if kind.endswith(("assigned", "granted")) and via in cfg["requestable_check_via"] and not obj.get("requestable"):
            return None, [f"'{name}' is not requestable, so an access request for it is refused"]
    if kind == "lifecycle_state" and change.get("to") not in cfg["lifecycle_states"]:
        return None, [f"lifecycle state '{change.get('to')}' is not configured (deny by default)"]
    if kind == "attribute_change" and not change.get("attribute"):
        return None, ["attribute change names no attribute (deny by default)"]
    return ident, []


def _accounts(ident: dict, source: str) -> list[dict]:
    return list(ident.get("accounts", {}).get(source, []))


def plan_change(change: dict, data: dict, cfg: dict) -> ChangeResult:
    cid = change.get("id", "?")
    res = ChangeResult(cid, change.get("identity") or "?", change.get("type") or "?")
    sources = data.get("sources", {})
    n = [0]

    def line(source, op, **kw):
        n[0] += 1
        ln = PlanLine(f"{cid}-{n[0]}", cid, source, op, **kw)
        res.lines.append(ln)
        return ln

    ident, errs = _validate(change, data, cfg)
    if errs:
        line("-", "REJECTED", reasons=errs)
        return _finish(res, change, sources, cfg)

    roles, aps = list(ident.get("roles", [])), list(ident.get("access_profiles", []))
    direct = list(ident.get("direct_entitlements", []))
    kind = change["type"]

    if kind in ("role_assigned", "access_profile_granted"):
        name = change.get("role") or change.get("access_profile")
        if kind == "role_assigned" and change.get("via") == "membership_criteria":
            ok, why = criteria_match(ident, data["roles"][name].get("criteria"))
            res.reasons.append(why)
            if not ok:
                line("-", "NO_CHANGE", target=name, reasons=[why + ": role is not assigned, nothing to provision"])
                return _finish(res, change, sources, cfg)
        if name in (roles if kind == "role_assigned" else aps):
            res.reasons.append(f"'{name}' is already assigned")
        new = grants([name], [], [], data) if kind == "role_assigned" else grants([], [name], [], data)
        for src in new:
            _plan_add(src, new[src], ident, change, sources, cfg, line)
    elif kind in ("role_removed", "access_profile_removed"):
        name = change.get("role") or change.get("access_profile")
        if kind == "role_removed":
            roles = [r for r in roles if r != name]
        else:
            aps = [a for a in aps if a != name]
        after = grants(roles, aps, direct, data)
        old = grants([name], [], [], data) if kind == "role_removed" else grants([], [name], [], data)
        for src, ents in old.items():
            if src not in sources:
                line(src, "REJECTED", reasons=[f"source '{src}' is not in the source catalog (deny by default)"])
                continue
            for ent in ents:
                holders = [a for a in _accounts(ident, src) if ent in a.get("entitlements", [])]
                still = after.get(src, {}).get(ent)
                if still:
                    line(src, "NO_CHANGE", target=ent, reasons=[f"kept: still granted by {', '.join(still)}"])
                elif not holders:
                    line(src, "NO_CHANGE", target=ent, reasons=["the identity does not hold it, nothing to remove"])
                else:
                    for a in holders:
                        line(src, "REMOVE_ENTITLEMENT", target=ent, account=a.get("id"),
                             reasons=[f"no other assignment grants {ent}"])
    elif kind == "lifecycle_state":
        state = change["to"]
        targets = cfg["lifecycle_states"][state]["disable_sources"]
        res.reasons.append(f"lifecycle state {ident.get('attributes', {}).get('cloudLifecycleState', '?')} -> {state}")
        names = sorted(ident.get("accounts", {})) if targets == "ALL" else list(targets)
        if not names:
            line("-", "NO_CHANGE", target=state, reasons=[f"lifecycle state '{state}' disables no accounts"])
        for src in names:
            if src not in sources:
                line(src, "REJECTED", reasons=[f"source '{src}' is not in the source catalog (deny by default)"])
                continue
            accts = _accounts(ident, src)
            if not accts:
                line(src, "NO_CHANGE", reasons=["identity has no account on this source"])
            for a in accts:
                if a.get("enabled", True):
                    line(src, "DISABLE", account=a.get("id"), reasons=[f"lifecycle state '{state}' disables accounts "
                                                                       f"on {src}"])
                else:
                    line(src, "NO_CHANGE", account=a.get("id"), reasons=["account is already disabled"])
    elif kind == "attribute_change":
        attr, value = change["attribute"], change.get("value")
        res.reasons.append(f"identity attribute {attr}: "
                           f"'{ident.get('attributes', {}).get(attr)}' -> '{value}'")
        hit = False
        for src in sorted(ident.get("accounts", {})):
            source = sources.get(src)
            if source is None:
                line(src, "REJECTED", reasons=[f"source '{src}' is not in the source catalog (deny by default)"])
                continue
            mapped = source.get("attribute_sync", {}).get(attr)
            if not mapped:
                continue
            hit = True
            ch, _ = channel_for(source, cfg)
            for a in _accounts(ident, src):
                if ch not in cfg["attribute_sync_channels"]:
                    line(src, "NO_CHANGE", target=mapped, account=a.get("id"),
                         reasons=[f"attribute sync needs a direct connector; {src} uses {ch}"])
                elif a.get("attributes", {}).get(mapped) == value:
                    line(src, "NO_CHANGE", target=mapped, account=a.get("id"), reasons=["value already matches"])
                else:
                    line(src, "MODIFY", target=mapped, account=a.get("id"), attributes={mapped: value},
                         reasons=[f"attribute sync: set {mapped} from '{a.get('attributes', {}).get(mapped)}' "
                                  f"to '{value}'"])
        if not hit:
            line("-", "NO_CHANGE", target=attr, reasons=[f"no source syncs identity attribute {attr}"])
    return _finish(res, change, sources, cfg)


def _plan_add(src, ents: dict, ident, change, sources, cfg, line) -> None:
    source = sources.get(src)
    if source is None:
        line(src, "REJECTED", entitlements=sorted(ents),
             reasons=[f"source '{src}' is not in the source catalog (deny by default)"])
        return
    accts = _accounts(ident, src)
    chosen = (change.get("account_selection") or {}).get(src)
    if not accts:
        attrs, errors, notes = render_create_policy(source, ident, cfg)
        if errors:
            line(src, "PLAN_ERROR", entitlements=sorted(ents), reasons=errors + notes)
        else:
            line(src, "CREATE_ACCOUNT", entitlements=sorted(ents), attributes=attrs,
                 reasons=["no account on the source: create it with the entitlements"] + notes)
        return
    if len(accts) > 1:
        picked = [a for a in accts if a.get("id") == chosen]
        if not picked:
            line(src, "MULTIPLE_ACCOUNTS", entitlements=sorted(ents),
                 reasons=[f"{len(accts)} accounts on {src} ({', '.join(a.get('id', '?') for a in accts)}) and "
                          + (f"selected account '{chosen}' is not one of them" if chosen else "no account selected")])
            return
        accts = picked
    acct = accts[0]
    for ent in sorted(ents):
        if ent in acct.get("entitlements", []):
            line(src, "NO_CHANGE", target=ent, account=acct.get("id"), reasons=["account already holds it"])
        else:
            line(src, "ADD_ENTITLEMENT", target=ent, account=acct.get("id"),
                 reasons=[f"add to account {acct.get('id')}" + (" (selected account)" if chosen else "")])


def _finish(res: ChangeResult, change: dict, sources: dict, cfg: dict) -> ChangeResult:
    execution = change.get("execution", {})
    for ln in res.lines:
        if ln.operation in FAILURES:
            ln.status = "FAILED"
            ln.troubleshooting = list(cfg["troubleshooting"][ln.operation])
            continue
        if ln.operation == "NO_CHANGE":
            continue
        ch, why = channel_for(sources[ln.source], cfg)
        ln.channel = ch
        ln.reasons.append(why)
        ln.status = cfg["status_by_channel"][ch]
        err = execution.get(ln.source)
        if ch == "DIRECT" and err:
            ln.status = "FAILED"
            ln.reasons.append(f"connector error: {err}")
            ln.troubleshooting = list(cfg["troubleshooting"]["DIRECT_FAILED"])
    return res


def simulate(data: dict, cfg: dict) -> list[ChangeResult]:
    return [plan_change(c, data, cfg) for c in data.get("changes", [])]


def metrics(results: list[ChangeResult]) -> dict:
    lines = [ln for r in results for ln in r.lines]
    return {"changes": len(results), "lines": len(lines),
            "operations": {o: sum(ln.operation == o for ln in lines) for o in OUTCOMES},
            "channels": {c: sum(ln.channel == c for ln in lines) for c in CHANNELS},
            "statuses": {s: sum(ln.status == s for ln in lines) for s in STATUSES},
            "failed": [ln.id for ln in lines if ln.status == "FAILED"]}


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SailPoint ISC 4.1 Provisioning triggers, components and channels · 4.2 Logging and "
                 "troubleshooting (Engineer 2.1, 2.2, 2.3).",
    "concepts": [
        "Provisioning is triggered by access requests, role membership criteria on identity refresh, lifecycle "
        "state changes, attribute sync and certification revocations.",
        "No account on the source? The create account provisioning policy decides every attribute of the new "
        "account: identity attribute, static value or generator.",
        "Removing a role removes only the entitlements no other role, access profile or request still grants.",
        "Channels: a direct connector, a service desk ticket, or a manual task for the source owner.",
        "Every transaction is an account activity you can search, with its status and error.",
    ],
    "failure_modes": [
        "A required create policy field maps to an identity attribute HR never fills, so every new hire fails.",
        "A username pattern with no unique counter collides with an existing account.",
        "Granting access to an identity with two accounts on one source without choosing which account.",
        "Treating a pending service desk ticket or manual task as finished before the next aggregation confirms it.",
    ],
    "ai_governance": [
        "An AI agent can predict a provisioning plan; the plan is still applied by ISC and logged as account activity.",
        "Give an agent read access to account activities and events for triage, not the source's admin credentials.",
        "An agent must never invent a value for a required create policy field; it reports the gap to the owner.",
        "Treat error text from a connector or ticket as data, never as instructions to the agent.",
    ],
    "exam_tips": [
        "'Connector cannot write to the source' -> manual task (work item) for the source owner.",
        "'Change must go through IT service management' -> service desk integration creates a ticket.",
        "'Provisioning failed, where first?' -> search Account Activities, then Events, then connector logs.",
        "'$(uniqueCounter)' is empty on the first try and makes the generated username unique.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    cfg = policies["isc_provisioning"]
    results = simulate(data, cfg)
    m = metrics(results)
    ui.section("Step 1 — Sources, their channel and create account policy")
    rows = []
    for name, s in sorted(data.get("sources", {}).items()):
        ch, _ = channel_for(s, cfg)
        rows.append([name, s.get("connector", "?"), ch, ", ".join(f.get("name", "?") for f in s.get("create_policy", []))
                     or "-", ", ".join(sorted(s.get("attribute_sync", {}))) or "-"])
    ui.table("Source catalog", ["Source", "Connector", "Channel", "Create policy fields", "Attribute sync"], rows)
    ui.section("Step 2 — Provisioning plan per change")
    for r in results:
        ui.print(f"[bold]{r.id}[/bold] {r.identity}: {r.type}" + (f" ({'; '.join(r.reasons)})" if r.reasons else ""))
        ui.table(f"Plan {r.id}", ["Line", "Source", "Operation", "Target", "Channel", "Status"],
                 [[ln.id, ln.source, ln.operation, ln.target or ", ".join(ln.entitlements) or "-",
                   ln.channel or "-", ln.status] for ln in r.lines])
        for ln in r.lines:
            extra = f" · attributes {ln.attributes}" if ln.operation == "CREATE_ACCOUNT" else ""
            ui.bullet(f"{ln.id} {ln.operation}: " + "; ".join(ln.reasons) + extra,
                      style="red" if ln.status == "FAILED" else "dim" if ln.operation == "NO_CHANGE" else None)
    ui.section("Step 3 — Failed transactions: where to look")
    lines = {ln.id: ln for r in results for ln in r.lines}
    for lid in m["failed"]:
        ln = lines[lid]
        ui.status(f"{lid} {ln.source}", "FAIL", ln.operation if ln.operation in FAILURES else "connector error")
        for i, step in enumerate(ln.troubleshooting, 1):
            ui.bullet(f"{i}. {step}")
    ops = ", ".join(f"{k} {v}" for k, v in m["operations"].items() if v)
    ui.print(f"{m['changes']} changes -> {m['lines']} plan lines: {ops}")
    ui.print("Channels: " + ", ".join(f"{k} {v}" for k, v in m["channels"].items())
             + f" · failed transactions: {len(m['failed'])}")
    ui.insight(INSIGHT)
    return {"lines": {ln.id: ln.operation for ln in lines.values()},
            "channels": {ln.id: ln.channel for ln in lines.values() if ln.channel},
            "statuses": {ln.id: ln.status for ln in lines.values()}, "metrics": m}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["isc_provisioning"]
    results = simulate(data, cfg)
    raw = {c.get("id"): c for c in data.get("changes", [])}
    lines = [ln for r in results for ln in r.lines]
    qs: list = []

    def ctx(ln):
        c = {k: v for k, v in raw.get(ln.change, {}).items() if k not in ("id", "execution")}
        ident = data.get("identities", {}).get(c.get("identity") or "", {})
        accts = {s: [a.get("id") for a in v] for s, v in ident.get("accounts", {}).items()}
        return f"change={c}\naccounts={accts}"

    seen = set()
    for ln in lines:                                   # predict the outcome, one per outcome
        if ln.operation in seen:
            continue
        seen.add(ln.operation)
        where = f" on {ln.source}" if ln.source != "-" else ""
        what = f" for {ln.target}" if ln.target else ""
        qs.append(Question(prompt=f"{ln.change}{where}{what}: what does the provisioning plan do?", context=ctx(ln),
                           choices=choices_with(ln.operation, OUTCOMES, key=ln.id), answer=ln.operation,
                           explanation="; ".join(ln.reasons), objective="4.1"))
    seen = set()
    for ln in lines:                                   # which channel
        if not ln.channel or ln.channel in seen:
            continue
        seen.add(ln.channel)
        qs.append(Question(prompt=f"{ln.change} {ln.operation} on {ln.source}: which channel carries it?",
                           context=f"source={data['sources'][ln.source]}", choices=list(CHANNELS), answer=ln.channel,
                           explanation=next((r for r in ln.reasons if ln.channel != "DIRECT" or "connector" in r),
                                            ln.reasons[-1]), objective="4.1"))
    for ln in lines:                                   # generated username
        gen = [f for f in data["sources"].get(ln.source, {}).get("create_policy", [])
               if f.get("generator") == "unique_username"]
        if ln.operation == "CREATE_ACCOUNT" and gen and gen[0]["name"] in ln.attributes:
            val = ln.attributes[gen[0]["name"]]
            stem = re.sub(r"\d+$", "", val)
            pool = [stem] + [f"{stem}{i}" for i in range(1, 5)]
            qs.append(Question(prompt=f"{ln.change}: which {gen[0]['name']} does the create policy generate on "
                                      f"{ln.source}?",
                               context=f"pattern={gen[0].get('pattern')} taken="
                                       f"{data['sources'][ln.source].get('existing_usernames', [])}",
                               choices=choices_with(val, pool, key=ln.id), answer=val,
                               explanation="; ".join(r for r in ln.reasons if gen[0]["name"] in r), objective="4.1"))
            break
    for ln in lines:                                   # why kept on removal
        if ln.operation == "NO_CHANGE" and any(r.startswith("kept: still granted") for r in ln.reasons):
            qs.append(Question(prompt=f"{ln.change}: why is {ln.target} NOT removed?", context=ctx(ln),
                               choices=["another assignment still grants it", "removals always need a ticket",
                                        "entitlements are never removed automatically",
                                        "the account is disabled"],
                               answer="another assignment still grants it", explanation=ln.reasons[0],
                               objective="4.1"))
            break
    firsts = {k: v[0] for k, v in cfg["troubleshooting"].items()}
    seen = set()
    for ln in lines:                                   # troubleshooting: where to look first
        if ln.status != "FAILED":
            continue
        key = ln.operation if ln.operation in FAILURES else "DIRECT_FAILED"
        if key in seen:
            continue
        seen.add(key)
        where = f" on {ln.source}" if ln.source != "-" else ""
        qs.append(Question(prompt=f"{ln.id}{where} failed. Where do you look first?", context=ctx(ln),
                           choices=sorted(firsts.values()), answer=firsts[key],
                           explanation="; ".join(ln.reasons), objective="4.2"))
    direct_steps = cfg["troubleshooting"]["DIRECT_FAILED"]
    log_step = next(s for s in direct_steps if "logging level" in s)
    qs.append(Question(prompt="Account activity shows only a short connector error. What gives you more detail?",
                       choices=sorted([log_step, "Delete the account and aggregate again",
                                       "Turn off the create account provisioning policy",
                                       "Mark the access request as complete"]),
                       answer=log_step, explanation="connector logging on the virtual appliance shows the full call "
                       "and error; return the level to normal afterwards", objective="4.2"))
    qs.append(Question(prompt="A provisioning plan names a source that is not in the catalog. What happens?",
                       choices=["REJECTED, nothing is sent", "DIRECT provisioning is attempted",
                                "a manual task is created", "the change is applied on the next aggregation"],
                       answer="REJECTED, nothing is sent",
                       explanation="deny by default: unknown sources and actions are never provisioned",
                       objective="4.1"))
    for term in ("create account provisioning policy", "attribute sync", "manual task", "account activity"):
        if term in cfg["concepts"]:
            qs.append(Question(prompt=f"Which term is this? \"{cfg['concepts'][term]}\"",
                               choices=sorted(cfg["concepts"]), answer=term, explanation=cfg["concepts"][term],
                               objective="4.2" if term == "account activity" else "4.1"))
    return qs


# --------------------------------------------------------------------------- #
# Seeded scenario generator
# --------------------------------------------------------------------------- #
_FIRST = ["Maya", "Jonah", "Priya", "Lucas", "Amara", "Theo", "Noor", "Elena", "Kofi", "Sofia", "Ravi", "Hana"]
_LAST = ["Brooks", "Okafor", "Silva", "Novak", "Haddad", "Larsen", "Mendez", "Iyer", "Quinn", "Tanaka", "Weber"]


def base_catalog(domain: str = "example.com") -> dict:
    """Sources, roles and access profiles shared by the sample data and the generator."""
    return {
        "sources": {
            "Active Directory": {
                "connector": "Active Directory", "provisioning": True, "owner": "it-identity@" + domain,
                "create_policy": [
                    {"name": "sAMAccountName", "type": "generator", "generator": "unique_username",
                     "pattern": "$(firstname).$(lastname)$(uniqueCounter)", "max_uniqueness_checks": 5,
                     "required": True},
                    {"name": "mail", "type": "identityAttribute", "attribute": "email", "required": True},
                    {"name": "department", "type": "identityAttribute", "attribute": "department", "required": True},
                    {"name": "description", "type": "static", "value": "Provisioned by Identity Security Cloud"},
                    {"name": "password", "type": "generator", "generator": "password", "required": True},
                ],
                "existing_usernames": [],
                "attribute_sync": {"department": "department", "title": "title"},
            },
            "Finance ERP": {
                "connector": "Web Services", "provisioning": True, "owner": "erp-admins@" + domain,
                "create_policy": [
                    {"name": "userName", "type": "identityAttribute", "attribute": "email", "required": True},
                    {"name": "costCenter", "type": "identityAttribute", "attribute": "costCenter", "required": True},
                    {"name": "userType", "type": "static", "value": "EMPLOYEE", "required": True},
                ],
                "attribute_sync": {"department": "dept"},
            },
            "Badge System": {
                "connector": "Delimited File", "provisioning": False, "service_desk": "ServiceNow Service Desk",
                "owner": "facilities@" + domain,
                "create_policy": [
                    {"name": "badgeHolder", "type": "identityAttribute", "attribute": "displayName", "required": True},
                    {"name": "site", "type": "static", "value": "HQ"},
                ],
                "attribute_sync": {"title": "title"},
            },
            "Legacy Payroll": {
                "connector": "Delimited File", "provisioning": False, "read_only": True,
                "owner": "payroll-lead@" + domain,
                "create_policy": [
                    {"name": "employeeId", "type": "identityAttribute", "attribute": "employeeNumber",
                     "required": True},
                ],
                "attribute_sync": {"title": "jobTitle"},
            },
        },
        "access_profiles": {
            "AP-AD-Finance": {"source": "Active Directory", "entitlements": ["CN=Finance-Share", "CN=VPN-Users"],
                              "requestable": False},
            "AP-AD-Sales": {"source": "Active Directory", "entitlements": ["CN=Sales-Team", "CN=VPN-Users"],
                            "requestable": False},
            "AP-AD-VPN": {"source": "Active Directory", "entitlements": ["CN=VPN-Users"], "requestable": True},
            "AP-ERP-AP-Clerk": {"source": "Finance ERP", "entitlements": ["AP Invoice Entry"], "requestable": False},
            "AP-ERP-Approver": {"source": "Finance ERP", "entitlements": ["Invoice Approver"], "requestable": True},
            "AP-Badge-HQ": {"source": "Badge System", "entitlements": ["HQ Floor 3"], "requestable": True},
            "AP-Payroll-View": {"source": "Legacy Payroll", "entitlements": ["Payroll Read"], "requestable": False},
            "AP-Old-CRM": {"source": "Old CRM", "entitlements": ["CRM User"], "requestable": True},
        },
        "roles": {
            "Finance Analyst": {"criteria": [{"attribute": "department", "equals": "Finance"}], "requestable": False,
                                "access_profiles": ["AP-AD-Finance", "AP-ERP-AP-Clerk", "AP-Payroll-View"]},
            "Sales Rep": {"criteria": [{"attribute": "department", "equals": "Sales"}], "requestable": False,
                          "access_profiles": ["AP-AD-Sales", "AP-Badge-HQ"]},
            "Facilities Access": {"criteria": [], "requestable": True, "access_profiles": ["AP-Badge-HQ"]},
        },
    }


def generate_scenario(rng, policies: dict) -> dict:
    dom = rng.choice(["alderbrook.example", "kestrelpoint.example", "marlowe.example"])
    data = base_catalog(dom)
    names = iter(rng.sample([(f, l) for f in _FIRST for l in _LAST], 10))
    ids: dict = {}

    def person(dept, title="Analyst", **kw):
        f, l = next(names)
        key = f"{f.lower()}.{l.lower()}"
        attrs = {"firstname": f, "lastname": l, "displayName": f"{f} {l}", "email": f"{key}@{dom}",
                 "department": dept, "title": title, "costCenter": f"CC-{rng.randint(100, 999)}",
                 "employeeNumber": f"E{rng.randint(10000, 99999)}", "cloudLifecycleState": "active"}
        attrs.update(kw.pop("attrs", {}))
        ids[key] = {"attributes": attrs, "roles": kw.pop("roles", []), "access_profiles": kw.pop("aps", []),
                    "direct_entitlements": kw.pop("direct", []), "accounts": kw.pop("accounts", {})}
        return key

    def acct(aid, ents=(), enabled=True, **attrs):
        return {"id": aid, "enabled": enabled, "entitlements": list(ents), "attributes": attrs}

    taken = rng.randint(1, 3)
    hire = person("Finance", attrs={"costCenter": None})
    stem = hire
    data["sources"]["Active Directory"]["existing_usernames"] = [stem] + [f"{stem}{i}" for i in range(1, taken)]
    req = person("Finance", accounts={"Finance ERP": [acct(f"erp-{rng.randint(1000, 9999)}", ["AP Invoice Entry"])]})
    mover = person("Sales", roles=["Sales Rep"], aps=["AP-AD-VPN"],
                   accounts={"Active Directory": [acct("mover", ["CN=Sales-Team", "CN=VPN-Users"])],
                             "Badge System": [acct("badge-77", ["HQ Floor 3"])]})
    two = person("IT", accounts={"Active Directory": [acct("two"), acct("adm-two")]})
    ids[two]["accounts"]["Active Directory"][0]["id"] = two
    leaver = person("Finance", roles=["Finance Analyst"],
                    accounts={"Active Directory": [acct("leaver", ["CN=Finance-Share", "CN=VPN-Users"])],
                              "Finance ERP": [acct("erp-2002", ["AP Invoice Entry"], enabled=False)],
                              "Badge System": [acct("badge-12", ["HQ Floor 3"])],
                              "Legacy Payroll": [acct("P-1", ["Payroll Read"])]})
    new_title = rng.choice(["Senior Analyst", "Team Lead", "Principal Analyst"])
    promo = person("Sales", accounts={"Active Directory": [acct("promo", title="Analyst")],
                                      "Legacy Payroll": [acct("P-2", jobTitle="Analyst")]})
    outsider = person("Sales")
    newbie = person("Facilities")
    data["identities"] = ids
    data["changes"] = [
        {"id": "C01", "identity": hire, "type": "role_assigned", "role": "Finance Analyst",
         "via": "membership_criteria"},
        {"id": "C02", "identity": req, "type": "access_profile_granted", "access_profile": "AP-ERP-Approver",
         "via": "access_request", "execution": {"Finance ERP": rng.choice(["HTTP 403 from the ERP API",
                                                                          "service account lacks role admin"])}},
        {"id": "C03", "identity": mover, "type": "role_removed", "role": "Sales Rep", "via": "admin"},
        {"id": "C04", "identity": two, "type": "access_profile_granted", "access_profile": "AP-AD-VPN",
         "via": "access_request"},
        {"id": "C05", "identity": two, "type": "access_profile_granted", "access_profile": "AP-AD-VPN",
         "via": "access_request", "account_selection": {"Active Directory": two}},
        {"id": "C06", "identity": leaver, "type": "lifecycle_state", "to": "inactive"},
        {"id": "C07", "identity": promo, "type": "attribute_change", "attribute": "title", "value": new_title},
        {"id": "C08", "identity": outsider, "type": "role_assigned", "role": "Finance Analyst",
         "via": "membership_criteria"},
        {"id": "C09", "identity": outsider, "type": "role_assigned", "role": "Finance Analyst",
         "via": "access_request"},
        {"id": "C10", "identity": newbie, "type": "role_assigned", "role": "Facilities Access",
         "via": "access_request"},
        {"id": "C11", "identity": newbie, "type": "access_profile_granted", "access_profile": "AP-Old-CRM",
         "via": "access_request"},
    ]
    rng.shuffle(data["changes"])
    for i, c in enumerate(data["changes"], 1):
        c["id"] = f"C{i:02d}"
    data["_description"] = f"Generated provisioning scenario for {dom}."
    return data
