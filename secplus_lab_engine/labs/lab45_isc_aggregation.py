"""
Lab 45 — Source Aggregation, Correlation & Account Deletion Safety
==================================================================

SailPoint ISC objectives (Identity Security Administrator)
-----------------------------------------------------------
* 7.2  Aggregation and correlation: reading accounts and entitlements from a
       source, full versus optimized aggregation, correlating accounts to
       identities, uncorrelated and manually correlated accounts.
* 7.3  Account deletion and source errors: the account delete threshold,
       why an empty file or a failed connection must never delete accounts,
       and where to look when an aggregation fails.
* 7.1  Sources and connector types: VA-based connectors (Active Directory,
       JDBC, LDAP, Web Services), SaaS connectors and flat-file (delimited
       file) sources.

For the SailPoint Identity Security Engineer course the same material maps
to 5.2 (aggregation, correlation and source troubleshooting) and 5.1
(sources and connectors).

How it works
------------
You are the Identity Security Cloud (ISC) administrator reviewing last
night's aggregations. Each source has a connector type, its previous account
list (what ISC already holds) and the result of a new aggregation. The engine
evaluates each source in this order, deny by default:

1. **Connector and connection.** An unknown connector type, a VA-based
   connector whose source cluster is missing or not healthy, or a result that
   is missing or reports an error (connection failure, authentication
   failure, invalid file) gives AGGREGATION_FAILED, with the place to look
   (Virtual Appliances page, Test Connection and source health, the source's
   Import Data history, Search for aggregation events). A failed run never
   changes or deletes an account. An account without an account ID makes the
   whole result invalid.
2. **Aggregation diff.** Every account is compared, by account ID, with the
   previous list: NEW, CHANGED (attributes or entitlements differ),
   UNCHANGED or REMOVED (in ISC but no longer on the source). In ``full``
   mode every account is processed; in ``optimized`` mode (``delta`` is read
   as optimized) unchanged accounts are skipped. An unknown mode runs as full.
3. **Account delete threshold.** If the result is empty while ISC holds
   accounts, or the removed accounts exceed the source's delete threshold
   (a percentage of the previous accounts; a missing or invalid threshold
   uses the policy default, 10 %), the run is ABORTED_DELETE_THRESHOLD:
   nothing is deleted. Exactly at the threshold is allowed. Otherwise the run
   is COMPLETED and removed accounts are deleted.
4. **Correlation** (COMPLETED runs, processed accounts only). A manual
   correlation is kept; an account already correlated keeps its identity;
   otherwise the source's correlation pairs (account attribute -> identity
   attribute) are tried in order, case-insensitive, and an empty value never
   matches. One identity -> CORRELATED, none -> next pair, then
   UNCORRELATED; more than one -> AMBIGUOUS (left uncorrelated and flagged).
5. **Entitlement aggregation** runs on its own whenever the source could be
   read: NEW and REMOVED entitlements against the catalog. An empty
   entitlement result never removes the existing entitlements.

Simplifications (check against the ISC documentation): the real product
does much more (account schema, correlation rules written in code,
authoritative sources creating identities through the identity profile,
connector-specific delta aggregation that only receives changes). Here an
aborted run applies nothing at all; ISC guarantees that no accounts are
deleted. Stopping correlation at the first ambiguous pair, and the empty
entitlement safety rule, are this simulation's choices.

Run it
------
    python main.py --course spadmin lab 45
"""

from __future__ import annotations

from dataclasses import dataclass, field

TITLE = "Lab 45 — Source Aggregation, Correlation & Account Deletion Safety"
OBJECTIVES = ("SailPoint ISC 7.2 Aggregation and correlation · 7.3 Account deletion and source errors · "
              "7.1 Sources and connector types")
COURSES = ("spadmin", "speng")

SOURCE_OUTCOMES = ["COMPLETED", "ABORTED_DELETE_THRESHOLD", "AGGREGATION_FAILED"]
ACCOUNT_STATUSES = ["NEW", "CHANGED", "UNCHANGED", "REMOVED"]
CORRELATION = ["CORRELATED", "UNCORRELATED", "AMBIGUOUS"]
ENTITLEMENT_STATUSES = ["NEW_ENTITLEMENT", "REMOVED_ENTITLEMENT"]


@dataclass
class AccountResult:
    id: str
    status: str                      # NEW / CHANGED / UNCHANGED / REMOVED
    processed: bool = True           # False: skipped by optimized aggregation, or run not applied
    correlation: str | None = None   # CORRELATED / UNCORRELATED / AMBIGUOUS, None when not evaluated
    identity: str | None = None
    matched_on: str | None = None    # "manual", "existing" or "accountAttr->identityAttr"
    reasons: list[str] = field(default_factory=list)


@dataclass
class SourceResult:
    id: str
    name: str
    connector: str
    kind: str | None
    mode: str
    outcome: str
    error: str | None = None
    where: str | None = None
    threshold: float | None = None
    removed_percent: float | None = None
    previous_count: int = 0
    accounts: list[AccountResult] = field(default_factory=list)
    new_entitlements: list[str] = field(default_factory=list)
    removed_entitlements: list[str] = field(default_factory=list)
    entitlement_run: bool = False
    deleted: int = 0
    deletions_prevented: int = 0
    reasons: list[str] = field(default_factory=list)

    def count(self, status: str) -> int:
        return sum(a.status == status for a in self.accounts)

    def correlations(self) -> dict:
        return {a.id: a.correlation for a in self.accounts if a.correlation}


# --------------------------------------------------------------------------- #
# Engine (pure functions)
# --------------------------------------------------------------------------- #
def _norm(v) -> str:
    return str(v).strip().casefold() if v is not None else ""


def connector_kind(source: dict, cfg: dict) -> str | None:
    info = cfg["connector_types"].get(source.get("connector") or "")
    return info["kind"] if info else None


def resolve_mode(source: dict, cfg: dict) -> tuple[str, str | None]:
    raw = _norm((source.get("aggregation") or {}).get("mode") or "full")
    raw = cfg.get("mode_aliases", {}).get(raw, raw)
    if raw in cfg["aggregation_modes"]:
        return raw, None
    return "full", f"unknown aggregation mode '{raw}': run as a full aggregation (every account processed)"


def resolve_threshold(source: dict, cfg: dict) -> tuple[float, str | None]:
    default = float(cfg["default_delete_threshold_percent"])
    t = source.get("delete_threshold_percent")
    if t is None:
        return default, f"no delete threshold set: the policy default of {default:g} % applies"
    if isinstance(t, bool) or not isinstance(t, (int, float)) or not 0 <= t <= 100:
        return default, f"invalid delete threshold {t!r}: the policy default of {default:g} % applies"
    return float(t), None


def connection_check(source: dict, cfg: dict) -> tuple[str | None, str]:
    """Return (error_type, reason) or (None, '') when the source could be read."""
    kind = connector_kind(source, cfg)
    if kind is None:
        return "unknown_error", (f"unknown connector type '{source.get('connector')}': nothing is read or "
                                 "deleted (deny by default)")
    if kind == "va":
        cluster = source.get("cluster") or {}
        status = cluster.get("status")
        if not cluster:
            return "va_unreachable", "VA-based connector with no source cluster: ISC cannot reach the system"
        if status not in cfg["healthy_cluster_statuses"]:
            return "va_unreachable", (f"source cluster '{cluster.get('name', '?')}' is {status or 'in an unknown state'}: "
                                      "the VA cannot run the connector")
    result = source.get("result")
    if not isinstance(result, dict):
        return "unknown_error", "no aggregation result: treated as a failed run, never as 'no accounts'"
    if result.get("status") != "ok":
        err = result.get("error") if result.get("error") in cfg["error_types"] else "unknown_error"
        msg = result.get("message") or cfg["error_types"][err]["label"]
        return err, f"the connector reported {cfg['error_types'][err]['label']}: {msg}"
    accounts = result.get("accounts")
    if not isinstance(accounts, list):
        return ("file_invalid" if kind == "file" else "unknown_error"), "the result has no account list"
    if any(not isinstance(a, dict) or not _norm(a.get("id")) for a in accounts):
        return ("file_invalid" if kind == "file" else "unknown_error"), (
            "at least one account has no account ID: the whole result is rejected")
    return None, ""


def _signature(acct: dict) -> tuple:
    attrs = acct.get("attributes") or {}
    return (tuple(sorted((k, str(v)) for k, v in attrs.items())), tuple(sorted(acct.get("entitlements") or [])))


def diff_accounts(previous: list[dict], current: list[dict]) -> list[AccountResult]:
    prev = {_norm(a.get("id")): a for a in previous if _norm(a.get("id"))}
    out, seen = [], set()
    for a in current:
        key = _norm(a.get("id"))
        if key in seen:
            continue
        seen.add(key)
        if key not in prev:
            out.append(AccountResult(a["id"], "NEW", reasons=["not in ISC before: a new account"]))
        elif _signature(prev[key]) != _signature(a):
            changed = sorted(k for k in set(prev[key].get("attributes") or {}) | set(a.get("attributes") or {})
                             if (prev[key].get("attributes") or {}).get(k) != (a.get("attributes") or {}).get(k))
            if sorted(prev[key].get("entitlements") or []) != sorted(a.get("entitlements") or []):
                changed.append("entitlements")
            out.append(AccountResult(a["id"], "CHANGED", reasons=[f"changed: {', '.join(changed)}"]))
        else:
            out.append(AccountResult(a["id"], "UNCHANGED", reasons=["same attributes and entitlements as before"]))
    for key, a in prev.items():
        if key not in seen:
            out.append(AccountResult(a.get("id"), "REMOVED", processed=False,
                                     reasons=["in ISC but no longer on the source"]))
    return out


def correlate(account: dict, source: dict, identities: list[dict], previous: dict | None = None) -> AccountResult:
    """Correlate one aggregated account. Returns an AccountResult with only the correlation fields filled."""
    r = AccountResult(account.get("id"), "")
    ids = {i.get("id"): i for i in identities}
    manual = (source.get("manual_correlations") or {}).get(account.get("id"))
    if manual is None and previous and previous.get("manually_correlated"):
        manual = previous.get("identity")
    if manual is not None:
        if manual in ids:
            r.correlation, r.identity, r.matched_on = "CORRELATED", manual, "manual"
            r.reasons.append(f"manually correlated to {manual}: kept, correlation pairs are not re-run")
        else:
            r.correlation = "UNCORRELATED"
            r.reasons.append(f"manual correlation points to unknown identity {manual}: left uncorrelated")
        return r
    if previous and previous.get("identity") in ids:
        r.correlation, r.identity, r.matched_on = "CORRELATED", previous["identity"], "existing"
        r.reasons.append(f"already correlated to {previous['identity']}: the link is kept")
        return r
    pairs = source.get("correlation") or []
    if not pairs:
        r.correlation = "UNCORRELATED"
        r.reasons.append("no correlation configured on the source: the account stays uncorrelated")
        return r
    attrs = account.get("attributes") or {}
    for p in pairs:
        aa, ia = p.get("account_attribute"), p.get("identity_attribute")
        label = f"{aa}->{ia}"
        value = _norm(attrs.get(aa))
        if not value:
            r.reasons.append(f"{label}: account has no {aa}, pair skipped (an empty value never matches)")
            continue
        hits = [i["id"] for i in identities if _norm((i.get("attributes") or {}).get(ia)) == value]
        if len(hits) == 1:
            r.correlation, r.identity, r.matched_on = "CORRELATED", hits[0], label
            r.reasons.append(f"{label}: '{attrs.get(aa)}' matches exactly one identity, {hits[0]}")
            return r
        if len(hits) > 1:
            r.correlation, r.matched_on = "AMBIGUOUS", label
            r.reasons.append(f"{label}: '{attrs.get(aa)}' matches {len(hits)} identities ({', '.join(hits)}): "
                             "left uncorrelated and flagged for review")
            return r
        r.reasons.append(f"{label}: no identity has {ia} '{attrs.get(aa)}'")
    r.correlation = "UNCORRELATED"
    r.reasons.append("no correlation pair matched an identity" +
                     (": on an authoritative source the identity profile would create a new identity"
                      if source.get("authoritative") else ""))
    return r


def entitlement_diff(source: dict) -> tuple[bool, list[str], list[str], list[str]]:
    res = source.get("entitlement_result")
    prev = list(source.get("previous_entitlements") or [])
    if not isinstance(res, dict) or res.get("status") != "ok" or not isinstance(res.get("entitlements"), list):
        return False, [], [], ["no entitlement aggregation result: the catalog is left as it is"]
    cur = res["entitlements"]
    if not cur and prev:
        return True, [], [], [f"entitlement aggregation returned nothing while the catalog holds {len(prev)}: "
                              "treated as suspect, nothing removed"]
    new = sorted(set(cur) - set(prev))
    gone = sorted(set(prev) - set(cur))
    reasons = []
    if new:
        reasons.append(f"new entitlements discovered: {', '.join(new)} (not in any access profile or role yet)")
    if gone:
        reasons.append(f"entitlements no longer on the source: {', '.join(gone)}")
    if not new and not gone:
        reasons.append("entitlement catalog unchanged")
    return True, new, gone, reasons


def aggregate(source: dict, identities: list[dict], cfg: dict) -> SourceResult:
    kind = connector_kind(source, cfg)
    mode, mode_note = resolve_mode(source, cfg)
    previous = [a for a in (source.get("previous_accounts") or []) if isinstance(a, dict)]
    sr = SourceResult(source.get("id", "?"), source.get("name", source.get("id", "?")), source.get("connector") or "?",
                      kind, mode, "AGGREGATION_FAILED", previous_count=len(previous))
    # Rule 1: connector and connection.
    err, why = connection_check(source, cfg)
    if err:
        sr.error, sr.where = err, cfg["error_types"][err]["where"]
        sr.reasons += [why, f"no account was added, changed or deleted; look at: {sr.where}"]
        return sr
    if mode_note:
        sr.reasons.append(mode_note)
    current = source["result"]["accounts"]
    # Rule 2: diff.
    sr.accounts = diff_accounts(previous, current)
    removed = sr.count("REMOVED")
    # Rule 3: delete threshold.
    threshold, t_note = resolve_threshold(source, cfg)
    sr.threshold = threshold
    if t_note:
        sr.reasons.append(t_note)
    pct = round(100.0 * removed / len(previous), 1) if previous else 0.0
    sr.removed_percent = pct
    ok_ent, new_e, gone_e, e_reasons = entitlement_diff(source)
    if not current and previous:
        sr.outcome, sr.deletions_prevented = "ABORTED_DELETE_THRESHOLD", removed
        sr.reasons.append(f"the result is empty while ISC holds {len(previous)} accounts: treated as a broken "
                          "file or export, never as 'everyone left'; aggregation cancelled, nothing deleted")
    elif pct > threshold:
        sr.outcome, sr.deletions_prevented = "ABORTED_DELETE_THRESHOLD", removed
        sr.reasons.append(f"{removed} of {len(previous)} accounts would be removed ({pct:g} %), above the delete "
                          f"threshold of {threshold:g} %: aggregation cancelled, nothing deleted")
    else:
        sr.outcome, sr.deleted = "COMPLETED", removed
        sr.reasons.append(f"{removed} of {len(previous)} accounts removed ({pct:g} %), within the delete threshold "
                          f"of {threshold:g} %" + (" (exactly at it is allowed)" if previous and pct == threshold
                                                   and removed else ""))
    if sr.outcome != "COMPLETED":
        for a in sr.accounts:
            a.processed = False
        sr.reasons.append("in this model nothing from the cancelled run is applied; fix the source data, then "
                          "re-run (or raise the threshold only after confirming the removals are real)")
    else:
        # Rule 4: correlation.
        prev_by = {_norm(a.get("id")): a for a in previous}
        cur_by = {_norm(a.get("id")): a for a in current}
        for a in sr.accounts:
            if a.status == "REMOVED":
                a.reasons.append("deleted from ISC")
                continue
            if mode == "optimized" and a.status == "UNCHANGED":
                a.processed = False
                p = prev_by.get(_norm(a.id), {})
                a.identity = (source.get("manual_correlations") or {}).get(a.id) or p.get("identity")
                a.reasons.append("skipped by optimized aggregation: previous correlation left as it was")
                continue
            c = correlate(cur_by[_norm(a.id)], source, identities, prev_by.get(_norm(a.id)))
            a.correlation, a.identity, a.matched_on = c.correlation, c.identity, c.matched_on
            a.reasons += c.reasons
    # Rule 5: entitlement aggregation (separate run; needs only a readable source).
    sr.entitlement_run, sr.new_entitlements, sr.removed_entitlements = ok_ent, new_e, gone_e
    sr.reasons += e_reasons
    return sr


def analyse(policies: dict, data: dict) -> list[SourceResult]:
    cfg = policies["isc_aggregation"]
    identities = data.get("identities") or []
    return [aggregate(s, identities, cfg) for s in data.get("sources") or []]


def metrics_of(results: list[SourceResult]) -> dict:
    done = [r for r in results if r.outcome == "COMPLETED"]
    every = [a for r in done for a in r.accounts]
    return {
        "sources": len(results),
        "completed": len(done),
        "aborted": sum(r.outcome == "ABORTED_DELETE_THRESHOLD" for r in results),
        "failed": sum(r.outcome == "AGGREGATION_FAILED" for r in results),
        "new": sum(a.status == "NEW" for a in every),
        "changed": sum(a.status == "CHANGED" for a in every),
        "unchanged": sum(a.status == "UNCHANGED" for a in every),
        "skipped": sum(a.status == "UNCHANGED" and not a.processed for a in every),
        "deleted": sum(r.deleted for r in results),
        "deletions_prevented": sum(r.deletions_prevented for r in results),
        "correlated": sum(a.correlation == "CORRELATED" for a in every),
        "uncorrelated": sum(a.correlation == "UNCORRELATED" for a in every),
        "ambiguous": sum(a.correlation == "AMBIGUOUS" for a in every),
        "new_entitlements": sum(len(r.new_entitlements) for r in results),
        "removed_entitlements": sum(len(r.removed_entitlements) for r in results),
    }


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SailPoint ISC 7.2 Aggregation and correlation · 7.3 Account deletion and source errors · "
                 "7.1 Sources and connector types (Engineer: 5.2 and 5.1).",
    "concepts": [
        "Aggregation reads accounts (and, separately, entitlements) from a source; correlation links each account "
        "to the identity that owns it.",
        "Correlation pairs an account attribute with an identity attribute (employeeNumber to employeeId, then "
        "email to email) and needs exactly one match.",
        "An account matching no identity, or several, stays uncorrelated; fix it with manual correlation, which "
        "later aggregations keep.",
        "The account delete threshold cancels an aggregation that would remove too large a share of accounts, so a "
        "truncated export cannot wipe a source.",
        "VA-based connectors (Active Directory, JDBC, LDAP) need a healthy source cluster; SaaS connectors run in "
        "SailPoint's cloud; a delimited file source has no connection at all.",
    ],
    "failure_modes": [
        "Uploading an empty or half-written CSV and letting it delete every account on the source.",
        "Raising the delete threshold to make an aborted aggregation 'go through' without checking the removals "
        "are real leavers.",
        "Correlating on a non-unique attribute (a shared or reused email) and linking an account to the wrong person.",
        "Changing the correlation configuration and expecting optimized aggregation to re-correlate unchanged "
        "accounts.",
        "Troubleshooting the application when the real problem is a disconnected virtual appliance.",
    ],
    "ai_governance": [
        "An AI agent can read aggregation history, source health and uncorrelated-account reports with a read-only "
        "API client.",
        "Manual correlation, raising a delete threshold and deleting accounts stay human-approved actions.",
        "Treat account attribute values and connector error messages as untrusted data, never as instructions.",
        "Every correlation the agent proposes must cite the attribute pair and the single identity it matched.",
    ],
    "exam_tips": [
        "Account delete threshold: a percentage on the source; above it the aggregation is cancelled and no "
        "accounts are deleted (check the default in the current ISC documentation).",
        "After changing correlation or the account schema, run an aggregation with optimization disabled so "
        "every account is processed.",
        "Failed aggregation: check the source's Import Data history, its health and Test Connection, the "
        "Virtual Appliances page for VA-based sources, and Search for the aggregation events.",
        "Uncorrelated accounts on an authoritative source become new identities through the identity profile.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    cfg = policies["isc_aggregation"]
    results = analyse(policies, data)
    tenant = (data.get("tenant") or {}).get("name", "the tenant")
    ui.section(f"Step 1 — Sources in {tenant}: connector types and connection")
    ui.table("Sources", ["ID", "Source", "Connector", "Kind", "Mode", "Delete threshold", "Outcome"],
             [[r.id, r.name, cfg["connector_types"].get(r.connector, {}).get("label", r.connector),
               r.kind or "unknown", r.mode, f"{r.threshold:g} %" if r.threshold is not None else "-", r.outcome]
              for r in results])
    for r in results:
        if r.outcome == "AGGREGATION_FAILED":
            ui.bullet(f"{r.id} → AGGREGATION_FAILED ({r.error}): " + "; ".join(r.reasons), style="red")
    ui.section("Step 2 — Aggregation diff and the account delete threshold")
    ui.table("Account changes", ["ID", "Before", "New", "Changed", "Unchanged", "Removed", "Removed %", "Result"],
             [[r.id, r.previous_count, r.count("NEW"), r.count("CHANGED"), r.count("UNCHANGED"), r.count("REMOVED"),
               f"{r.removed_percent:g} %" if r.removed_percent is not None else "-", r.outcome]
              for r in results if r.outcome != "AGGREGATION_FAILED"])
    for r in results:
        if r.outcome != "AGGREGATION_FAILED":
            ui.bullet(f"{r.id} → {r.outcome}: " + "; ".join(x for x in r.reasons if "entitlement" not in x),
                      style="yellow" if r.outcome == "ABORTED_DELETE_THRESHOLD" else None)
    ui.section("Step 3 — Correlation")
    rows = []
    for r in results:
        if r.outcome != "COMPLETED":
            continue
        for a in r.accounts:
            rows.append([r.id, a.id, a.status, "yes" if a.processed else "no", a.correlation or "-",
                         a.identity or "-", a.matched_on or "-"])
    ui.table("Accounts", ["Source", "Account", "Status", "Processed", "Correlation", "Identity", "Matched on"], rows)
    for r in results:
        for a in r.accounts:
            if r.outcome == "COMPLETED" and a.correlation in ("UNCORRELATED", "AMBIGUOUS"):
                ui.bullet(f"{r.id}/{a.id} → {a.correlation}: " + "; ".join(a.reasons), style="yellow")
    ui.section("Step 4 — Entitlement aggregation")
    ui.table("Entitlements", ["ID", "Ran", "New", "Removed"],
             [[r.id, "yes" if r.entitlement_run else "no", ", ".join(r.new_entitlements) or "-",
               ", ".join(r.removed_entitlements) or "-"] for r in results])
    m = metrics_of(results)
    ui.print(f"{m['sources']} sources: {m['completed']} completed, {m['aborted']} cancelled by the delete threshold, "
             f"{m['failed']} failed · {m['new']} new, {m['changed']} changed, {m['unchanged']} unchanged "
             f"({m['skipped']} skipped by optimized aggregation), {m['deleted']} deleted, "
             f"{m['deletions_prevented']} deletions prevented · correlation: {m['correlated']} correlated, "
             f"{m['uncorrelated']} uncorrelated, {m['ambiguous']} ambiguous · entitlements: "
             f"{m['new_entitlements']} new, {m['removed_entitlements']} removed")
    ui.insight(INSIGHT)
    return {"sources": {r.id: r.outcome for r in results},
            "errors": {r.id: r.error for r in results if r.error},
            "accounts": {r.id: {a.id: a.status for a in r.accounts} for r in results},
            "correlation": {r.id: r.correlations() for r in results if r.outcome == "COMPLETED"},
            "entitlements": {r.id: {"new": r.new_entitlements, "removed": r.removed_entitlements}
                             for r in results if r.entitlement_run},
            "metrics": m}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def _source_context(src: dict, cfg: dict) -> str:
    conn = cfg["connector_types"].get(src.get("connector") or "", {}).get("label", src.get("connector"))
    lines = [f"connector: {conn}"]
    if src.get("cluster"):
        lines.append(f"source cluster: {src['cluster'].get('name')} ({src['cluster'].get('status')})")
    res = src.get("result") or {}
    if res.get("status") == "ok":
        lines.append(f"previous accounts: {len(src.get('previous_accounts') or [])}, accounts returned: "
                     f"{len(res.get('accounts') or [])}")
    else:
        lines.append(f"connector message: {res.get('message', 'none')}")
    t = src.get("delete_threshold_percent")
    lines.append(f"delete threshold: {f'{t} %' if t is not None else 'not set'}")
    return "\n".join(lines)


def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["isc_aggregation"]
    results = analyse(policies, data)
    raw = {s.get("id"): s for s in data.get("sources") or []}
    wheres = sorted({v["where"] for v in cfg["error_types"].values()})
    qs: list = []
    for r in results:
        src = raw.get(r.id, {})
        ctx = _source_context(src, cfg)
        obj = "7.2" if r.outcome == "COMPLETED" else "7.3"
        qs.append(Question(prompt=f"{r.id} ({r.name}): what is the result of this aggregation?", context=ctx,
                           choices=SOURCE_OUTCOMES, answer=r.outcome, explanation="; ".join(r.reasons),
                           objective=obj))
        if r.kind:
            kinds = {"va": "VA-based connector", "saas": "SaaS connector", "file": "flat-file source"}
            qs.append(Question(prompt=f"{r.id}: what kind of source is {r.name}?",
                               context=f"connector: {cfg['connector_types'][r.connector]['label']}",
                               choices=sorted(kinds.values()), answer=kinds[r.kind],
                               explanation=cfg["connector_kinds"][r.kind], objective="7.1"))
        if r.outcome == "AGGREGATION_FAILED" and r.where:
            qs.append(Question(prompt=f"{r.id}: the aggregation failed. Where do you look first?", context=ctx,
                               choices=choices_with(r.where, wheres, key=r.id), answer=r.where,
                               explanation="; ".join(r.reasons), objective="7.3"))
        if r.outcome == "ABORTED_DELETE_THRESHOLD":
            ans = "no accounts are deleted" if r.deleted == 0 else "all of the missing accounts"
            qs.append(Question(prompt=f"{r.id}: the run was cancelled. How many accounts does ISC delete?",
                               context=ctx,
                               choices=["no accounts are deleted", "only the accounts above the threshold",
                                        "all of the missing accounts", "the missing accounts, after a 24-hour delay"],
                               answer=ans, explanation="; ".join(r.reasons), objective="7.3"))
        if r.outcome == "COMPLETED":
            for a in r.accounts:
                if a.correlation and a.matched_on not in ("existing",):
                    acct = next((x for x in src["result"]["accounts"] if _norm(x.get("id")) == _norm(a.id)), {})
                    pairs = " then ".join(f"{p.get('account_attribute')}->{p.get('identity_attribute')}"
                                          for p in src.get("correlation") or []) or "none"
                    qs.append(Question(prompt=f"{r.id}/{a.id}: what is the correlation result?",
                                       context=f"account attributes: {acct.get('attributes') or {}}\n"
                                               f"correlation pairs: {pairs}"
                                               + ("\nmanual correlation on record" if a.matched_on == "manual" else ""),
                                       choices=CORRELATION, answer=a.correlation,
                                       explanation="; ".join(a.reasons), objective="7.2"))
            for a in r.accounts:
                if a.status in ("NEW", "CHANGED", "REMOVED"):
                    qs.append(Question(prompt=f"{r.id}/{a.id}: how does the aggregation classify this account?",
                                       context=f"mode: {r.mode}; " + "; ".join(a.reasons[:1]),
                                       choices=ACCOUNT_STATUSES, answer=a.status,
                                       explanation="; ".join(a.reasons), objective="7.2"))
                    break
        if r.new_entitlements:
            e = r.new_entitlements[0]
            pool = list((src.get("entitlement_result") or {}).get("entitlements") or []) + \
                list(src.get("previous_entitlements") or [])
            qs.append(Question(prompt=f"{r.id}: which entitlement did entitlement aggregation newly discover?",
                               choices=choices_with(e, pool, exclude=r.new_entitlements[1:], key=r.id), answer=e,
                               explanation="; ".join(x for x in r.reasons if "entitlement" in x), objective="7.2"))
    # Rule and concept questions, answers computed by the engine.
    probe_prev = [{"id": f"u{i}", "attributes": {}} for i in range(10)]
    edge = aggregate({"id": "P", "connector": "saas", "delete_threshold_percent": 10, "previous_accounts": probe_prev,
                      "result": {"status": "ok", "accounts": probe_prev[1:]}}, [], cfg)
    qs.append(Question(prompt="A source with a 10 % delete threshold holds 10 accounts; the new aggregation is "
                              "missing exactly 1 of them. What happens?",
                       choices=["the aggregation completes and the account is deleted",
                                "the aggregation is cancelled and nothing is deleted",
                                "the account is disabled but kept",
                                "the aggregation fails with a connection error"],
                       answer="the aggregation completes and the account is deleted" if edge.outcome == "COMPLETED"
                       else "the aggregation is cancelled and nothing is deleted",
                       explanation="; ".join(edge.reasons), objective="7.3"))
    empty = aggregate({"id": "P", "connector": "delimited_file", "delete_threshold_percent": 100,
                       "previous_accounts": probe_prev, "result": {"status": "ok", "accounts": []}}, [], cfg)
    qs.append(Question(prompt="A delimited file source has its threshold set to 100 % and someone uploads a CSV with "
                              "a header row and no accounts. What happens?",
                       choices=["the aggregation is cancelled and nothing is deleted",
                                "every account is deleted because the threshold allows it",
                                "the file is merged with the previous one",
                                "only disabled accounts are deleted"],
                       answer="the aggregation is cancelled and nothing is deleted"
                       if empty.outcome == "ABORTED_DELETE_THRESHOLD" else
                       "every account is deleted because the threshold allows it",
                       explanation="; ".join(empty.reasons), objective="7.3"))
    qs.append(Question(prompt="You changed a source's correlation configuration. Which aggregation re-correlates the "
                              "accounts that did not change on the source?",
                       choices=["a full aggregation with optimization disabled", "an optimized aggregation",
                                "an entitlement aggregation", "a Test Connection"],
                       answer="a full aggregation with optimization disabled",
                       explanation=cfg["concepts"]["optimized aggregation"], objective="7.2"))
    for term in ("correlation", "uncorrelated account", "account delete threshold", "virtual appliance",
                 "entitlement aggregation"):
        if term in cfg["concepts"]:
            qs.append(Question(prompt=f"Which term is this? \"{cfg['concepts'][term]}\"",
                               choices=choices_with(term, cfg["concepts"], key=term), answer=term,
                               explanation=cfg["concepts"][term],
                               objective={"account delete threshold": "7.3", "virtual appliance": "7.1"}.get(term,
                                                                                                             "7.2")))
    return qs


# --------------------------------------------------------------------------- #
# Scenario generator
# --------------------------------------------------------------------------- #
FIRST = ["Ava", "Ben", "Chloe", "Dev", "Elif", "Finn", "Grace", "Hamid", "Ines", "Jon", "Kai", "Lena", "Milo",
         "Nadia", "Omar", "Pia"]
LAST = ["Lindqvist", "Okoro", "Marsh", "Patel", "Kaya", "Byrne", "Ito", "Rahimi", "Duarte", "Moreau", "Nakamura",
        "Vogel"]


def generate_scenario(rng, policies: dict) -> dict:
    domain = rng.choice(["fernwood", "harbourline", "quillstone"]) + ".example"
    names = rng.sample(FIRST, 10)
    people = [(n, rng.choice(LAST)) for n in names]
    identities = []
    for i, (f, l) in enumerate(people):
        identities.append({"id": f"ID-{2001 + i}", "name": f"{f} {l}",
                           "attributes": {"employeeId": f"E{2001 + i}", "email": f"{f.lower()}.{l.lower()}@{domain}"}})
    # A rehire duplicate: two identities with the same email (drives AMBIGUOUS).
    dup = identities[-1]
    identities.append({"id": f"ID-{2001 + len(people)}", "name": dup["name"] + " (rehire)",
                       "attributes": {"employeeId": f"E{2001 + len(people)}", "email": dup["attributes"]["email"]}})

    def acct(idx, ident=None, **extra):
        f, l = people[idx]
        a = {"id": f"{f[0].lower()}{l.lower()}", "attributes": {"employeeID": f"E{2001 + idx}",
                                                                 "mail": f"{f.lower()}.{l.lower()}@{domain}",
                                                                 "department": rng.choice(["Sales", "IT", "Ops"])},
             "entitlements": [rng.choice(["Staff", "VPN Users"])]}
        a["attributes"].update(extra)
        if ident:
            a["identity"] = ident
        return a

    pairs_ad = [{"account_attribute": "employeeID", "identity_attribute": "employeeId"},
                {"account_attribute": "mail", "identity_attribute": "email"}]
    n_prev = rng.randint(8, 9)
    prev = [acct(i, identities[i]["id"]) for i in range(n_prev)]
    cur = [dict(a, attributes=dict(a["attributes"])) for a in prev[1:]]   # one removed
    for a in cur:
        a.pop("identity", None)
    cur[0]["attributes"]["department"] = "Finance-" + str(rng.randint(1, 9))     # changed
    new_ok = acct(n_prev)
    new_ok.pop("identity", None)
    new_mail = acct(n_prev + 1 if n_prev + 1 < len(people) - 1 else n_prev)
    new_mail["id"] = new_mail["id"] + "2"
    new_mail["attributes"]["employeeID"] = ""                                      # falls to the email pair
    orphan = {"id": f"test-{rng.randint(10, 99)}", "attributes": {"description": "test account"}, "entitlements": []}
    cur += [new_ok, new_mail, orphan]
    threshold_ad = rng.choice([15, 20, 25])
    sources = [{
        "id": "S1", "name": "Corporate Active Directory", "connector": "active_directory",
        "cluster": {"name": "Main cluster", "status": "HEALTHY"}, "aggregation": {"mode": "full"},
        "delete_threshold_percent": threshold_ad, "correlation": pairs_ad, "previous_accounts": prev,
        "result": {"status": "ok", "accounts": cur},
        "previous_entitlements": ["Staff", "VPN Users", "Old Print Ops"],
        "entitlement_result": {"status": "ok", "entitlements": ["Staff", "VPN Users", "Payroll Readers"]}}]
    # SaaS source, optimized: unchanged skipped, ambiguous, manual.
    saas_prev = [{"id": identities[i]["attributes"]["email"], "identity": identities[i]["id"],
                  "attributes": {"email": identities[i]["attributes"]["email"], "role": "Member"}} for i in range(3)]
    amb = {"id": dup["attributes"]["email"], "attributes": {"email": dup["attributes"]["email"], "role": "Member"}}
    bot = {"id": f"bot@{domain}", "attributes": {"email": f"bot@{domain}", "role": "Bot"}}
    saas_cur = [dict(a) for a in saas_prev] + [dict(amb, attributes=dict(amb["attributes"], role="Admin")), bot,
                                               {"id": "guest@partner.example",
                                                "attributes": {"email": "guest@partner.example", "role": "Guest"}}]
    for a in saas_cur:
        a.pop("identity", None)
    sources.append({"id": "S2", "name": rng.choice(["Team Chat", "Video Meetings"]), "connector": "saas",
                    "aggregation": {"mode": rng.choice(["optimized", "delta"])}, "delete_threshold_percent": 10,
                    "correlation": [{"account_attribute": "email", "identity_attribute": "email"}],
                    "manual_correlations": {bot["id"]: identities[1]["id"]},
                    "previous_accounts": saas_prev + [amb, dict(bot)],
                    "result": {"status": "ok", "accounts": saas_cur},
                    "previous_entitlements": ["Member", "Admin"],
                    "entitlement_result": {"status": "ok", "entitlements": ["Member", "Admin", "Owner"]}})
    # Failures.
    sources.append({"id": "S3", "name": "Finance database", "connector": "jdbc",
                    "cluster": {"name": "Branch cluster", "status": rng.choice(["UNREACHABLE", "DISCONNECTED"])},
                    "delete_threshold_percent": 10, "previous_accounts": prev[:3],
                    "result": {"status": "error", "error": "va_unreachable", "message": "no VA in the cluster responded"}})
    sources.append({"id": "S4", "name": "Expense app", "connector": "saas", "previous_accounts": saas_prev,
                    "result": {"status": "error", "error": rng.choice(["auth_failure", "connection_failure"]),
                               "message": rng.choice(["401 Unauthorized", "connection timed out after 60 seconds"])}})
    # Empty file and a threshold breach.
    sources.append({"id": "S5", "name": "Badge system", "connector": "delimited_file",
                    "delete_threshold_percent": rng.choice([50, 100]), "previous_accounts": prev[:5],
                    "result": {"status": "ok", "accounts": []}})
    keep = rng.randint(3, 5)
    sources.append({"id": "S6", "name": "Engineering LDAP", "connector": "ldap",
                    "cluster": {"name": "Main cluster", "status": "HEALTHY"}, "delete_threshold_percent": 20,
                    "correlation": pairs_ad, "previous_accounts": prev[:8],
                    "result": {"status": "ok", "accounts": [dict(a) for a in prev[:keep]]}})
    sources.append({"id": "S7", "name": "Training records", "connector": "delimited_file",
                    "result": {"status": "ok", "accounts": [{"id": "", "attributes": {}}]},
                    "previous_accounts": prev[:2]})
    return {"_description": f"Generated ISC aggregation review for {domain}", "tenant": {"name": domain},
            "identities": identities, "sources": sources}
