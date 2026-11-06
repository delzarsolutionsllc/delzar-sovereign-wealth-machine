"""
Lab 48 — Certification Campaigns & Separation-of-Duties Policies
================================================================

SailPoint ISC objectives
------------------------
* 6.2  Certification types and lifecycle (Identity Security Administrator):
       manager, source owner, search and role composition campaigns; staging,
       activation, decisions, reassignment, sign-off, completion and
       remediation; data issues that break a campaign.
* 6.3  Policies in Identity Security Cloud (Identity Security Administrator):
       Separation of Duties (SoD) policies, violations and the preventive
       check on access requests.
* Engineer mapping: the same content covers Identity Security Engineer
  8.1 (Certification preparation, types and data issues) and 8.2 (Access
  request approvers and separation of duties).

Lab 26 teaches generic reconciliation and attestation. This lab is specific
to SailPoint Identity Security Cloud (ISC). SailPoint's 2026 documentation
also calls the product "SailPoint Human Fabric (previously known as Identity
Security Cloud)"; the exam guide and this course use ISC.

How it works
------------
1. **Campaign planner.** Each business requirement is matched against the
   policy's ordered keyword rules (first match wins; an explicit
   ``subject`` field overrides the text) and turned into a campaign type:
   * ROLE_COMPOSITION (what a role contains; reviewer: role owner),
   * SEARCH with search type UNCORRELATED_ACCOUNTS (reviewer: source owner),
     ACCESS_ITEMS (everyone who holds an item) or IDENTITIES (a query that
     returns a set of identities, or exactly one identity to certify ALL of
     its access),
   * SOURCE_OWNER (one or more critical sources; reviewer: source owner),
   * MANAGER (each manager reviews all access of their direct reports).
   A manager review that must include identities WITHOUT a manager becomes a
   SEARCH (IDENTITIES) campaign with Manager as reviewer, because manager
   campaigns exclude those identities and a search campaign sends them to
   the campaign owner. A search campaign with no query or no chosen
   reviewer, a source owner campaign with no source, or text no rule
   matches is NEEDS_CLARIFICATION: no campaign is launched on a guess.
2. **Campaign lifecycle** (STAGED -> ACTIVE -> COMPLETED; any other action
   is refused). For every review item, in order:
   a. no correlated identity (uncorrelated account) or unknown identity ->
      NOT_CERTIFIABLE: it cannot appear in an identity-based campaign;
      correlate it or run an uncorrelated-accounts search campaign.
   b. reviewer by campaign type: MANAGER = the identity's manager (none ->
      REVIEWER_MISSING, the identity is excluded; manager not found ->
      REVIEWER_MISSING, reassign it); SOURCE_OWNER = the source owner;
      SEARCH with Manager reviewer = the manager, else the campaign owner.
   c. self-certification is prevented: the item goes to the identity's
      manager, else the campaign owner, else an org admin.
   d. a manual reassignment is refused if the new reviewer is the identity
      under review, is unknown, or (this course's setting) has no reason.
   e. decision: a revoke without the required comment is not recorded;
      revoking a role assigned by membership criteria can only be
      ACKNOWLEDGED (change the criteria or the identity data instead);
      approve -> APPROVED, revoke -> REVOKED, nothing -> UNDECIDED.
   f. a reviewer can sign off only when every item is decided.
   g. completion: all reviewers signed off -> COMPLETED; else past the
      deadline an admin completes it and undecided items get the
      campaign's undecided action (missing -> REVOKE here, deny by default;
      SailPoint itself recommends maintaining access); else it stays ACTIVE.
   h. remediation for revoked items: PROVISIONING_TASK for a
      direct-connected source, MANUAL_WORK_ITEM for a flat-file or unknown
      source; then verify that the access is really gone.
3. **SoD policies.** A policy has List A and List B of access items
   (entitlements, access profiles, roles). Access profiles and roles are
   decomposed to entitlements; a human identity that holds any entitlement
   from both lists is in VIOLATION (with the conflicting pair). Disabled
   policies are skipped. Access the engine cannot decompose (unknown item)
   gives CANNOT_EVALUATE, never OK. A pending access request is checked
   against current access plus everything in the request: WOULD_VIOLATE
   (BLOCKED when the policy blocks submission, or has no setting; else
   ROUTED_TO_APPROVERS with the violation shown), OK (normal approval), or
   CANNOT_EVALUATE (request HELD).

Simplifications: real campaigns also have campaign filters, recommendations,
machine-account campaigns, governance-group reviewers and email settings.
The completion doc says unsigned decisions are preserved when an admin
completes a campaign; this engine follows that. Older ISC preventive SoD
only compared requested access with PROVISIONED access (two conflicting
items in one request were missed); the policy flag
``include_in_flight_access`` models the newer pending-access check.

Run it
------
    python main.py --course spadmin lab 48
    python main.py --course speng lab 48
"""

from __future__ import annotations

from dataclasses import dataclass, field

TITLE = "Lab 48 — Certification Campaigns & Separation-of-Duties Policies"
OBJECTIVES = "SailPoint ISC 6.2 Certification types and lifecycle · 6.3 Policies in Identity Security Cloud"
COURSES = ("spadmin", "speng")
PLAN_OUTCOMES = ["MANAGER", "SOURCE_OWNER", "SEARCH", "ROLE_COMPOSITION", "NEEDS_CLARIFICATION"]
ITEM_OUTCOMES = ["APPROVED", "REVOKED", "ACKNOWLEDGED", "UNDECIDED", "REVIEWER_MISSING", "NOT_CERTIFIABLE"]
REMEDIATIONS = ["PROVISIONING_TASK", "MANUAL_WORK_ITEM", "PENDING_SIGN_OFF", "NONE"]
SOD_OUTCOMES = ["VIOLATION", "OK", "CANNOT_EVALUATE"]
REQUEST_OUTCOMES = ["WOULD_VIOLATE", "OK", "CANNOT_EVALUATE"]
SECTION = "isc_certifications_sod"


@dataclass
class PlanResult:
    id: str
    text: str
    campaign_type: str
    search_type: str | None
    reviewer: str | None
    subject: str | None
    reasons: list[str] = field(default_factory=list)


@dataclass
class ItemResult:
    id: str
    identity: str | None
    access: str
    source: str
    reviewer: str | None
    outcome: str
    remediation: str
    reasons: list[str] = field(default_factory=list)


@dataclass
class CampaignResult:
    name: str
    type: str
    history: list[str]
    status: str
    undecided_action: str
    signed_off: list[str]
    not_signed_off: list[str]
    items: list[ItemResult]
    reasons: list[str] = field(default_factory=list)


@dataclass
class SodResult:
    id: str
    outcome: str
    conflicts: list[dict] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


@dataclass
class RequestResult:
    id: str
    identity: str
    outcome: str
    action: str
    conflicts: list[dict] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Part 1 — campaign planner
# --------------------------------------------------------------------------- #
def classify(req: dict, cfg: dict) -> tuple[str | None, str | None]:
    """(subject, the keyword that fired). An explicit, known ``subject`` wins over the text."""
    if req.get("subject") in cfg["subject_plans"]:
        return req["subject"], "explicit subject"
    text = (req.get("text") or "").lower()
    for rule in cfg["planner_rules"]:
        for kw in rule["keywords"]:
            if kw in text:
                return rule["subject"], kw
    return None, None


def plan_campaign(req: dict, cfg: dict) -> PlanResult:
    rid, text = req.get("id", "?"), req.get("text", "")
    subject, kw = classify(req, cfg)

    def unclear(reason: str) -> PlanResult:
        return PlanResult(rid, text, "NEEDS_CLARIFICATION", None, None, subject,
                          ([f"matched '{kw}' -> {subject}"] if subject else []) +
                          [reason + " (deny by default: no campaign is launched on a guess)"])

    if subject is None:
        return unclear("no planning rule matched: ask the business owner what is reviewed and by whom")
    plan = cfg["subject_plans"][subject]
    ctype, stype = plan["type"], plan["search_type"]
    reviewer = req.get("reviewer") or plan["reviewer"]
    reasons = [f"matched '{kw}' -> {subject}"]
    query = req.get("query")
    if subject == "all_identities":
        text_l = text.lower()
        if req.get("include_identities_without_manager") or any(k in text_l for k in cfg["no_manager_keywords"]):
            ctype, stype, reviewer, query = "SEARCH", "IDENTITIES", "manager", query or "*"
            reasons.append("manager campaigns exclude identities without a manager; a search campaign with Manager "
                           "as reviewer includes them and sends their reviews to the campaign owner")
        else:
            reasons.append("each identity's manager reviews all of its access")
    if subject == "source":
        if not req.get("source"):
            return unclear("a source owner campaign needs at least one named source")
        reasons.append(f"the owner of {req['source']} reviews the accounts and access on it")
    if subject == "role_composition":
        reasons.append("certifies the role itself (its access and membership criteria), reviewed by the role owner")
    if subject == "uncorrelated_accounts":
        reasons.append("uncorrelated accounts are not linked to an identity, so only an uncorrelated-accounts search "
                       "campaign can review them")
    if subject == "access_items":
        reasons.append("an access-items search campaign reviews every identity that holds the chosen items")
    if subject in ("identities_query", "single_identity"):
        if not query:
            return unclear("a search campaign of type Identities needs a search query")
        reasons.append("a query that returns one identity certifies ALL of that identity's access" if
                       subject == "single_identity" else f"the identities returned by '{query}' are certified")
    if ctype == "SEARCH" and not reviewer:
        return unclear("a search campaign needs a chosen reviewer (individual, governance group, manager, ...)")
    reasons.append(f"reviewer: {reviewer}")
    return PlanResult(rid, text, ctype, stype, reviewer, subject, reasons)


# --------------------------------------------------------------------------- #
# Part 2 — campaign lifecycle
# --------------------------------------------------------------------------- #
def transition(status: str, action: str, cfg: dict) -> tuple[str, str]:
    """(new status, reason). Unknown status or action is refused and the status is unchanged."""
    nxt = cfg["certification"]["transitions"].get(status, {}).get(action)
    if nxt is None:
        return status, f"'{action}' is not allowed from {status}: refused"
    return nxt, f"{status} --{action}--> {nxt}"


def _reviewer(it: dict, ident: dict, camp: dict, ids: dict, sources: dict, cfg: dict) -> tuple[str | None, list[str]]:
    """Reviewer for one item, or (None, reasons) when it is missing."""
    ctype, owner, iid = camp.get("type"), camp.get("owner"), ident["id"]
    mgr = ident.get("manager")
    if ctype == "MANAGER":
        if not mgr:
            return None, [f"{iid} has no manager: manager campaigns exclude this identity (see the Identities "
                          "Without Managers report); fix manager correlation or use a search campaign with Manager "
                          "as reviewer"]
        if mgr not in ids:
            return None, [f"manager {mgr} does not exist in ISC: the certification errors and must be reassigned"]
        reviewer, why = mgr, f"manager {mgr}"
    elif ctype == "SOURCE_OWNER":
        reviewer = (sources.get(it.get("source")) or {}).get("owner")
        if not reviewer:
            return None, [f"source {it.get('source')} has no owner: no reviewer (deny by default)"]
        why = f"source owner {reviewer}"
    elif ctype == "SEARCH":
        if mgr in ids:
            reviewer, why = mgr, f"manager {mgr}"
        elif owner:
            reviewer, why = owner, f"no manager: sent to campaign owner {owner}"
        else:
            return None, ["no manager and no campaign owner"]
    else:
        return None, [f"unknown campaign type '{ctype}' (deny by default)"]
    reasons = [f"reviewer: {why}"]
    if reviewer == iid:
        if mgr and mgr != iid and mgr in ids:
            reviewer = mgr
        elif owner and owner != iid:
            reviewer = owner
        else:
            reviewer = cfg["certification"]["admin_fallback"]
        reasons.append(f"self-certification prevented: moved to {reviewer}")
    return reviewer, reasons


def run_campaign(data: dict, cfg: dict) -> CampaignResult:
    ccfg = cfg["certification"]
    camp = data.get("campaign", {})
    ids = {i["id"]: i for i in data.get("identities", [])}
    sources = data.get("sources", {})
    history, status = [], camp.get("status", "STAGED")
    status, why = transition(status, "activate", cfg)
    history.append(why)
    results: list[ItemResult] = []
    for it in camp.get("items", []):
        base = dict(id=it.get("id", "?"), identity=it.get("identity"), access=f"{it.get('access_type', '?')}:"
                    f"{it.get('access', '?')}", source=it.get("source", "?"))
        ident = ids.get(it.get("identity"))
        if ident is None:
            why = ("account is uncorrelated (no identity): not certifiable in an identity campaign; correlate it or "
                   "run an uncorrelated-accounts search campaign") if not it.get("identity") else \
                  f"identity {it['identity']} is not in ISC: not certifiable"
            results.append(ItemResult(**base, reviewer=None, outcome="NOT_CERTIFIABLE", remediation="NONE",
                                      reasons=[why]))
            continue
        reviewer, reasons = _reviewer(it, ident, camp, ids, sources, cfg)
        if reviewer is None:
            results.append(ItemResult(**base, reviewer=None, outcome="REVIEWER_MISSING", remediation="NONE",
                                      reasons=reasons))
            continue
        target = it.get("reassigned_to")
        if target:
            if target == ident["id"]:
                reasons.append(f"reassignment to {target} refused: the certification contains {target}'s own access")
            elif target not in ids:
                reasons.append(f"reassignment to {target} refused: no such identity")
            elif ccfg["require_reassign_reason"] and not (it.get("reassign_reason") or "").strip():
                reasons.append(f"reassignment to {target} refused: a reason is required")
            else:
                reasons.append(f"reassigned {reviewer} -> {target}: {it['reassign_reason']}")
                reviewer = target
        decision = it.get("decision")
        if decision in ccfg["comment_required_for"] and not (it.get("comment") or "").strip():
            reasons.append(f"'{decision}' without the required comment was not recorded")
            decision = None
        if decision == "revoke" and it.get("access_type") == "ROLE" and it.get("assignment") == "criteria":
            outcome = "ACKNOWLEDGED"
            reasons.append("role is assigned by membership criteria: the reviewer can only acknowledge it; change "
                           "the criteria or the identity's data to remove it")
        elif decision == "approve":
            outcome = "APPROVED"
            reasons.append(f"approved by {reviewer}")
        elif decision == "revoke":
            outcome = "REVOKED"
            reasons.append(f"revoked by {reviewer}: {it.get('comment')}")
        else:
            outcome = "UNDECIDED"
            reasons.append("no recorded decision")
        results.append(ItemResult(**base, reviewer=reviewer, outcome=outcome, remediation="NONE", reasons=reasons))

    reviewers = sorted({r.reviewer for r in results if r.reviewer})
    claimed = set(camp.get("signed_off", []))
    signed, not_signed, camp_reasons = [], [], []
    for rv in reviewers:
        open_items = [r.id for r in results if r.reviewer == rv and r.outcome == "UNDECIDED"]
        if rv in claimed and not open_items:
            signed.append(rv)
        else:
            not_signed.append(rv)
            if rv in claimed:
                camp_reasons.append(f"{rv} sign-off refused: undecided items {', '.join(open_items)}")
    action = camp.get("undecided_action")
    if action not in ("REVOKE", "MAINTAIN"):
        action = ccfg["undecided_action_default"]
        camp_reasons.append(f"no valid undecided action set: using {action} (deny by default)")
    if not not_signed:
        status, why = transition(status, "complete", cfg)
        history.append(why + " (all reviewers signed off)")
    elif camp.get("deadline_passed"):
        status, why = transition(status, "complete", cfg)
        history.append(why + f" (admin completed after the deadline; undecided items: {action})")
    else:
        camp_reasons.append("deadline not passed and reviewers still open: campaign stays ACTIVE")
    remed = ccfg["remediation_by_connection"]
    for r in results:
        conn = (sources.get(r.source) or {}).get("connection")
        task = remed.get(conn, ccfg["remediation_unknown_connection"])
        removes = r.outcome == "REVOKED" or (r.outcome == "UNDECIDED" and status == "COMPLETED" and action == "REVOKE")
        if not removes:
            if r.outcome == "UNDECIDED" and status == "COMPLETED":
                r.reasons.append("undecided at completion: access maintained")
            continue
        if r.outcome == "UNDECIDED":
            r.reasons.append("undecided at completion: auto-revoked")
        if status == "COMPLETED" or r.reviewer in signed:
            r.remediation = task
            r.reasons.append(f"remediation: {task} on {r.source} ({conn or 'unknown'} connection)")
        else:
            r.remediation = "PENDING_SIGN_OFF"
            r.reasons.append("revocation is processed only after sign-off")
    return CampaignResult(camp.get("name", "Campaign"), camp.get("type", "?"), history, status, action, signed,
                          not_signed, results, camp_reasons)


# --------------------------------------------------------------------------- #
# Part 3 — Separation of Duties
# --------------------------------------------------------------------------- #
def expand(ref: dict, catalog: dict) -> dict[str, str] | None:
    """Entitlement id -> how it is held, for one access item; None when it is unknown."""
    kind, rid = ref.get("type"), ref.get("id")
    ents, aps, roles = catalog.get("entitlements", {}), catalog.get("access_profiles", {}), catalog.get("roles", {})
    if kind == "ENTITLEMENT":
        return {rid: "direct"} if rid in ents else None
    if kind == "ACCESS_PROFILE":
        if rid not in aps or any(e not in ents for e in aps[rid].get("entitlements", [])):
            return None
        return {e: f"via access profile {rid}" for e in aps[rid].get("entitlements", [])}
    if kind == "ROLE":
        if rid not in roles:
            return None
        out = {}
        for ap in roles[rid].get("access_profiles", []):
            sub = expand({"type": "ACCESS_PROFILE", "id": ap}, catalog)
            if sub is None:
                return None
            out.update({e: f"via role {rid} > access profile {ap}" for e in sub})
        for e in roles[rid].get("entitlements", []):
            if e not in ents:
                return None
            out[e] = f"via role {rid}"
        return out
    return None


def effective(refs: list[dict], catalog: dict) -> tuple[dict[str, str], list[str]]:
    held, unknown = {}, []
    for ref in refs:
        sub = expand(ref, catalog)
        if sub is None:
            unknown.append(f"{ref.get('type')}:{ref.get('id')}")
        else:
            for e, p in sub.items():
                held.setdefault(e, p)
    return held, unknown


def _lists(policy: dict, catalog: dict) -> tuple[set, set]:
    a, _ = effective(policy.get("list_a", {}).get("items", []), catalog)
    b, _ = effective(policy.get("list_b", {}).get("items", []), catalog)
    return set(a), set(b)


def conflicts_for(held: dict[str, str], policies: list[dict], catalog: dict, new: set | None = None,
                  current: set | None = None, in_flight: bool = True) -> list[dict]:
    """Every (policy, A entitlement, B entitlement) pair the holder has. With ``new``, only pairs touching new access;
    with in_flight False, a pair must have one side already provisioned (``current``)."""
    out = []
    names = catalog.get("entitlements", {})
    for p in policies:
        if p.get("enabled", True) is False:
            continue
        a_set, b_set = _lists(p, catalog)
        for a in sorted(a_set & set(held)):
            for b in sorted(b_set & set(held)):
                if a == b:
                    continue
                if new is not None:
                    if a not in new and b not in new:
                        continue
                    if not in_flight and a in new and b in new and not ({a, b} & (current or set())):
                        continue
                out.append({"policy": p.get("id"), "name": p.get("name"), "level": p.get("level"),
                            "a": names.get(a, {}).get("name", a), "b": names.get(b, {}).get("name", b),
                            "a_path": held[a], "b_path": held[b], "setting": p.get("access_requests"),
                            "owner": p.get("violation_owner")})
    return out


def _pair(c: dict) -> str:
    return f"{c['a']} ({c['a_path']}) x {c['b']} ({c['b_path']})"


def evaluate_identity(entry: dict, sod: dict) -> SodResult:
    catalog, policies = sod.get("catalog", {}), sod.get("policies", [])
    held, unknown = effective(entry.get("access", []), catalog)
    found = conflicts_for(held, policies, catalog)
    skipped = [p["id"] for p in policies if p.get("enabled", True) is False]
    note = [f"disabled policy skipped: {', '.join(skipped)}"] if skipped else []
    if found:
        return SodResult(entry.get("id", "?"), "VIOLATION", found,
                         [f"{c['policy']} '{c['name']}' ({c['level']}): {_pair(c)}; violation owner {c['owner']}"
                          for c in found] + note)
    if unknown:
        return SodResult(entry.get("id", "?"), "CANNOT_EVALUATE", [],
                         [f"cannot decompose {', '.join(unknown)} to entitlements: identity not cleared "
                          "(deny by default)"] + note)
    return SodResult(entry.get("id", "?"), "OK", [], ["no enabled policy has access from both lists"] + note)


def evaluate_request(req: dict, sod: dict, cfg: dict) -> RequestResult:
    scfg = cfg["sod"]
    catalog, policies = sod.get("catalog", {}), sod.get("policies", [])
    by_id = {i["id"]: i for i in sod.get("identities", [])}
    rid, who = req.get("id", "?"), req.get("identity")
    if who not in by_id:
        return RequestResult(rid, who or "?", "CANNOT_EVALUATE", "HELD",
                             reasons=[f"identity {who} has no access data: request held (deny by default)"])
    current, unknown_cur = effective(by_id[who].get("access", []), catalog)
    requested, unknown = effective(req.get("items", []), catalog)
    if unknown or not req.get("items"):
        return RequestResult(rid, who, "CANNOT_EVALUATE", "HELD",
                             reasons=[f"cannot decompose {', '.join(unknown) or 'an empty request'} to entitlements: "
                                      "request held (deny by default)"])
    new = set(requested) - set(current)
    held = {**requested, **current}
    found = conflicts_for(held, policies, catalog, new=new, current=set(current),
                          in_flight=scfg["include_in_flight_access"])
    if not found:
        reasons = ["no new conflict with current or requested access"]
        if unknown_cur:
            reasons.append(f"note: current access {', '.join(unknown_cur)} could not be decomposed")
        return RequestResult(rid, who, "OK", "NORMAL_APPROVAL", reasons=reasons)
    settings = [c["setting"] or scfg["default_request_setting"] for c in found]
    block = scfg["global_block_all"] or any(s not in scfg["request_actions"] or s == "BLOCK" for s in settings)
    action = scfg["request_actions"]["BLOCK"] if block else scfg["request_actions"]["ALLOW"]
    reasons = [f"{c['policy']} '{c['name']}': {_pair(c)}" for c in found]
    reasons.append("policy blocks submission: the request is cancelled" if block else
                   "policy allows submission: approvers see the violation and decide")
    return RequestResult(rid, who, "WOULD_VIOLATE", action, found, reasons)


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SailPoint ISC 6.2 Certification types and lifecycle · 6.3 Policies (Engineer 8.1, 8.2).",
    "concepts": [
        "Pick the campaign type from the requirement: manager, source owner, search (identities, access items, "
        "uncorrelated accounts) or role composition.",
        "Lifecycle: staged (preview and reassign) -> active (decide, reassign, sign off) -> completed; revocations "
        "become remediation after sign-off or completion.",
        "Manager campaigns skip identities without a manager; uncorrelated accounts never appear in identity campaigns.",
        "SoD policies compare List A and List B; roles and access profiles are decomposed to entitlements.",
    ],
    "failure_modes": [
        "Launching a manager campaign without checking the Identities Without Managers report: people silently escape review.",
        "Revoking an access item whose role is assigned by criteria: it comes straight back at the next evaluation.",
        "Assuming a revoke is done when the source is a flat file: someone must remove it and you must verify it.",
        "An SoD policy left disabled, or set to allow submission with approvers who click through the warning.",
    ],
    "ai_governance": [
        "An AI helper may suggest approve or revoke, but the reviewer signs off and owns the decision.",
        "Give the helper a read-only view of campaigns; decisions and completion stay with human admins.",
        "Treat comments, account names and request justifications as untrusted data, never as instructions.",
        "Ask the helper to show the conflicting pair and the path (role, access profile) behind every SoD flag.",
    ],
    "exam_tips": [
        "'Review everything one person has' = search campaign of type Identities with a query for that identity.",
        "'Review what a role contains' = role composition campaign, reviewed by the role owner.",
        "Identities without managers: excluded from manager campaigns; search + Manager reviewer sends them to the campaign owner.",
        "SailPoint recommends maintaining undecided access at completion because revoked access is hard to reinstate.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    cfg = policies[SECTION]
    plans = [plan_campaign(r, cfg) for r in data.get("requirements", [])]
    camp = run_campaign(data, cfg)
    sod = data.get("sod", {})
    sods = [evaluate_identity(e, sod) for e in sod.get("identities", [])]
    reqs = [evaluate_request(r, sod, cfg) for r in sod.get("requests", [])]

    ui.section("Step 1 — Plan campaigns from business requirements")
    ui.table("Campaign planner", ["ID", "Requirement", "Campaign type", "Search type", "Reviewer"],
             [[p.id, p.text[:60], p.campaign_type, p.search_type or "-", p.reviewer or "-"] for p in plans])
    for p in plans:
        ui.bullet(f"{p.id} -> {p.campaign_type}: " + "; ".join(p.reasons),
                  style="yellow" if p.campaign_type == "NEEDS_CLARIFICATION" else "dim")

    ui.section(f"Step 2 — Run the campaign: {camp.name} ({camp.type})")
    for h in camp.history:
        ui.bullet(h)
    ui.table("Review items", ["ID", "Identity", "Access", "Reviewer", "Outcome", "Remediation"],
             [[r.id, r.identity or "-", r.access, r.reviewer or "-", r.outcome, r.remediation] for r in camp.items])
    for r in camp.items:
        ui.bullet(f"{r.id} -> {r.outcome}: " + "; ".join(r.reasons),
                  style={"APPROVED": "green", "REVOKED": "red"}.get(r.outcome, "yellow"))
    for line in camp.reasons:
        ui.bullet(line, style="yellow")
    ui.status("Campaign status", "PASS" if camp.status == "COMPLETED" else "WARN", camp.status)
    ui.print(f"Signed off: {', '.join(camp.signed_off) or 'none'} · not signed off: "
             f"{', '.join(camp.not_signed_off) or 'none'} · undecided action: {camp.undecided_action}")

    ui.section("Step 3 — Separation of Duties: identities and pending access requests")
    ui.table("SoD policy check", ["Identity", "Outcome", "Conflicting pair"],
             [[s.id, s.outcome, f"{s.conflicts[0]['a']} x {s.conflicts[0]['b']}" if s.conflicts else "-"]
              for s in sods])
    for s in sods:
        ui.bullet(f"{s.id} -> {s.outcome}: " + "; ".join(s.reasons),
                  style={"OK": "green", "VIOLATION": "red"}.get(s.outcome, "yellow"))
    ui.table("Access request SoD check", ["Request", "Identity", "Outcome", "Action"],
             [[q.id, q.identity, q.outcome, q.action] for q in reqs])
    for q in reqs:
        ui.bullet(f"{q.id} -> {q.outcome}: " + "; ".join(q.reasons),
                  style={"OK": "green", "WOULD_VIOLATE": "red"}.get(q.outcome, "yellow"))
    ui.insight(INSIGHT)

    count = lambda xs: {k: sum(x == k for x in xs) for k in sorted(set(xs))}  # noqa: E731
    return {
        "plans": {p.id: p.campaign_type for p in plans},
        "items": {r.id: r.outcome for r in camp.items},
        "remediation": {r.id: r.remediation for r in camp.items if r.remediation != "NONE"},
        "campaign_status": camp.status,
        "sod": {s.id: s.outcome for s in sods},
        "requests": {q.id: q.outcome for q in reqs},
        "request_actions": {q.id: q.action for q in reqs},
        "metrics": {"requirements": len(plans), "items": len(camp.items),
                    "item_outcomes": count([r.outcome for r in camp.items]),
                    "remediation_tasks": sum(r.remediation in ("PROVISIONING_TASK", "MANUAL_WORK_ITEM")
                                             for r in camp.items),
                    "signed_off": len(camp.signed_off), "not_signed_off": len(camp.not_signed_off),
                    "violations": sum(s.outcome == "VIOLATION" for s in sods),
                    "requests_would_violate": sum(q.outcome == "WOULD_VIOLATE" for q in reqs)},
    }


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies[SECTION]
    plans = [plan_campaign(r, cfg) for r in data.get("requirements", [])]
    camp = run_campaign(data, cfg)
    sod = data.get("sod", {})
    sods = [evaluate_identity(e, sod) for e in sod.get("identities", [])]
    reqs = [evaluate_request(r, sod, cfg) for r in sod.get("requests", [])]
    raw_items = {i.get("id"): i for i in data.get("campaign", {}).get("items", [])}
    qs: list = []

    for p in plans:
        label = p.campaign_type + (f" ({p.search_type})" if p.search_type else "")
        pool = ["MANAGER", "SOURCE_OWNER", "SEARCH (IDENTITIES)", "SEARCH (ACCESS_ITEMS)",
                "SEARCH (UNCORRELATED_ACCOUNTS)", "ROLE_COMPOSITION", "NEEDS_CLARIFICATION"]
        qs.append(Question(prompt=f"{p.id}: which certification campaign fits this requirement?",
                           context=f"requirement: \"{p.text}\"" + "".join(
                               f"\n{k}: {v}" for k, v in data["requirements"][plans.index(p)].items()
                               if k in ("query", "reviewer", "source", "role")),
                           choices=choices_with(label, pool, k=3, key=p.id), answer=label,
                           explanation="; ".join(p.reasons), objective="6.2"))
    for p in plans:   # "which rule fired": a requirement that matches more than one rule's keywords
        text = p.text.lower()
        hits = [r["subject"] for r in cfg["planner_rules"] if any(k in text for k in r["keywords"])]
        if len(hits) > 1 and p.subject == hits[0]:
            qs.append(Question(prompt=f"{p.id} matches the keywords of {len(hits)} planning rules. Which subject "
                                      "decides the campaign?", context=f"requirement: \"{p.text}\"",
                               choices=sorted(hits), answer=p.subject,
                               explanation=f"rules are checked in order and the first match wins: {p.reasons[0]}",
                               objective="6.2"))
            break
    seen = set()
    for r in camp.items:
        if r.outcome in seen and not raw_items.get(r.id, {}).get("reassigned_to"):
            continue
        seen.add(r.outcome)
        src = {k: v for k, v in raw_items.get(r.id, {}).items() if k != "id"}
        qs.append(Question(prompt=f"{r.id}: what is the final result of this review item?",
                           context=f"campaign type {camp.type}; item={src}",
                           choices=ITEM_OUTCOMES, answer=r.outcome, explanation="; ".join(r.reasons),
                           objective="6.2"))
    for r in camp.items:
        if r.remediation in ("PROVISIONING_TASK", "MANUAL_WORK_ITEM"):
            conn = data.get("sources", {}).get(r.source, {}).get("connection", "unknown")
            qs.append(Question(prompt=f"{r.id} was revoked on {r.source} ({conn} connection). What remediation follows?",
                               choices=["PROVISIONING_TASK", "MANUAL_WORK_ITEM", "nothing: revoking removes it at once",
                                        "the identity is disabled"],
                               answer=r.remediation, explanation="; ".join(r.reasons), objective="6.2"))
            if r.remediation == "MANUAL_WORK_ITEM":
                break
    qs.append(Question(prompt="What is the campaign status after the deadline, given who signed off?",
                       context="; ".join(camp.reasons) or "all reviewers signed off",
                       choices=["STAGED", "ACTIVE", "COMPLETED", "DELETED"], answer=camp.status,
                       explanation="; ".join(camp.history), objective="6.2"))
    _, why = transition("STAGED", "complete", cfg)
    qs.append(Question(prompt="An admin tries to complete a campaign that is still STAGED. What happens?",
                       choices=["the action is refused: a staged campaign must be activated first",
                                "the campaign completes and all items are approved",
                                "the campaign completes and all items are revoked",
                                "the campaign is deleted"],
                       answer="the action is refused: a staged campaign must be activated first",
                       explanation=why, objective="6.2"))
    for s in sods:
        ctx = f"access={next(e['access'] for e in sod['identities'] if e['id'] == s.id)}"
        qs.append(Question(prompt=f"Identity {s.id}: what does the SoD policy check return?", context=ctx,
                           choices=SOD_OUTCOMES, answer=s.outcome, explanation="; ".join(s.reasons),
                           objective="6.3"))
    for s in sods:
        if s.conflicts:
            c = s.conflicts[0]
            right = f"{c['a']} and {c['b']}"
            ents = sorted(v["name"] for v in sod["catalog"]["entitlements"].values())
            pool = sorted({f"{x} and {y}" for x in ents[:4] for y in ents[4:]} - {right})
            qs.append(Question(prompt=f"Identity {s.id} violates {c['policy']}. Which entitlements form the conflicting pair?",
                               choices=choices_with(right, pool, key=s.id), answer=right,
                               explanation="; ".join(s.reasons), objective="6.3"))
    for q in reqs:
        req = next(r for r in sod["requests"] if r["id"] == q.id)
        label = q.outcome if q.outcome != "WOULD_VIOLATE" else f"WOULD_VIOLATE ({q.action})"
        qs.append(Question(prompt=f"Access request {q.id}: what does the SoD check decide?",
                           context=f"identity {q.identity} requests {req['items']}",
                           choices=["OK", "CANNOT_EVALUATE", "WOULD_VIOLATE (BLOCKED)",
                                    "WOULD_VIOLATE (ROUTED_TO_APPROVERS)"],
                           answer=label, explanation="; ".join(q.reasons), objective="6.3"))
    qs.append(Question(prompt="What does SailPoint recommend for undecided items when a campaign is completed?",
                       choices=["maintain access, because revoked access is hard to reinstate",
                                "always revoke, because undecided means unneeded",
                                "delete the identities that were not reviewed",
                                "leave the campaign open forever"],
                       answer="maintain access, because revoked access is hard to reinstate",
                       explanation="SailPoint strongly recommends maintaining undecided access; this course's "
                                   f"policy uses {cfg['certification']['undecided_action_default']} to show the "
                                   "deny-by-default choice", objective="6.2"))
    concepts = cfg["concepts"]
    for term in ("role composition campaign", "sign-off", "SoD policy", "violation owner"):
        if term in concepts:
            qs.append(Question(prompt=f"Which term is this? \"{concepts[term]}\"",
                               choices=choices_with(term, sorted(concepts), key=term), answer=term,
                               explanation=concepts[term], objective="6.3" if term in ("SoD policy",
                                                                                       "violation owner") else "6.2"))
    return qs


# --------------------------------------------------------------------------- #
# Random scenario
# --------------------------------------------------------------------------- #
_FIRST = ["Avery", "Bea", "Cyrus", "Dalia", "Emre", "Fen", "Gita", "Hugo", "Ines", "Jonah", "Kira", "Lars", "Mina",
          "Niko", "Oona", "Pavel", "Rhea", "Sami"]
_LAST = ["Abara", "Brandt", "Chen", "Duarte", "Eklund", "Farah", "Gomez", "Haddad", "Ito", "Juarez", "Kowal",
         "Lindqvist", "Moreau", "Nwosu", "Ortiz", "Petrov"]
_COMPANIES = ["Juniper Example Logistics", "Northgate Example Foods", "Cobalt Example Utilities",
              "Saltmarsh Example Clinics"]


def generate_scenario(rng, policies: dict) -> dict:
    """A seeded scenario with the sample's shape; every outcome of every part appears at least once."""
    cfg = policies[SECTION]
    names = rng.sample([f"{f} {l}" for f in _FIRST for l in _LAST], 9)
    base = rng.randint(1, 8) * 1000
    ids = [f"EX{base + n}" for n in range(9)]
    exec_, director, ap, analyst, contractor, gl, controller, admin, extra = ids
    erp, ad, flat = rng.choice(["Oracle ERP", "NetSuite ERP", "SAP S/4HANA"]), "Active Directory", \
        rng.choice(["Legacy Payroll", "Timesheet CSV", "Badge Export"])
    missing_mgr = f"EX{base + 999}"
    identities = [
        {"id": exec_, "name": names[0], "title": "Chief Financial Officer", "manager": None},
        {"id": director, "name": names[1], "title": "Finance Director", "manager": exec_},
        {"id": ap, "name": names[2], "title": "Accounts Payable Lead", "manager": director},
        {"id": analyst, "name": names[3], "title": "Financial Analyst", "manager": director},
        {"id": contractor, "name": names[4], "title": "Contract Accountant", "manager": missing_mgr},
        {"id": gl, "name": names[5], "title": "General Ledger Accountant", "manager": controller},
        {"id": controller, "name": names[6], "title": "Controller", "manager": director},
        {"id": admin, "name": names[7], "title": "Certification Administrator", "manager": exec_},
        {"id": extra, "name": names[8], "title": "Treasury Analyst", "manager": director},
    ]
    sources = {erp: {"owner": controller, "connection": "direct"}, ad: {"owner": admin, "connection": "direct"},
               flat: {"owner": director, "connection": "flat_file"}}
    first = lambda i: identities[ids.index(i)]["name"]  # noqa: E731
    requirements = [
        {"id": "R1", "text": "Every quarter, managers review all access of their direct reports."},
        {"id": "R2", "text": f"The owner of the {erp} source reviews every account on the source.", "source": erp},
        {"id": "R3", "text": "Review the identities in the Treasury department whose lifecycle state is active.",
         "query": "attributes.department:Treasury", "reviewer": "governance group: Finance Controls"},
        {"id": "R4", "text": "Confirm what the Finance Analyst role contains.", "role": "Finance Analyst"},
        {"id": "R5", "text": f"Review all access held by one identity, {first(contractor)}.",
         "query": f"id:{contractor}", "reviewer": f"individual: {director}"},
        {"id": "R6", "text": "Quarterly manager review that must also cover contractors without a manager."},
        {"id": "R7", "text": f"Review the uncorrelated accounts found on {flat}.", "source": flat},
        {"id": "R8", "text": rng.choice(["Make sure finance access is fine.", "Check access is OK."])},
        {"id": "R9", "text": "Review everyone who has the Vendor Master Maintain entitlement.",
         "reviewer": "access owner"},
    ]
    rng.shuffle(requirements)

    def item(n, who, src, access, decision, **kw):
        return {"id": f"C{n:02d}", "identity": who, "account": f"acct{n}", "source": src,
                "access_type": kw.pop("access_type", "ENTITLEMENT"), "access": access,
                "assignment": kw.pop("assignment", "requested"), "decision": decision, **kw}

    items = [
        item(1, ap, erp, "AP Clerk", "approve"),
        item(2, ap, erp, "Vendor Master Maintain", "revoke", comment="Moved to procurement."),
        item(3, analyst, flat, "Payroll Export", "revoke", comment="Not needed."),
        item(4, analyst, erp, "Finance Analyst", "revoke", comment="Wrong role.", access_type="ROLE",
             assignment="criteria"),
        item(5, gl, ad, "VPN Users", None),
        item(6, gl, erp, "Journal Entry Post", "approve"),
        item(7, exec_, erp, "Journal Entry Approve", None),
        item(8, contractor, erp, "AP Clerk", None),
        item(9, None, erp, "AP Payment Release", None),
        item(10, ap, ad, "Finance Share Write", "approve", reassigned_to=ap, reassign_reason="knows best"),
        item(11, analyst, erp, "Purchasing Approver", "revoke", comment="", reassigned_to=controller,
             reassign_reason="owns purchasing"),
        item(12, director, erp, "Journal Entry Approve", "approve"),
    ]
    for n in range(13, 13 + rng.randint(0, 3)):
        items.append(item(n, extra, rng.choice([erp, ad]), rng.choice(["Report Viewer", "Expense Submit"]),
                          "approve"))
    rng.shuffle(items)
    catalog = {
        "entitlements": {"e.vendor": {"name": "Vendor Master Maintain", "source": erp},
                         "e.pay": {"name": "AP Payment Release", "source": erp},
                         "e.clerk": {"name": "AP Clerk", "source": erp},
                         "e.post": {"name": "Journal Entry Post", "source": erp},
                         "e.approve": {"name": "Journal Entry Approve", "source": erp},
                         "e.vpn": {"name": "VPN Users", "source": ad},
                         "e.payadmin": {"name": "Payroll Administrator", "source": flat},
                         "e.worker": {"name": "Worker Data Edit", "source": flat}},
        "access_profiles": {"Payment Release": {"entitlements": ["e.pay"]}, "GL Posting": {"entitlements": ["e.post"]}},
        "roles": {"Finance Analyst": {"access_profiles": ["GL Posting"], "entitlements": ["e.vpn"]},
                  "Controller": {"access_profiles": [], "entitlements": ["e.approve"]}},
    }
    E = lambda i: {"type": "ENTITLEMENT", "id": i}  # noqa: E731
    AP = lambda i: {"type": "ACCESS_PROFILE", "id": i}  # noqa: E731
    R = lambda i: {"type": "ROLE", "id": i}  # noqa: E731
    sod_policies = [
        {"id": "SOD-01", "name": "Vendor maintenance vs payment release", "enabled": True, "level": "High",
         "violation_owner": controller, "access_requests": "BLOCK",
         "list_a": {"name": "Vendor", "items": [E("e.vendor")]}, "list_b": {"name": "Pay", "items": [AP("Payment Release")]}},
        {"id": "SOD-02", "name": "Post vs approve journal entries", "enabled": True, "level": "Critical",
         "violation_owner": director, "access_requests": "ALLOW",
         "list_a": {"name": "Post", "items": [AP("GL Posting")]}, "list_b": {"name": "Approve", "items": [R("Controller")]}},
        {"id": "SOD-03", "name": "Payroll administration vs worker data edit", "enabled": False, "level": "Medium",
         "violation_owner": director, "access_requests": "BLOCK",
         "list_a": {"name": "Admin", "items": [E("e.payadmin")]}, "list_b": {"name": "Worker", "items": [E("e.worker")]}},
    ]
    sod_ids = [
        {"id": ap, "access": [E("e.vendor"), AP("Payment Release")]},
        {"id": analyst, "access": [R("Finance Analyst")]},
        {"id": gl, "access": [R("Finance Analyst"), E("e.approve")]},
        {"id": contractor, "access": [E("e.payadmin"), E("e.worker")]},
        {"id": director, "access": [E("e.approve"), AP("Unknown Treasury")]},
        {"id": exec_, "access": [E("e.vendor")]},
        {"id": controller, "access": [E("e.vpn")]},
    ]
    requests = [
        {"id": "AR-1", "identity": analyst, "items": [R("Controller")]},
        {"id": "AR-2", "identity": controller, "items": [E("e.post")]},
        {"id": "AR-3", "identity": contractor, "items": [E("e.vendor"), AP("Payment Release")]},
        {"id": "AR-4", "identity": ap, "items": [AP("Unknown Treasury")]},
        {"id": "AR-5", "identity": exec_, "items": [E("e.pay")]},
    ]
    rng.shuffle(sod_ids)
    rng.shuffle(requests)
    return {"_description": "Generated certification and SoD scenario (fictional).", "company": rng.choice(_COMPANIES),
            "identities": identities, "sources": sources, "requirements": requirements,
            "campaign": {"name": "Generated Manager Certification", "type": "MANAGER", "status": "STAGED",
                         "owner": admin, "deadline_passed": True, "undecided_action": "REVOKE",
                         "signed_off": [director, exec_, controller], "items": items},
            "sod": {"catalog": catalog, "policies": sod_policies, "identities": sod_ids, "requests": requests}}
