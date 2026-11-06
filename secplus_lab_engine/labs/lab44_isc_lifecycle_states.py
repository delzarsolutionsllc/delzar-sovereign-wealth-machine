"""
Lab 44 — Lifecycle States & Joiner-Mover-Leaver Automation
==========================================================

SailPoint ISC objectives
------------------------
* 3.3  Lifecycle states and the cloud lifecycle state attribute: lifecycle
       states configured on an identity profile, their technical names, and
       the ``cloudLifecycleState`` identity attribute that selects them.
* 4.1  Provisioning triggers: what a lifecycle state change provisions
       (access profiles granted or removed, accounts enabled or disabled,
       email notifications) and what it does not.

Course mapping: SailPoint Identity Security Administrator objective 3.3
(primary) and 4.1; SailPoint Identity Security Engineer objective 1.3
(identity profiles, lifecycle states and the transforms behind them).

How it works
------------
You administer SailPoint Identity Security Cloud (ISC). HR is the
authoritative source. Every identity profile has a set of lifecycle states
(for example prehire, active, leave, terminated, inactive). Each state has a
display name, a technical name, an identity state and the actions that run
when an identity ENTERS it: access profiles to grant, access profiles to
remove, accounts to enable or disable (on listed sources, or all sources) and
whether an email notification is sent (and to whom).

Step 1, calculate cloudLifecycleState from the HR record. Real tenants do
this with a transform (dateCompare plus conditional, or a rule); this module
uses a simplified, policy-driven version. Rules, in order:

1. HR status missing or not in the policy's status map → ``inactive``
   (deny by default: an unrecognised status never gets new access).
2. Status terminated → ``terminated``; once the end date is more than
   ``post_termination_days`` in the past → ``inactive`` (post-termination).
3. Status leave → ``leave``.
4. Status active: an end date before today ends employment → ``terminated``
   (or ``inactive`` after the post-termination window), unless the start
   date is after that end date (a rehire: the old end date is ignored).
   The end date itself is still a working day.
5. Status active with a missing or unreadable start date → ``inactive``
   (deny by default); a start date after today → ``prehire``; else ``active``.

Step 2, apply the lifecycle state. For each identity event, in order:

1. Unknown identity profile, or a calculated value that equals no lifecycle
   state's technical name on that profile (an exact match) → UNKNOWN_STATE:
   no actions run, flagged for an administrator.
2. Calculated state equals the current state → NO_CHANGE: lifecycle actions
   run only when the state changes, so nothing is provisioned.
3. Otherwise the state's configured actions run, and only those: GRANT and
   REMOVE access profiles, ENABLE and DISABLE accounts, NOTIFY recipients.
4. Findings on the new state (the most severe wins, else TRANSITIONED):
   LEAVER_KEEPS_ACCESS when a leaver state (terminated, inactive) disables no
   accounts, or leaves one of the identity's accounts enabled;
   PREHIRE_ACCESS_TOO_EARLY when a pre-hire state grants an access profile
   or enables accounts outside the allowed onboarding set.

Run it
------
    python main.py --course spadmin lab 44
    python main.py --course speng lab 44
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, timedelta

TITLE = "Lab 44 — Lifecycle States & Joiner-Mover-Leaver Automation"
OBJECTIVES = ("SailPoint ISC 3.3 Lifecycle states and the cloud lifecycle state attribute · "
              "4.1 Provisioning triggers")
COURSES = ("spadmin", "speng")
SECTION = "isc_lifecycle_states"
OUTCOMES = ["UNKNOWN_STATE", "LEAVER_KEEPS_ACCESS", "PREHIRE_ACCESS_TOO_EARLY", "TRANSITIONED", "NO_CHANGE"]
STATES = ["prehire", "active", "leave", "terminated", "inactive"]
ALL = "ALL"


@dataclass
class EventResult:
    id: str
    identity: str
    profile: str
    event: str
    previous: str | None
    calculated: str
    calc_rule: str
    outcome: str
    actions: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Step 1 — cloudLifecycleState calculation (simplified transform)
# --------------------------------------------------------------------------- #
def _date(value) -> date | None:
    try:
        return date.fromisoformat(str(value)) if value else None
    except ValueError:
        return None


def calculate_state(hr: dict | None, today, cfg: dict) -> tuple[str, str, str]:
    """Return (cloudLifecycleState value, rule name, reason). Pure; deny by default on missing input."""
    fallback = cfg["deny_by_default_state"]
    hr = hr or {}
    now = _date(today)
    if now is None:
        return fallback, "deny_by_default", f"no valid 'today' date: {fallback} (deny by default)"
    status = str(hr.get("status") or "").strip().lower()
    mapped = cfg["status_map"].get(status)
    if mapped is None:
        shown = f"'{hr.get('status')}'" if hr.get("status") else "missing"
        return fallback, "unknown_status", f"HR status {shown} is not in the status map: {fallback} (deny by default)"
    start, end = _date(hr.get("start_date")), _date(hr.get("end_date"))
    window = cfg["post_termination_days"]

    def ended(why: str) -> tuple[str, str, str]:
        if end is not None and (now - end).days > window:
            return fallback, "post_termination", (f"{why}; end date {end} is {(now - end).days} days ago "
                                                  f"> {window}: post-termination {fallback}")
        return "terminated", "terminated", why

    if mapped == "terminated":
        return ended(f"HR status '{status}'")
    if mapped == "leave":
        return "leave", "leave", f"HR status '{status}': leave of absence"
    # mapped == "active"
    if end is not None and end < now:
        if start is not None and start > end:
            pass                                # rehire: the end date belongs to the previous employment
        else:
            return ended(f"HR status still '{status}' but end date {end} has passed")
    if start is None:
        return fallback, "missing_start_date", f"active status with no valid start date: {fallback} (deny by default)"
    rehire = " (rehire: start date is after the old end date)" if end is not None and start > end else ""
    if end is not None and end == now:
        rehire += " (end date is today: still a working day)"
    if start > now:
        return "prehire", "prehire", f"start date {start} is after today {now}: prehire{rehire}"
    return "active", "active", f"start date {start} reached{rehire}"


# --------------------------------------------------------------------------- #
# Step 2 — apply the lifecycle state's configured actions
# --------------------------------------------------------------------------- #
def find_state(profile: dict | None, value: str) -> dict | None:
    # Exact match on the technical name (simplification: treat it as case-sensitive; keep values lowercase).
    for st in (profile or {}).get("lifecycle_states", []):
        if st.get("technical_name") == value:
            return st
    return None


def _sources(spec, accounts: list[str] | None) -> list[str]:
    if spec == ALL:
        return sorted(accounts) if accounts else ["all sources"]
    return list(spec or [])


def state_actions(state: dict, accounts: list[str] | None = None) -> list[str]:
    """The provisioning a state change triggers: only what the state configures."""
    acts = [f"GRANT {ap}" for ap in state.get("grant_access_profiles", [])]
    acts += [f"REMOVE {ap}" for ap in state.get("remove_access_profiles", [])]
    acts += [f"ENABLE {s}" for s in _sources(state.get("enable_accounts"), accounts)]
    acts += [f"DISABLE {s}" for s in _sources(state.get("disable_accounts"), accounts)]
    notify = state.get("notify") or {}
    if notify.get("enabled") and notify.get("recipients"):
        acts.append("NOTIFY " + ", ".join(notify["recipients"]))
    return acts


def state_findings(state: dict, accounts: list[str] | None, cfg: dict) -> list[tuple[str, str]]:
    found = []
    tech = state.get("technical_name")
    if tech in cfg["leaver_states"]:
        disable = state.get("disable_accounts")
        if not disable:
            found.append(("LEAVER_KEEPS_ACCESS", f"leaver state '{tech}' disables no accounts"
                          + ("" if state.get("remove_access_profiles") else " and removes no access profiles")))
        elif disable != ALL:
            left = sorted(set(accounts or []) - set(disable))
            if left:
                found.append(("LEAVER_KEEPS_ACCESS", f"leaver state '{tech}' leaves accounts enabled on "
                              + ", ".join(left)))
    if tech in cfg["prehire_states"]:
        extra = [ap for ap in state.get("grant_access_profiles", []) if ap not in cfg["prehire_allowed_access_profiles"]]
        if extra:
            found.append(("PREHIRE_ACCESS_TOO_EARLY", "pre-hire grants " + ", ".join(extra)
                          + " before the start date"))
        enable = state.get("enable_accounts")
        allowed = cfg["prehire_allowed_enable_sources"]
        bad = ["all sources"] if enable == ALL else [s for s in (enable or []) if s not in allowed]
        if bad:
            found.append(("PREHIRE_ACCESS_TOO_EARLY", "pre-hire enables accounts on " + ", ".join(bad)))
    found.sort(key=lambda f: cfg["flag_severity"].index(f[0]))
    return found


def process_event(event: dict, profiles: dict, today, cfg: dict) -> EventResult:
    pname = event.get("identity_profile") or "-"
    profile = profiles.get(pname)
    prev = event.get("previous_state")
    value, rule, why = calculate_state(event.get("hr"), event.get("today", today), cfg)
    res = EventResult(event.get("id", "?"), event.get("identity", "?"), pname, event.get("event", "-"), prev,
                      value, rule, "UNKNOWN_STATE", reasons=[f"cloudLifecycleState = '{value}': {why}"])
    if profile is None:
        res.flags = ["UNKNOWN_STATE"]
        res.reasons.append(f"identity profile '{pname}' is not configured: no actions (deny by default)")
        return res
    state = find_state(profile, value)
    if state is None:
        names = ", ".join(s.get("technical_name", "?") for s in profile.get("lifecycle_states", []))
        res.flags = ["UNKNOWN_STATE"]
        res.reasons.append(f"no lifecycle state on '{pname}' has technical name '{value}' (configured: {names}): "
                           "no actions run")
        return res
    if value == prev:
        res.outcome = "NO_CHANGE"
        res.reasons.append(f"already in '{value}': actions run only when the lifecycle state changes")
        return res
    accounts = event.get("accounts")
    res.actions = state_actions(state, accounts)
    found = state_findings(state, accounts, cfg)
    res.flags = [f for f, _ in found]
    res.outcome = found[0][0] if found else "TRANSITIONED"
    res.reasons.append(f"'{prev or 'none'}' → '{value}' ({state.get('name', value)}): "
                       + (f"{len(res.actions)} configured action(s) run" if res.actions else "no actions configured"))
    res.reasons += [r for _, r in found]
    return res


def process_all(data: dict, cfg: dict) -> list[EventResult]:
    profiles = data.get("identity_profiles", {})
    return [process_event(e, profiles, data.get("today"), cfg) for e in data.get("events", [])]


def metrics_of(results: list[EventResult]) -> dict:
    counts = {o: sum(r.outcome == o for r in results) for o in OUTCOMES}
    return {"events": len(results), "outcome_counts": counts,
            "flagged": sum(counts[o] for o in ("UNKNOWN_STATE", "LEAVER_KEEPS_ACCESS", "PREHIRE_ACCESS_TOO_EARLY")),
            "actions": sum(len(r.actions) for r in results),
            "state_changes": sum(r.outcome not in ("NO_CHANGE", "UNKNOWN_STATE") for r in results)}


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SailPoint ISC 3.3 Lifecycle states and cloudLifecycleState · 4.1 Provisioning triggers.",
    "concepts": [
        "Lifecycle states live on an identity profile; cloudLifecycleState must equal a state's technical name.",
        "cloudLifecycleState is calculated from HR data, usually by a transform comparing start and end dates.",
        "Entering a state runs only its configured actions: grant or remove access profiles, enable or disable "
        "accounts, send email.",
        "Lifecycle actions fire on a change of state during identity refresh, not on every aggregation.",
        "Engineers own the calculation (transforms, rules); administrators own the state configuration.",
    ],
    "failure_modes": [
        "A typo in a technical name ('loa' versus 'leave'): identities sit in an unrecognised state and nothing happens.",
        "A terminated state that only sends an email: leavers keep every account and access profile.",
        "Disabling 'selected sources' and forgetting a new SaaS source: leavers keep that account.",
        "A pre-hire state that grants production access weeks before the person starts.",
        "Mapping an unknown HR status to active: a data error becomes a new joiner with access.",
    ],
    "ai_governance": [
        "An AI agent may propose lifecycle state changes, but the transform and state configuration stay "
        "change-controlled and reviewed.",
        "Give agents an identity profile and leaver state like any other identity, so their access ends on schedule.",
        "Treat HR fields such as status text as untrusted data; unknown values fall back to the safest state.",
    ],
    "exam_tips": [
        "'Lifecycle state not applied' → check that cloudLifecycleState matches the technical name exactly.",
        "Changing lifecycle state triggers provisioning only for the actions configured on the new state.",
        "Same calculated state on refresh → no lifecycle actions run again.",
        "Leaver states should disable accounts on all sources and remove birthright access profiles.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    cfg = policies[SECTION]
    results = process_all(data, cfg)
    m = metrics_of(results)
    ui.section("Step 1 — Lifecycle states configured on each identity profile")
    rows = []
    for pname, prof in data.get("identity_profiles", {}).items():
        for st in prof.get("lifecycle_states", []):
            n = st.get("notify") or {}
            rows.append([pname, st.get("name", "-"), st.get("technical_name", "-"), st.get("identity_state", "-"),
                         ", ".join(st.get("grant_access_profiles", [])) or "-",
                         ", ".join(st.get("remove_access_profiles", [])) or "-",
                         _spec(st.get("enable_accounts")), _spec(st.get("disable_accounts")),
                         ", ".join(n.get("recipients", [])) if n.get("enabled") else "off"])
    ui.table("Lifecycle states", ["Profile", "State", "Technical name", "Identity state", "Grant", "Remove",
                                  "Enable", "Disable", "Email"], rows)
    ui.section(f"Step 2 — Calculate cloudLifecycleState from HR data (today {data.get('today', '-')})")
    ui.table("Calculation", ["ID", "Identity", "Event", "HR status", "Start", "End", "Rule", "cloudLifecycleState"],
             [[r.id, r.identity, r.event, (e.get("hr") or {}).get("status") or "-",
               (e.get("hr") or {}).get("start_date") or "-", (e.get("hr") or {}).get("end_date") or "-",
               r.calc_rule, r.calculated] for r, e in zip(results, data.get("events", []))])
    ui.section("Step 3 — State change, triggered provisioning and findings")
    ui.table("Events", ["ID", "Profile", "From", "To", "Outcome", "Actions"],
             [[r.id, r.profile, r.previous or "-", r.calculated, r.outcome, len(r.actions)] for r in results])
    for r in results:
        style = {"TRANSITIONED": "green", "NO_CHANGE": "dim"}.get(r.outcome, "red")
        ui.bullet(f"{r.id} {r.identity} → {r.outcome}: " + "; ".join(r.reasons), style=style)
        for a in r.actions:
            ui.print(f"      {a}")
    c = m["outcome_counts"]
    ui.status("Lifecycle findings", "PASS" if m["flagged"] == 0 else "FAIL",
              f"{m['flagged']} flagged of {m['events']} events")
    ui.print(f"{c['TRANSITIONED']} transitioned · {c['NO_CHANGE']} no change · {c['UNKNOWN_STATE']} unknown state · "
             f"{c['LEAVER_KEEPS_ACCESS']} leaver keeps access · {c['PREHIRE_ACCESS_TOO_EARLY']} pre-hire too early · "
             f"{m['actions']} provisioning actions")
    ui.insight(INSIGHT)
    return {"events": {r.id: r.outcome for r in results}, "states": {r.id: r.calculated for r in results},
            "metrics": m}


def _spec(spec) -> str:
    return "all sources" if spec == ALL else (", ".join(spec) if spec else "-")


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies[SECTION]
    results = process_all(data, cfg)
    raw = {e.get("id"): e for e in data.get("events", [])}
    today = data.get("today")
    qs: list = []

    def ctx(r: EventResult) -> str:
        e = raw.get(r.id, {})
        return (f"today={e.get('today', today)} profile={r.profile} current={r.previous or 'none'} "
                f"HR={e.get('hr')}" + (f" accounts={e['accounts']}" if e.get("accounts") else ""))

    for r in results:
        qs.append(Question(prompt=f"{r.id} ({r.event.replace('_', ' ')}): what is the result for {r.identity}?",
                           context=ctx(r), choices=list(OUTCOMES), answer=r.outcome,
                           explanation="; ".join(r.reasons), objective="3.3"))
    rule_seen = set()
    state_pool = sorted(set(STATES) | {r.calculated for r in results})
    for r in results:
        if r.calc_rule in rule_seen:
            continue
        rule_seen.add(r.calc_rule)
        qs.append(Question(prompt=f"{r.id}: which cloudLifecycleState value does the calculation produce?",
                           context=f"today={raw.get(r.id, {}).get('today', today)} HR={raw.get(r.id, {}).get('hr')}",
                           choices=choices_with(r.calculated, state_pool, k=4, key=r.id), answer=r.calculated,
                           explanation=r.reasons[0], objective="3.3"))
    all_actions = sorted({a for r in results for a in r.actions})
    act_seen = set()
    for r in results:
        if not r.actions or r.calculated in act_seen:
            continue
        pool = [a for a in all_actions if a not in r.actions]
        if len(pool) < 3:
            continue
        act_seen.add(r.calculated)
        ans = r.actions[0]
        qs.append(Question(prompt=f"{r.id}: {r.identity} moves from '{r.previous or 'none'}' to '{r.calculated}'. "
                                  "Which provisioning action does this change trigger?",
                           context=ctx(r), choices=choices_with(ans, pool, key=r.id), answer=ans,
                           explanation="entering the state runs exactly its configured actions: " + "; ".join(r.actions),
                           objective="4.1"))
    qs.append(Question(prompt="An identity refresh recalculates the same lifecycle state the identity already has. "
                              "What does the lifecycle state provision?",
                       choices=["nothing: lifecycle actions run only when the state changes",
                                "all of the state's actions run again on every refresh",
                                "every access profile is removed and granted again",
                                "only the email notification is sent again"],
                       answer="nothing: lifecycle actions run only when the state changes",
                       explanation="state change is the trigger; an unchanged state triggers no provisioning",
                       objective="4.1"))
    qs.append(Question(prompt="An identity's lifecycle state is changed. Which provisioning happens?",
                       choices=["only the actions configured on the new lifecycle state",
                                "every access profile on the identity profile is granted",
                                "all accounts are deleted and recreated",
                                "the actions of the previous state are reversed automatically"],
                       answer="only the actions configured on the new lifecycle state",
                       explanation="a lifecycle state triggers its own configured grants, removals, account "
                                   "enables/disables and emails, nothing else", objective="4.1"))
    unknown = next((r for r in results if r.outcome == "UNKNOWN_STATE" and r.profile in
                    data.get("identity_profiles", {})), None)
    if unknown:
        qs.append(Question(prompt=f"{unknown.id}: why do no lifecycle actions run for {unknown.identity}?",
                           context=ctx(unknown),
                           choices=["cloudLifecycleState matches no lifecycle state technical name on the profile",
                                    "the identity already has this lifecycle state",
                                    "the lifecycle state has email notifications turned off",
                                    "the HR source was aggregated twice"],
                           answer="cloudLifecycleState matches no lifecycle state technical name on the profile",
                           explanation="; ".join(unknown.reasons), objective="3.3"))
    qs.append(Question(prompt="HR sends a status value the calculation does not recognise. Which state results?",
                       choices=choices_with(cfg["deny_by_default_state"], STATES, k=3, key="unknown"),
                       answer=cfg["deny_by_default_state"],
                       explanation="deny by default: an unrecognised status never becomes active with new access",
                       objective="3.3"))
    for term in ("cloudLifecycleState", "technical name", "identity refresh", "transform"):
        if term in cfg["concepts"]:
            qs.append(Question(prompt=f"Which term is this? \"{cfg['concepts'][term]}\"",
                               choices=choices_with(term, cfg["concepts"], key=term), answer=term,
                               explanation=cfg["concepts"][term],
                               objective="4.1" if term == "identity refresh" else "3.3"))
    return qs


# --------------------------------------------------------------------------- #
# Seeded scenario generator
# --------------------------------------------------------------------------- #
_FIRST = ["Amara", "Bastien", "Chiara", "Dmitri", "Esme", "Farid", "Greta", "Hiroshi", "Ines", "Jonas", "Keziah",
          "Lorcan", "Mireille", "Nnamdi", "Oona", "Pavel", "Quinn", "Rosalind", "Soren", "Tamsin"]
_LAST = ["Achterberg", "Bramwell", "Castellanos", "Duvall", "Eklund", "Fairbairn", "Gallagher", "Halvorsen",
         "Ibekwe", "Jaramillo", "Kowalczyk", "Lindqvist", "Moreau", "Nakagawa", "Okafor", "Petrakis"]
_EXTRA_SOURCES = ["Salesforce", "ServiceNow", "Concur", "GitHub Enterprise", "Zendesk"]


def base_profiles() -> dict:
    """Two identity profiles: a well-built employee profile and a contractor profile with gaps."""
    def st(name, tech, ident, grant=(), remove=(), enable=(), disable=(), notify=()):
        return {"name": name, "technical_name": tech, "identity_state": ident, "grant_access_profiles": list(grant),
                "remove_access_profiles": list(remove), "enable_accounts": enable if enable == ALL else list(enable),
                "disable_accounts": disable if disable == ALL else list(disable),
                "notify": {"enabled": bool(notify), "recipients": list(notify)}}
    core = ["Active Directory", "Microsoft Entra ID"]
    return {
        "Employees": {"source": "PeopleCore HR", "lifecycle_states": [
            st("Pre-Hire", "prehire", "ACTIVE", grant=["Birthright - Onboarding Portal"], notify=["manager"]),
            st("Active", "active", "ACTIVE", grant=["Birthright - All Staff"], enable=ALL,
               notify=["manager", "identity"]),
            st("Leave of Absence", "leave", "INACTIVE_SHORT_TERM", disable=core, notify=["manager"]),
            st("Terminated", "terminated", "INACTIVE_LONG_TERM",
               remove=["Birthright - All Staff", "Birthright - Onboarding Portal"], disable=ALL,
               notify=["manager", "admins"]),
            st("Inactive", "inactive", "INACTIVE_LONG_TERM", remove=["Birthright - All Staff"], disable=core),
        ]},
        "Contractors": {"source": "VendorLink Contractors", "lifecycle_states": [
            st("Pre-Hire", "prehire", "ACTIVE", grant=["Birthright - Onboarding Portal",
                                                       "Engineering - Production Support"],
               enable=["Active Directory", "GitHub Enterprise"], notify=["manager"]),
            st("Active", "active", "ACTIVE", grant=["Birthright - Contractor"], enable=ALL, notify=["manager"]),
            st("Leave of Absence", "loa", "INACTIVE_SHORT_TERM", disable=ALL),
            st("Terminated", "terminated", "INACTIVE_LONG_TERM", notify=["manager"]),
        ]},
    }


def generate_scenario(rng, policies: dict) -> dict:
    cfg = policies[SECTION]
    today = date(2026, 1, 1) + timedelta(days=rng.randint(0, 600))
    extra = rng.choice(_EXTRA_SOURCES)
    names = iter(f"{f} {l}" for f, l in rng.sample([(f, l) for f in _FIRST for l in _LAST], 20))
    window = cfg["post_termination_days"]

    def d(offset: int) -> str:
        return (today + timedelta(days=offset)).isoformat()

    core = ["Active Directory", "Microsoft Entra ID"]
    events = []

    def add(event, profile, prev, hr, accounts=None):
        e = {"id": f"EV-{len(events) + 1:02d}", "identity": next(names), "identity_profile": profile,
             "event": event, "previous_state": prev, "hr": hr}
        if accounts is not None:
            e["accounts"] = accounts
        events.append(e)

    add("new_hire", "Employees", None, {"status": "active", "start_date": d(rng.randint(3, 40))})
    add("start_date_reached", "Employees", "prehire", {"status": "active", "start_date": d(-rng.randint(0, 3))},
        accounts=core)
    add("leave_of_absence", "Employees", "active", {"status": "leave", "start_date": d(-rng.randint(200, 900))},
        accounts=core + [extra])
    add("termination", "Employees", "active", {"status": "terminated", "start_date": d(-rng.randint(400, 2000)),
                                               "end_date": d(-rng.randint(0, window))}, accounts=core + [extra])
    add("rehire", "Employees", "inactive", {"status": "active", "start_date": d(-rng.randint(0, 5)),
                                            "end_date": d(-rng.randint(200, 700))}, accounts=core)
    add("unknown_hr_status", "Employees", "active",
        {"status": rng.choice(["suspended_pending", "SUSP", "transfer?"]), "start_date": d(-rng.randint(100, 900))},
        accounts=core + [extra])
    add("attribute_change", "Employees", "active", {"status": "active", "start_date": d(-rng.randint(30, 900))},
        accounts=core)
    add("post_termination", "Employees", "terminated",
        {"status": "terminated", "start_date": d(-1500), "end_date": d(-rng.randint(window + 1, window + 90))},
        accounts=core)
    add("new_hire", "Contractors", None, {"status": "hired", "start_date": d(rng.randint(5, 30))})
    add("leave_of_absence", "Contractors", "active", {"status": "leave", "start_date": d(-rng.randint(60, 400))},
        accounts=["Active Directory", "GitHub Enterprise"])
    add("termination", "Contractors", "active", {"status": "terminated", "start_date": d(-rng.randint(60, 400)),
                                                 "end_date": d(-rng.randint(0, 5))}, accounts=["Active Directory",
                                                                                              "GitHub Enterprise"])
    add("unknown_hr_status", "Contractors", "active", {"start_date": d(-rng.randint(30, 300))})
    if rng.random() < 0.5:
        add("termination", "Employees", "active", {"status": "active", "start_date": d(-rng.randint(300, 900)),
                                                   "end_date": d(-rng.randint(1, window))}, accounts=core)
    rng.shuffle(events)
    for i, e in enumerate(events, 1):
        e["id"] = f"EV-{i:02d}"
    return {"_description": "Generated lifecycle state scenario for a fictional company.",
            "today": today.isoformat(), "identity_profiles": base_profiles(), "events": events}
