"""
Lab 31 — Identity Monitoring: Sign-in Logs, ID Protection Risk & Detections
===========================================================================

SC-300 objectives
-----------------
* 4.4  Monitor identity activity by using logs, workbooks and reports:
       sign-in logs and audit logs, result codes, routing logs to a Log
       Analytics workspace with diagnostic settings, KQL queries and workbooks.
* 2.3  Manage risk by using Microsoft Entra ID Protection: user risk and
       sign-in risk, risk-based responses (require MFA, require a secure
       password change, confirm compromised, block and revoke sessions).

How it works
------------
You are the identity operations analyst reading one day of Microsoft Entra
sign-in logs and audit logs. Rules run in this order:

1. **Data quality first.** A sign-in record with no timestamp (or one that
   cannot be parsed) or no IP address is reported as UNVERIFIABLE_RECORD. It
   is left out of the time-window detections (it cannot be placed in a window)
   and it is never silently trusted: its user cannot be closed as NO_ACTION.
2. **Detections over time windows**, with thresholds from the policy:
   * PASSWORD_SPRAY: one IP address, password failures (ResultType 50126 or
     50053) against at least N distinct users inside the window.
   * BRUTE_FORCE: one user, at least N password failures inside the window.
   * MFA_FATIGUE: one user, at least N denied or unanswered MFA prompts
     (ResultType 500121) inside the window AND a successful sign-in after them
     inside the same window: the attacker has the password and got in.
   * LEGACY_AUTH_USE: any sign-in attempt over a legacy client protocol
     (IMAP4, POP3, Authenticated SMTP, Exchange ActiveSync, Other clients...).
   * IMPOSSIBLE_TRAVEL: two consecutive sign-ins where the password was
     correct (success or an MFA step), in different countries, at a speed
     above the policy limit. An unknown country cannot be checked and is said so.
   * PRIVILEGED_ROLE_ADDED (audit log): a role-assignment activity for a
     privileged role; a missing role name is treated as privileged.
3. **Risk-based response per user** (ID Protection policy, first match wins):
   1. confirmed compromised by the security team, or a compromise detection
      (MFA_FATIGUE) → BLOCK_AND_REVOKE_SESSIONS;
   2. high user risk → REQUIRE_SECURE_PASSWORD_CHANGE;
   3. medium or high sign-in risk → REQUIRE_MFA;
   4. an unverifiable record → REQUIRE_MFA (deny by default);
   5. otherwise → NO_ACTION.
   A missing or unknown risk level (for example "hidden") is treated as high.

Run it
------
    python main.py --course sc300 lab 31
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

TITLE = "Lab 31 — Identity Monitoring: Sign-in Logs, ID Protection Risk & Detections"
OBJECTIVES = "SC-300 4.4 Monitor identity activity: logs, workbooks, reports · 2.3 Manage risk with ID Protection"
COURSES = ("sc300",)

DETECTIONS = ["PASSWORD_SPRAY", "BRUTE_FORCE", "MFA_FATIGUE", "LEGACY_AUTH_USE", "IMPOSSIBLE_TRAVEL",
              "PRIVILEGED_ROLE_ADDED"]
RESPONSES = ["BLOCK_AND_REVOKE_SESSIONS", "REQUIRE_SECURE_PASSWORD_CHANGE", "REQUIRE_MFA", "NO_ACTION"]
DATA_QUALITY = "UNVERIFIABLE_RECORD"
RULES = {
    "confirmed": "confirmed compromised (block and revoke)",
    "compromise_detection": "compromise detection (block and revoke)",
    "user_risk": "high user risk (secure password change)",
    "signin_risk": "medium or high sign-in risk (MFA)",
    "unverifiable": "unverifiable log record (deny by default)",
    "none": "no risk and no finding (no action)",
}


@dataclass
class Detection:
    type: str
    subject: str                       # IP address, user or audit record id
    users: list[str]
    records: list[str]
    reasons: list[str] = field(default_factory=list)


@dataclass
class UserResponse:
    user: str
    response: str
    rule: str
    user_risk: str
    signin_risk: str
    detections: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def parse_time(value) -> datetime | None:
    """ISO 8601 → aware datetime; None when missing or unparseable (never guessed)."""
    if not value or not isinstance(value, str):
        return None
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def code_of(s: dict) -> str:
    return str(s.get("result", "")).strip()


def risk_of(value, cfg: dict) -> tuple[str, str | None]:
    """(level, note). Missing or unknown levels are treated as the policy's unknown level (high)."""
    level = str(value).lower() if value is not None else None
    if level in cfg["risk_levels"]:
        return level, None
    return cfg["unknown_risk_level"], f"risk level '{value}' is missing or unknown: treated as {cfg['unknown_risk_level']}"


def km_between(a, b) -> float:
    (la1, lo1), (la2, lo2) = [tuple(map(math.radians, p)) for p in (a, b)]
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 2 * 6371 * math.asin(math.sqrt(h))


# --------------------------------------------------------------------------- #
# Step 1 — data quality
# --------------------------------------------------------------------------- #
def check_records(signins: list[dict]) -> tuple[list[dict], dict[str, list[str]]]:
    """Split sign-ins into trusted (with parsed ``_t``) and unverifiable {id: reasons}."""
    good, bad = [], {}
    for s in signins:
        why = []
        if parse_time(s.get("time")) is None:
            why.append("no timestamp" if not s.get("time") else f"timestamp '{s.get('time')}' cannot be parsed")
        if not s.get("ip"):
            why.append("no IP address")
        if why:
            bad[s.get("id", "?")] = why + ["record reported, excluded from window detections, not trusted"]
        else:
            good.append({**s, "_t": parse_time(s["time"])})
    good.sort(key=lambda s: (s["_t"], s.get("id", "")))
    return good, bad


def _windows(events: list[dict], minutes: int):
    """Yield each event-anchored window [t, t + minutes] as a list (events sorted by time)."""
    span = timedelta(minutes=minutes)
    for i, e in enumerate(events):
        yield [x for x in events[i:] if x["_t"] - e["_t"] <= span]


# --------------------------------------------------------------------------- #
# Step 2 — detections
# --------------------------------------------------------------------------- #
def detect_spray(good: list[dict], cfg: dict) -> list[Detection]:
    p, out = cfg["password_spray"], []
    fails = [s for s in good if code_of(s) in cfg["password_failure_codes"]]
    for ip in sorted({s["ip"] for s in fails}):
        best = max((w for w in _windows([s for s in fails if s["ip"] == ip], p["window_minutes"])),
                   key=lambda w: len({s.get("user") for s in w}))
        users = sorted({s.get("user") for s in best})
        if len(users) >= p["min_distinct_users"]:
            out.append(Detection("PASSWORD_SPRAY", ip, users, [s["id"] for s in best],
                                 [f"{ip}: password failures against {len(users)} distinct users within "
                                  f"{p['window_minutes']} min (threshold {p['min_distinct_users']})"]))
    return out


def detect_brute_force(good: list[dict], cfg: dict) -> list[Detection]:
    p, out = cfg["brute_force"], []
    fails = [s for s in good if code_of(s) in cfg["password_failure_codes"]]
    for user in sorted({s.get("user") for s in fails}):
        best = max(_windows([s for s in fails if s.get("user") == user], p["window_minutes"]), key=len)
        if len(best) >= p["min_failures"]:
            ips = sorted({s["ip"] for s in best})
            out.append(Detection("BRUTE_FORCE", user, [user], [s["id"] for s in best],
                                 [f"{user}: {len(best)} password failures within {p['window_minutes']} min "
                                  f"(threshold {p['min_failures']}) from {', '.join(ips)}"]))
    return out


def detect_mfa_fatigue(good: list[dict], cfg: dict) -> list[Detection]:
    p, out = cfg["mfa_fatigue"], []
    span = timedelta(minutes=p["window_minutes"])
    for user in sorted({s.get("user") for s in good}):
        mine = [s for s in good if s.get("user") == user]
        prompts = [s for s in mine if code_of(s) in cfg["mfa_failure_codes"]]
        for w in (_windows(prompts, p["window_minutes"]) if prompts else []):
            if len(w) < p["min_failed_prompts"]:
                continue
            ok = [s for s in mine if code_of(s) in cfg["success_codes"]
                  and w[-1]["_t"] < s["_t"] <= w[0]["_t"] + span]
            if ok:
                out.append(Detection("MFA_FATIGUE", user, [user], [s["id"] for s in w] + [ok[0]["id"]],
                                     [f"{user}: {len(w)} denied or unanswered MFA prompts then a success "
                                      f"({ok[0]['id']}) within {p['window_minutes']} min"]))
                break
    return out


def detect_legacy(good: list[dict], cfg: dict) -> list[Detection]:
    out = []
    legacy = [s for s in good if s.get("client_app") not in cfg["modern_client_apps"]]
    for user in sorted({s.get("user") for s in legacy}):
        mine = [s for s in legacy if s.get("user") == user]
        apps = sorted({str(s.get("client_app") or "missing") for s in mine})
        unknown = [a for a in apps if a not in cfg["legacy_client_apps"]]
        out.append(Detection("LEGACY_AUTH_USE", user, [user], [s["id"] for s in mine],
                             [f"{user}: {len(mine)} attempt(s) over {', '.join(apps)} (cannot do MFA)"]
                             + [f"client app {', '.join(unknown)} is not a known modern client: treated as legacy"
                                for _ in unknown[:1]]))
    return out


def detect_travel(good: list[dict], cfg: dict) -> tuple[list[Detection], list[str]]:
    coords, limit, out, notes = cfg["country_coordinates"], cfg["impossible_travel"]["max_kmh"], [], []
    auth = [s for s in good if code_of(s) in cfg["travel_result_codes"]]
    for user in sorted({s.get("user") for s in auth}):
        mine = [s for s in auth if s.get("user") == user]
        for a, b in zip(mine, mine[1:]):
            if a.get("country") == b.get("country"):
                continue
            if a.get("country") not in coords or b.get("country") not in coords:
                notes.append(f"{user} {a['id']}→{b['id']}: country unknown, travel cannot be checked")
                continue
            km = km_between(coords[a["country"]], coords[b["country"]])
            hours = (b["_t"] - a["_t"]).total_seconds() / 3600
            kmh = math.inf if hours == 0 else km / hours
            if kmh > limit:
                out.append(Detection("IMPOSSIBLE_TRAVEL", user, [user], [a["id"], b["id"]],
                                     [f"{user}: {a['country']} → {b['country']} {round(km)} km in "
                                      f"{round(hours * 60)} min = {'instant' if kmh == math.inf else round(kmh)} "
                                      f"km/h > {limit} km/h"]))
    return out, notes


def detect_roles(audits: list[dict], cfg: dict) -> list[Detection]:
    out = []
    for a in audits:
        if a.get("activity") not in cfg["role_assignment_activities"]:
            continue
        role = a.get("role")
        if role and role not in cfg["privileged_roles"]:
            continue
        why = (f"'{a.get('activity')}': {role} to {a.get('target')} by {a.get('actor') or 'unknown actor'}"
               if role else f"'{a.get('activity')}' with no role name: treated as privileged (deny by default)")
        if not parse_time(a.get("time")):
            why += "; audit record has no valid timestamp"
        out.append(Detection("PRIVILEGED_ROLE_ADDED", a.get("id", "?"), [a.get("target") or "?"], [a.get("id", "?")],
                             [why]))
    return out


def detect_all(data: dict, cfg: dict) -> tuple[list[Detection], dict[str, list[str]], list[str]]:
    good, bad = check_records(data.get("signins", []))
    travel, notes = detect_travel(good, cfg)
    dets = (detect_spray(good, cfg) + detect_brute_force(good, cfg) + detect_mfa_fatigue(good, cfg)
            + detect_legacy(good, cfg) + travel + detect_roles(data.get("audit_logs", []), cfg))
    return dets, bad, notes


# --------------------------------------------------------------------------- #
# Step 3 — risk-based response
# --------------------------------------------------------------------------- #
def respond(data: dict, cfg: dict, detections=None, bad=None) -> list[UserResponse]:
    rp, order = cfg["response_policy"], cfg["risk_levels"]
    if detections is None:
        detections, bad, _ = detect_all(data, cfg)
    signins = data.get("signins", [])
    confirmed = set(data.get("confirmed_compromised", []))
    users = sorted({s.get("user") or "?" for s in signins} | confirmed)
    out = []
    for u in users:
        mine = [s for s in signins if (s.get("user") or "?") == u]
        notes, worst = [], {"user_risk": "none", "signin_risk": "none"}
        for s in mine:
            for key in worst:
                lvl, note = risk_of(s.get(key), cfg)
                if note:
                    notes.append(f"{s.get('id')}: {key.replace('_', ' ')} {note}")
                if order.index(lvl) > order.index(worst[key]):
                    worst[key] = lvl
        ur, sr = worst["user_risk"], worst["signin_risk"]
        mine_dets = [d for d in detections if u in d.users]
        dtypes = sorted({d.type for d in mine_dets}, key=DETECTIONS.index)
        unver = [s.get("id", "?") for s in mine if s.get("id", "?") in (bad or {})]
        compromise = [d for d in dtypes if d in rp["compromise_detections"]]
        if u in confirmed:
            rule, resp, why = "confirmed", "BLOCK_AND_REVOKE_SESSIONS", [
                "confirmed compromised by the security team: block sign-in and revoke all refresh tokens"]
        elif compromise:
            rule, resp, why = "compromise_detection", "BLOCK_AND_REVOKE_SESSIONS", [
                f"{', '.join(compromise)}: attacker holds the password and a session; block and revoke sessions"]
        elif ur in rp["user_risk_for_password_change"]:
            rule, resp, why = "user_risk", "REQUIRE_SECURE_PASSWORD_CHANGE", [
                f"user risk is {ur}: require MFA then a secure password change to remediate"]
        elif sr in rp["signin_risk_for_mfa"]:
            rule, resp, why = "signin_risk", "REQUIRE_MFA", [f"sign-in risk is {sr}: require MFA to remediate"]
        elif unver:
            rule, resp, why = "unverifiable", rp["unverifiable_record_response"], [
                f"record(s) {', '.join(unver)} cannot be verified (missing timestamp or IP): not trusted, "
                f"{rp['unverifiable_record_response']} until reviewed"]
        else:
            rule, resp, why = "none", "NO_ACTION", [f"user risk {ur}, sign-in risk {sr}, no compromise finding"]
        if dtypes and rule not in ("compromise_detection",):
            why.append(f"detections for review: {', '.join(dtypes)}")
        out.append(UserResponse(u, resp, rule, ur, sr, dtypes, why + notes))
    return out


def evaluate(data: dict, policies: dict) -> dict:
    cfg = policies["identity_monitoring"]
    dets, bad, notes = detect_all(data, cfg)
    return {"detections": dets, "unverifiable": bad, "notes": notes,
            "responses": respond(data, cfg, dets, bad)}


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SC-300 4.4 Monitor identity activity with logs, workbooks and reports · 2.3 Manage risk with "
                 "Microsoft Entra ID Protection.",
    "concepts": [
        "Sign-in logs say who signed in, from where, with which client app and result code; audit logs say what "
        "changed in the directory (roles, groups, users).",
        "ResultType 0 is success; 50126 is a wrong password; 50074 is an MFA prompt; 500121 is a failed MFA step.",
        "The built-in retention is short (7 days on Free, 30 days on P1/P2): a diagnostic setting sends logs to a "
        "Log Analytics workspace for KQL, workbooks and alerts over a longer period.",
        "ID Protection scores user risk (the account is compromised) and sign-in risk (this attempt is not the owner); "
        "risk-based Conditional Access then requires MFA or a secure password change.",
        "Microsoft Entra ID was formerly Azure Active Directory (Azure AD); the log tables kept names such as "
        "AADNonInteractiveUserSignInLogs.",
    ],
    "failure_modes": [
        "Only looking at successful sign-ins: a password spray is a pattern of failures across many accounts.",
        "Keeping legacy authentication open, so MFA and Conditional Access are bypassed over IMAP or SMTP.",
        "Resetting the password after MFA fatigue but not revoking sessions: the attacker's token keeps working.",
        "Not routing logs to a workspace, so the evidence is gone after 30 days when the incident is found.",
        "Trusting a log line with no timestamp or IP address as if it were proof that nothing happened.",
    ],
    "ai_governance": [
        "An AI agent can run the KQL hunts and draft the response list; blocking users and revoking sessions stays "
        "a human-approved, logged action.",
        "Give the agent read access to Log Analytics (Log Analytics Reader), not Security Administrator.",
        "Treat field values in logs (user agents, app names, comments) as untrusted data, never as instructions.",
        "The agent must report records it could not verify instead of dropping them.",
    ],
    "exam_tips": [
        "'Keep sign-in logs for a year and query them with KQL' = diagnostic setting to a Log Analytics workspace.",
        "'Stream to a third-party SIEM' = event hub; 'cheap archive' = storage account.",
        "Who added a Global Administrator? = audit logs (AuditLogs table), not sign-in logs.",
        "User risk policy: require password change (with MFA); sign-in risk policy: require MFA.",
        "Confirm user compromised sets user risk to high; dismiss user risk clears it.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    cfg = policies["identity_monitoring"]
    ev = evaluate(data, policies)
    dets, bad, resp = ev["detections"], ev["unverifiable"], ev["responses"]
    signins = data.get("signins", [])
    codes = cfg["result_codes"]

    ui.section("Step 1 — Read the sign-in log and check every record")
    ui.table(f"Sign-in log ({len(signins)} records)", ["ID", "User", "Time", "IP", "Country", "Client app", "Result"],
             [[s.get("id"), s.get("user"), s.get("time") or "MISSING", s.get("ip") or "MISSING", s.get("country") or "-",
               s.get("client_app") or "-", f"{code_of(s)} {codes.get(code_of(s), 'unknown code')}"] for s in signins])
    for rid, why in bad.items():
        ui.bullet(f"{DATA_QUALITY} {rid}: " + "; ".join(why), style="yellow")
    if not bad:
        ui.bullet("every record has a timestamp and an IP address", style="green")

    ui.section("Step 2 — Detections over time windows (sign-in and audit logs)")
    ui.table("Detections", ["Detection", "Subject", "Users", "Records", "Table / column"],
             [[d.type, d.subject, ", ".join(d.users), ", ".join(d.records),
               f"{cfg['detection_queries'][d.type]['table']}.{cfg['detection_queries'][d.type]['column']}"]
              for d in dets])
    for d in dets:
        ui.bullet(f"{d.type}: " + "; ".join(d.reasons), style="red")
    for n in ev["notes"]:
        ui.bullet(n, style="yellow")
    for t in sorted({d.type for d in dets}, key=DETECTIONS.index):
        ui.print(f"  KQL {t}: {cfg['detection_queries'][t]['kql']}", style="dim")

    ui.section("Step 3 — ID Protection risk-based response per user")
    ui.table("Responses", ["User", "User risk", "Sign-in risk", "Detections", "Response"],
             [[r.user, r.user_risk, r.signin_risk, ", ".join(r.detections) or "-", r.response] for r in resp])
    for r in resp:
        ui.bullet(f"{r.user} → {r.response}: " + "; ".join(r.reasons),
                  style={"NO_ACTION": "green", "REQUIRE_MFA": "yellow"}.get(r.response, "red"))

    ui.section("Step 4 — Keep the evidence: route logs with a diagnostic setting")
    for dest, use in cfg["log_routing"].items():
        ui.bullet(f"{dest}: {use}")
    ui.print("Built-in retention: " + ", ".join(f"{k} {v} days" for k, v in cfg["builtin_retention_days"].items()))

    counts = {o: sum(r.response == o for r in resp) for o in RESPONSES}
    dcounts = {t: sum(d.type == t for d in dets) for t in DETECTIONS}
    ui.print(f"Records {len(signins)} · unverifiable {len(bad)} · detections {len(dets)} · users {len(resp)} · "
             + " · ".join(f"{k} {v}" for k, v in counts.items()))
    ui.insight(INSIGHT)
    return {"responses": {r.user: r.response for r in resp},
            "detections": [{"type": d.type, "subject": d.subject, "users": d.users} for d in dets],
            "unverifiable": sorted(bad),
            "metrics": {"records": len(signins), "audit_records": len(data.get("audit_logs", [])),
                        "users": len(resp), "detections": len(dets), "unverifiable": len(bad),
                        "response_counts": counts, "detection_counts": dcounts}}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def _short(s: dict, cfg: dict) -> str:
    c = code_of(s)
    return (f"{s.get('id')} {s.get('time') or 'NO-TIME'} ip={s.get('ip') or 'NO-IP'} {s.get('country') or '-'} "
            f"{s.get('client_app')} result={c} ({cfg['result_codes'].get(c, 'unknown')}) "
            f"mfa={s.get('mfa_detail') or '-'} user_risk={s.get('user_risk')} signin_risk={s.get('signin_risk')}")


def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["identity_monitoring"]
    ev = evaluate(data, policies)
    dets, bad, resp = ev["detections"], ev["unverifiable"], ev["responses"]
    signins = data.get("signins", [])
    by_id = {s.get("id"): s for s in signins}
    by_id.update({a.get("id"): a for a in data.get("audit_logs", [])})
    confirmed = data.get("confirmed_compromised", [])
    qs: list = []

    # Predict the response for every user, then "which rule decided" for one user per rule.
    seen_rules = set()
    for r in resp:
        ctx = "\n".join(_short(s, cfg) for s in signins if (s.get("user") or "?") == r.user)
        ctx += f"\nconfirmed compromised list: {confirmed or 'empty'}; detections: {', '.join(r.detections) or 'none'}"
        qs.append(Question(prompt=f"{r.user}: what is the risk-based response?", context=ctx, choices=RESPONSES,
                           answer=r.response, explanation="; ".join(r.reasons), objective="2.3"))
        if r.rule not in seen_rules:
            seen_rules.add(r.rule)
            qs.append(Question(prompt=f"{r.user}: which response rule decided the outcome (first match wins)?",
                               context=ctx, choices=list(RULES.values()), answer=RULES[r.rule],
                               explanation=r.reasons[0], objective="2.3"))

    # Which detection fires for this evidence?
    for t in DETECTIONS:
        d = next((x for x in dets if x.type == t), None)
        if not d:
            continue
        ev_lines = [(_short(by_id[i], cfg) if "user" in by_id.get(i, {}) else f"audit {by_id.get(i)}")
                    for i in d.records if i in by_id]
        also = {x.type for x in dets if set(x.records) & set(d.records)} - {t}
        qs.append(Question(prompt=f"Which detection do these records trigger (subject {d.subject})?",
                           context="\n".join(ev_lines), choices=choices_with(t, DETECTIONS, exclude=also, key=d.subject),
                           answer=t, explanation="; ".join(d.reasons), objective="4.4"))
        q = cfg["detection_queries"][t]
        qs.append(Question(prompt=f"To hunt for {t.replace('_', ' ').lower()} in Log Analytics, which table do you query?",
                           choices=sorted(cfg["log_tables"]), answer=q["table"],
                           explanation=f"{q['table']}: {cfg['log_tables'][q['table']]}. Example: {q['kql']}",
                           objective="4.4"))

    # Threshold edge: which IP is a password spray?
    spray = [d for d in dets if d.type == "PASSWORD_SPRAY"]
    fail_ips = sorted({s["ip"] for s in signins if s.get("ip") and code_of(s) in cfg["password_failure_codes"]})
    if len(spray) == 1 and len(fail_ips) > 1:
        qs.append(Question(prompt="Several IP addresses have password failures. Which one is a password spray?",
                           choices=choices_with(spray[0].subject, fail_ips, key="spray"), answer=spray[0].subject,
                           explanation=spray[0].reasons[0] + f"; others stay under "
                           f"{cfg['password_spray']['min_distinct_users']} distinct users in the window",
                           objective="4.4"))

    # Data quality.
    for rid, why in list(bad.items())[:1]:
        qs.append(Question(prompt=f"Record {rid} is missing data ({why[0]}). How is it handled?",
                           context=_short(by_id[rid], cfg),
                           choices=["reported as unverifiable, kept out of window detections and not trusted",
                                    "silently dropped because it cannot be analysed",
                                    "trusted, using the time of the previous record",
                                    "treated as proof the user is compromised"],
                           answer="reported as unverifiable, kept out of window detections and not trusted",
                           explanation="; ".join(why), objective="4.4"))

    # Log and KQL concepts.
    for col in ("ResultType", "ClientAppUsed"):
        qs.append(Question(prompt=f"Which SigninLogs column holds {cfg['signin_columns'][col]}?",
                           choices=sorted(cfg["signin_columns"]), answer=col,
                           explanation=f"{col}: {cfg['signin_columns'][col]}", objective="4.4"))
    for code in ("50126", "500121"):
        desc = cfg["result_codes"][code]
        qs.append(Question(prompt=f"A sign-in has ResultType {code}. What does it mean?",
                           choices=sorted(set(cfg["result_codes"].values())), answer=desc,
                           explanation=f"{code} = {desc}", objective="4.4"))
    qs.append(Question(prompt="Which log shows who assigned the Global Administrator role to an account?",
                       choices=sorted(cfg["log_tables"]), answer="AuditLogs",
                       explanation=f"AuditLogs: {cfg['log_tables']['AuditLogs']}", objective="4.4"))
    for dest, use in cfg["log_routing"].items():
        qs.append(Question(prompt=f"In a diagnostic setting, which destination do you pick to {use}?",
                           choices=sorted(cfg["log_routing"]), answer=dest, explanation=f"{dest}: {use}",
                           objective="4.4"))
    ret = cfg["builtin_retention_days"]
    p12 = "Microsoft Entra ID P1 or P2"
    qs.append(Question(prompt=f"How long does a tenant with {p12} keep sign-in logs before you route them elsewhere?",
                       choices=sorted({f"{v} days" for v in ret.values()} | {"90 days", "365 days"}),
                       answer=f"{ret[p12]} days",
                       explanation="; ".join(f"{k}: {v} days" for k, v in ret.items())
                       + "; route to a Log Analytics workspace to keep them longer", objective="4.4"))
    # ID Protection concepts.
    for term, definition in sorted(cfg["concepts"].items()):
        qs.append(Question(prompt=f"Which term is this? \"{definition}\"",
                           choices=choices_with(term, cfg["concepts"], k=3, key=term), answer=term,
                           explanation=f"{term}: {definition}",
                           objective="4.4" if term in ("diagnostic setting", "password spray", "legacy authentication")
                           else "2.3"))
    return qs


# --------------------------------------------------------------------------- #
# Seeded scenario generator
# --------------------------------------------------------------------------- #
FIRST = ["amira", "bruno", "carmen", "dmitri", "elena", "felix", "greta", "hamid", "irene", "jamal", "kirsten",
         "luis", "maya", "nils", "oona", "pavel", "rhea", "sven", "tara", "umar"]
LAST = ["adler", "brook", "castell", "dunmore", "everly", "farrow", "galloway", "hale", "ives", "jansen"]


def generate_scenario(rng, policies: dict) -> dict:
    cfg = policies["identity_monitoring"]
    dom = rng.choice(["fabrikam-demo.example", "tailspin-demo.example", "harbor-demo.example"])
    names = rng.sample(FIRST, 11)
    users = [f"{n}.{rng.choice(LAST)}@{dom}" for n in names]
    base = datetime(2026, 10, rng.randint(1, 28), 1, 0, tzinfo=timezone.utc)
    recs: list[dict] = []

    def add(user, minutes, ip, country, result, client="Browser", app="Office 365 Exchange Online",
            mfa=None, ur="low", sr="low", **extra):
        rec = {"id": "", "user": user, "time": (base + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "ip": ip, "country": country, "app": app, "client_app": client, "result": result,
               "mfa_detail": mfa, "user_risk": ur, "signin_risk": sr}
        rec.update(extra)
        recs.append(rec)

    home = "NL"
    office = f"192.0.2.{rng.randint(10, 60)}"
    spray_ip, brute_ip, att_ip = (f"203.0.113.{rng.randint(1, 250)}", f"198.51.100.{rng.randint(1, 250)}",
                                  f"203.0.113.{rng.randint(1, 250)}")
    # Normal users (NO_ACTION), a few of them spray victims.
    sp = cfg["password_spray"]
    victims = users[:max(sp["min_distinct_users"], 4)]
    t0 = rng.randint(60, 120)
    for i, u in enumerate(victims):
        add(u, t0 + i * rng.randint(1, 5), spray_ip, "SG", "50126", ur="none", sr="none")
        add(u, 400 + i * 10, office, home, "0", client="Mobile Apps and Desktop clients", ur="none", sr="none")
    # Brute force + high user risk.
    bf = users[4]
    for i in range(cfg["brute_force"]["min_failures"] + rng.randint(0, 2)):
        add(bf, 200 + i * 2, brute_ip, "NG", "50126", ur="high", sr="none")
    add(bf, 480, office, home, "0", ur="high", sr="low")
    # MFA fatigue → compromise.
    mf = users[5]
    for i in range(cfg["mfa_fatigue"]["min_failed_prompts"]):
        add(mf, 300 + i * 3, att_ip, "SG", "500121", mfa=rng.choice(["denied", "no response (timed out)"]), ur="low",
            sr="medium")
    add(mf, 300 + cfg["mfa_fatigue"]["min_failed_prompts"] * 3 + 2, att_ip, "SG", "0", mfa="approved (push)",
        ur="low", sr="medium")
    # Impossible travel with high sign-in risk.
    tr = users[6]
    add(tr, 100, office, home, "0", ur="medium", sr="low")
    add(tr, 100 + rng.randint(30, 120), f"198.51.100.{rng.randint(1, 250)}", rng.choice(["BR", "JP", "AU"]), "0",
        ur="medium", sr="high")
    # Legacy authentication, otherwise clean.
    lg = users[7]
    add(lg, 500, office, home, "0", client=rng.choice(["IMAP4", "Authenticated SMTP", "Exchange ActiveSync"]),
        ur="none", sr="none")
    # Unverifiable record.
    uv = users[8]
    add(uv, 520, office, home, "0", ur="low", sr="low")
    add(uv, 530, None, home, "0", ur="low", sr="low")
    # Confirmed compromised with low risk.
    cc = users[9]
    add(cc, 540, office, home, "0", ur="low", sr="low")
    # Medium sign-in risk only.
    md = users[10]
    add(md, 560, office, home, "0", ur="low", sr="medium")
    rng.shuffle(recs)
    recs.sort(key=lambda r: r["time"] or "")
    for i, r in enumerate(recs, 1):
        r["id"] = f"S{i:02d}"
    actor = rng.choice([mf, cc])
    audits = [
        {"id": "AU1", "time": (base + timedelta(minutes=330)).strftime("%Y-%m-%dT%H:%M:%SZ"),
         "activity": "Add member to role", "actor": actor, "target": actor,
         "role": rng.choice(["Global Administrator", "Privileged Role Administrator"])},
        {"id": "AU2", "time": (base + timedelta(minutes=600)).strftime("%Y-%m-%dT%H:%M:%SZ"),
         "activity": "Add member to role", "actor": users[0], "target": users[1], "role": "Reports Reader"},
        {"id": "AU3", "time": (base + timedelta(minutes=610)).strftime("%Y-%m-%dT%H:%M:%SZ"),
         "activity": "Update user", "actor": users[0], "target": users[2], "role": None},
    ]
    return {"_description": f"Generated identity monitoring day for {dom}", "tenant": dom, "signins": recs,
            "audit_logs": audits, "confirmed_compromised": [cc]}
