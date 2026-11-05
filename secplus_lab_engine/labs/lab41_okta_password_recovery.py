"""
Lab 41 — Okta Password Policies, Self-Service Recovery & Sign-In Troubleshooting
================================================================================

Okta Professional objectives
----------------------------
* 4.4  Password policies and self-service recovery: policy priority and group
       assignment, complexity, history, minimum and maximum age, lockout and
       auto-unlock, recovery authenticators and self-service unlock.
* 5.1  Sign-in troubleshooting and session management: reading a user's status,
       failed attempts, password age and enrolled authenticators to find why
       they cannot sign in, and choosing the right admin action.

How it works
------------
You are the Okta administrator for a mid-sized company. Okta Identity Engine
keeps password rules in password policies (Security > Authenticators >
Password). Each policy is assigned to groups and has a priority.

Part 1, which policy applies. Policies are checked from priority 1 downward;
inactive policies are skipped. The first active policy assigned to one of the
user's groups wins (every user is in Everyone, so the Default Policy is the last
match). If nothing matches, a strict fallback policy from the config is used.

Part 2, password change attempts. An unknown user → REJECTED_UNKNOWN_USER (deny
by default). Otherwise every check runs and the first failure, in this order,
is the outcome:

1. TOO_SHORT: fewer characters than ``minLength`` (a missing password is empty).
2. MISSING_CLASS: fewer lowercase, uppercase, number or symbol characters than required.
3. CONTAINS_USERNAME: ``excludeUsername`` is on and the password contains the
   username, or a part of it (split at . - _ @ and similar, parts of 3+ letters).
4. COMMON_PASSWORD: the common-password check is on and the password is on the
   common list (compared without case).
5. IN_HISTORY: the password matches one of the last ``historyCount`` passwords.
   An older password, outside the window, is allowed again.
6. TOO_SOON: the current password is younger than ``minAgeMinutes``. Missing age
   is treated as "just changed".

No failure → ACCEPTED. The outcome is written REJECTED_<rule>.

Part 3, self-service recovery (reset or unlock) → RECOVERY_ALLOWED or
RECOVERY_BLOCKED. Blocked when: the user is unknown; the user's status does not
allow recovery (Suspended, Deactivated, Staged, Pending user action or an unknown
status); the method is unknown or not allowed by the user's policy; the matching
authenticator (email, phone, Okta Verify) is not enrolled; or, for an unlock, the
user is not locked out or the policy does not allow self-service unlock.

Part 4, "user cannot sign in" tickets. Rules, in evaluation order, give a cause
and one admin fix:

1. Unknown or missing status → UNKNOWN_STATUS, ESCALATE (treated as cannot sign
   in; no fix is guessed).
2. Deactivated: offboarded on purpose → OFFBOARDED, NONE; else → DEACTIVATED,
   REACTIVATE (the user returns to Pending user action and must activate again).
3. Suspected compromise → SUSPECTED_COMPROMISE, EXPIRE_PASSWORD_AND_CLEAR_SESSIONS.
4. Suspended → SUSPENDED, UNSUSPEND.
5. Staged → NOT_ACTIVATED, ACTIVATE_USER; Pending user action →
   ACTIVATION_PENDING, ACTIVATE_USER (resend the activation email).
6. Locked out → LOCKED_OUT: NONE if the auto-unlock time has passed or the user
   can self-unlock (policy allows it and an allowed recovery authenticator is
   enrolled); otherwise UNLOCK.
7. Password expired → PASSWORD_EXPIRED, RESET_PASSWORD.
8. Active with a lost phone and Okta Verify or phone enrolled → LOST_AUTHENTICATOR,
   RESET_AUTHENTICATORS.
9. Active with failed attempts: no allowed recovery authenticator enrolled →
   FORGOTTEN_PASSWORD, RESET_PASSWORD; otherwise NONE (the user can use
   "Forgot password?").
10. Active and the password is older than ``maxAgeDays`` → PASSWORD_PAST_MAX_AGE,
    NONE (Okta asks for a new password at the next sign-in).
11. Otherwise → NO_ACCOUNT_ISSUE, NONE (look at app assignment and sign-on policies).

Run it
------
    python main.py --course okta lab 41
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

TITLE = "Lab 41 — Okta Password Policies, Self-Service Recovery & Sign-In Troubleshooting"
OBJECTIVES = ("Okta Professional 4.4 Password policies and self-service recovery · "
              "5.1 Sign-in troubleshooting and session management")
COURSES = ("okta",)
SECTION = "okta_password_recovery"

RULES = ["TOO_SHORT", "MISSING_CLASS", "CONTAINS_USERNAME", "COMMON_PASSWORD", "IN_HISTORY", "TOO_SOON"]
CHANGE_OUTCOMES = ["ACCEPTED"] + [f"REJECTED_{r}" for r in RULES] + ["REJECTED_UNKNOWN_USER"]
RECOVERY_OUTCOMES = ["RECOVERY_ALLOWED", "RECOVERY_BLOCKED"]
FIXES = ["UNLOCK", "RESET_PASSWORD", "EXPIRE_PASSWORD_AND_CLEAR_SESSIONS", "ACTIVATE_USER", "UNSUSPEND",
         "REACTIVATE", "RESET_AUTHENTICATORS", "NONE", "ESCALATE"]
CAUSES = ["UNKNOWN_STATUS", "OFFBOARDED", "DEACTIVATED", "SUSPECTED_COMPROMISE", "SUSPENDED", "NOT_ACTIVATED",
          "ACTIVATION_PENDING", "LOCKED_OUT", "PASSWORD_EXPIRED", "LOST_AUTHENTICATOR", "FORGOTTEN_PASSWORD",
          "PASSWORD_PAST_MAX_AGE", "NO_ACCOUNT_ISSUE"]
CLASSES = [("minLowerCase", "lowercase letter", str.islower), ("minUpperCase", "uppercase letter", str.isupper),
           ("minNumber", "number", str.isdigit), ("minSymbol", "symbol", lambda c: not c.isalnum())]


@dataclass
class ChangeResult:
    id: str
    user: str
    policy: str
    outcome: str
    failures: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


@dataclass
class RecoveryResult:
    id: str
    user: str
    method: str
    purpose: str
    policy: str
    outcome: str
    reasons: list[str] = field(default_factory=list)


@dataclass
class TicketResult:
    id: str
    user: str
    status: str
    cause: str
    fix: str
    can_sign_in: bool
    policy: str
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def password_hash(password: str) -> str:
    """Stand-in for a stored password hash (real Okta stores salted, slow hashes; this only compares)."""
    return hashlib.sha256(str(password).encode("utf-8")).hexdigest()


def find_user(login: str | None, data: dict) -> dict | None:
    for u in data.get("users", []):
        if str(u.get("login", "")).lower() == str(login or "").lower() and login:
            return u
    return None


def policy_for(user: dict | None, data: dict, cfg: dict) -> tuple[dict, list[str]]:
    """First active policy, by priority, assigned to one of the user's groups (Everyone always included)."""
    groups = {cfg["everyone_group"], *((user or {}).get("groups") or [])}
    reasons = []
    for pol in sorted(data.get("password_policies", []), key=lambda p: p.get("priority", 10 ** 6)):
        hit = groups & set(pol.get("groups") or [])
        if not hit:
            continue
        if str(pol.get("status", "ACTIVE")).upper() != "ACTIVE":
            reasons.append(f"'{pol.get('name')}' (priority {pol.get('priority')}) matches {sorted(hit)[0]} "
                           "but is inactive, so it is skipped")
            continue
        reasons.append(f"'{pol.get('name')}' (priority {pol.get('priority')}) is the first active policy "
                       f"assigned to the user's group {sorted(hit)[0]}")
        return pol, reasons
    fb = cfg["fallback_policy"]
    reasons.append(f"no active policy matches the user's groups: the strict fallback '{fb['name']}' applies")
    return fb, reasons


def username_parts(login: str, cfg: dict) -> list[str]:
    local = str(login or "").split("@")[0].lower()
    parts = [local]
    token = ""
    for ch in local:
        if ch in cfg["username_delimiters"]:
            parts.append(token)
            token = ""
        else:
            token += ch
    parts.append(token)
    n = cfg["username_part_min_length"]
    return sorted({p for p in parts if len(p) >= n}, key=lambda p: (-len(p), p))


def history_position(password: str, history: list) -> int | None:
    """1-based position of the password in the stored history (newest first), or None."""
    h = password_hash(password)
    for i, old in enumerate(history or [], 1):
        if old == h:
            return i
    return None


def minutes_since_change(attempt: dict, user: dict) -> float | None:
    if attempt.get("minutes_since_last_change") is not None:
        return float(attempt["minutes_since_last_change"])
    if user.get("password_age_days") is not None:
        return float(user["password_age_days"]) * 1440
    return None


def _enrolled(record: dict) -> set:
    return {str(a).lower() for a in (record.get("enrolled") or [])}


def recovery_options(policy: dict, enrolled: set, cfg: dict) -> list[str]:
    """Recovery methods the policy allows AND the user has the authenticator for."""
    out = []
    for m in (policy.get("recovery") or {}).get("methods") or []:
        meta = cfg["recovery_methods"].get(m)
        if meta and meta["authenticator"] in enrolled:
            out.append(m)
    return out


# --------------------------------------------------------------------------- #
# Part 2 — password change attempts
# --------------------------------------------------------------------------- #
def evaluate_change(attempt: dict, data: dict, cfg: dict) -> ChangeResult:
    aid, login = attempt.get("id", "?"), attempt.get("user")
    user = find_user(login, data)
    if user is None:
        return ChangeResult(aid, login or "-", "-", "REJECTED_UNKNOWN_USER",
                            ["UNKNOWN_USER"], [f"user '{login}' is not in the directory: rejected (deny by default)"])
    pol, reasons = policy_for(user, data, cfg)
    cx, age = pol.get("complexity") or {}, pol.get("age") or {}
    pw = attempt.get("new_password")
    if not isinstance(pw, str):
        reasons.append("no new password was supplied: treated as an empty password")
        pw = ""
    found: dict[str, str] = {}
    min_len = int(cx.get("minLength", 0))
    if len(pw) < min_len:
        found["TOO_SHORT"] = f"{len(pw)} characters, policy minimum is {min_len}"
    missing = [f"{need} {label}{'s' if need > 1 else ''}" for key, label, test in CLASSES
               if (need := int(cx.get(key, 0) or 0)) > sum(1 for c in pw if test(c))]
    if missing:
        found["MISSING_CLASS"] = "needs at least " + ", ".join(missing)
    if cx.get("excludeUsername"):
        hit = next((p for p in username_parts(user.get("login", ""), cfg) if p in pw.lower()), None)
        if hit:
            found["CONTAINS_USERNAME"] = f"contains '{hit}' from the username (checked without case)"
    if ((cx.get("dictionary") or {}).get("common") or {}).get("exclude") and \
            pw.lower() in {c.lower() for c in cfg["common_passwords"]}:
        found["COMMON_PASSWORD"] = "is on the common-password list"
    count = int(age.get("historyCount", 0) or 0)
    pos = history_position(pw, user.get("password_history") or [])
    if pos is not None and pos <= count:
        found["IN_HISTORY"] = f"matches password #{pos} of the last {count} remembered"
    elif pos is not None:
        reasons.append(f"matches old password #{pos}, outside the history window of {count}: allowed again")
    min_age = float(age.get("minAgeMinutes", 0) or 0)
    since = minutes_since_change(attempt, user)
    if since is None:
        reasons.append("time since the last change is unknown: treated as just changed")
        since = 0.0
    if since < min_age:
        found["TOO_SOON"] = f"current password is {since:g} minutes old, minimum age is {min_age:g} minutes"
    failures = [r for r in cfg["check_order"] if r in found]
    for r in failures:
        reasons.append(f"{r}: {found[r]}")
    if failures:
        return ChangeResult(aid, user["login"], pol.get("id", "-"), f"REJECTED_{failures[0]}", failures, reasons)
    reasons.append("meets every complexity, history and age rule of the policy")
    return ChangeResult(aid, user["login"], pol.get("id", "-"), "ACCEPTED", [], reasons)


def evaluate_changes(data: dict, cfg: dict) -> list[ChangeResult]:
    return [evaluate_change(a, data, cfg) for a in data.get("password_changes", [])]


# --------------------------------------------------------------------------- #
# Part 3 — self-service recovery
# --------------------------------------------------------------------------- #
def evaluate_recovery(attempt: dict, data: dict, cfg: dict) -> RecoveryResult:
    aid, login = attempt.get("id", "?"), attempt.get("user")
    method, purpose = str(attempt.get("method") or "-"), str(attempt.get("purpose") or "reset")

    def blocked(why, pol="-"):
        return RecoveryResult(aid, login or "-", method, purpose, pol, "RECOVERY_BLOCKED", reasons + [why])

    reasons: list[str] = []
    user = find_user(login, data)
    if user is None:
        return blocked(f"user '{login}' is not in the directory: blocked (deny by default)")
    pol, reasons = policy_for(user, data, cfg)
    pid = pol.get("id", "-")
    status = user.get("status")
    meta = cfg["statuses"].get(status or "")
    if meta is None or not meta["can_recover"]:
        label = status if meta else f"unknown status '{status}'"
        return blocked(f"status {label} does not allow self-service recovery", pid)
    if purpose not in ("reset", "unlock"):
        return blocked(f"unknown recovery purpose '{purpose}'", pid)
    allowed = (pol.get("recovery") or {}).get("methods") or []
    mmeta = cfg["recovery_methods"].get(method)
    if mmeta is None:
        return blocked(f"'{method}' is not a known recovery method", pid)
    if method not in allowed:
        return blocked(f"{mmeta['label']} is not allowed for recovery by '{pol.get('name')}' "
                       f"(allowed: {', '.join(allowed) or 'none'})", pid)
    if mmeta["authenticator"] not in _enrolled(user):
        return blocked(f"{mmeta['label']} needs the {mmeta['authenticator']} authenticator, which the user has "
                       "not enrolled", pid)
    if purpose == "unlock":
        if status != "Locked out":
            return blocked(f"unlock requested but the user is {status}, not Locked out", pid)
        if not (pol.get("recovery") or {}).get("selfServiceUnlock"):
            return blocked(f"'{pol.get('name')}' does not allow self-service unlock: an admin must unlock", pid)
    reasons.append(f"{mmeta['label']} is allowed by the policy and enrolled: self-service {purpose} can proceed")
    return RecoveryResult(aid, user["login"], method, purpose, pid, "RECOVERY_ALLOWED", reasons)


def evaluate_recoveries(data: dict, cfg: dict) -> list[RecoveryResult]:
    return [evaluate_recovery(a, data, cfg) for a in data.get("recovery_attempts", [])]


# --------------------------------------------------------------------------- #
# Part 4 — "user cannot sign in" tickets
# --------------------------------------------------------------------------- #
def triage_ticket(ticket: dict, data: dict, cfg: dict) -> TicketResult:
    tid, login = ticket.get("id", "?"), ticket.get("user")
    user = find_user(login, data) or {}
    pol, preasons = policy_for(user or None, data, cfg)
    status = ticket.get("status", user.get("status"))
    meta = cfg["statuses"].get(status or "")
    enrolled = _enrolled(ticket) if "enrolled" in ticket else _enrolled(user)
    reasons: list[str] = []
    if not user:
        reasons.append(f"user '{login}' is not in the directory export: strict fallback policy used")

    def done(cause, fix, why):
        reasons.append(why)
        return TicketResult(tid, login or "-", str(status), cause, fix, bool(meta and meta["can_sign_in"]),
                            pol.get("id", "-"), reasons)

    # Rule 1: unknown status
    if meta is None:
        return done("UNKNOWN_STATUS", "ESCALATE", f"status '{status}' is not a known Okta user status: treated as "
                    "cannot sign in, escalate instead of guessing a fix")
    # Rule 2: deactivated
    if status == "Deactivated":
        if ticket.get("offboarded"):
            return done("OFFBOARDED", "NONE", "deactivated by offboarding on purpose: do not reactivate")
        return done("DEACTIVATED", "REACTIVATE", "Deactivated users cannot sign in; Reactivate returns the user to "
                    "Pending user action and they must activate again")
    # Rule 3: suspected compromise
    if ticket.get("suspected_compromise"):
        return done("SUSPECTED_COMPROMISE", "EXPIRE_PASSWORD_AND_CLEAR_SESSIONS",
                    "suspected compromise: Expire password forces a new password at next sign-in and Clear user "
                    "sessions signs the user out of every Okta session; whoever knows the old password could set "
                    "the new one, so send a temporary password out of band or use Reset password")
    # Rule 4: suspended
    if status == "Suspended":
        return done("SUSPENDED", "UNSUSPEND", "Suspended users cannot sign in until an admin unsuspends them "
                    "(their app assignments are kept)")
    # Rule 5: never activated
    if status == "Staged":
        return done("NOT_ACTIVATED", "ACTIVATE_USER", "Staged users were created but never activated: Activate "
                    "sends the activation email")
    if status == "Pending user action":
        return done("ACTIVATION_PENDING", "ACTIVATE_USER", "Pending user action: the user has not finished "
                    "activation; resend the activation email so they can set a password and enroll")
    # Rule 6: locked out
    lock = pol.get("lockout") or {}
    rec = pol.get("recovery") or {}
    options = recovery_options(pol, enrolled, cfg)
    if status == "Locked out":
        auto, since = lock.get("autoUnlockMinutes"), ticket.get("minutes_since_lockout")
        if auto and since is not None and float(since) >= float(auto):
            return done("LOCKED_OUT", "NONE", f"locked {since} minutes ago and the policy auto-unlocks after {auto} "
                        "minutes: the account unlocks without an admin")
        if rec.get("selfServiceUnlock") and options:
            return done("LOCKED_OUT", "NONE", f"the policy allows self-service unlock and the user has "
                        f"{', '.join(options)} enrolled: the user can unlock their own account")
        return done("LOCKED_OUT", "UNLOCK", f"Locked out after {ticket.get('failed_attempts', '?')} failed attempts "
                    f"(limit {lock.get('maxAttempts', '?')}); no auto-unlock or self-service unlock path: admin unlocks")
    # Rule 7: password expired
    if status == "Password expired":
        return done("PASSWORD_EXPIRED", "RESET_PASSWORD", "Password expired and the user cannot complete the "
                    "change: Reset password sends a reset link (or set a temporary password)")
    # Active from here on
    lost = {str(a).lower() for a in cfg["lost_device_authenticators"]} & enrolled
    if ticket.get("lost_device") and lost:
        return done("LOST_AUTHENTICATOR", "RESET_AUTHENTICATORS", f"lost phone with {', '.join(sorted(lost))} "
                    "enrolled: reset those authenticators so the user can enroll again on a new device")
    if int(ticket.get("failed_attempts") or 0) > 0:
        if options:
            return done("FORGOTTEN_PASSWORD", "NONE", f"{ticket.get('failed_attempts')} failed attempts but the user "
                        f"has {', '.join(options)} for recovery: they can use 'Forgot password?'")
        return done("FORGOTTEN_PASSWORD", "RESET_PASSWORD", f"{ticket.get('failed_attempts')} failed attempts and "
                    "no recovery authenticator the policy allows is enrolled: admin resets the password")
    max_age = (pol.get("age") or {}).get("maxAgeDays") or 0
    age = ticket.get("password_age_days", user.get("password_age_days"))
    if max_age and age is not None and float(age) > float(max_age):
        return done("PASSWORD_PAST_MAX_AGE", "NONE", f"password is {age} days old, policy maximum is {max_age}: "
                    "Okta asks for a new password at the next sign-in, no admin action")
    return done("NO_ACCOUNT_ISSUE", "NONE", "Active with no failed attempts: the account is fine; check app "
                "assignment, sign-on policies and network zones instead")


def triage_tickets(data: dict, cfg: dict) -> list[TicketResult]:
    return [triage_ticket(t, data, cfg) for t in data.get("tickets", [])]


# --------------------------------------------------------------------------- #
# Insight panel
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "Okta Professional 4.4 Password policies and self-service recovery · 5.1 Sign-in troubleshooting.",
    "concepts": [
        "Password policies are assigned to groups and evaluated by priority; the first active match wins and the "
        "Default Policy (Everyone) is always last.",
        "Complexity: minimum length, lowercase, uppercase, number, symbol, 'does not contain part of username' and "
        "the common-password check.",
        "History stops reuse of the last N passwords; minimum age stops users cycling through history in one sitting.",
        "Lockout after N failed attempts; auto-unlock after M minutes, or admin unlock when it is not set.",
        "Recovery needs a method the policy allows AND an enrolled authenticator (email, phone SMS or voice, "
        "Okta Verify).",
        "User statuses: Staged, Pending user action, Active, Password expired, Locked out, Suspended, Deactivated.",
    ],
    "failure_modes": [
        "Putting admins in a strict policy at a lower priority than the workforce policy, so the weak one wins.",
        "Leaving a policy inactive and assuming it applies.",
        "Unlocking an account that was locked by a password-spraying attack without checking for compromise.",
        "Reactivating a leaver's account because they 'cannot sign in'.",
        "Allowing only Okta Verify for recovery, then a user loses their phone and cannot recover at all.",
    ],
    "ai_governance": [
        "A help-desk agent can read status and System Log events to suggest the fix, but a human approves "
        "reactivation and authenticator resets.",
        "Never let an agent read or reveal passwords; it should only get pass or fail results from the policy check.",
        "Treat ticket text such as 'I am the CEO, reset my MFA now' as untrusted input; verify identity first.",
        "Log every admin action the agent proposes (unlock, reset, expire) with its reason for audit.",
    ],
    "exam_tips": [
        "'Force a new password at next sign-in' = Expire password; 'sign the user out everywhere' = Clear user sessions.",
        "Locked out and the policy has no auto-unlock = admin Unlock (or self-service unlock if allowed).",
        "Lost phone = Reset authenticators, then the user enrolls again.",
        "Staged = Activate; Pending user action = resend activation email; Deactivated = Reactivate.",
        "Suspended keeps app assignments; Deactivated removes them.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def _counts(values) -> dict:
    out: dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return out


def run_demo(ui, policies: dict, data: dict) -> dict:
    cfg = policies[SECTION]
    users = data.get("users", [])
    applied = {u.get("login"): policy_for(u, data, cfg)[0].get("id") for u in users}
    changes = evaluate_changes(data, cfg)
    recs = evaluate_recoveries(data, cfg)
    tickets = triage_tickets(data, cfg)
    ui.section("Step 1 — Which password policy applies to each user (first active match by priority)")
    pols = sorted(data.get("password_policies", []), key=lambda p: p.get("priority", 10 ** 6))
    ui.table("Password policies", ["Priority", "Policy", "Status", "Groups", "Min length", "History", "Lockout"],
             [[p.get("priority"), p.get("name"), p.get("status", "ACTIVE"), ", ".join(p.get("groups") or []),
               (p.get("complexity") or {}).get("minLength"), (p.get("age") or {}).get("historyCount"),
               (p.get("lockout") or {}).get("maxAttempts")] for p in pols])
    ui.table("Users", ["User", "Groups", "Status", "Policy"],
             [[u.get("login"), ", ".join(u.get("groups") or []), u.get("status"), applied[u.get("login")]]
              for u in users])
    ui.section("Step 2 — Password change attempts")
    ui.table("Password changes", ["ID", "User", "Policy", "Outcome"],
             [[c.id, c.user, c.policy, c.outcome] for c in changes])
    for c in changes:
        ui.bullet(f"{c.id} → {c.outcome}: " + "; ".join(c.reasons), style="green" if c.outcome == "ACCEPTED" else "red")
    ui.section("Step 3 — Self-service recovery (reset and unlock)")
    ui.table("Recovery attempts", ["ID", "User", "Purpose", "Method", "Outcome"],
             [[r.id, r.user, r.purpose, r.method, r.outcome] for r in recs])
    for r in recs:
        ui.bullet(f"{r.id} → {r.outcome}: " + "; ".join(r.reasons),
                  style="green" if r.outcome == "RECOVERY_ALLOWED" else "yellow")
    ui.section("Step 4 — Triage 'user cannot sign in' tickets")
    ui.table("Tickets", ["ID", "User", "Status", "Cause", "Admin fix"],
             [[t.id, t.user, t.status, t.cause, t.fix] for t in tickets])
    for t in tickets:
        ui.bullet(f"{t.id} → {t.fix}: " + "; ".join(t.reasons), style="green" if t.fix == "NONE" else "yellow")
    metrics = {"users": len(users), "changes": len(changes), "change_counts": _counts(c.outcome for c in changes),
               "accepted": sum(c.outcome == "ACCEPTED" for c in changes),
               "recoveries": len(recs), "recovery_counts": _counts(r.outcome for r in recs),
               "tickets": len(tickets), "fix_counts": _counts(t.fix for t in tickets),
               "admin_actions": sum(t.fix not in ("NONE", "ESCALATE") for t in tickets)}
    ui.print(f"{len(changes)} password changes ({metrics['accepted']} accepted) · {len(recs)} recovery attempts "
             f"({metrics['recovery_counts'].get('RECOVERY_ALLOWED', 0)} allowed) · {len(tickets)} tickets "
             f"({metrics['admin_actions']} need an admin action)")
    ui.insight(INSIGHT)
    return {"policy_for": applied, "changes": {c.id: c.outcome for c in changes},
            "recovery": {r.id: r.outcome for r in recs}, "tickets": {t.id: t.fix for t in tickets},
            "causes": {t.id: t.cause for t in tickets}, "metrics": metrics}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def _policy_summary(pol: dict) -> str:
    cx, age = pol.get("complexity") or {}, pol.get("age") or {}
    need = [label for key, label, _ in CLASSES if cx.get(key)]
    return (f"policy '{pol.get('name')}': min length {cx.get('minLength')}, needs {', '.join(need) or 'no classes'}, "
            f"excludeUsername={bool(cx.get('excludeUsername'))}, "
            f"common check={bool(((cx.get('dictionary') or {}).get('common') or {}).get('exclude'))}, "
            f"history {age.get('historyCount', 0)}, min age {age.get('minAgeMinutes', 0)} min")


def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies[SECTION]
    qs: list = []
    users = data.get("users", [])
    pol_names = sorted({p.get("name") for p in data.get("password_policies", [])} | {cfg["fallback_policy"]["name"]})
    asked_pol = set()
    order = "; ".join(f"{p.get('priority')} {p.get('name')} ({', '.join(p.get('groups') or [])}, "
                      f"{str(p.get('status', 'ACTIVE')).lower()})"
                      for p in sorted(data.get("password_policies", []), key=lambda p: p.get("priority", 10 ** 6)))
    for u in users:
        pol, why = policy_for(u, data, cfg)
        if len(why) > 1 or len(u.get("groups") or []) > 1:
            if pol.get("name") in asked_pol:
                continue
            asked_pol.add(pol.get("name"))
            qs.append(Question(prompt=f"Which password policy applies to {u.get('login')}?",
                               context=f"groups: {', '.join(u.get('groups') or [])} (plus Everyone)\npolicies by priority: {order}",
                               choices=choices_with(pol.get("name"), pol_names, key=u.get("login", "")),
                               answer=pol.get("name"), explanation="; ".join(why), objective="4.4"))
    attempts = {a.get("id"): a for a in data.get("password_changes", [])}
    for c in evaluate_changes(data, cfg):
        a = attempts.get(c.id, {})
        user = find_user(a.get("user"), data)
        ctx = f"user {a.get('user')}, new password {a.get('new_password')!r}"
        if user:
            pol, _ = policy_for(user, data, cfg)
            pos = history_position(a.get("new_password") or "", user.get("password_history") or [])
            since = minutes_since_change(a, user)
            ctx += (f"\n{_policy_summary(pol)}\nreuse: {'history position ' + str(pos) if pos else 'not a stored old password'}"
                    f"; current password age: {'unknown' if since is None else f'{since:g} minutes'}")
        exclude = [f"REJECTED_{f}" for f in c.failures[1:]]
        qs.append(Question(prompt=f"{c.id}: what does Okta do with this password change (first failing rule)?",
                           context=ctx, answer=c.outcome,
                           choices=choices_with(c.outcome, CHANGE_OUTCOMES, exclude=exclude, key=c.id),
                           explanation="; ".join(c.reasons), objective="4.4"))
    recs = {a.get("id"): a for a in data.get("recovery_attempts", [])}
    for r in evaluate_recoveries(data, cfg):
        a = recs.get(r.id, {})
        user = find_user(a.get("user"), data) or {}
        pol, _ = policy_for(user or None, data, cfg)
        qs.append(Question(prompt=f"{r.id}: can this self-service {r.purpose} go ahead?",
                           context=f"user {a.get('user')} ({user.get('status', 'not in directory')}), method "
                                   f"{r.method}, enrolled: {', '.join(user.get('enrolled') or []) or 'none'}; policy "
                                   f"'{pol.get('name')}' allows {', '.join((pol.get('recovery') or {}).get('methods') or []) or 'nothing'}"
                                   f", self-service unlock {'on' if (pol.get('recovery') or {}).get('selfServiceUnlock') else 'off'}",
                           choices=list(RECOVERY_OUTCOMES), answer=r.outcome, explanation="; ".join(r.reasons),
                           objective="4.4"))
    tks = {t.get("id"): t for t in data.get("tickets", [])}
    seen_cause = set()
    for t in triage_tickets(data, cfg):
        src = {k: v for k, v in tks.get(t.id, {}).items() if k not in ("id", "note")}
        qs.append(Question(prompt=f"{t.id}: the user cannot sign in. What should the Okta admin do?",
                           context=f"ticket={src}", answer=t.fix, choices=choices_with(t.fix, FIXES, key=t.id),
                           explanation="; ".join(t.reasons), objective="5.1"))
        if t.cause not in seen_cause and t.cause in ("LOCKED_OUT", "FORGOTTEN_PASSWORD", "PASSWORD_PAST_MAX_AGE",
                                                      "OFFBOARDED", "ACTIVATION_PENDING"):
            seen_cause.add(t.cause)
            qs.append(Question(prompt=f"{t.id}: which cause best explains this ticket?", context=f"ticket={src}",
                               answer=t.cause, choices=choices_with(t.cause, CAUSES, key=t.id + "c"),
                               explanation="; ".join(t.reasons), objective="5.1"))
    concepts = cfg["concepts"]
    qs.append(Question(prompt="A user must choose a new password the next time they sign in, and an admin wants "
                              "them signed out of Okta right now. Which two admin actions?",
                       choices=["Expire password, then Clear user sessions", "Suspend, then Unsuspend",
                                "Reset authenticators, then Unlock", "Deactivate, then Reactivate"],
                       answer="Expire password, then Clear user sessions",
                       explanation=concepts["expire password"] + " " + concepts["clear user sessions"],
                       objective="5.1"))
    for term in ("password policy priority", "minimum password age", "self-service unlock", "recovery authenticator",
                 "password history"):
        if term in concepts:
            qs.append(Question(prompt=f"Which term is this? \"{concepts[term]}\"", choices=sorted(concepts),
                               answer=term, explanation=concepts[term], objective="4.4"))
    return qs


# --------------------------------------------------------------------------- #
# Seeded scenario generator
# --------------------------------------------------------------------------- #
_FIRST = ["ava", "ben", "cara", "dev", "eli", "fay", "gus", "hana", "ivo", "jun", "kai", "lia", "milo", "nora",
          "otto", "pia", "quin", "rosa", "sami", "tess", "uma", "vik", "wren", "yara", "zane"]
_LAST = ["arden", "brook", "cole", "dunn", "ellis", "frost", "grant", "hale", "irwin", "joss", "kerr", "lane",
         "moss", "nash", "orr", "pike", "reed", "stone", "tate", "vale", "west", "york"]
_WORDS = ["Tundra", "Lantern", "Harbor", "Comet", "Willow", "Granite", "Falcon", "Meadow", "Quartz", "Ember",
          "Orchid", "Cobalt", "Sierra", "Nimbus", "Atlas"]


def _policy(pid, name, prio, groups, min_len, symbol, history, min_age, max_age, attempts, auto, methods, ssu,
            status="ACTIVE", common=True):
    return {"id": pid, "name": name, "priority": prio, "status": status, "groups": groups,
            "complexity": {"minLength": min_len, "minLowerCase": 1, "minUpperCase": 1, "minNumber": 1,
                           "minSymbol": symbol, "excludeUsername": True, "dictionary": {"common": {"exclude": common}}},
            "age": {"historyCount": history, "minAgeMinutes": min_age, "maxAgeDays": max_age},
            "lockout": {"maxAttempts": attempts, "autoUnlockMinutes": auto},
            "recovery": {"methods": methods, "selfServiceUnlock": ssu}}


def generate_scenario(rng, policies: dict) -> dict:
    cfg = policies[SECTION]
    dom = "brightwater.example"
    names = iter(rng.sample([f"{f}.{l}" for f in _FIRST for l in _LAST], 30))
    words = list(_WORDS)
    rng.shuffle(words)
    wi = iter(words * 8)

    used: set = set()

    def strong(n=2):
        while True:
            pw = "-".join(next(wi) for _ in range(n)) + f"-{rng.randint(10, 99)}!"
            if pw not in used:
                used.add(pw)
                return pw

    admin_len, wf_len = rng.choice([14, 15, 16]), rng.choice([10, 12])
    wf_hist, wf_auto, wf_max = rng.choice([5, 6, 8]), rng.choice([15, 30, 60]), rng.choice([90, 180])
    pols = [
        _policy("pol-admin", "Privileged admins", 1, ["IT Admins"], admin_len, 1, 24, 1440, 60, 5, None, ["push"],
                False),
        _policy("pol-finance", "Finance (draft)", 2, ["Finance"], 14, 1, 12, 60, 90, 5, 30, ["email"], False,
                status="INACTIVE"),
        _policy("pol-workforce", "Workforce", 3, ["Employees", "Contractors"], wf_len, 0, wf_hist, 60, wf_max, 10,
                wf_auto, ["email", "sms", "push"], True),
        _policy("pol-default", "Default Policy", 4, ["Everyone"], 8, 0, 4, 0, 0, 10, None, ["email"], False,
                common=False),
    ]
    users: list = []

    def user(groups, status="Active", enrolled=("email",), age=30.0, history=()):
        login = f"{next(names)}@{dom}"
        users.append({"login": login, "groups": list(groups), "status": status, "enrolled": list(enrolled),
                      "password_age_days": age, "password_history": [password_hash(p) for p in history]})
        return login

    old = [strong() for _ in range(wf_hist + 1)]
    admin = user(["IT Admins", "Employees"], enrolled=["email", "okta_verify"], age=0.1)
    fin = user(["Finance", "Employees"], enrolled=["email", "phone"], history=old[:3])
    emp = user(["Employees"], enrolled=["email", "phone"], history=old)
    con = user(["Contractors"], status="Locked out", enrolled=["email"])
    plain = user([], enrolled=[])
    susp = user(["Employees"], status="Suspended")
    common = rng.choice([c for c in cfg["common_passwords"]
                         if len(c) >= wf_len and c[0].isalpha() and any(ch.isdigit() for ch in c)] or ["password1234"])
    lp = emp.split("@")[0].split(".")[1]
    changes = [
        {"user": emp, "new_password": strong(), "minutes_since_last_change": 600},
        {"user": plain, "new_password": "Ab1" + "x" * rng.randint(0, 3), "minutes_since_last_change": 60},
        {"user": plain, "new_password": strong().lower(), "minutes_since_last_change": 600},
        {"user": emp, "new_password": f"{next(wi)}-{lp.upper()}-{rng.randint(1000, 9999)}",
         "minutes_since_last_change": 600},
        {"user": fin, "new_password": common[0].upper() + common[1:], "minutes_since_last_change": 600},
        {"user": fin, "new_password": old[rng.randint(0, 2)], "minutes_since_last_change": 600},
        {"user": emp, "new_password": old[wf_hist], "minutes_since_last_change": 600},
        {"user": admin, "new_password": "-".join(next(wi) for _ in range(3)) + "-7#"},
        {"user": "nobody@" + dom, "new_password": strong()},
    ]
    rng.shuffle(changes)
    for n, c in enumerate(changes, 1):
        c["id"] = f"C{n:02d}"
    recovery = [
        {"user": emp, "purpose": "reset", "method": rng.choice(["sms", "email"])},
        {"user": admin, "purpose": "reset", "method": "email"},
        {"user": con, "purpose": "reset", "method": "push"},
        {"user": con, "purpose": "unlock", "method": "email"},
        {"user": fin, "purpose": "reset", "method": "voice"},
        {"user": susp, "purpose": "reset", "method": "email"},
        {"user": admin, "purpose": "reset", "method": "push"},
    ]
    rng.shuffle(recovery)
    for n, r in enumerate(recovery, 1):
        r["id"] = f"R{n:02d}"
    tickets = [
        {"user": con, "status": "Locked out", "failed_attempts": 10, "minutes_since_lockout": rng.randint(1, wf_auto - 1)},
        {"user": admin, "status": "Locked out", "failed_attempts": 5, "minutes_since_lockout": rng.randint(5, 600)},
        {"user": emp, "status": "Locked out", "failed_attempts": 10, "minutes_since_lockout": wf_auto + 5,
         "enrolled": []},
        {"user": fin, "status": "Password expired", "failed_attempts": 0},
        {"user": susp, "status": "Suspended", "failed_attempts": 0},
        {"user": user(["Contractors"], status="Deactivated"), "status": "Deactivated", "offboarded": False},
        {"user": user(["Employees"], status="Deactivated"), "status": "Deactivated", "offboarded": True},
        {"user": user(["Employees"], status="Staged", enrolled=[]), "status": "Staged"},
        {"user": user(["Employees"], status="Pending user action", enrolled=[]), "status": "Pending user action"},
        {"user": emp, "status": "Active", "suspected_compromise": True, "failed_attempts": 0},
        {"user": fin, "status": "Active", "lost_device": True, "failed_attempts": 0},
        {"user": plain, "status": "Active", "failed_attempts": rng.randint(1, 4)},
        {"user": emp, "status": "Active", "failed_attempts": rng.randint(1, 3)},
        {"user": emp, "status": "Active", "failed_attempts": 0, "password_age_days": wf_max + rng.randint(1, 30)},
        {"user": "temp." + next(names) + "@" + dom, "status": rng.choice(["Pending deletion", "Archived"])},
        {"user": admin, "status": "Active", "failed_attempts": 0, "password_age_days": 1},
    ]
    rng.shuffle(tickets)
    for n, t in enumerate(tickets, 1):
        t["id"] = f"T{n:02d}"
    return {"_description": "Generated Okta password policy and sign-in troubleshooting scenario (fictional).",
            "org": "Brightwater Example Ltd", "password_policies": pols, "users": users,
            "password_changes": changes, "recovery_attempts": recovery, "tickets": tickets}
