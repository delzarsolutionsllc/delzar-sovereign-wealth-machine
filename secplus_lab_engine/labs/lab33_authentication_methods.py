"""
Lab 33 — Authentication Methods, SSPR & Authentication Strengths
================================================================

SC-300 objectives
-----------------
* 2.1  Plan, implement and manage Microsoft Entra user authentication:
       the authentication methods policy, passwordless and phishing-resistant
       methods, Temporary Access Pass and self-service password reset (SSPR).
* 2.2  Plan, implement and manage Microsoft Entra Conditional Access:
       authentication strengths used as a Conditional Access grant control.

How it works
------------
An identity administrator at a fictional hospital checks three things.

**Sign-in against an authentication strength** (rules in this order, first match wins):

1. Unknown user → METHOD_DISABLED (no methods are enabled for an identity we
   cannot find; deny by default).
2. Unknown method combination → NOT_SATISFIED.
3. Every underlying method must be **enabled** in the authentication methods
   policy and **targeted** at one of the user's groups ("all_users" counts),
   and the user must not be in an excluded group (exclusion wins). Microsoft
   Authenticator also needs the right authentication mode for the group
   ("any", "push" or "deviceBasedPush" = passwordless). Otherwise → METHOD_DISABLED.
4. Missing or unknown required strength → NOT_SATISFIED.
5. The combination must be in the strength's allowed list (built-in MFA,
   Passwordless MFA, Phishing-resistant MFA, or a custom strength). A custom
   strength may restrict passkeys to approved AAGUIDs (key models). Otherwise
   → NOT_SATISFIED; else SATISFIED. Every result lists the combinations that
   would satisfy the strength with methods enabled for that user.

Only passkeys (FIDO2), Windows Hello for Business and multifactor
certificate-based authentication are phishing-resistant. Authenticator
passwordless phone sign-in is passwordless but not phishing-resistant; a
Temporary Access Pass satisfies MFA only.

**SSPR readiness** (per user):

1. Unknown user → NOT_REGISTERED.
2. Anyone holding an admin role (an unrecognised role counts as admin) is
   under the **administrator SSPR policy**: always on, always two methods,
   never security questions. Fewer than two → ADMIN_POLICY.
3. A non-admin outside the SSPR scope → NOT_REGISTERED (cannot use SSPR).
4. Registered methods are mapped to SSPR methods (SMS and voice are one
   mobile phone; passkeys, Windows Hello, certificates and TAP do not count)
   and filtered to the tenant's allowed SSPR methods. None → NOT_REGISTERED;
   fewer than required → INSUFFICIENT_METHODS; else SSPR_READY.

**Temporary Access Pass (TAP)**: TAP_REJECTED if the user is unknown or TAP
is not enabled for them, the lifetime is missing or outside the policy's
minimum/maximum, the policy demands one-time use but a multi-use pass was
requested, a one-time pass was already used, or it has expired; else TAP_VALID.

Run it
------
    python main.py --course sc300 lab 33
"""

from __future__ import annotations

from dataclasses import dataclass, field

TITLE = "Lab 33 — Authentication Methods, SSPR & Authentication Strengths"
OBJECTIVES = "SC-300 2.1 Microsoft Entra user authentication · 2.2 Conditional Access (authentication strengths)"
COURSES = ("sc300",)

SIGN_IN_OUTCOMES = ["SATISFIED", "NOT_SATISFIED", "METHOD_DISABLED"]
SSPR_OUTCOMES = ["SSPR_READY", "NOT_REGISTERED", "INSUFFICIENT_METHODS", "ADMIN_POLICY"]
TAP_OUTCOMES = ["TAP_VALID", "TAP_REJECTED"]

ALL_USERS = "all_users"


@dataclass
class SignInResult:
    id: str
    user: str
    method: str
    strength: str
    outcome: str
    rule: str
    satisfying: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


@dataclass
class SsprResult:
    user: str
    admin: bool
    counted: list[str]
    required: int
    outcome: str
    reasons: list[str] = field(default_factory=list)


@dataclass
class TapResult:
    id: str
    user: str
    lifetime: object
    outcome: str
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Authentication methods policy
# --------------------------------------------------------------------------- #
def method_enabled(method: str, user: dict, tenant: dict, mode: str | None = None) -> tuple[bool, str]:
    """Is ``method`` usable by ``user``? Missing method config = disabled (deny by default)."""
    cfg = tenant.get("methods", {}).get(method)
    if not cfg:
        return False, f"{method} is not configured in the authentication methods policy"
    if cfg.get("state") != "enabled":
        return False, f"{method} is disabled tenant-wide"
    groups = set(user.get("groups", [])) | {ALL_USERS}
    excluded = groups & set(cfg.get("exclude", []))
    if excluded:
        return False, f"{method}: user is in excluded group {sorted(excluded)[0]} (exclusion wins)"
    targets = [g for g in cfg.get("include", []) if g in groups]
    if not targets:
        return False, f"{method} is not targeted at any of the user's groups"
    if mode:
        modes = cfg.get("modes", {})
        allowed = set()
        for g in targets:
            allowed |= set(_AUTH_MODES.get(modes.get(g, "any"), []))
        if mode not in allowed:
            return False, (f"{method} authentication mode for {', '.join(targets)} does not allow "
                           f"{'passwordless phone sign-in' if mode == 'deviceBasedPush' else 'push'}")
    return True, f"{method} enabled for {targets[0]}"


_AUTH_MODES = {"any": ["push", "deviceBasedPush"], "push": ["push"], "deviceBasedPush": ["deviceBasedPush"]}


def combination_enabled(combo: str, user: dict, tenant: dict, cfg: dict) -> tuple[bool, list[str]]:
    spec = cfg["combinations"].get(combo)
    if spec is None:
        return False, [f"unknown method combination '{combo}'"]
    reasons = []
    for m in spec["methods"]:
        ok, why = method_enabled(m, user, tenant, spec.get("authenticator_mode"))
        if not ok:
            return False, [why]
        reasons.append(why)
    return True, reasons or ["password needs no method policy entry"]


def strength_of(name: str | None, tenant: dict, cfg: dict) -> dict | None:
    if not name:
        return None
    return cfg["builtin_strengths"].get(name) or tenant.get("custom_strengths", {}).get(name)


def satisfying(strength: dict | None, user: dict | None, tenant: dict, cfg: dict) -> list[str]:
    """Combinations in ``strength`` that this user could use (all their methods enabled for the user)."""
    if not strength or user is None:
        return []
    return [c for c in strength["combinations"] if c in cfg["combinations"]
            and combination_enabled(c, user, tenant, cfg)[0]]


def _label(combo: str, cfg: dict) -> str:
    return cfg["combinations"].get(combo, {}).get("label", combo)


def evaluate_sign_in(attempt: dict, data: dict, cfg: dict) -> SignInResult:
    tenant = data.get("tenant", {})
    users = {u["id"]: u for u in data.get("users", [])}
    user = users.get(attempt.get("user"))
    combo = attempt.get("method") or ""
    sname = attempt.get("required_strength") or ""
    strength = strength_of(sname, tenant, cfg)
    sat = satisfying(strength, user, tenant, cfg)

    def res(outcome, rule, reasons):
        return SignInResult(attempt.get("id", "?"), attempt.get("user") or "?", combo or "-", sname or "-",
                            outcome, rule, sat, reasons)

    if user is None:
        return res("METHOD_DISABLED", "unknown user",
                   [f"user '{attempt.get('user')}' is not in the directory: no methods enabled (deny by default)"])
    if combo not in cfg["combinations"]:
        return res("NOT_SATISFIED", "unknown method", [f"unknown method combination '{combo or 'none'}' (deny by default)"])
    ok, why = combination_enabled(combo, user, tenant, cfg)
    if not ok:
        return res("METHOD_DISABLED", "method not enabled", why)
    if strength is None:
        return res("NOT_SATISFIED", "unknown strength",
                   [f"required strength '{sname or 'none'}' is not defined (deny by default)"])
    sdisp = strength.get("name", sname)
    if combo not in strength["combinations"]:
        extra = ""
        if combo in cfg["builtin_strengths"]["passwordless_mfa"]["combinations"]:
            extra = " (passwordless, but not phishing-resistant)"
        elif combo in cfg["builtin_strengths"]["mfa"]["combinations"]:
            extra = " (counts as MFA only)"
        elif combo in ("sms", "password", "email", "x509CertificateSingleFactor"):
            extra = " (single factor)"
        return res("NOT_SATISFIED", "not in strength",
                   why + [f"{_label(combo, cfg)} is not allowed by '{sdisp}'{extra}"])
    allowed_keys = strength.get("fido2_allowed_aaguids")
    if combo == "fido2" and allowed_keys is not None and attempt.get("aaguid") not in allowed_keys:
        return res("NOT_SATISFIED", "AAGUID not allowed",
                   why + [f"passkey AAGUID {attempt.get('aaguid') or 'missing'} is not an approved key model "
                          f"for '{sdisp}'"])
    return res("SATISFIED", "allowed by strength", why + [f"{_label(combo, cfg)} is allowed by '{sdisp}'"])


def evaluate_sign_ins(data: dict, cfg: dict) -> list[SignInResult]:
    return [evaluate_sign_in(a, data, cfg) for a in data.get("sign_ins", [])]


# --------------------------------------------------------------------------- #
# SSPR readiness
# --------------------------------------------------------------------------- #
def is_admin(user: dict, cfg: dict) -> bool:
    adm = cfg["admin_sspr"]
    for role in user.get("roles", []) or []:
        if role in adm["admin_roles"] or adm.get("unknown_role_is_admin", True):
            return True
    return False


def sspr_methods(user: dict, cfg: dict) -> list[str]:
    """Distinct SSPR methods the user's registrations count as (sorted)."""
    m = cfg["sspr_method_map"]
    return sorted({m[r] for r in user.get("registered", []) if not r.startswith("_") and r in m})


def sspr_in_scope(user: dict, sspr: dict) -> bool:
    mode = sspr.get("enabled_for", "none")
    if mode == "all":
        return True
    if mode == "selected":
        return bool(set(user.get("groups", [])) & set(sspr.get("groups", [])))
    return False


def evaluate_sspr(user_id: str, data: dict, cfg: dict) -> SsprResult:
    users = {u["id"]: u for u in data.get("users", [])}
    sspr = data.get("tenant", {}).get("sspr", {})
    user = users.get(user_id)
    if user is None:
        return SsprResult(user_id, False, [], 0, "NOT_REGISTERED", [f"user '{user_id}' is not in the directory"])
    mapped = sspr_methods(user, cfg)
    ignored = sorted(r for r in user.get("registered", []) if r not in cfg["sspr_method_map"])
    note = [f"not SSPR methods: {', '.join(ignored)}"] if ignored else []
    mm = cfg["sspr_method_map"]
    for target in mapped:
        same = sorted(r for r in user.get("registered", []) if mm.get(r) == target)
        if len(same) > 1:
            note.append(f"{' and '.join(same)} share one {target} entry, so they count once")
    if is_admin(user, cfg):
        adm = cfg["admin_sspr"]
        counted = [m for m in mapped if m in adm["allowed_methods"]]
        dropped = [m for m in mapped if m not in adm["allowed_methods"]]
        need = adm["methods_required"]
        reasons = [f"admin role {', '.join(user['roles'])}: administrator SSPR policy applies "
                   f"(always on, {need} methods, no security questions)"]
        if dropped:
            reasons.append(f"not allowed for admins: {', '.join(dropped)}")
        reasons += note
        if len(counted) < need:
            return SsprResult(user_id, True, counted, need, "ADMIN_POLICY",
                              reasons + [f"{len(counted)} of {need} admin methods registered"])
        return SsprResult(user_id, True, counted, need, "SSPR_READY",
                          reasons + [f"{len(counted)} admin methods registered: {', '.join(counted)}"])
    need = int(sspr.get("methods_required", 2))
    if not sspr_in_scope(user, sspr):
        return SsprResult(user_id, False, [], need, "NOT_REGISTERED",
                          ["not in the SSPR-enabled scope, so the user cannot register for or use SSPR"])
    allowed = set(sspr.get("allowed_methods", []))
    counted = [m for m in mapped if m in allowed]
    dropped = [m for m in mapped if m not in allowed]
    reasons = ([f"not allowed by the tenant SSPR policy: {', '.join(dropped)}"] if dropped else []) + note
    if not counted:
        return SsprResult(user_id, False, [], need, "NOT_REGISTERED",
                          reasons + ["no usable SSPR method registered"])
    if len(counted) < need:
        return SsprResult(user_id, False, counted, need, "INSUFFICIENT_METHODS",
                          reasons + [f"{len(counted)} of {need} required methods: {', '.join(counted)}"])
    return SsprResult(user_id, False, counted, need, "SSPR_READY",
                      reasons + [f"{len(counted)} of {need} required methods: {', '.join(counted)}"])


def evaluate_all_sspr(data: dict, cfg: dict) -> list[SsprResult]:
    return [evaluate_sspr(u["id"], data, cfg) for u in data.get("users", [])]


# --------------------------------------------------------------------------- #
# Temporary Access Pass
# --------------------------------------------------------------------------- #
def evaluate_tap(req: dict, data: dict, cfg: dict) -> TapResult:
    tenant = data.get("tenant", {})
    pol = tenant.get("tap", {})
    users = {u["id"]: u for u in data.get("users", [])}
    user = users.get(req.get("user"))
    life = req.get("lifetime_minutes")
    rid = req.get("id", "?")

    def rej(why):
        return TapResult(rid, req.get("user") or "?", life, "TAP_REJECTED", [why])

    if user is None:
        return rej(f"user '{req.get('user')}' is not in the directory (deny by default)")
    ok, why = method_enabled("temporaryAccessPass", user, tenant)
    if not ok:
        return rej(why)
    lo, hi = pol.get("min_lifetime_minutes"), pol.get("max_lifetime_minutes")
    if not isinstance(life, (int, float)) or lo is None or hi is None:
        return rej("lifetime or policy limits missing (deny by default)")
    if life > hi:
        return rej(f"lifetime {life} min is over the policy maximum of {hi} min")
    if life < lo:
        return rej(f"lifetime {life} min is under the policy minimum of {lo} min")
    one_time = req.get("one_time", True)
    if pol.get("one_time_only") and not one_time:
        return rej("policy requires one-time use, but a multi-use pass was requested")
    if one_time and (req.get("uses") or 0) >= 1:
        return rej("one-time pass has already been used")
    if (req.get("minutes_since_issue") or 0) > life:
        return rej(f"expired: issued {req.get('minutes_since_issue')} min ago, lifetime {life} min")
    return TapResult(rid, user["id"], life, "TAP_VALID",
                     [f"{life} min is within {lo}-{hi} min, {'one-time' if one_time else 'multi-use'}, unused/in date"])


def evaluate_taps(data: dict, cfg: dict) -> list[TapResult]:
    return [evaluate_tap(r, data, cfg) for r in data.get("tap_requests", [])]


def _counts(results, outcomes) -> dict:
    return {o: sum(r.outcome == o for r in results) for o in outcomes}


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SC-300 2.1 Microsoft Entra user authentication · 2.2 Conditional Access authentication strengths.",
    "concepts": [
        "The authentication methods policy decides which methods each group may register and use; exclusions win.",
        "An authentication strength is a Conditional Access grant control listing the allowed method combinations.",
        "Built-in strengths: MFA (includes SMS, voice, push and TAP) ⊃ Passwordless MFA ⊃ Phishing-resistant MFA.",
        "Phishing-resistant = passkeys (FIDO2), Windows Hello for Business, multifactor certificate-based authentication.",
        "Administrators are always under the admin SSPR policy: two methods, no security questions.",
        "Temporary Access Pass bootstraps passwordless registration; keep lifetimes short and one-time use.",
    ],
    "failure_modes": [
        "Requiring 'MFA' for admins: SMS and push still pass, so adversary-in-the-middle phishing still works.",
        "Enabling Authenticator passwordless for a group whose mode is 'push' only, then wondering why it fails.",
        "Users who registered only passkeys find they cannot reset their password with SSPR.",
        "Issuing day-long, multi-use TAPs over chat: they become a second password.",
    ],
    "ai_governance": [
        "An AI help-desk agent must never issue a TAP on a chat request alone; tie issuance to verified identity and log it.",
        "Give automation workload identities certificates or managed identities, not users with SMS MFA.",
        "Let an agent report which users are not SSPR-ready, but keep policy changes human-approved.",
    ],
    "exam_tips": [
        "'Phishing-resistant' on the exam = FIDO2/passkey, Windows Hello for Business or CBA (multifactor). Not Authenticator.",
        "Number matching is always on for Authenticator push notifications; it fights MFA fatigue, not phishing proxies.",
        "Authentication strengths are applied in Conditional Access under Grant → Require authentication strength.",
        "TAP satisfies the MFA strength but not Passwordless or Phishing-resistant MFA.",
        "Admin SSPR: always enabled, two methods, security questions not allowed.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    cfg = policies["authentication_methods"]
    tenant = data.get("tenant", {})
    sign_ins = evaluate_sign_ins(data, cfg)
    sspr = evaluate_all_sspr(data, cfg)
    taps = evaluate_taps(data, cfg)

    ui.section(f"Step 1 — Authentication methods policy for {tenant.get('name', 'the tenant')}")
    ui.table("Methods", ["Method", "State", "Include", "Exclude", "Authenticator modes"],
             [[m, c.get("state", "?"), ", ".join(c.get("include", [])) or "-", ", ".join(c.get("exclude", [])) or "-",
               ", ".join(f"{g}={v}" for g, v in c.get("modes", {}).items()) or "-"]
              for m, c in tenant.get("methods", {}).items()])

    ui.section("Step 2 — Sign-ins checked against Conditional Access authentication strengths")
    ui.table("Sign-in attempts", ["ID", "User", "Method", "Required strength", "Outcome"],
             [[r.id, r.user, r.method, r.strength, r.outcome] for r in sign_ins])
    for r in sign_ins:
        fix = "" if r.outcome == "SATISFIED" else (" · would satisfy: " + (", ".join(r.satisfying) or "none available"))
        ui.bullet(f"{r.id} → {r.outcome}: " + "; ".join(r.reasons) + fix,
                  style={"SATISFIED": "green", "METHOD_DISABLED": "red"}.get(r.outcome, "yellow"))

    ui.section("Step 3 — Self-service password reset readiness")
    ui.table("SSPR", ["User", "Admin", "Counted methods", "Required", "Outcome"],
             [[s.user, "yes" if s.admin else "no", ", ".join(s.counted) or "-", s.required, s.outcome] for s in sspr])
    for s in sspr:
        ui.bullet(f"{s.user} → {s.outcome}: " + "; ".join(s.reasons),
                  style="green" if s.outcome == "SSPR_READY" else "yellow")

    ui.section("Step 4 — Temporary Access Pass requests")
    ui.table("TAP", ["ID", "User", "Lifetime (min)", "Outcome"], [[t.id, t.user, t.lifetime, t.outcome] for t in taps])
    for t in taps:
        ui.bullet(f"{t.id} → {t.outcome}: " + "; ".join(t.reasons),
                  style="green" if t.outcome == "TAP_VALID" else "red")

    metrics = {"sign_ins": _counts(sign_ins, SIGN_IN_OUTCOMES), "sspr": _counts(sspr, SSPR_OUTCOMES),
               "tap": _counts(taps, TAP_OUTCOMES)}
    ui.print(f"Sign-ins {metrics['sign_ins']} · SSPR {metrics['sspr']} · TAP {metrics['tap']}")
    ui.insight(INSIGHT)
    return {"sign_ins": {r.id: r.outcome for r in sign_ins}, "sspr": {s.user: s.outcome for s in sspr},
            "tap": {t.id: t.outcome for t in taps}, "metrics": metrics}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["authentication_methods"]
    sign_ins = evaluate_sign_ins(data, cfg)
    sspr = evaluate_all_sspr(data, cfg)
    taps = evaluate_taps(data, cfg)
    raw = {a.get("id"): a for a in data.get("sign_ins", [])}
    users = {u["id"]: u for u in data.get("users", [])}
    qs: list = []

    for r in sign_ins:
        a = raw.get(r.id, {})
        u = users.get(r.user)
        ctx = (f"user={r.user} groups={u.get('groups') if u else 'not found'} · method={r.method} · "
               f"required strength={r.strength}" + (f" · AAGUID={a['aaguid']}" if a.get("aaguid") else ""))
        qs.append(Question(prompt=f"{r.id} ({a.get('ca_policy', 'Conditional Access')}): what is the result?",
                           context=ctx, choices=list(SIGN_IN_OUTCOMES), answer=r.outcome,
                           explanation="; ".join(r.reasons), objective="2.2"))
    rules = sorted({r.rule for r in sign_ins} | {"method not enabled", "not in strength", "unknown strength",
                                                "AAGUID not allowed", "allowed by strength", "unknown user"})
    for r in sign_ins:
        if r.rule in ("AAGUID not allowed", "method not enabled"):
            qs.append(Question(prompt=f"{r.id}: which check decided this sign-in?", choices=choices_with(r.rule, rules, key=r.id),
                               answer=r.rule, explanation="; ".join(r.reasons), objective="2.1"))

    for s in sspr:
        u = users.get(s.user, {})
        qs.append(Question(prompt=f"{s.user}: what is the self-service password reset readiness?",
                           context=f"roles={u.get('roles') or 'none'} groups={u.get('groups')} registered={u.get('registered')}",
                           choices=list(SSPR_OUTCOMES), answer=s.outcome, explanation="; ".join(s.reasons),
                           objective="2.1"))
    for t in taps:
        req = next((x for x in data.get("tap_requests", []) if x.get("id") == t.id), {})
        qs.append(Question(prompt=f"{t.id}: is this Temporary Access Pass accepted?",
                           context=f"request={ {k: v for k, v in req.items() if k != 'id'} } · policy={data.get('tenant', {}).get('tap')}",
                           choices=list(TAP_OUTCOMES), answer=t.outcome, explanation="; ".join(t.reasons),
                           objective="2.1"))

    pr = cfg["builtin_strengths"]["phishing_resistant_mfa"]["combinations"]
    non_pr = [_label(c, cfg) for c in cfg["builtin_strengths"]["mfa"]["combinations"] if c not in pr]
    for c in pr:
        qs.append(Question(prompt="Which method satisfies the built-in Phishing-resistant MFA strength?",
                           choices=choices_with(_label(c, cfg), non_pr, key=c), answer=_label(c, cfg),
                           explanation="phishing-resistant methods: " + ", ".join(_label(x, cfg) for x in pr),
                           objective="2.2"))
    pl = cfg["builtin_strengths"]["passwordless_mfa"]["combinations"]
    only_pl = [c for c in pl if c not in pr]
    for c in only_pl:
        qs.append(Question(prompt=f"{_label(c, cfg)} satisfies which built-in strengths?",
                           choices=["MFA and Passwordless MFA, but not Phishing-resistant MFA",
                                    "all three built-in strengths", "MFA only", "none of the built-in strengths"],
                           answer="MFA and Passwordless MFA, but not Phishing-resistant MFA",
                           explanation="it is passwordless, but a relaying proxy can still trick the user into approving",
                           objective="2.2"))
    bs = cfg["builtin_strengths"]
    tap_in = [k for k in ("mfa", "passwordless_mfa", "phishing_resistant_mfa")
              if "temporaryAccessPassOneTime" in bs[k]["combinations"]]
    tap_choice = {("mfa",): "MFA only", ("mfa", "passwordless_mfa"): "MFA and Passwordless MFA, but not Phishing-resistant MFA",
                  ("mfa", "passwordless_mfa", "phishing_resistant_mfa"): "all three built-in strengths",
                  (): "none of the built-in strengths"}
    if tuple(tap_in) in tap_choice:
        qs.append(Question(prompt="A Temporary Access Pass (one-time use) satisfies which built-in strengths?",
                           choices=sorted(tap_choice.values()), answer=tap_choice[tuple(tap_in)],
                           explanation="TAP is listed in: " + (", ".join(bs[k]["name"] for k in tap_in) or "none")
                           + "; it exists to bootstrap registration of stronger methods", objective="2.2"))
    adm = cfg["admin_sspr"]
    qs.append(Question(prompt="Which statement about the administrator SSPR policy is true?",
                       choices=[f"admins always need {adm['methods_required']} methods and cannot use security questions",
                                "admins follow the same SSPR policy as users",
                                "admins can use security questions as one of their methods",
                                "SSPR is always disabled for admins"],
                       answer=f"admins always need {adm['methods_required']} methods and cannot use security questions",
                       explanation="the admin policy is enforced by Microsoft regardless of the tenant's user policy",
                       objective="2.1"))
    qs.append(Question(prompt="What does number matching in Microsoft Authenticator mainly defend against?",
                       choices=["MFA fatigue (push bombing) approvals", "SIM swapping of SMS codes",
                                "adversary-in-the-middle token theft", "password spraying"],
                       answer="MFA fatigue (push bombing) approvals",
                       explanation=cfg["concepts"].get("number matching", ""), objective="2.1"))
    terms = sorted(k for k in cfg["concepts"] if not k.startswith("_"))
    for term in terms:
        qs.append(Question(prompt=f"Which term is this? \"{cfg['concepts'][term]}\"",
                           choices=choices_with(term, terms, key=term), answer=term,
                           explanation=cfg["concepts"][term],
                           objective="2.2" if "strength" in term else "2.1"))
    return qs


# --------------------------------------------------------------------------- #
# Random scenario
# --------------------------------------------------------------------------- #
_FIRST = ["Ava", "Bo", "Cy", "Di", "Ed", "Flo", "Gil", "Hal", "Ines", "Jo", "Kai", "Lu", "Mo", "Nia"]
_LAST = ["Arden", "Brook", "Cole", "Dale", "Ellis", "Frost", "Gray", "Hale", "Iver", "Joss"]


def generate_scenario(rng, policies: dict) -> dict:
    cfg = policies["authentication_methods"]
    groups = ["Staff", "Contractors", "Admins", "Clinicians", "Finance", "Interns"]
    sms_ex = rng.choice([["Admins"], []])
    tenant = {
        "name": "Random Example Org",
        "methods": {
            "fido2": {"state": "enabled", "include": ["all_users"], "exclude": []},
            "windowsHelloForBusiness": {"state": "enabled", "include": ["all_users"], "exclude": []},
            "x509Certificate": {"state": "enabled", "include": [rng.choice(["Clinicians", "Staff"])], "exclude": []},
            "microsoftAuthenticator": {"state": "enabled", "include": ["Staff", "Contractors"], "exclude": [],
                                       "modes": {"Staff": "any", "Contractors": rng.choice(["push", "any"])}},
            "sms": {"state": "enabled", "include": ["Contractors", "Staff"], "exclude": sms_ex},
            "voice": {"state": rng.choice(["disabled", "enabled"]), "include": ["all_users"], "exclude": []},
            "hardwareOath": {"state": "enabled", "include": ["Finance"], "exclude": []},
            "softwareOath": {"state": "disabled", "include": [], "exclude": []},
            "temporaryAccessPass": {"state": "enabled", "include": ["Staff", "Admins"], "exclude": []},
            "email": {"state": "enabled", "include": ["all_users"], "exclude": []},
        },
        "custom_strengths": {"custom_keys": {"name": "Approved Keys", "combinations": ["fido2", "password,hardwareOath"],
                                             "fido2_allowed_aaguids": ["aaaa-1111"]}},
        "sspr": {"enabled_for": "selected", "groups": ["Staff", "Contractors"], "methods_required": rng.choice([1, 2]),
                 "allowed_methods": ["mobileApp", "mobilePhone", "email", "securityQuestions"]},
        "tap": {"min_lifetime_minutes": 60, "max_lifetime_minutes": rng.choice([240, 480]),
                "default_lifetime_minutes": 60, "one_time_only": rng.choice([True, False])},
    }
    regs = ["fido2", "windowsHelloForBusiness", "microsoftAuthenticator", "sms", "voice", "email",
            "securityQuestions", "officePhone", "hardwareOath"]
    users = []
    n = rng.randint(7, 10)
    for i in range(n):
        g = sorted(set(rng.sample(groups, rng.randint(1, 2))))
        roles = [rng.choice(["Global Administrator", "Helpdesk Administrator"])] if "Admins" in g else []
        users.append({"id": f"u{i + 1:02d}", "name": f"{rng.choice(_FIRST)} {rng.choice(_LAST)}", "groups": g,
                      "roles": roles, "registered": sorted(rng.sample(regs, rng.randint(0, 4)))})
    # Fixed users so every outcome can appear.
    users += [
        {"id": "adm.x", "name": "Admin X", "groups": ["Admins"], "roles": ["Global Administrator"],
         "registered": ["fido2", "securityQuestions", "microsoftAuthenticator"]},
        {"id": "staff.ok", "name": "Staff OK", "groups": ["Staff"], "roles": [],
         "registered": ["microsoftAuthenticator", "email", "sms"]},
        {"id": "staff.one", "name": "Staff One", "groups": ["Staff"], "roles": [], "registered": ["officePhone", "sms"]},
        {"id": "staff.none", "name": "Staff None", "groups": ["Staff"], "roles": [], "registered": ["fido2"]},
    ]
    combos = [c for c in cfg["combinations"]]
    strengths = list(cfg["builtin_strengths"]) + ["custom_keys"]
    sign_ins = []
    for i in range(rng.randint(8, 12)):
        u = rng.choice(users)["id"] if rng.random() > 0.08 else "ghost.user"
        s = {"id": f"S{i + 1:02d}", "user": u, "app": rng.choice(["Office 365", "Azure portal", "Finance ERP"]),
             "ca_policy": "CA random", "required_strength": rng.choice(strengths), "method": rng.choice(combos)}
        if s["method"] == "fido2":
            s["aaguid"] = rng.choice(["aaaa-1111", "bbbb-2222"])
        sign_ins.append(s)
    k = len(sign_ins)
    sign_ins += [
        {"id": f"S{k + 1:02d}", "user": "staff.ok", "app": "Office 365", "ca_policy": "CA MFA",
         "required_strength": "mfa", "method": "password,microsoftAuthenticatorPush"},
        {"id": f"S{k + 2:02d}", "user": "staff.ok", "app": "Azure portal", "ca_policy": "CA PR",
         "required_strength": "phishing_resistant_mfa", "method": "deviceBasedPush"},
        {"id": f"S{k + 3:02d}", "user": "staff.ok", "app": "Office 365", "ca_policy": "CA MFA",
         "required_strength": "mfa", "method": "password,softwareOath"},
    ]
    taps = []
    for i in range(rng.randint(5, 8)):
        taps.append({"id": f"T{i + 1:02d}", "user": rng.choice(users)["id"],
                     "lifetime_minutes": rng.choice([30, 60, 120, 480, 1440]), "one_time": rng.choice([True, False]),
                     "uses": rng.choice([0, 0, 1]), "minutes_since_issue": rng.choice([0, 10, 90])})
    taps.append({"id": f"T{len(taps) + 1:02d}", "user": "staff.ok", "lifetime_minutes": 60, "one_time": True,
                 "uses": 0, "minutes_since_issue": 0})
    return {"_description": "Randomly generated authentication methods scenario", "tenant": tenant, "users": users,
            "sign_ins": sign_ins, "tap_requests": taps}
