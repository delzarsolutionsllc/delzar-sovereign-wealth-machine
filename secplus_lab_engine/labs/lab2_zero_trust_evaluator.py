"""
Lab 2 — Zero Trust Access Evaluator
===================================

Security+ SY0-701 objectives
----------------------------
* 1.2  Zero Trust: Control Plane (adaptive identity, threat scope reduction,
       policy-driven access control, Policy Engine, Policy Administrator) and
       Data Plane (implicit trust zones, subject/system, Policy Enforcement Point).
* 4.6  Context-aware / conditional access, MFA.

Architecture (NIST SP 800-207)
------------------------------
::

    Subject ──request──▶ PEP ──▶ Policy Engine (PE)  ─ decides (trust algorithm)
                          ▲          │
                          │          ▼
                          └──── Policy Administrator (PA) ─ issues/revokes tokens
    (data plane)              (control plane)

* **PE** scores every request using context: identity risk, MFA, device
  posture, IP reputation, geo, time of day, resource sensitivity.
* **PA** turns the PE verdict into an action: mint a short-lived, scoped,
  HMAC-signed token, require step-up MFA, or deny. It can also revoke.
* **PEP** sits in front of the resource and enforces: no valid token, no data.
  It checks signature, expiry, scope and revocation on *every* request —
  "never trust, always verify".

Run it
------
    python main.py lab 2
"""

from __future__ import annotations

import base64
import dataclasses
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable

from utils.crypto_helpers import canonical_json, hmac_sign, hmac_verify

TITLE = "Lab 2 — Zero Trust Access Evaluator (PE / PA / PEP)"
OBJECTIVES = "SY0-701 1.2 Zero Trust control & data planes · 4.6 Conditional access"


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class DevicePosture:
    id: str
    managed: bool
    health_score: int  # 0-100 from EDR/MDM posture check


@dataclass
class AccessRequest:
    id: str
    subject: str
    resource: str
    action: str
    hour: int
    mfa: bool
    device: DevicePosture
    ip: str
    ip_reputation: str          # good | suspicious | bad
    geo: str
    usual_geo: str
    user_risk: str = "low"      # low | medium | high (from UEBA / IdP risk)
    note: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "AccessRequest":
        dev = d["device"]
        return cls(
            id=d["id"],
            subject=d["subject"],
            resource=d["resource"],
            action=d.get("action", "read"),
            hour=int(d["hour"]),
            mfa=bool(d["mfa"]),
            device=DevicePosture(dev["id"], bool(dev["managed"]), int(dev["health_score"])),
            ip=d["ip"],
            ip_reputation=d.get("ip_reputation", "good"),
            geo=d.get("geo", ""),
            usual_geo=d.get("usual_geo", d.get("geo", "")),
            user_risk=d.get("user_risk", "low"),
            note=d.get("note", ""),
        )


@dataclass
class PolicyDecision:
    request_id: str
    verdict: str                # ALLOW | STEP_UP | DENY
    trust_score: int
    required_score: int
    reasons: list[str] = field(default_factory=list)


@dataclass
class EnforcementResult:
    allowed: bool
    reason: str
    data: str | None = None


# --------------------------------------------------------------------------- #
# Control plane: Policy Engine
# --------------------------------------------------------------------------- #
class PolicyEngine:
    """The 'brain': applies the trust algorithm and returns a verdict."""

    def __init__(self, policy: dict):
        self.p = policy
        self.w = policy["weights"]

    def evaluate(self, req: AccessRequest) -> PolicyDecision:
        reasons: list[str] = []
        res_policy = self.p["resource_sensitivity"].get(req.resource)
        if res_policy is None:
            return PolicyDecision(req.id, "DENY", 0, 100, [f"unknown resource '{req.resource}' (default deny)"])

        # 1. Entitlement: is the subject even allowed this resource? (least privilege)
        if req.resource not in self.p["entitlements"].get(req.subject, []):
            return PolicyDecision(req.id, "DENY", 0, res_policy["min_score"], [f"'{req.subject}' not entitled to '{req.resource}'"])

        # 2. Hard stop: known-bad infrastructure is never trusted.
        score = 100
        if req.ip_reputation == "bad":
            score -= self.w["ip_bad_reputation"]
            reasons.append(f"IP {req.ip} has BAD reputation (-{self.w['ip_bad_reputation']})")
        elif req.ip_reputation == "suspicious":
            score -= self.w["ip_suspicious_reputation"]
            reasons.append(f"IP {req.ip} is suspicious (-{self.w['ip_suspicious_reputation']})")

        # 3. Device posture
        if req.device.health_score < self.p["min_device_health"]:
            score -= self.w["device_unhealthy"]
            reasons.append(f"device health {req.device.health_score} < {self.p['min_device_health']} (-{self.w['device_unhealthy']})")
        if not req.device.managed:
            score -= self.w["device_unmanaged"]
            reasons.append(f"device {req.device.id} is unmanaged (-{self.w['device_unmanaged']})")

        # 4. Identity signals (adaptive identity)
        if not req.mfa:
            score -= self.w["no_mfa"]
            reasons.append(f"no MFA presented (-{self.w['no_mfa']})")
        if req.user_risk == "high":
            score -= self.w["high_user_risk"]
            reasons.append(f"IdP/UEBA user risk HIGH (-{self.w['high_user_risk']})")
        if req.geo != req.usual_geo:
            score -= self.w["geo_anomaly"]
            reasons.append(f"geo '{req.geo}' differs from usual '{req.usual_geo}' (-{self.w['geo_anomaly']})")

        # 5. Environment
        bh = self.p["business_hours"]
        if not (bh["start"] <= req.hour < bh["end"]):
            score -= self.w["outside_business_hours"]
            reasons.append(f"request at {req.hour:02d}:00 outside business hours (-{self.w['outside_business_hours']})")

        score = max(0, score)
        required = res_policy["min_score"]

        if req.ip_reputation == "bad":
            verdict = "DENY"
            reasons.append("hard rule: bad-reputation source is always denied")
        elif res_policy.get("requires_mfa") and not req.mfa:
            verdict = "STEP_UP" if score >= self.p["thresholds"]["step_up"] else "DENY"
            reasons.append("resource requires MFA")
        elif score >= required:
            verdict = "ALLOW"
        elif score >= self.p["thresholds"]["step_up"]:
            verdict = "STEP_UP"
            reasons.append(f"score {score} < {required}: require step-up authentication")
        else:
            verdict = "DENY"
        if not reasons:
            reasons.append("all signals nominal")
        return PolicyDecision(req.id, verdict, score, required, reasons)


# --------------------------------------------------------------------------- #
# Control plane: Policy Administrator
# --------------------------------------------------------------------------- #
class PolicyAdministrator:
    """Executes PE decisions: mints, signs and revokes short-lived session tokens."""

    def __init__(self, signing_key: str, ttl_seconds: int, clock: Callable[[], float] = time.time):
        self.key = signing_key
        self.ttl = ttl_seconds
        self.clock = clock
        self.revoked: set[str] = set()
        self.issued: dict[str, dict] = {}

    def issue(self, req: AccessRequest, decision: PolicyDecision, ttl: int | None = None) -> str | None:
        """Return a signed token for ALLOW verdicts, otherwise ``None``."""
        if decision.verdict != "ALLOW":
            return None
        now = int(self.clock())
        claims = {
            "jti": secrets.token_hex(8),
            "sub": req.subject,
            "scope": req.resource,
            "act": req.action,
            "dev": req.device.id,
            "iat": now,
            "exp": now + (ttl or self.ttl),
        }
        self.issued[claims["jti"]] = claims
        return self._encode(claims)

    def revoke_subject(self, subject: str) -> int:
        """Revoke every token ever issued to ``subject`` (account compromise). Returns count."""
        jtis = [j for j, c in self.issued.items() if c["sub"] == subject and j not in self.revoked]
        self.revoked.update(jtis)
        return len(jtis)

    def revoke(self, token: str) -> None:
        claims = self.decode_unverified(token)
        self.revoked.add(claims["jti"])

    # token format: base64(claims_json).hex_hmac
    def _encode(self, claims: dict) -> str:
        body = base64.urlsafe_b64encode(canonical_json(claims).encode()).decode()
        return f"{body}.{hmac_sign(self.key, body)}"

    @staticmethod
    def decode_unverified(token: str) -> dict:
        body, _, _ = token.partition(".")
        return json.loads(base64.urlsafe_b64decode(body.encode()))

    def verify(self, token: str) -> tuple[bool, str, dict | None]:
        try:
            body, sig = token.split(".", 1)
        except (ValueError, AttributeError):
            return False, "malformed token", None
        if not hmac_verify(self.key, body, sig):
            return False, "signature invalid (forged or tampered token)", None
        claims = json.loads(base64.urlsafe_b64decode(body.encode()))
        if claims["jti"] in self.revoked:
            return False, "token revoked by Policy Administrator", claims
        if self.clock() >= claims["exp"]:
            return False, "token expired", claims
        return True, "ok", claims


# --------------------------------------------------------------------------- #
# Data plane: Policy Enforcement Point
# --------------------------------------------------------------------------- #
class PolicyEnforcementPoint:
    """The gate in front of resources. Verifies every request; forwards only valid ones."""

    def __init__(self, admin: PolicyAdministrator, resources: dict[str, str]):
        self.admin = admin
        self.resources = resources  # resource name -> simulated payload
        self.log: list[dict] = []

    def handle(self, token: str | None, resource: str, action: str = "read") -> EnforcementResult:
        if not token:
            return self._record(resource, False, "no token presented (implicit trust is not allowed)")
        ok, reason, claims = self.admin.verify(token)
        if not ok:
            return self._record(resource, False, reason)
        if claims["scope"] != resource:
            return self._record(resource, False, f"token scoped to '{claims['scope']}', not '{resource}'")
        if claims["act"] != action:
            return self._record(resource, False, f"token permits '{claims['act']}', not '{action}'")
        return self._record(resource, True, f"forwarded for {claims['sub']}", self.resources.get(resource))

    def _record(self, resource: str, allowed: bool, reason: str, data: str | None = None) -> EnforcementResult:
        self.log.append({"resource": resource, "allowed": allowed, "reason": reason})
        return EnforcementResult(allowed, reason, data)


class ZeroTrustGateway:
    """Convenience wrapper wiring PE + PA + PEP together."""

    def __init__(self, policy: dict, clock: Callable[[], float] = time.time):
        self.policy = policy
        self.risky_subjects: set[str] = set()
        self.pe = PolicyEngine(policy)
        self.pa = PolicyAdministrator(policy["signing_key"], policy["token_ttl_seconds"], clock)
        payloads = {name: f"<{name} records>" for name in policy["resource_sensitivity"]}
        self.pep = PolicyEnforcementPoint(self.pa, payloads)

    def request_access(self, req: AccessRequest) -> tuple[PolicyDecision, str | None]:
        decision = self.pe.evaluate(req)
        return decision, self.pa.issue(req, decision)

    def complete_step_up(
        self, req: AccessRequest, decision: PolicyDecision, mfa_passed: bool
    ) -> tuple[PolicyDecision, str | None]:
        """
        Finish a STEP_UP verdict (adaptive identity).

        * MFA failed or was denied → DENY and raise the user's risk (it may be
          an MFA-fatigue attack or stolen credentials).
        * MFA passed → re-evaluate with MFA present plus an assurance bonus.
          Fresh MFA proves *who* is asking. It cannot fix *what* they are asking
          from, so an unhealthy device can still fail.
        * Success issues a token with a SHORTER lifetime than a normal one.
        """
        if decision.verdict != "STEP_UP":
            raise ValueError(f"{req.id} is {decision.verdict}, not STEP_UP")
        cfg = self.policy.get("step_up", {"bonus": 15, "ttl_divisor": 3})
        if not mfa_passed:
            self.risky_subjects.add(req.subject)
            return PolicyDecision(req.id, "DENY", decision.trust_score, decision.required_score,
                                  ["step-up MFA failed/denied; user risk raised (possible MFA fatigue or stolen creds)"]), None
        reeval = self.pe.evaluate(dataclasses.replace(req, mfa=True))
        score = min(100, reeval.trust_score + cfg["bonus"])
        reasons = reeval.reasons + [f"fresh MFA step-up (+{cfg['bonus']}) → {score}"]
        if reeval.verdict == "DENY" or score < reeval.required_score:
            reasons.append(f"still below {reeval.required_score}: remediate the device/context, MFA alone is not enough")
            return PolicyDecision(req.id, "DENY", score, reeval.required_score, reasons), None
        final = PolicyDecision(req.id, "ALLOW", score, reeval.required_score, reasons)
        ttl = max(60, self.policy["token_ttl_seconds"] // cfg["ttl_divisor"])
        return final, self.pa.issue(req, final, ttl=ttl)


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SY0-701 1.2 Zero Trust (control plane vs data plane) and 4.6 conditional access.",
    "concepts": [
        "Control plane = Policy Engine (decides) + Policy Administrator (issues/revokes). Data plane = PEP + resources.",
        "Adaptive identity: the same user gets ALLOW, STEP_UP or DENY depending on real-time context.",
        "Threat scope reduction: tokens are short-lived and scoped to ONE resource + action.",
        "Never trust, always verify: the PEP re-validates on every request, even inside the network.",
    ],
    "failure_modes": [
        "Treating 'on the VPN' or 'inside the LAN' as trusted (implicit trust zone).",
        "Long-lived or broadly-scoped tokens enable replay and lateral movement.",
        "MFA push approval alone treated as proof — MFA fatigue attacks bypass it.",
        "No revocation path: compromised sessions stay valid until expiry.",
    ],
    "ai_governance": [
        "Treat every AI agent as a non-human SUBJECT with its own identity, entitlements and device/workload posture.",
        "Agents should receive short-lived, narrowly-scoped tokens per task — never standing credentials.",
        "The PE should weigh agent-specific risk signals (anomalous call volume, new tool usage).",
        "The PA must be able to revoke an agent's tokens instantly (kill switch).",
    ],
    "exam_tips": [
        "'Component that makes the access decision' => Policy Engine. 'Component that enforces it' => PEP.",
        "'Establishes and terminates the session / issues tokens' => Policy Administrator.",
        "Zero Trust replaces perimeter trust with continuous, per-request verification.",
        "Microsegmentation and implicit trust zones are data-plane concepts.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict, clock: Callable[[], float] | None = None) -> dict:
    zt_policy = policies["zero_trust"]
    fake_now = [clock() if clock else 1_800_000_000.0]
    gw = ZeroTrustGateway(zt_policy, clock=lambda: fake_now[0])

    ui.section("Control plane — Policy Engine decisions")
    rows, tokens = [], {}
    decisions = []
    for raw in data["requests"]:
        req = AccessRequest.from_dict(raw)
        dec, tok = gw.request_access(req)
        decisions.append(dec)
        if tok:
            tokens[req.id] = (req, tok)
        rows.append([req.id, req.subject, req.resource, f"{dec.trust_score}/{dec.required_score}", dec.verdict, "; ".join(dec.reasons)])
    ui.table("Trust algorithm results", ["Req", "Subject", "Resource", "Score/Need", "Verdict", "Signals"], rows)

    ui.section("Control plane — Policy Administrator token issuance")
    for rid, (req, tok) in tokens.items():
        claims = gw.pa.decode_unverified(tok)
        ui.status(f"{rid} token for {req.subject} -> {req.resource}", "GRANTED", f"jti={claims['jti']} ttl={zt_policy['token_ttl_seconds']}s")

    ui.section("Adaptive identity — completing STEP_UP challenges")
    step_rows = []
    outcomes = data.get("step_up_outcomes", {})
    for raw, dec in zip(data["requests"], decisions):
        if dec.verdict != "STEP_UP":
            continue
        req = AccessRequest.from_dict(raw)
        passed = outcomes.get(req.id, True)
        final, tok = gw.complete_step_up(req, dec, passed)
        detail = final.reasons[-1]
        if tok:
            c = gw.pa.decode_unverified(tok)
            detail += f" · token ttl={c['exp'] - c['iat']}s"
        step_rows.append([req.id, req.subject, "passed" if passed else "FAILED", f"{final.trust_score}/{final.required_score}",
                          final.verdict, detail])
    ui.table("Step-up results", ["Req", "Subject", "MFA", "Score/Need", "Final", "Detail"],
             step_rows or [["-", "-", "-", "-", "-", "no STEP_UP verdicts"]])

    ui.section("Data plane — PEP enforcement (legit traffic + attacks)")
    results = []
    if "REQ-01" in tokens:
        req, tok = tokens["REQ-01"]
        r = gw.pep.handle(tok, req.resource, req.action)
        results.append(["LEGIT", "Valid token, correct scope", "ALLOW" if r.allowed else "BLOCK", r.reason])
        for atk in data.get("pep_attacks", []):
            kind = atk["kind"]
            if kind == "scope":
                r = gw.pep.handle(tok, "finance-ledger", "read")
            elif kind == "forged":
                claims = gw.pa.decode_unverified(tok)
                claims["scope"] = "prod-db"
                body = base64.urlsafe_b64encode(canonical_json(claims).encode()).decode()
                r = gw.pep.handle(f"{body}.{tok.split('.', 1)[1]}", "prod-db", "read")
            elif kind == "none":
                r = gw.pep.handle(None, "hr-database", "read")
            elif kind == "revoked":
                fresh_req = AccessRequest.from_dict(data["requests"][0])
                _, fresh = gw.request_access(fresh_req)
                gw.pa.revoke(fresh)
                r = gw.pep.handle(fresh, fresh_req.resource, fresh_req.action)
            elif kind == "expired":
                saved = fake_now[0]
                fake_now[0] += zt_policy["token_ttl_seconds"] + 1
                r = gw.pep.handle(tok, req.resource, req.action)
                fake_now[0] = saved
            else:
                continue
            results.append([atk["id"], atk["description"], "ALLOW" if r.allowed else "BLOCK", r.reason])
    ui.table("PEP gate log", ["Case", "Scenario", "Result", "Reason"], results)

    ui.insight(INSIGHT)
    return {
        "allow": sum(d.verdict == "ALLOW" for d in decisions),
        "step_up": sum(d.verdict == "STEP_UP" for d in decisions),
        "step_up_granted": sum(r[4] == "ALLOW" for r in step_rows),
        "deny": sum(d.verdict == "DENY" for d in decisions),
        "attacks_blocked": sum(1 for r in results[1:] if r[2] == "BLOCK"),
    }


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
_ATTACK_ANSWERS = {
    "expired": "Expiry (exp claim)",
    "scope": "Scope check",
    "forged": "HMAC signature check",
    "revoked": "Revocation list",
    "none": "No token presented",
}


def build_challenges(policies: dict, data: dict) -> list:
    """Predict the Policy Engine verdict, then which PEP check stops each attack."""
    from utils.challenge import Question

    zt = policies["zero_trust"]
    pe = PolicyEngine(zt)
    qs: list = []
    for raw in data["requests"]:
        req = AccessRequest.from_dict(raw)
        d = pe.evaluate(req)
        need = zt["resource_sensitivity"].get(req.resource, {})
        qs.append(Question(
            prompt=f"{req.id}: what does the Policy Engine decide for {req.subject} → {req.resource} ({req.action})?",
            context=(f"{req.note}\nMFA={req.mfa}  device={req.device.id} managed={req.device.managed} "
                     f"health={req.device.health_score}  ip={req.ip} ({req.ip_reputation})  geo={req.geo} "
                     f"(usual {req.usual_geo})  hour={req.hour:02d}:00  user_risk={req.user_risk}\n"
                     f"Resource needs score ≥ {need.get('min_score')} (MFA required: {need.get('requires_mfa')}); "
                     f"step-up floor = {zt['thresholds']['step_up']}"),
            choices=["ALLOW", "STEP_UP", "DENY"],
            answer=d.verdict,
            explanation=f"Trust score {d.trust_score}/{d.required_score}. " + "; ".join(d.reasons),
            objective="1.2",
        ))
    for atk in data.get("pep_attacks", []):
        if atk["kind"] not in _ATTACK_ANSWERS:
            continue
        qs.append(Question(
            prompt=f"{atk['id']}: {atk['description']}. Which PEP check stops it?",
            choices=sorted(_ATTACK_ANSWERS.values()),
            answer=_ATTACK_ANSWERS[atk["kind"]],
            explanation="The PEP re-validates every request: signature first, then revocation, expiry, "
                        "scope and action. Nothing is trusted because of where it came from.",
            objective="1.2",
        ))
    return qs
