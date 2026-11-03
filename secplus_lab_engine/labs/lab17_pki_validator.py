"""
Lab 17 — PKI & Certificate Validator
====================================

Security+ SY0-701 objectives
----------------------------
* 1.4  Use appropriate cryptographic solutions: public key infrastructure
       (public/private keys, key escrow), certificates (certificate
       authorities, CRLs, OCSP, self-signed, third-party, root of trust,
       CSR generation, wildcard), key length, algorithms.

What it does
------------
A browser-style validator for TLS certificate chains. Certificates are
structured JSON records (subject, issuer, serial, validity, key, signature
algorithm, CA flag, SAN, EKU, SPKI hash), so the trust rules are visible
instead of buried in ASN.1. For each connection it checks, deny by default:

1. **Path & trust**: each cert's issuer is the next cert's subject; every
   issuer is a CA; the chain ends at (or is issued by) a trusted root.
   → INCOMPLETE_CHAIN, NOT_A_CA, SELF_SIGNED, UNTRUSTED_ROOT
2. **Validity**: every cert is inside its notBefore/notAfter window.
   → EXPIRED, NOT_YET_VALID; warnings EXPIRING_SOON, VALIDITY_TOO_LONG (> 398 days)
3. **Hostname**: matches a SAN entry (CN only if there is no SAN). A wildcard
   covers exactly ONE label: ``*.example.com`` matches ``a.example.com`` but
   not ``a.b.example.com`` or ``example.com``.  → HOSTNAME_MISMATCH
4. **Strength**: RSA ≥ 2048 / EC ≥ 256 bits; SHA-2 signatures only.
   → WEAK_KEY, WEAK_SIGNATURE
5. **Usage**: the leaf's EKU must include serverAuth.  → WRONG_KEY_USAGE
6. **Revocation**: OCSP status or the issuer's CRL.  → REVOKED;
   no status available → REVOCATION_UNKNOWN (a warning under soft-fail,
   an error under hard-fail)
7. **Pinning**: if the app pins SPKI hashes, the presented key must match.
   → PIN_MISMATCH (classic sign of TLS interception)

Verdict: UNTRUSTED (any error) / TRUSTED_WITH_WARNINGS / TRUSTED.

Run it
------
    python main.py lab 17
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

TITLE = "Lab 17 — PKI & Certificate Validator"
OBJECTIVES = "SY0-701 1.4 PKI: CAs, chains, CRL/OCSP, wildcard/SAN, self-signed, key length, pinning"
VERDICTS = ["TRUSTED", "TRUSTED_WITH_WARNINGS", "UNTRUSTED"]
FIXES = {
    "REVOKED": "Replace the certificate now; it was revoked (often key compromise). Investigate the key.",
    "PIN_MISMATCH": "Treat as interception: verify the network path / proxy; never disable the pin to 'make it work'.",
    "UNTRUSTED_ROOT": "Chain to a publicly trusted CA, or deploy your private root to managed devices only.",
    "SELF_SIGNED": "Issue the certificate from your internal CA (or a public CA); don't train users to click through warnings.",
    "INCOMPLETE_CHAIN": "Configure the server to send the full chain (leaf + intermediates).",
    "NOT_A_CA": "Re-issue from a real CA: a leaf certificate (CA:FALSE) cannot sign other certificates.",
    "EXPIRED": "Renew and automate renewal (ACME); monitor expiry dates.",
    "NOT_YET_VALID": "Check the server clock / NTP and the certificate's notBefore date.",
    "HOSTNAME_MISMATCH": "Re-issue with the correct SAN entries (a wildcard covers only one label).",
    "WEAK_SIGNATURE": "Re-issue with a SHA-256 or stronger signature; SHA-1/MD5 are broken.",
    "WEAK_KEY": "Generate a new key pair (RSA ≥ 2048 or EC P-256+) and a new CSR.",
    "WRONG_KEY_USAGE": "Request a certificate with the serverAuth extended key usage.",
    "REVOCATION_UNKNOWN": "Enable OCSP stapling so clients always get a fresh revocation status.",
    "VALIDITY_TOO_LONG": "Public TLS certificates are limited to 398 days; shorter lifetimes limit exposure.",
    "EXPIRING_SOON": "Renew before expiry; alert at 30 days.",
}


@dataclass
class Issue:
    code: str
    level: str          # error | warning
    message: str


@dataclass
class Validation:
    id: str
    hostname: str
    verdict: str
    primary: str
    issues: list[Issue] = field(default_factory=list)

    @property
    def codes(self) -> set[str]:
        return {i.code for i in self.issues}


def hostname_matches(host: str, pattern: str) -> bool:
    """RFC 6125-style matching: exact, or a wildcard covering exactly one leftmost label."""
    host, pattern = host.lower().rstrip("."), pattern.lower().rstrip(".")
    if not pattern.startswith("*."):
        return host == pattern
    rest = pattern[2:]
    if "*" in rest or rest.count(".") < 1:
        return False                                    # no partial / multi wildcards, no '*.com'
    labels = host.split(".")
    return len(labels) == rest.count(".") + 2 and labels[0] != "" and ".".join(labels[1:]) == rest


def validate(scenario: dict, cfg: dict, as_of: date) -> Validation:
    chain: list[dict] = scenario["chain"]
    rev = scenario.get("revocation", {})
    roots = set(cfg["trusted_roots"])
    issues: list[Issue] = []
    warn_codes = set(cfg["warning_codes"])

    def add(code: str, msg: str, level: str | None = None) -> None:
        issues.append(Issue(code, level or ("warning" if code in warn_codes else "error"), msg))

    if not chain:
        add("INCOMPLETE_CHAIN", "no certificate presented")
        return Validation(scenario["id"], scenario.get("hostname", ""), "UNTRUSTED", "INCOMPLETE_CHAIN", issues)
    leaf = chain[0]

    # 1. path building & trust anchoring ----------------------------------------------
    for cert, nxt in zip(chain, chain[1:]):
        if cert["issuer"] != nxt["subject"]:
            add("INCOMPLETE_CHAIN", f"'{cert['subject']}' is issued by '{cert['issuer']}' but the next certificate is '{nxt['subject']}'")
        if not nxt.get("is_ca"):
            add("NOT_A_CA", f"'{nxt['subject']}' signed '{cert['subject']}' but is not a CA (basicConstraints CA:FALSE)")
    last = chain[-1]
    anchor_is_last = last["subject"] == last["issuer"]
    if anchor_is_last:
        if last["subject"] not in roots:
            if len(chain) == 1:
                add("SELF_SIGNED", f"'{last['subject']}' is self-signed and not in the trust store")
            else:
                add("UNTRUSTED_ROOT", f"chain ends at '{last['subject']}', which is not a trusted root")
    elif last["issuer"] not in roots:
        add("INCOMPLETE_CHAIN", f"issuer '{last['issuer']}' was not sent and is not a trusted root (missing intermediate)")
    checked = chain[:-1] if anchor_is_last and last["subject"] in roots else chain   # trust anchors are not re-checked

    # 2. validity ------------------------------------------------------------------------------
    for cert in chain:
        nb, na = date.fromisoformat(cert["not_before"]), date.fromisoformat(cert["not_after"])
        if as_of < nb:
            add("NOT_YET_VALID", f"'{cert['subject']}' is not valid until {nb}")
        elif as_of > na:
            add("EXPIRED", f"'{cert['subject']}' expired on {na}")
    nb, na = date.fromisoformat(leaf["not_before"]), date.fromisoformat(leaf["not_after"])
    if (na - nb).days > cfg["max_leaf_validity_days"]:
        add("VALIDITY_TOO_LONG", f"leaf is valid for {(na - nb).days} days (> {cfg['max_leaf_validity_days']})")
    if as_of <= na and (na - as_of).days <= cfg["expiry_warning_days"]:
        add("EXPIRING_SOON", f"leaf expires in {(na - as_of).days} days ({na})")

    # 3. hostname ---------------------------------------------------------------------------------
    names = leaf.get("san") or [leaf["subject"]]
    host = scenario.get("hostname", "")
    if not any(hostname_matches(host, n) for n in names):
        add("HOSTNAME_MISMATCH", f"'{host}' is not covered by {names}"
            + ("" if leaf.get("san") else " (no SAN; CN fallback used)"))

    # 4. strength ------------------------------------------------------------------------------------
    for cert in checked:
        need = cfg["min_key_bits"].get(cert.get("key_type", "RSA"), 10**6)
        if cert.get("key_bits", 0) < need:
            add("WEAK_KEY", f"'{cert['subject']}' uses {cert.get('key_type')}-{cert.get('key_bits')} (< {need})")
        if cert.get("sig_alg") not in cfg["allowed_signature_algorithms"]:
            add("WEAK_SIGNATURE", f"'{cert['subject']}' is signed with {cert.get('sig_alg')}")

    # 5. usage -----------------------------------------------------------------------------------------
    if "eku" in leaf and "serverAuth" not in leaf["eku"]:
        add("WRONG_KEY_USAGE", f"leaf EKU {leaf['eku']} does not allow TLS server authentication")

    # 6. revocation -------------------------------------------------------------------------------------
    crl, ocsp = rev.get("crl", {}), rev.get("ocsp", {})
    for cert in checked:
        status = ocsp.get(cert["serial"])
        if status == "revoked" or cert["serial"] in crl.get(cert["issuer"], []):
            add("REVOKED", f"'{cert['subject']}' (serial {cert['serial']}) is revoked "
                           f"({'OCSP' if status == 'revoked' else 'CRL from ' + cert['issuer']})")
    if ocsp.get(leaf["serial"]) in (None, "unknown") and leaf["issuer"] not in crl:
        add("REVOCATION_UNKNOWN", "no OCSP answer and no CRL for the leaf; status cannot be confirmed",
            level="error" if cfg["revocation_hard_fail"] else "warning")

    # 7. pinning -------------------------------------------------------------------------------------------
    pins = scenario.get("pinned_spki")
    if pins and not any(c.get("spki_sha256") in pins for c in chain):
        add("PIN_MISMATCH", f"presented key {leaf.get('spki_sha256', '?')[:16]}… is not one of the app's pinned keys")

    sev = cfg["severity"]
    errors = [i for i in issues if i.level == "error"]
    verdict = "UNTRUSTED" if errors else "TRUSTED_WITH_WARNINGS" if issues else "TRUSTED"
    primary = max(issues, key=lambda i: (i.level == "error", sev[i.code])).code if issues else "None"
    return Validation(scenario["id"], host, verdict, primary, issues)


def validate_all(data: dict, policies: dict) -> list[Validation]:
    as_of = date.fromisoformat(data["as_of"])
    return [validate(s, policies["pki"], as_of) for s in data["scenarios"]]


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SY0-701 1.4 Public key infrastructure, certificates and revocation.",
    "concepts": [
        "Trust flows down a chain: root (trust anchor, self-signed) → intermediate CA → leaf. Every link must be valid and every issuer a CA.",
        "Revocation: CRLs are lists you download; OCSP asks about one certificate in real time; OCSP stapling lets the server deliver it.",
        "Names come from the SAN; a wildcard covers exactly one label (*.example.com ≠ a.b.example.com, ≠ example.com).",
        "Key length and algorithm matter: RSA ≥ 2048 / EC ≥ 256 bits with SHA-2 signatures; SHA-1 and MD5 are broken.",
    ],
    "failure_modes": [
        "Servers that send only the leaf certificate: works in some browsers (cached intermediates), fails in apps and APIs.",
        "Training users to click through self-signed certificate warnings, which makes MITM attacks invisible.",
        "Soft-fail revocation checking: an attacker who blocks OCSP makes a revoked certificate look fine.",
        "Expired certificates taking down production because renewal was a calendar reminder, not automation.",
    ],
    "ai_governance": [
        "Agents that call APIs must validate certificates and must never be configured with 'verify=False'.",
        "An AI ops agent may renew certificates through ACME, but issuing from the internal CA or adding trust anchors needs a human.",
        "Pin the endpoints your agents depend on; a PIN_MISMATCH should stop the agent, not be retried around.",
        "Private keys (including agents' own signing keys) belong in an HSM/KMS, never in prompts, logs or tickets.",
    ],
    "exam_tips": [
        "'Real-time status of a single certificate' = OCSP; 'downloaded list of revoked serials' = CRL.",
        "'Covers all first-level subdomains' = wildcard certificate; 'lists several different names' = SAN.",
        "'Request sent to a CA containing the public key' = CSR. 'Third party holds a copy of keys' = key escrow.",
        "Root of trust = the CA certificate in the trust store that everything else chains to.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    results = validate_all(data, policies)
    ui.section(f"Step 1 — Validate each TLS connection (as of {data['as_of']})")
    ui.table("Connections", ["ID", "Hostname", "Chain", "Verdict", "Primary problem"],
             [[r.id, r.hostname, " → ".join(c["subject"] for c in s["chain"]), r.verdict, r.primary]
              for r, s in zip(results, data["scenarios"])])
    ui.section("Step 2 — Why, and how to fix it")
    for r, s in zip(results, data["scenarios"]):
        ui.print(f"[bold]{r.id} {s['title']}[/bold] → {r.verdict}")
        for i in r.issues:
            ui.bullet(f"{i.level.upper()} {i.code}: {i.message}", style="red" if i.level == "error" else "yellow")
        if r.issues:
            ui.bullet(f"Fix: {FIXES[r.primary]}", style="green")
        else:
            ui.bullet("Valid chain, name, strength, usage and revocation status.", style="green")
    ui.insight(INSIGHT)
    return {r.id: r.verdict for r in results}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
# Terms close enough that one must never be a distractor for the other.
CONCEPT_NEIGHBOURS = {
    "Root of trust": ["Self-signed certificate"], "Self-signed certificate": ["Root of trust"],
    "OCSP": ["OCSP stapling", "CRL"], "OCSP stapling": ["OCSP"], "CRL": ["OCSP"],
    "Wildcard certificate": ["SAN"], "SAN": ["Wildcard certificate"],
}
WILDCARD_CASES = [("shop.example.com", "*.example.com"), ("a.b.example.com", "*.example.com"),
                  ("example.com", "*.example.com"), ("www.example.com", "www.example.com"),
                  ("api.example.com", "*.example.org")]


def _brief(s: dict) -> str:
    lines = [f"Connecting to {s['hostname']}" + (f" · app pins {len(s['pinned_spki'])} key(s)" if s.get("pinned_spki") else "")]
    for c in s["chain"]:
        lines.append(f"  [{c['subject']}] issued by [{c['issuer']}] · {c['not_before']}..{c['not_after']} · "
                     f"{c.get('key_type')}-{c.get('key_bits')} {c.get('sig_alg')} · CA={c.get('is_ca')} · "
                     f"SAN={c.get('san', [])} · EKU={c.get('eku', '-')} · serial {c['serial']}")
    lines.append(f"  revocation data: {s.get('revocation', {})}")
    return "\n".join(lines)


def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["pki"]
    codes = sorted(cfg["severity"])
    qs: list = []
    for s, r in zip(data["scenarios"], validate_all(data, policies)):
        ctx = _brief(s) + f"\nTrusted roots: {cfg['trusted_roots']} · as of {data['as_of']}"
        why = "; ".join(f"{i.code}: {i.message}" for i in r.issues) or "no issues"
        qs.append(Question(prompt=f"{r.id}: does the client trust this connection?", context=ctx, choices=VERDICTS,
                           answer=r.verdict, explanation=why, objective="1.4"))
        if r.primary != "None":
            qs.append(Question(prompt=f"{r.id}: what is the MOST serious problem?", context=ctx,
                               choices=choices_with(r.primary, codes, exclude=r.codes, key=r.id), answer=r.primary,
                               explanation=f"{why}. Fix: {FIXES[r.primary]}", objective="1.4"))
    for host, pattern in WILDCARD_CASES:
        ok = hostname_matches(host, pattern)
        qs.append(Question(prompt=f"Does a certificate for '{pattern}' cover '{host}'?", choices=["Yes", "No"],
                           answer="Yes" if ok else "No",
                           explanation="A wildcard matches exactly one leftmost label; non-wildcard names must match exactly.",
                           objective="1.4"))
    terms = sorted(cfg["concepts"])
    for term in terms:
        qs.append(Question(prompt=f"Which term matches: \"{cfg['concepts'][term]}\"?",
                           choices=choices_with(term, terms, key=term, exclude=CONCEPT_NEIGHBOURS.get(term, [])),
                           answer=term,
                           explanation=f"{term}: {cfg['concepts'][term]}", objective="1.4"))
    return qs
