"""
Lab 10 — Email Security Analyzer
================================

Security+ SY0-701 objectives
----------------------------
* 4.5  Email security: SPF, DKIM, DMARC, gateway, secure/MIME.
* 2.2  Threat vectors & attack surfaces: message-based (email), phishing,
       business email compromise, impersonation, brand impersonation,
       typosquatting, file-based (malicious attachments).

What the analyzer does
----------------------
1. **Parses** raw RFC 5322 messages with the standard library ``email`` package.
2. **Re-computes authentication itself** against an offline DNS table:
   * SPF: connecting IP (from our own MX's ``Received`` header) vs the
     envelope domain's ``v=spf1`` record (``ip4:``, ``include:``, ``-all``/``~all``).
   * DKIM: recomputes the body hash (simple canonicalisation, SHA-256) and
     compares it with ``bh=``; checks the selector key is published.
     (Signature RSA maths is out of scope; body integrity + key presence is modelled.)
   * DMARC: passes if SPF *or* DKIM passes **and** is aligned with the From
     domain (relaxed: same organisational domain), then applies ``p=``.
   A sender-supplied ``Authentication-Results`` header is never trusted; if
   it claims "pass" where we computed "fail", that itself is an indicator.
3. **Scores indicators**: lookalike/brand domains, display-name impersonation
   of executives or brands, Reply-To mismatch, urgency/credential/payment
   keywords, risky links (IP literal, shortener, punycode, anchor/href
   mismatch, suspicious TLD), dangerous or double-extension attachments.
4. **Verdict**, deny by default: REJECT / QUARANTINE / DELIVER_WITH_BANNER / DELIVER,
   plus an attack category.

Run it
------
    python main.py lab 10
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from email import message_from_string
from email.utils import getaddresses, parseaddr
from html import unescape
from urllib.parse import urlparse

TITLE = "Lab 10 — Email Security Analyzer (SPF / DKIM / DMARC / phishing)"
OBJECTIVES = "SY0-701 4.5 Email security · 2.2 Message-based threat vectors"

VERDICTS = ["DELIVER", "DELIVER_WITH_BANNER", "QUARANTINE", "REJECT"]
CATEGORIES = ["Legitimate", "Domain spoofing", "Business email compromise", "Credential phishing",
              "Malware delivery", "Suspicious / spam"]
HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s"})
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
ANCHOR_RE = re.compile(r"<a\s[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.I | re.S)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def org_domain(domain: str) -> str:
    """Organisational domain (simplified: last two labels; no public-suffix list offline)."""
    parts = domain.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()


def domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower().strip(">") if "@" in address else ""


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def dkim_body_hash(body: str) -> str:
    """DKIM 'simple' body canonicalisation: CRLF line endings, trailing empty lines → one CRLF."""
    b = body.replace("\r\n", "\n").replace("\n", "\r\n")
    b = b.rstrip("\r\n") + "\r\n"
    return base64.b64encode(hashlib.sha256(b.encode("utf-8")).digest()).decode()


def split_raw(raw: str) -> tuple[str, str]:
    raw = raw.replace("\r\n", "\n")
    head, _, body = raw.partition("\n\n")
    return head, body


def lookalike_of(domain: str, protected: list[str], max_distance: int, owned: dict | None = None) -> str | None:
    """Return the protected domain this one imitates (typosquat / homoglyph / brand-in-name), if any."""
    od = org_domain(domain)
    for p in protected:
        if od == p or od in (owned or {}).get(p, []):
            return None
    normalized = od.translate(HOMOGLYPHS).replace("rn", "m")
    for p in protected:
        brand = p.split(".")[0]
        if levenshtein(od, p) <= max_distance or normalized == p or brand in normalized.split(".")[0]:
            return p
    return None


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #
def spf_check(ip: str | None, domain: str, dns: dict, depth: int = 0) -> str:
    """Evaluate SPF: pass | fail | softfail | neutral | none | permerror."""
    record = dns.get("spf", {}).get(domain)
    if record is None:
        return "none"
    if ip is None or depth > 5:
        return "permerror"
    addr = ipaddress.ip_address(ip)
    for term in record.split()[1:]:
        if term.startswith("ip4:"):
            if addr in ipaddress.ip_network(term[4:], strict=False):
                return "pass"
        elif term.startswith("include:"):
            if spf_check(ip, term[8:], dns, depth + 1) == "pass":
                return "pass"
        elif term.endswith("all"):
            return {"-": "fail", "~": "softfail", "?": "neutral", "+": "pass"}.get(term[0], "pass")
    return "neutral"


def parse_tags(header: str) -> dict:
    tags = {}
    for part in header.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip()] = re.sub(r"\s+", "", v)
    return tags


def dkim_check(msg, body: str, dns: dict) -> tuple[str, str | None]:
    """Return (result, signing domain). result: pass | fail | none."""
    sig = msg.get("DKIM-Signature")
    if not sig:
        return "none", None
    t = parse_tags(sig)
    d, s, bh = t.get("d", "").lower(), t.get("s", ""), t.get("bh", "")
    if f"{s}._domainkey.{d}" not in dns.get("dkim_keys", []):
        return "fail", d
    return ("pass" if bh == dkim_body_hash(body) else "fail"), d


def dmarc_policy(from_domain: str, dns: dict) -> str | None:
    rec = dns.get("dmarc", {}).get(org_domain(from_domain))
    return parse_tags(rec).get("p", "none") if rec else None


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #
@dataclass
class EmailReport:
    id: str
    subject: str
    from_addr: str
    from_domain: str
    spf: str
    spf_domain: str
    spf_aligned: bool
    dkim: str
    dkim_domain: str | None
    dkim_aligned: bool
    dmarc: str               # pass | fail
    dmarc_policy: str | None
    score: int
    verdict: str
    category: str
    indicators: list[tuple[int, str]] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)


def connecting_ip(msg, inbound_mx: str) -> str | None:
    """IP of the host that handed the message to OUR MX (only trust our own Received line)."""
    for rcv in msg.get_all("Received", []):
        if f"by {inbound_mx}" in rcv:
            m = re.search(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", rcv)
            if m:
                return m.group(1)
    return None


def analyze(item: dict, cfg: dict, dns: dict) -> EmailReport:
    raw = item["raw"]
    msg = message_from_string(raw)
    _, body = split_raw(raw)
    ind: list[tuple[int, str]] = []

    def add(points: int, text: str) -> None:
        ind.append((points, text))

    display, from_addr = parseaddr(msg.get("From", ""))
    from_domain = domain_of(from_addr)
    envelope = domain_of(parseaddr(msg.get("Return-Path", ""))[1]) or from_domain
    ip = connecting_ip(msg, cfg["inbound_mx"])
    org = cfg["org_domain"]

    # --- authentication ------------------------------------------------------
    spf = spf_check(ip, envelope, dns)
    dkim, dkim_d = dkim_check(msg, body, dns)
    spf_aligned = org_domain(envelope) == org_domain(from_domain)
    dkim_aligned = bool(dkim_d) and org_domain(dkim_d) == org_domain(from_domain)
    dmarc = "pass" if (spf == "pass" and spf_aligned) or (dkim == "pass" and dkim_aligned) else "fail"
    policy = dmarc_policy(from_domain, dns)
    if spf in ("fail", "permerror"):
        add(2, f"SPF {spf}: {ip} is not authorised to send for {envelope}")
    elif spf == "softfail":
        add(1, f"SPF softfail for {envelope}")
    elif spf == "none":
        add(1, f"{envelope} publishes no SPF record")
    if dkim == "fail":
        add(3, f"DKIM fail for d={dkim_d}: body hash mismatch or no published key (message altered or forged)")
    elif dkim == "none":
        add(1, "message is not DKIM-signed")
    if policy is None:
        add(2, f"{org_domain(from_domain)} publishes no DMARC policy")
    elif dmarc == "fail" and policy == "none":
        add(3, "DMARC fail (policy p=none: monitoring only)")
    claimed = (msg.get("Authentication-Results") or "").lower()
    if claimed and any(f"{k}=pass" in claimed and v != "pass" for k, v in (("spf", spf), ("dkim", dkim), ("dmarc", dmarc))):
        add(2, "sender-supplied Authentication-Results claims 'pass' but our checks failed (forged header)")

    # --- impersonation -------------------------------------------------------
    owned = cfg.get("brand_owned_domains", {})
    look = lookalike_of(from_domain, cfg["protected_domains"], cfg["lookalike_max_distance"], owned)
    if look:
        add(4, f"From domain '{from_domain}' imitates '{look}' (typosquat/homoglyph/brand)")
    external = org_domain(from_domain) != org
    for exe in cfg["executives"]:
        if exe.lower() in display.lower() and external:
            add(3, f"display name impersonates executive '{exe}' from external domain {from_domain}")
    for p in cfg["protected_domains"]:
        brand = p.split(".")[0]
        if brand in display.lower().replace(" ", "") and org_domain(from_domain) != p:
            add(3, f"display name uses brand '{brand}' but mail is from {from_domain}")
    reply_to = [domain_of(a) for _, a in getaddresses(msg.get_all("Reply-To", []))]
    if any(r and org_domain(r) != org_domain(from_domain) for r in reply_to):
        add(2, f"Reply-To {reply_to} differs from From domain {from_domain}")

    # --- content ---------------------------------------------------------------
    text_parts, attachments = [], []
    for part in msg.walk():
        fn = part.get_filename()
        if fn:
            attachments.append(fn)
        elif part.get_content_maintype() == "text":
            payload = part.get_payload(decode=True)
            text_parts.append(payload.decode("utf-8", "replace") if payload else str(part.get_payload()))
    html = "\n".join(text_parts)
    plain = unescape(re.sub(r"<[^>]+>", " ", html))
    haystack = f"{msg.get('Subject', '')} {plain}".lower()
    hits = [(w, k) for k, w in cfg["phishing_keywords"].items() if k in haystack]
    if hits:
        add(sum(w for w, _ in hits), f"pressure/credential/payment language: {[k for _, k in hits]}")

    # Analyse where links GO: every href, plus bare URLs outside anchors (not the visible link text).
    anchors = ANCHOR_RE.findall(html)
    urls = sorted({href for href, _ in anchors if href.lower().startswith("http")}
                  | set(URL_RE.findall(ANCHOR_RE.sub(" ", html))))
    for href, text in anchors:
        shown = URL_RE.search(unescape(re.sub(r"<[^>]+>", "", text)))
        if shown and urlparse(shown.group(0)).hostname != urlparse(href).hostname:
            add(3, f"link text shows {urlparse(shown.group(0)).hostname} but points to {urlparse(href).hostname}")
    for u in urls:
        host = (urlparse(u).hostname or "").lower()
        try:
            ipaddress.ip_address(host)
            add(3, f"link to a raw IP address: {u}")
            continue
        except ValueError:
            pass
        if host in cfg["url_shorteners"]:
            add(2, f"URL shortener hides the destination: {u}")
        if "xn--" in host:
            add(3, f"punycode (internationalised) domain: {host}")
        if any(host.endswith(t) for t in cfg["suspicious_tlds"]):
            add(2, f"suspicious TLD: {host}")
        lk = lookalike_of(host, cfg["protected_domains"], cfg["lookalike_max_distance"], owned)
        if lk:
            add(4, f"link domain {host} imitates {lk}")

    dangerous = []
    for fn in attachments:
        low = fn.lower()
        exts = re.findall(r"\.[a-z0-9]+", low)
        if exts and exts[-1] in cfg["dangerous_extensions"]:
            dangerous.append(fn)
            add(4, f"dangerous attachment type: {fn}")
        if len(exts) >= 2 and exts[-2] in cfg["document_extensions"] and exts[-1] in cfg["dangerous_extensions"]:
            add(4, f"double extension disguises an executable: {fn}")

    score = sum(p for p, _ in ind)

    # --- verdict (deny-by-default precedence) -------------------------------------
    if dmarc == "fail" and policy == "reject":
        verdict = "REJECT"
    elif dmarc == "fail" and policy == "quarantine" or dangerous or score >= cfg["quarantine_score"]:
        verdict = "QUARANTINE"
    elif score >= cfg["banner_score"]:
        verdict = "DELIVER_WITH_BANNER"
    else:
        verdict = "DELIVER"

    kw = {k for _, k in hits}
    if dangerous:
        category = "Malware delivery"
    elif dmarc == "fail" and (org_domain(from_domain) == org or org_domain(from_domain) in cfg["protected_domains"]):
        category = "Domain spoofing"
    elif kw & set(cfg["payment_keywords"]) and any("impersonates" in t or "Reply-To" in t for _, t in ind):
        category = "Business email compromise"
    elif kw & set(cfg["credential_keywords"]) and urls:
        category = "Credential phishing"
    elif verdict == "DELIVER":
        category = "Legitimate"
    else:
        category = "Suspicious / spam"

    return EmailReport(item["id"], msg.get("Subject", ""), from_addr, from_domain, spf, envelope, spf_aligned,
                       dkim, dkim_d, dkim_aligned, dmarc, policy, score, verdict, category, ind, attachments, urls)


def analyze_all(data: dict, policies: dict) -> list[EmailReport]:
    cfg = policies["email_security"]
    return [analyze(m, cfg, data["dns"]) for m in data["messages"]]


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SY0-701 4.5 Email security (SPF, DKIM, DMARC, gateways) and 2.2 message-based threat vectors.",
    "concepts": [
        "SPF authorises sending IPs for the ENVELOPE domain; DKIM signs the message for the d= domain.",
        "DMARC ties them to the visible From: SPF or DKIM must pass AND align with the From domain; p= says what to do on failure.",
        "Authentication proves where mail came from, not that it is safe: a lookalike domain can pass SPF, DKIM and DMARC.",
        "Content signals (impersonation, urgency, mismatched links, double extensions) catch what authentication cannot.",
    ],
    "failure_modes": [
        "Publishing DMARC p=none forever: you can see the spoofing but never block it.",
        "Trusting an Authentication-Results header added by an untrusted hop.",
        "Allowing external mail whose display name matches the CEO, with no 'external sender' banner.",
        "Blocking .exe but not .pdf.exe, .iso, .lnk or macro-enabled documents.",
    ],
    "ai_governance": [
        "An AI mail-triage agent may quarantine and add banners; releasing quarantined mail or allow-listing senders needs a human.",
        "Mail content is untrusted input: an email that tells the agent to 'mark this sender safe' is prompt injection.",
        "Agents must base verdicts on recomputed SPF/DKIM/DMARC, never on headers the sender controls.",
        "Log every agent verdict with its indicators so false positives can be tuned, as in the Lab 8 feedback loop.",
    ],
    "exam_tips": [
        "SPF = which servers may send · DKIM = digital signature on the message · DMARC = policy + alignment + reporting.",
        "BEC/impersonation: 'CEO' from a free-mail address asking for a wire transfer or changed bank details.",
        "Typosquatting / brand impersonation: micros0ft-support.com, paypa1.com.",
        "Secure email gateways enforce these checks at the perimeter; S/MIME provides end-to-end signing/encryption.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    reports = analyze_all(data, policies)
    ui.section("Step 1 — Authentication (recomputed, never trusted from headers)")
    ui.table("SPF / DKIM / DMARC", ["ID", "From", "SPF (domain)", "Aligned", "DKIM (d=)", "Aligned", "DMARC (p=)"],
             [[r.id, r.from_addr, f"{r.spf} ({r.spf_domain})", "yes" if r.spf_aligned else "no",
               f"{r.dkim} ({r.dkim_domain or '-'})", "yes" if r.dkim_aligned else "no",
               f"{r.dmarc} (p={r.dmarc_policy or 'none published'})"] for r in reports])

    ui.section("Step 2 — Verdicts")
    ui.table("Gateway decisions", ["ID", "Subject", "Score", "Verdict", "Category"],
             [[r.id, r.subject, r.score, r.verdict, r.category] for r in reports])

    ui.section("Step 3 — Indicators per message")
    for r in reports:
        ui.print(f"[bold]{r.id}[/bold] {r.subject}")
        for pts, text in r.indicators or [(0, "no indicators")]:
            ui.bullet(f"+{pts} {text}" if pts else text)

    ui.insight(INSIGHT)
    return {"verdicts": {r.id: r.verdict for r in reports}, "categories": {r.id: r.category for r in reports}}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question

    qs: list = []
    for m, r in zip(data["messages"], analyze_all(data, policies)):
        head, _ = split_raw(m["raw"])
        ctx = head + (f"\n[attachments: {r.attachments}]" if r.attachments else "") + \
            (f"\n[links: {r.urls}]" if r.urls else "")
        why = "; ".join(t for _, t in r.indicators) or "no indicators"
        qs.append(Question(prompt=f"{r.id}: what should the email gateway do?", context=ctx, choices=VERDICTS,
                           answer=r.verdict, explanation=f"score {r.score}, DMARC {r.dmarc} (p={r.dmarc_policy}). {why}",
                           objective="4.5"))
        qs.append(Question(prompt=f"{r.id}: what kind of message is this?", context=ctx, choices=CATEGORIES,
                           answer=r.category, explanation=why, objective="2.2"))
        qs.append(Question(
            prompt=f"{r.id}: what is the DMARC result?",
            context=f"SPF {r.spf} for {r.spf_domain} · DKIM {r.dkim} for d={r.dkim_domain} · From domain {r.from_domain}",
            choices=["pass", "fail"], answer=r.dmarc,
            explanation=(f"SPF {'aligned' if r.spf_aligned else 'NOT aligned'} ({r.spf_domain} vs {r.from_domain}); "
                         f"DKIM {'aligned' if r.dkim_aligned else 'NOT aligned'} (d={r.dkim_domain}). DMARC passes only if a "
                         "passing mechanism is also aligned with the From domain."),
            objective="4.5"))
    return qs
