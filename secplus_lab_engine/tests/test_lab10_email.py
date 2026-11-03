"""Lab 10 — email security analyzer tests."""

from __future__ import annotations

import copy

import pytest

from labs.lab10_email_security import (
    analyze, analyze_all, dkim_body_hash, levenshtein, lookalike_of, org_domain, spf_check,
)

DNS = {
    "spf": {"a.com": "v=spf1 ip4:10.0.0.0/24 include:b.com -all", "b.com": "v=spf1 ip4:10.9.9.0/24 ~all",
            "soft.com": "v=spf1 ~all"},
    "dmarc": {"a.com": "v=DMARC1; p=reject", "q.com": "v=DMARC1; p=quarantine"},
    "dkim_keys": ["s._domainkey.a.com"],
}


@pytest.fixture
def cfg(policies):
    return policies["email_security"]


def _raw(frm="x@a.com", rp="x@a.com", ip="10.0.0.5", body="hello\n", subject="hi", extra=(), dkim=None):
    h = [f"Received: from h (h [{ip}]) by mx1.delzarsolutions.com", f"Return-Path: <{rp}>", f"From: {frm}",
         "To: t@delzarsolutions.com", f"Subject: {subject}", *extra]
    if dkim:
        d, bh = dkim
        h.insert(0, f"DKIM-Signature: v=1; d={d}; s=s; bh={bh}; b=x")
    return {"id": "T", "raw": "\n".join(h) + "\n\n" + body}


def test_helpers():
    assert org_domain("mail.sub.Example.com") == "example.com"
    assert levenshtein("paypal.com", "paypa1.com") == 1
    assert dkim_body_hash("a\n\n\n") == dkim_body_hash("a\r\n")


@pytest.mark.parametrize("ip,domain,result", [
    ("10.0.0.7", "a.com", "pass"), ("10.9.9.9", "a.com", "pass"),      # via include
    ("8.8.8.8", "a.com", "fail"), ("8.8.8.8", "soft.com", "softfail"), ("8.8.8.8", "none.com", "none"),
])
def test_spf(ip, domain, result):
    assert spf_check(ip, domain, DNS) == result


def test_lookalike(cfg):
    p = cfg["protected_domains"]
    assert lookalike_of("paypa1.com", p, 2) == "paypal.com"
    assert lookalike_of("micros0ft-support.com", p, 2) == "microsoft.com"
    assert lookalike_of("paypal.com", p, 2) is None
    assert lookalike_of("login.microsoftonline.com", p, 2, cfg["brand_owned_domains"]) is None
    assert lookalike_of("example.org", p, 2) is None


def test_clean_aligned_mail_delivers(cfg):
    body = "hello\n"
    r = analyze(_raw(body=body, dkim=("a.com", dkim_body_hash(body))), cfg, DNS)
    assert (r.spf, r.dkim, r.dmarc, r.verdict) == ("pass", "pass", "pass", "DELIVER")


def test_dkim_detects_body_tampering(cfg):
    r = analyze(_raw(body="changed\n", dkim=("a.com", dkim_body_hash("original\n"))), cfg, DNS)
    assert r.dkim == "fail"


def test_dkim_without_published_key_fails(cfg):
    r = analyze(_raw(dkim=("evil.com", dkim_body_hash("hello\n"))), cfg, DNS)
    assert r.dkim == "fail"


def test_spoof_with_reject_policy_is_rejected(cfg):
    r = analyze(_raw(ip="6.6.6.6"), cfg, DNS)
    assert r.spf == "fail" and r.dmarc == "fail" and r.verdict == "REJECT"


def test_unaligned_spf_alone_fails_dmarc(cfg):
    # SPF passes for the envelope domain b.com, but From is a.com and there is no DKIM
    r = analyze(_raw(rp="bounce@b.com", ip="10.9.9.9"), cfg, DNS)
    assert r.spf == "pass" and not r.spf_aligned and r.dmarc == "fail" and r.verdict == "REJECT"


def test_dmarc_quarantine_policy(cfg):
    r = analyze(_raw(frm="x@q.com", rp="x@q.com", ip="6.6.6.6"), cfg, DNS)
    assert r.verdict == "QUARANTINE"


def test_forged_auth_results_header_flagged(cfg):
    r = analyze(_raw(ip="6.6.6.6", extra=["Authentication-Results: x; spf=pass; dmarc=pass"]), cfg, DNS)
    assert any("forged" in t for _, t in r.indicators)


def test_untrusted_received_hops_are_ignored(cfg):
    raw = _raw(ip="6.6.6.6")
    raw["raw"] = "Received: from h (h [10.0.0.9]) by attacker-relay.example\n" + raw["raw"]
    assert analyze(raw, cfg, DNS).spf == "fail"


def test_double_extension_attachment(cfg):
    body = ("--b\nContent-Type: text/plain\n\nsee attached\n--b\nContent-Type: application/octet-stream\n"
            "Content-Disposition: attachment; filename=\"report.docx.js\"\n\nAAAA\n--b--\n")
    r = analyze(_raw(body=body, extra=["MIME-Version: 1.0", 'Content-Type: multipart/mixed; boundary="b"']), cfg, DNS)
    assert r.attachments == ["report.docx.js"] and r.verdict == "QUARANTINE" and r.category == "Malware delivery"


def test_anchor_mismatch_and_ip_link(cfg):
    body = '<a href="http://1.2.3.4/x">https://www.paypal.com/</a>'
    r = analyze(_raw(body=body, extra=["Content-Type: text/html"]), cfg, DNS)
    texts = " ".join(t for _, t in r.indicators)
    assert "link text shows www.paypal.com" in texts and "raw IP" in texts


def test_sample_outcomes(policies, data):
    rep = {r.id: r for r in analyze_all(data("sample_emails.json"), policies)}
    assert {k: v.verdict for k, v in rep.items()} == {
        "E-01": "DELIVER", "E-02": "DELIVER", "E-03": "QUARANTINE",
        "E-04": "QUARANTINE", "E-05": "QUARANTINE", "E-06": "REJECT"}
    assert {k: v.category for k, v in rep.items()} == {
        "E-01": "Legitimate", "E-02": "Legitimate", "E-03": "Credential phishing",
        "E-04": "Business email compromise", "E-05": "Malware delivery", "E-06": "Domain spoofing"}
    assert not rep["E-02"].spf_aligned and rep["E-02"].dkim_aligned and rep["E-02"].dmarc == "pass"
    assert rep["E-03"].dmarc == "pass"        # authenticated lookalike is still quarantined


def test_tampering_with_sample_body_breaks_dkim(policies, data):
    d = copy.deepcopy(data("sample_emails.json"))
    d["messages"][0]["raw"] = d["messages"][0]["raw"].replace("November roadmap", "December roadmap")
    r = analyze_all(d, policies)[0]
    assert r.dkim == "fail" and r.dmarc == "pass"   # SPF still aligned-passes; DKIM catches the edit
