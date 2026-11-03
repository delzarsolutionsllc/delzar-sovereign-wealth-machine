"""Lab 17 — PKI & certificate validator tests."""

from __future__ import annotations

import copy
from datetime import date

import pytest

from labs.lab17_pki_validator import hostname_matches, validate, validate_all

AS_OF = date(2026, 11, 3)


@pytest.mark.parametrize("host,pattern,ok", [
    ("shop.example.com", "*.example.com", True),
    ("a.b.example.com", "*.example.com", False),       # one label only
    ("example.com", "*.example.com", False),           # apex not covered
    ("SHOP.Example.com.", "*.example.com", True),      # case / trailing dot
    ("www.example.com", "www.example.com", True),
    ("www.example.com", "api.example.com", False),
    ("x.com", "*.com", False),                         # no wildcard on a public suffix
    ("ab.example.com", "a*.example.com", False),       # no partial wildcards
])
def test_hostname_matching(host, pattern, ok):
    assert hostname_matches(host, pattern) is ok


@pytest.fixture
def cfg(policies):
    return policies["pki"]


def good():
    return {
        "id": "T", "hostname": "www.example.com",
        "chain": [
            {"subject": "www.example.com", "issuer": "Delzar Issuing CA 1", "serial": "1", "not_before": "2026-06-01",
             "not_after": "2027-06-01", "key_type": "RSA", "key_bits": 2048, "sig_alg": "sha256WithRSAEncryption",
             "is_ca": False, "san": ["www.example.com"], "eku": ["serverAuth"], "spki_sha256": "aa"},
            {"subject": "Delzar Issuing CA 1", "issuer": "Delzar Root CA G2", "serial": "2", "not_before": "2024-01-01",
             "not_after": "2030-01-01", "key_type": "RSA", "key_bits": 4096, "sig_alg": "sha384WithRSAEncryption",
             "is_ca": True, "spki_sha256": "bb"}],
        "revocation": {"ocsp": {"1": "good", "2": "good"}},
    }


def test_valid_chain_is_trusted(cfg):
    r = validate(good(), cfg, AS_OF)
    assert r.verdict == "TRUSTED" and r.primary == "None" and not r.issues


def test_root_included_in_chain_is_fine(cfg):
    s = good()
    s["chain"].append({**s["chain"][1], "subject": "Delzar Root CA G2", "issuer": "Delzar Root CA G2", "serial": "3",
                       "sig_alg": "sha1WithRSAEncryption"})      # anchor's own self-signature is not checked
    assert validate(s, cfg, AS_OF).verdict == "TRUSTED"


@pytest.mark.parametrize("mutate,code", [
    (lambda s: s["chain"][0].update(not_after="2026-10-01"), "EXPIRED"),
    (lambda s: s["chain"][0].update(not_before="2026-12-01"), "NOT_YET_VALID"),
    (lambda s: s.update(hostname="api.example.com"), "HOSTNAME_MISMATCH"),
    (lambda s: s["chain"].pop(), "INCOMPLETE_CHAIN"),
    (lambda s: s["chain"][1].update(is_ca=False), "NOT_A_CA"),
    (lambda s: s["chain"][0].update(key_bits=1024), "WEAK_KEY"),
    (lambda s: s["chain"][0].update(key_type="EC", key_bits=192), "WEAK_KEY"),
    (lambda s: s["chain"][0].update(sig_alg="sha1WithRSAEncryption"), "WEAK_SIGNATURE"),
    (lambda s: s["chain"][0].update(eku=["clientAuth"]), "WRONG_KEY_USAGE"),
    (lambda s: s["revocation"]["ocsp"].update({"1": "revoked"}), "REVOKED"),
    (lambda s: s.update(revocation={"crl": {"Delzar Issuing CA 1": ["1"]}}), "REVOKED"),
    (lambda s: s.update(pinned_spki=["zz"]), "PIN_MISMATCH"),
])
def test_each_error_makes_untrusted(cfg, mutate, code):
    s = good()
    mutate(s)
    r = validate(s, cfg, AS_OF)
    assert code in r.codes and r.verdict == "UNTRUSTED"


def test_self_signed_vs_untrusted_root(cfg):
    s = good()
    s["chain"] = [{**s["chain"][0], "issuer": "www.example.com", "is_ca": True}]
    assert validate(s, cfg, AS_OF).primary == "SELF_SIGNED"
    s = good()
    s["chain"][1]["issuer"] = "Evil Root"
    s["chain"].append({**s["chain"][1], "subject": "Evil Root", "issuer": "Evil Root", "serial": "9"})
    assert "UNTRUSTED_ROOT" in validate(s, cfg, AS_OF).codes


def test_pin_matching_intermediate_is_accepted(cfg):
    s = good()
    s["pinned_spki"] = ["bb"]
    assert validate(s, cfg, AS_OF).verdict == "TRUSTED"


def test_warnings_only(cfg):
    s = good()
    s["chain"][0]["not_after"] = "2026-11-20"                    # expires in 17 days
    s["revocation"] = {"ocsp": {"1": "unknown"}}
    r = validate(s, cfg, AS_OF)
    assert r.verdict == "TRUSTED_WITH_WARNINGS" and {"EXPIRING_SOON", "REVOCATION_UNKNOWN"} <= r.codes


def test_revocation_hard_fail_policy(cfg):
    s = good()
    s["revocation"] = {}
    hard = {**cfg, "revocation_hard_fail": True}
    assert validate(s, cfg, AS_OF).verdict == "TRUSTED_WITH_WARNINGS"
    assert validate(s, hard, AS_OF).verdict == "UNTRUSTED"


def test_validity_too_long_is_a_warning(cfg):
    s = good()
    s["chain"][0]["not_before"], s["chain"][0]["not_after"] = "2026-01-01", "2027-12-31"
    r = validate(s, cfg, AS_OF)
    assert r.codes == {"VALIDITY_TOO_LONG"} and r.verdict == "TRUSTED_WITH_WARNINGS"


def test_cn_fallback_without_san(cfg):
    s = good()
    del s["chain"][0]["san"]
    assert validate(s, cfg, AS_OF).verdict == "TRUSTED"


def test_sample_outcomes(policies, data):
    res = {r.id: r for r in validate_all(data("sample_certificates.json"), policies)}
    assert {k: v.primary for k, v in res.items()} == {
        "P-01": "None", "P-02": "EXPIRED", "P-03": "HOSTNAME_MISMATCH", "P-04": "INCOMPLETE_CHAIN",
        "P-05": "SELF_SIGNED", "P-06": "REVOKED", "P-07": "WEAK_KEY", "P-08": "PIN_MISMATCH",
        "P-09": "REVOCATION_UNKNOWN", "P-10": "NOT_A_CA"}
    assert res["P-09"].verdict == "TRUSTED_WITH_WARNINGS"
    assert {"WEAK_KEY", "WEAK_SIGNATURE"} <= res["P-07"].codes


def test_sample_unchanged_by_validation(policies, data):
    d = data("sample_certificates.json")
    before = copy.deepcopy(d)
    validate_all(d, policies)
    assert d == before
