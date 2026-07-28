"""PIID position-9 instrument decoding."""
from delzar_ops.watch.piid import decode_piid


def test_bpa():
    d = decode_piid("75H711-23-A-0001".replace("-", ""))
    assert d["type_code"] == "A"
    assert "BPA" in d["instrument"]


def test_dashes_stripped():
    d = decode_piid("75H711-24-P-0042")
    assert d["type_code"] == "P"
    assert "Purchase order" in d["instrument"]


def test_order_against_agreement_flags_channel():
    d = decode_piid("75H71124F0007")
    assert d["type_code"] == "F"
    assert "never publicly competed" in d["channel_note"]


def test_contract_and_idiq():
    assert decode_piid("W912BV24C0011")["type_code"] == "C"
    assert decode_piid("W912BV24D0011")["type_code"] == "D"


def test_short_piid_no_guess():
    d = decode_piid("ABC123")
    assert d["type_code"] is None


def test_lowercase_normalized():
    assert decode_piid("75h71124q0007")["type_code"] == "Q"
