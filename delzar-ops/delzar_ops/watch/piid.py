"""PIID instrument-type decoder.

Position 9 of a federal Procurement Instrument Identifier encodes the
instrument type (FAR 4.1603(a)(3)). This tells you instantly whether
work was publicly competed or flowed through an existing agreement.
"""
from __future__ import annotations

INSTRUMENT_TYPES: dict[str, str] = {
    "A": "BPA (Blanket Purchase Agreement)",
    "B": "Invitation for bid (IFB)",
    "C": "Contract (definitive, all types except IDCs)",
    "D": "IDIQ / indefinite-delivery contract",
    "E": "Reserved",
    "F": "Order / call against an existing agreement (BPA call, delivery order, task order)",
    "G": "Basic agreement",
    "H": "Agreement (other)",
    "K": "Short form research contract",
    "L": "Lease agreement",
    "M": "Purchase order (manual)",
    "N": "Notice of intent",
    "P": "Purchase order (automated)",
    "Q": "Request for quotation (RFQ)",
    "R": "Request for proposal (RFP)",
    "S": "Sales contract",
    "T": "Automated requisition",
    "U": "Grant-like agreement",
    "V": "Purchase order/BPA under FAR 13 (some systems)",
    "W": "Reserved",
}

CHANNEL_NOTES: dict[str, str] = {
    "A": "An agreement was ESTABLISHED - future orders may never be publicly posted.",
    "F": "Flowed to an EXISTING agreement holder - this work was likely never publicly competed.",
    "C": "Publicly competed contract.",
    "P": "Purchase order - typically competed via RFQ, small dollar.",
    "M": "Purchase order - typically competed via RFQ, small dollar.",
    "Q": "Open solicitation (RFQ) - you can quote this.",
    "D": "IDIQ vehicle - orders flow to holders.",
}


def decode_piid(piid: str) -> dict:
    """Decode instrument type from position 9 of a PIID.

    Returns {'piid', 'type_code', 'instrument', 'channel_note'}.
    Non-conforming identifiers return type_code None rather than guessing.
    """
    cleaned = (piid or "").strip().upper().replace("-", "")
    if len(cleaned) < 9:
        return {"piid": piid, "type_code": None,
                "instrument": "Unknown (identifier shorter than 9 characters)",
                "channel_note": ""}
    code = cleaned[8]
    return {
        "piid": piid,
        "type_code": code,
        "instrument": INSTRUMENT_TYPES.get(code, f"Unknown code '{code}'"),
        "channel_note": CHANNEL_NOTES.get(code, ""),
    }
