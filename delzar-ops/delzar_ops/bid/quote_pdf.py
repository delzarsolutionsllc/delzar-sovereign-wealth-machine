"""Export a submittable LPTA quote PDF with the minimum required elements:
vendor name, UEI, prompt payment terms, delivery time, quote expiration,
warranty, and line-item pricing.

Policy encoded here (see regulatory.json policy_notes):
- NEVER offer a prompt payment discount - not evaluated at this office.
- Reminder line for the IEE Representation form (HHSAR 352.226-7).
"""
from __future__ import annotations

from datetime import date, timedelta
from decimal import Decimal
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .. import COMPANY
from .estimator import EstimateInput, ModelResult


def render_quote(
    est: EstimateInput,
    model: ModelResult,
    bid_price: Decimal,
    out_path: Path,
    delivery_days: int = 30,
    quote_valid_days: int = 60,
    warranty: str = "One (1) year on workmanship from date of acceptance.",
) -> Path:
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(
        str(out_path), pagesize=letter,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
    )
    story = []

    story.append(Paragraph(f"<b>{COMPANY['name']}</b>", styles["Title"]))
    story.append(Paragraph(
        f"{COMPANY['address']} &nbsp;|&nbsp; UEI: {COMPANY['uei']} &nbsp;|&nbsp; "
        f"CAGE: {COMPANY['cage']} &nbsp;|&nbsp; NAICS {COMPANY['naics_primary']} &nbsp;|&nbsp; "
        f"{COMPANY['ownership']}",
        styles["Normal"]))
    story.append(Spacer(1, 14))

    story.append(Paragraph("<b>QUOTATION</b>", styles["Heading2"]))
    today = date.today()
    meta = [
        ["Date:", today.strftime("%B %d, %Y")],
        ["Solicitation:", est.solicitation_no or "-"],
        ["Project:", est.title],
        ["Quote expires:", (today + timedelta(days=quote_valid_days)).strftime("%B %d, %Y")
         + f" ({quote_valid_days} days)"],
        ["Delivery / performance:", f"Work complete within {delivery_days} calendar days of notice to proceed."],
        ["Payment terms:", "Net 30 - prompt payment per the Prompt Payment Act. No discount offered."],
        ["Warranty:", warranty],
    ]
    t = Table(meta, colWidths=[1.7 * inch, 5.1 * inch])
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)
    story.append(Spacer(1, 14))

    story.append(Paragraph("<b>Line-Item Pricing</b>", styles["Heading3"]))
    rows = [["Item", "Amount"]]
    for k, v in model.components.items():
        if v:
            rows.append([k.title(), f"${v:,.2f}"])
    rows.append(["Contingency, overhead & profit (allocated)",
                 f"${bid_price - model.direct_cost:,.2f}"])
    rows.append(["TOTAL FIRM FIXED PRICE", f"${bid_price:,.2f}"])
    pt = Table(rows, colWidths=[5.0 * inch, 1.8 * inch])
    pt.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ("ALIGN", (1, 0), (1, -1), "RIGHT"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 0), (-1, 0), colors.Color(0.92, 0.92, 0.92)),
        ("BACKGROUND", (0, -1), (-1, -1), colors.Color(0.92, 0.92, 0.92)),
    ]))
    story.append(pt)
    story.append(Spacer(1, 16))

    story.append(Paragraph(
        "Price includes all labor, materials, equipment, mobilization, permits, and payment "
        "protection required for a complete and acceptable installation. Davis-Bacon prevailing "
        "wages will be paid and certified payrolls (WH-347) submitted weekly.",
        styles["Normal"]))
    doc.build(story)
    return out_path
