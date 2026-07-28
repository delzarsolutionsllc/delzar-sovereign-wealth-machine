"""Render a certified payroll as a PDF reproducing the Form WH-347 layout,
including the page-2 Statement of Compliance.

The layout follows the official form (OMB No. 1235-0008): landscape grid
with two rows per employee (O = overtime, S = straight time) and the
standard column set. Zero-activity weeks render a single 'NO WORK
PERFORMED THIS WEEK' row - submitting these is required for every week
of performance (29 CFR 5.5(a)(3)(ii)).
"""
from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.units import inch
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import Table, TableStyle

from .. import COMPANY
from .payroll import PayrollResult, week_start

PAGE = landscape(letter)
W, H = PAGE
DAY_NAMES = ["S", "M", "T", "W", "T", "F", "S"]


def _fmt(x) -> str:
    return f"{x:,.2f}" if x else ""


def render_wh347(
    result: PayrollResult,
    contract: dict,
    out_path: Path,
    contractor_is_sub: bool = False,
    signatory_name: str = "",
    signatory_title: str = "Owner",
    fringe_in_cash: bool = True,
    remarks: str = "",
) -> Path:
    c = Canvas(str(out_path), pagesize=PAGE)
    _page1(c, result, contract, contractor_is_sub)
    c.showPage()
    _statement_of_compliance(
        c, result, contract, signatory_name, signatory_title, fringe_in_cash, remarks
    )
    c.showPage()
    c.save()
    return out_path


def _page1(c: Canvas, result: PayrollResult, contract: dict, is_sub: bool):
    m = 0.4 * inch
    y = H - m

    c.setFont("Helvetica-Bold", 11)
    c.drawString(m, y, "PAYROLL")
    c.setFont("Helvetica", 7)
    c.drawString(m + 70, y, "(For Contractor's Optional Use; See Instructions at www.dol.gov/whd/forms/wh347instr.htm)")
    c.drawRightString(W - m, y, "U.S. Department of Labor  |  Wage and Hour Division  |  OMB No.: 1235-0008")
    c.drawRightString(W - m, y - 9, "Form WH-347 (layout reproduction)")
    y -= 0.25 * inch

    c.setFont("Helvetica", 7)
    prime_box = "[X]" if not is_sub else "[  ]"
    sub_box = "[X]" if is_sub else "[  ]"
    c.drawString(m, y, f"NAME OF CONTRACTOR {prime_box}  OR SUBCONTRACTOR {sub_box}:")
    c.setFont("Helvetica-Bold", 9)
    c.drawString(m + 200, y, COMPANY["name"])
    c.setFont("Helvetica", 7)
    c.drawString(m + 380, y, "ADDRESS:")
    c.setFont("Helvetica-Bold", 9)
    c.drawString(m + 420, y, COMPANY["address"])
    y -= 0.2 * inch

    ws = week_start(result.week_ending)
    payroll_no = f"{result.payroll_number}" + ("  (FINAL)" if getattr(result, "is_final", False) else "")
    fields = [
        ("PAYROLL NO.", payroll_no),
        ("FOR WEEK ENDING", result.week_ending.strftime("%m/%d/%Y")),
        ("PROJECT AND LOCATION", f"{contract['title']} - {contract.get('place_of_performance') or ''}"),
        ("PROJECT OR CONTRACT NO.", contract["contract_no"]),
    ]
    x = m
    for label, val in fields:
        c.setFont("Helvetica", 6.5)
        c.drawString(x, y, label)
        c.setFont("Helvetica-Bold", 9)
        c.drawString(x, y - 11, val[:60])
        x += [90, 110, 300, 150][fields.index((label, val))]
    y -= 0.42 * inch

    # ---- grid ----
    day_dates = [(ws + timedelta(days=i)).day for i in range(7)]
    header_top = [
        "(1)\nNAME AND INDIVIDUAL\nIDENTIFYING NUMBER\n(e.g., LAST FOUR DIGITS\nOF SSN) OF WORKER",
        "(2)\nNO. OF\nW/H\nEXEMP.",
        "(3)\nWORK\nCLASSIFICATION",
        "",  # O/S marker col
    ] + [f"{DAY_NAMES[i]}\n{day_dates[i]}" for i in range(7)] + [
        "(5)\nTOTAL\nHOURS",
        "(6)\nRATE\nOF PAY\n(INCL.\nFRINGE)",
        "(7)\nGROSS\nAMOUNT\nEARNED",
        "FICA",
        "WITH-\nHOLDING\nTAX",
        "OTHER",
        "TOTAL\nDEDUCTIONS",
        "(9)\nNET\nWAGES\nPAID\nFOR WEEK",
    ]

    rows = [header_top]
    if result.is_zero_activity:
        rows.append(["NO WORK PERFORMED THIS WEEK", "", "", ""] + [""] * 7 + [""] * 8)
    else:
        for ln in result.lines:
            ot_row = (
                ["", "", "", "O"]
                + [str(h) if h else "" for h in ln.day_ot_hours]
                + [str(ln.ot_hours) if ln.ot_hours else "", _fmt(ln.ot_hourly_pay) if ln.ot_hours else "", "", "", "", "", "", ""]
            )
            st_row = (
                [f"{ln.employee_name}\nXXX-XX-{ln.id_last4 or '____'}",
                 str(ln.withholding_exemptions or ""),
                 ln.classification,
                 "S"]
                + [str(h) if h else "" for h in ln.day_hours]
                + [str(ln.straight_hours),
                   f"{_fmt(ln.base_rate)} + {_fmt(ln.fringe_rate)}f",
                   _fmt(ln.gross),
                   _fmt(ln.fica),
                   _fmt(ln.fed_withholding),
                   _fmt(ln.other_deductions),
                   _fmt(ln.total_deductions),
                   _fmt(ln.net)]
            )
            rows.append(ot_row)
            rows.append(st_row)

    col_widths = (
        [1.55 * inch, 0.42 * inch, 1.0 * inch, 0.22 * inch]
        + [0.34 * inch] * 7
        + [0.5 * inch, 0.72 * inch, 0.62 * inch, 0.5 * inch, 0.5 * inch, 0.5 * inch, 0.62 * inch, 0.62 * inch]
    )
    t = Table(rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, 0), 5),
        ("FONTSIZE", (0, 1), (-1, -1), 7),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("BACKGROUND", (0, 0), (-1, 0), colors.Color(0.92, 0.92, 0.92)),
    ]))
    tw, th = t.wrap(W - 2 * m, y)
    t.drawOn(c, m, y - th)
    y = y - th - 12

    # column (4)/(8) super-headers annotation
    c.setFont("Helvetica", 5.5)
    c.drawString(m + sum(col_widths[:4]), y + th + 14, "")
    c.setFont("Helvetica-Oblique", 6.5)
    c.drawString(m, y, "(4) DAY AND DATE - HOURS WORKED EACH DAY.  O = overtime, S = straight time."
                       "   (8) DEDUCTIONS.   Rate of pay shows base + cash fringe ('f').")
    if result.is_zero_activity:
        c.setFont("Helvetica-Bold", 8)
        c.drawString(m, y - 14,
                     "ZERO-ACTIVITY PAYROLL: no covered work was performed during this payroll week. "
                     "Submitted to maintain an unbroken weekly sequence per 29 CFR 5.5(a)(3)(ii).")


def _statement_of_compliance(
    c: Canvas,
    result: PayrollResult,
    contract: dict,
    signatory_name: str,
    signatory_title: str,
    fringe_in_cash: bool,
    remarks: str,
):
    m = 0.55 * inch
    y = H - m
    ws = week_start(result.week_ending)

    c.setFont("Helvetica-Bold", 10)
    c.drawCentredString(W / 2, y, "STATEMENT OF COMPLIANCE")
    y -= 24

    c.setFont("Helvetica", 8.5)
    sig = signatory_name or COMPANY["name"] + " (authorized signatory)"
    intro = (
        f"Date: {date.today().strftime('%m/%d/%Y')}",
        f"I, {sig}, {signatory_title}, do hereby state:",
        f"(1) That I pay or supervise the payment of the persons employed by {COMPANY['name']} on the "
        f"{contract['title']}; that during the payroll period commencing on the {ws.strftime('%d')} day of "
        f"{ws.strftime('%B, %Y')}, and ending the {result.week_ending.strftime('%d')} day of "
        f"{result.week_ending.strftime('%B, %Y')}, all persons employed on said project have been paid the full "
        "weekly wages earned, that no rebates have been or will be made either directly or indirectly to or on "
        f"behalf of said {COMPANY['name']} from the full weekly wages earned by any person, and that no deductions "
        "have been made either directly or indirectly from the full wages earned by any person, other than "
        "permissible deductions as defined in Regulations, Part 3 (29 CFR Subtitle A), issued by the Secretary of "
        "Labor under the Copeland Act, as amended (48 Stat. 948, 63 Stat. 108, 72 Stat. 967; 76 Stat. 357; 40 U.S.C. 3145).",
        "(2) That any payrolls otherwise under this contract required to be submitted for the above period are "
        "correct and complete; that the wage rates for laborers or mechanics contained therein are not less than "
        "the applicable wage rates contained in any wage determination incorporated into the contract; that the "
        "classifications set forth therein for each laborer or mechanic conform with the work he performed.",
        "(3) That any apprentices employed in the above period are duly registered in a bona fide apprenticeship "
        "program registered with a State apprenticeship agency recognized by the Bureau of Apprenticeship and "
        "Training, United States Department of Labor, or if no such recognized agency exists in a State, are "
        "registered with the Bureau of Apprenticeship and Training, United States Department of Labor.",
        "(4) That:",
    )
    for para in intro:
        y = _wrap_text(c, para, m, y, W - 2 * m, leading=10.5) - 6

    box_a = "[  ]"
    box_b = "[  ]"
    if fringe_in_cash:
        box_b = "[X]"
    else:
        box_a = "[X]"
    y = _wrap_text(
        c,
        f"{box_a}  (a) WHERE FRINGE BENEFITS ARE PAID TO APPROVED PLANS, FUNDS, OR PROGRAMS - In addition to the "
        "basic hourly wage rates paid to each laborer or mechanic listed in the above referenced payroll, payments "
        "of fringe benefits as listed in the contract have been or will be made to appropriate programs for the "
        "benefit of such employees, except as noted in section 4(c) below.",
        m + 12, y, W - 2 * m - 12, leading=10.5) - 6
    y = _wrap_text(
        c,
        f"{box_b}  (b) WHERE FRINGE BENEFITS ARE PAID IN CASH - Each laborer or mechanic listed in the above "
        "referenced payroll has been paid, as indicated on the payroll, an amount not less than the sum of the "
        "applicable basic hourly wage rate plus the amount of the required fringe benefits as listed in the "
        "contract, except as noted in section 4(c) below.",
        m + 12, y, W - 2 * m - 12, leading=10.5) - 6
    y = _wrap_text(
        c,
        "(c) EXCEPTIONS:  " + (remarks or "NONE"),
        m + 12, y, W - 2 * m - 12, leading=10.5) - 10

    y = _wrap_text(
        c,
        "REMARKS:  " + (
            "NO WORK PERFORMED THIS WEEK. This statement is submitted to maintain the required unbroken weekly "
            "payroll sequence." if result.is_zero_activity else (remarks or "")),
        m, y, W - 2 * m, leading=10.5) - 20

    c.setFont("Helvetica", 8.5)
    c.drawString(m, y, f"NAME AND TITLE: {sig}, {signatory_title}")
    c.drawString(W / 2 + 30, y, "SIGNATURE: ______________________________")
    y -= 22
    c.setFont("Helvetica-Bold", 7.5)
    y = _wrap_text(
        c,
        "THE WILLFUL FALSIFICATION OF ANY OF THE ABOVE STATEMENTS MAY SUBJECT THE CONTRACTOR OR SUBCONTRACTOR TO "
        "CIVIL OR CRIMINAL PROSECUTION. SEE SECTION 1001 OF TITLE 18 AND SECTION 231 OF TITLE 31 OF THE UNITED "
        "STATES CODE.",
        m, y, W - 2 * m, leading=9, font="Helvetica-Bold", size=7.5)


def _wrap_text(c: Canvas, text: str, x: float, y: float, width: float,
               leading: float = 11, font: str = "Helvetica", size: float = 8.5) -> float:
    from reportlab.pdfbase.pdfmetrics import stringWidth
    c.setFont(font, size)
    words = text.split()
    line = ""
    for w in words:
        trial = (line + " " + w).strip()
        if stringWidth(trial, font, size) > width:
            c.drawString(x, y, line)
            y -= leading
            line = w
        else:
            line = trial
    if line:
        c.drawString(x, y, line)
        y -= leading
    return y
