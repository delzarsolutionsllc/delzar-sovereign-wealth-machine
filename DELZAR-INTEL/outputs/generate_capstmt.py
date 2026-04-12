"""
Generate Delzar Solutions LLC Federal Capability Statement PDF
"""
import subprocess, sys

# Ensure reportlab is available
try:
    import reportlab
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "reportlab", "-q"])

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from reportlab.pdfgen import canvas
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.platypus import Paragraph, Frame, Table, TableStyle
from reportlab.lib.styles import ParagraphStyle
import os

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Delzar_Capability_Statement.pdf")

# Colors
GOLD = HexColor("#D4AF37")
DARK = HexColor("#1A1A1A")
WHITE = HexColor("#FFFFFF")
LIGHT_GOLD = HexColor("#F5E6B8")
MED_GRAY = HexColor("#2A2A2A")
DARK_GRAY = HexColor("#333333")

def draw_page(c):
    width, height = letter  # 612 x 792
    margin = 0.4 * inch
    usable_w = width - 2 * margin

    # =========================================================================
    # BACKGROUND
    # =========================================================================
    c.setFillColor(DARK)
    c.rect(0, 0, width, height, fill=1, stroke=0)

    # =========================================================================
    # TOP GOLD BAR
    # =========================================================================
    bar_h = 8
    c.setFillColor(GOLD)
    c.rect(0, height - bar_h, width, bar_h, fill=1, stroke=0)

    # =========================================================================
    # HEADER SECTION
    # =========================================================================
    y = height - bar_h - 30
    c.setFillColor(GOLD)
    c.setFont("Helvetica-Bold", 22)
    c.drawCentredString(width / 2, y, "DELZAR SOLUTIONS LLC")

    y -= 18
    c.setFont("Helvetica", 9)
    c.setFillColor(LIGHT_GOLD)
    c.drawCentredString(width / 2, y, "Cherokee Nation Citizen-Owned  |  Indian Economic Enterprise (IEE)")

    # Thin gold line under header
    y -= 10
    c.setStrokeColor(GOLD)
    c.setLineWidth(1.5)
    c.line(margin, y, width - margin, y)

    # =========================================================================
    # TWO-COLUMN LAYOUT
    # =========================================================================
    col_gap = 14
    left_col_w = usable_w * 0.52
    right_col_w = usable_w - left_col_w - col_gap
    left_x = margin
    right_x = margin + left_col_w + col_gap

    y -= 18

    # --- SECTION HEADER STYLE ---
    def section_header(c, x, y_pos, text, w):
        c.setFillColor(GOLD)
        c.rect(x, y_pos - 2, w, 15, fill=1, stroke=0)
        c.setFillColor(DARK)
        c.setFont("Helvetica-Bold", 9)
        c.drawString(x + 4, y_pos + 1, text.upper())
        return y_pos - 20

    # =========================================================================
    # LEFT COLUMN - CORE COMPETENCIES
    # =========================================================================
    cur_y = section_header(c, left_x, y, "Core Competencies", left_col_w)

    competencies = [
        "Federal & Tribal Procurement Intelligence",
        "AI-Powered Risk Analysis & Prediction",
        "Logistics & Transportation (CDL Class A, HazMat, Tanker)",
        "IT Infrastructure & Cybersecurity Support",
        "Compliance Monitoring & Audit Services",
        "MCP Server Development & AI Middleware",
    ]

    c.setFont("Helvetica", 8)
    for comp in competencies:
        c.setFillColor(GOLD)
        c.drawString(left_x + 4, cur_y + 1, "\u25B8")
        c.setFillColor(WHITE)
        c.drawString(left_x + 16, cur_y + 1, comp)
        cur_y -= 13

    # =========================================================================
    # LEFT COLUMN - DIFFERENTIATORS
    # =========================================================================
    cur_y -= 8
    cur_y = section_header(c, left_x, cur_y, "Differentiators", left_col_w)

    differentiators = [
        "Only intelligence firm combining AI-powered procurement analysis with CDL logistics capability",
        "Cherokee Nation Tier 1 TERO preference across 14-county jurisdiction",
        "66,000+ federal procurement records analyzed covering $163B+ in spending",
        "Multi-model AI system (Claude, GPT, Gemini) for exhaustive pattern detection",
    ]

    style_diff = ParagraphStyle(
        "diff",
        fontName="Helvetica",
        fontSize=7.5,
        leading=9.5,
        textColor=WHITE,
    )

    for diff_text in differentiators:
        # Gold bullet
        c.setFillColor(GOLD)
        c.drawString(left_x + 4, cur_y + 1, "\u25B8")

        # Paragraph for wrapping
        p = Paragraph(diff_text, style_diff)
        pw, ph = p.wrap(left_col_w - 20, 100)
        p.drawOn(c, left_x + 16, cur_y - ph + 10)
        cur_y -= (ph + 4)

    # =========================================================================
    # LEFT COLUMN - PAST PERFORMANCE
    # =========================================================================
    cur_y -= 6
    cur_y = section_header(c, left_x, cur_y, "Past Performance", left_col_w)

    pp_text = (
        "While building our federal portfolio, Delzar offers extensive commercial "
        "experience in logistics, procurement intelligence, and AI-powered analytics. "
        "Per FAR 15.305(a)(2)(iv), our proposal warrants a neutral past performance "
        "evaluation that shall not be held unfavorably against our offer."
    )
    style_pp = ParagraphStyle(
        "pp",
        fontName="Helvetica-Oblique",
        fontSize=7,
        leading=9,
        textColor=LIGHT_GOLD,
    )
    p = Paragraph(pp_text, style_pp)
    pw, ph = p.wrap(left_col_w - 8, 200)
    p.drawOn(c, left_x + 4, cur_y - ph + 8)
    cur_y -= (ph + 4)

    # =========================================================================
    # RIGHT COLUMN - COMPANY DATA
    # =========================================================================
    ry = y
    ry = section_header(c, right_x, ry, "Company Data", right_col_w)

    company_data = [
        ("UEI:", "TKMXZNCBPS27"),
        ("NAICS:", "541512, 561210, 561720,"),
        ("", "236220, 541330, 484110, 484121"),
        ("Tribal:", "Cherokee Nation (Enrolled Citizen)"),
        ("IEE Status:", "Self-certified per DIAR 1480.201"),
        ("Set-Asides:", "Buy Indian Act, 8(a),"),
        ("", "Indian-Owned, Small Business"),
        ("Location:", "Tulsa, Oklahoma"),
    ]

    c.setFont("Helvetica", 7.5)
    for label, value in company_data:
        if label:
            c.setFillColor(GOLD)
            c.setFont("Helvetica-Bold", 7.5)
            c.drawString(right_x + 4, ry + 1, label)
        c.setFillColor(WHITE)
        c.setFont("Helvetica", 7.5)
        c.drawString(right_x + 60, ry + 1, value)
        ry -= 12

    # =========================================================================
    # RIGHT COLUMN - IEE STATEMENT
    # =========================================================================
    ry -= 8
    ry = section_header(c, right_x, ry, "IEE Certification Statement", right_col_w)

    iee_text = (
        "Delzar Solutions LLC is a proud Cherokee Nation citizen-owned Indian Economic "
        "Enterprise (IEE) as defined in DIAR 1480.201, eligible for Buy Indian Act "
        "set-aside awards under 25 U.S.C. \u00a7 47. We maintain active IEE/ISBEE "
        "representations in SAM.gov and are committed to advancing Indian "
        "self-determination through quality service delivery."
    )
    style_iee = ParagraphStyle(
        "iee",
        fontName="Helvetica",
        fontSize=7,
        leading=9,
        textColor=LIGHT_GOLD,
    )
    p = Paragraph(iee_text, style_iee)
    pw, ph = p.wrap(right_col_w - 8, 200)
    p.drawOn(c, right_x + 4, ry - ph + 8)
    ry -= (ph + 4)

    # =========================================================================
    # RIGHT COLUMN - NAICS DESCRIPTIONS (compact table)
    # =========================================================================
    ry -= 8
    ry = section_header(c, right_x, ry, "NAICS Descriptions", right_col_w)

    naics_items = [
        ("541512", "Computer Systems Design"),
        ("561210", "Facilities Support Services"),
        ("561720", "Janitorial Services"),
        ("236220", "Commercial Construction"),
        ("541330", "Engineering Services"),
        ("484110", "General Freight Trucking, Local"),
        ("484121", "General Freight Trucking, Long-Distance"),
    ]

    c.setFont("Helvetica", 6.5)
    for code, desc in naics_items:
        c.setFillColor(GOLD)
        c.setFont("Helvetica-Bold", 6.5)
        c.drawString(right_x + 4, ry + 1, code)
        c.setFillColor(WHITE)
        c.setFont("Helvetica", 6.5)
        c.drawString(right_x + 42, ry + 1, desc)
        ry -= 11

    # =========================================================================
    # BOTTOM GOLD BAR - CONTACT
    # =========================================================================
    bar_y = margin - 6
    bar_height = 48
    c.setFillColor(GOLD)
    c.rect(0, bar_y, width, bar_height, fill=1, stroke=0)

    # Contact info
    contact_y = bar_y + bar_height - 14
    c.setFillColor(DARK)
    c.setFont("Helvetica-Bold", 10)
    c.drawCentredString(width / 2, contact_y, 'Dominique "DJ" Lovelace  \u2014  Founder & CEO')

    contact_y -= 13
    c.setFont("Helvetica", 8.5)
    c.drawCentredString(width / 2, contact_y, "(918) 504-0592   |   dominique@delzarsolutionsllc.com")

    contact_y -= 12
    c.setFont("Helvetica-Bold", 8)
    c.drawCentredString(width / 2, contact_y, "www.delzarsolutionsllc.com")

    # Bottom thin dark line
    c.setStrokeColor(DARK)
    c.setLineWidth(2)
    c.line(0, bar_y, width, bar_y)

    # =========================================================================
    # DECORATIVE CORNER ACCENTS
    # =========================================================================
    accent_len = 20
    c.setStrokeColor(GOLD)
    c.setLineWidth(1.5)
    # Top-left
    c.line(margin - 4, height - bar_h - 6, margin - 4 + accent_len, height - bar_h - 6)
    c.line(margin - 4, height - bar_h - 6, margin - 4, height - bar_h - 6 - accent_len)
    # Top-right
    c.line(width - margin + 4, height - bar_h - 6, width - margin + 4 - accent_len, height - bar_h - 6)
    c.line(width - margin + 4, height - bar_h - 6, width - margin + 4, height - bar_h - 6 - accent_len)
    # Bottom-left
    c.line(margin - 4, bar_y + bar_height + 6, margin - 4 + accent_len, bar_y + bar_height + 6)
    c.line(margin - 4, bar_y + bar_height + 6, margin - 4, bar_y + bar_height + 6 + accent_len)
    # Bottom-right
    c.line(width - margin + 4, bar_y + bar_height + 6, width - margin + 4 - accent_len, bar_y + bar_height + 6)
    c.line(width - margin + 4, bar_y + bar_height + 6, width - margin + 4, bar_y + bar_height + 6 + accent_len)


def main():
    c = canvas.Canvas(OUTPUT_PATH, pagesize=letter)
    c.setTitle("Delzar Solutions LLC - Federal Capability Statement")
    c.setAuthor("Delzar Solutions LLC")
    c.setSubject("Federal Capability Statement")
    draw_page(c)
    c.showPage()
    c.save()
    print(f"PDF created successfully: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
