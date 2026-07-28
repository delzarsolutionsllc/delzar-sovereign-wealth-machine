"""Acceptance criteria: a valid WH-347 PDF for a test contract,
including a zero-activity week, and a quote PDF."""
from datetime import date
from decimal import Decimal

from delzar_ops.bid.estimator import demo_estimate, run_models
from delzar_ops.bid.quote_pdf import render_quote
from delzar_ops.comply.payroll import build_payroll
from delzar_ops.comply.wh347_pdf import render_wh347


def test_wh347_pdf_with_work_week(conn, contract, wage_determination, employee, tmp_path):
    for day in ["2026-07-06", "2026-07-07", "2026-07-08"]:
        conn.execute(
            "INSERT INTO time_entries (contract_id, employee_id, work_date, hours) VALUES (?,?,?,10)",
            (contract["id"], employee["id"], day))
    conn.commit()
    result = build_payroll(conn, contract["id"], date(2026, 7, 11))
    out = tmp_path / "wh347.pdf"
    render_wh347(result, dict(contract), out, signatory_name="Test Owner")
    data = out.read_bytes()
    assert data[:5] == b"%PDF-"
    assert len(data) > 2000  # two rendered pages, not an empty shell


def test_wh347_pdf_zero_activity_week(conn, contract, wage_determination, tmp_path):
    result = build_payroll(conn, contract["id"], date(2026, 7, 11))
    assert result.is_zero_activity
    out = tmp_path / "wh347-zero.pdf"
    render_wh347(result, dict(contract), out)
    assert out.read_bytes()[:5] == b"%PDF-"


def test_quote_pdf(tmp_path):
    est = demo_estimate()
    m = run_models(est)["hybrid"]
    out = tmp_path / "quote.pdf"
    render_quote(est, m, m.suggested_price, out)
    assert out.read_bytes()[:5] == b"%PDF-"
