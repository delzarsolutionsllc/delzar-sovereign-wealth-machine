"""Cash: aging, projection, factoring, discount math, the gate."""
from datetime import date
from decimal import Decimal

from delzar_ops.cash.forecast import (
    D,
    discount_annualized,
    factoring_model,
    gate_decision,
    instruments_outstanding,
    lowest_point,
    project_cash,
    receivables_aging,
    set_cash_on_hand,
    working_capital_check,
)

AS_OF = date(2026, 7, 20)


def test_aging_buckets(conn, contract):
    conn.execute(
        "INSERT INTO receivables (contract_id, invoice_no, amount, invoiced_date) VALUES (?, 'INV-1', 5000, '2026-07-01')",
        (contract["id"],))
    conn.execute(
        "INSERT INTO receivables (contract_id, invoice_no, amount, invoiced_date) VALUES (?, 'INV-2', 3000, '2026-05-01')",
        (contract["id"],))
    conn.commit()
    aging = receivables_aging(conn, AS_OF)
    by_no = {a["invoice_no"]: a for a in aging}
    assert by_no["INV-1"]["bucket"] == "0-30"
    assert by_no["INV-2"]["bucket"] == "61-90"


def test_projection_models_the_gap(conn, contract):
    """Materials paid week 1, government pays day 30+: cash dips then recovers."""
    set_cash_on_hand(conn, D("5000"))
    # pay materials + sub in the first week
    conn.execute("INSERT INTO outflows (contract_id, category, amount, due_date) VALUES (?, 'materials', 4000, '2026-07-22')", (contract["id"],))
    conn.execute("INSERT INTO outflows (contract_id, category, amount, due_date) VALUES (?, 'subcontractor', 3000, '2026-07-24')", (contract["id"],))
    # invoice paid ~30 days out
    conn.execute(
        "INSERT INTO receivables (contract_id, amount, invoiced_date, expected_date) VALUES (?, 12000, '2026-07-25', '2026-08-24')",
        (contract["id"],))
    conn.commit()
    proj = project_cash(conn, AS_OF)
    low_date, low_cash = lowest_point(proj)
    assert low_cash == Decimal("-2000.00")          # 5000 - 7000
    assert low_date == AS_OF                        # dip happens in week 1
    assert proj[-1].ending_cash == Decimal("10000.00")  # after the government pays


def test_overdue_receivable_still_counts_forward(conn, contract):
    set_cash_on_hand(conn, D("0"))
    conn.execute(
        "INSERT INTO receivables (contract_id, amount, invoiced_date, expected_date) VALUES (?, 1000, '2026-05-01', '2026-06-01')",
        (contract["id"],))
    conn.commit()
    proj = project_cash(conn, AS_OF)
    assert proj[0].inflows == Decimal("1000.00")  # lands 'now', not lost in the past


def test_instruments_stack(conn, contract):
    for _ in range(5):
        conn.execute(
            "INSERT INTO payment_instruments (contract_id, instrument_type, amount) VALUES (?, 'ILC', 20000)",
            (contract["id"],))
    conn.commit()
    assert instruments_outstanding(conn) == Decimal("100000")


def test_factoring_model():
    m = factoring_model(D("10000"), D("0.85"), D("0.03"), days_early=25)
    assert m["advance_now"] == Decimal("8500.00")
    assert m["fee"] == Decimal("300.00")
    assert m["reserve_paid_later"] == Decimal("1200.00")
    assert m["total_net"] == Decimal("9700.00")
    # 3% for 25 days = 43.8% APR
    assert m["effective_apr"] == Decimal("0.4380")


def test_discount_2_10_net_30():
    m = discount_annualized(D("0.02"), 10, 30)
    # (0.02/0.98) * (365/20) = 37.24% annualized
    assert m["annualized"] == Decimal("0.3724")


def test_gate_four_yeses_accepts(conn):
    r = gate_decision(conn, "Test job", D("60000"), {
        "crew_ok": True, "materials_float_ok": True,
        "protection_ok": True, "payroll_capacity_ok": True})
    assert r["recommendation"] == "accept"


def test_gate_any_no_declines_and_logs(conn):
    r = gate_decision(conn, "Test job", D("60000"), {
        "crew_ok": True, "materials_float_ok": True,
        "protection_ok": False, "payroll_capacity_ok": True})
    assert r["recommendation"] == "decline"
    assert any("Payment protection" in f for f in r["failed"])
    row = conn.execute("SELECT * FROM gate_decisions").fetchone()
    assert row["recommendation"] == "decline" and row["protection_ok"] == 0


def test_working_capital_check(conn, contract):
    set_cash_on_hand(conn, D("10000"))
    wc = working_capital_check(conn, D("15000"), AS_OF)
    assert not wc["ok"]
    assert wc["low_point_after"] == Decimal("-5000.00")
    wc2 = working_capital_check(conn, D("4000"), AS_OF)
    assert wc2["ok"]
