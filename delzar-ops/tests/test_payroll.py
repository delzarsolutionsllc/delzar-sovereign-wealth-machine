"""Payroll math: OT split, gross/deductions/net, wage validation,
zero-activity weeks, missing-week detection."""
from datetime import date
from decimal import Decimal

from delzar_ops.comply.payroll import (
    D,
    build_payroll,
    check_wage,
    missing_weeks,
    saturdays_between,
    save_payroll,
    split_overtime,
    week_start,
)


def test_week_start():
    assert week_start(date(2026, 7, 11)) == date(2026, 7, 5)  # Sat -> prior Sun


def test_saturdays_between_covers_partial_weeks():
    # start Monday 2026-07-06, end Wednesday 2026-07-15
    sats = saturdays_between(date(2026, 7, 6), date(2026, 7, 15))
    assert sats == [date(2026, 7, 11), date(2026, 7, 18)]


def test_split_overtime_none():
    days = [D(0), D(8), D(8), D(8), D(8), D(8), D(0)]  # 40h
    straight, ot = split_overtime(days)
    assert sum(straight) == 40 and sum(ot) == 0


def test_split_overtime_peels_from_end():
    days = [D(0), D(8), D(8), D(8), D(8), D(8), D(8)]  # 48h Mon-Sat
    straight, ot = split_overtime(days)
    assert sum(straight) == 40
    assert sum(ot) == 8
    assert ot[6] == 8  # Saturday hours are the OT


def test_gross_and_net_with_ot(conn, contract, wage_determination, employee):
    # Mon-Sat 8h each = 48h at $20 base + $6.10 fringe
    for day in ["2026-07-06", "2026-07-07", "2026-07-08", "2026-07-09", "2026-07-10", "2026-07-11"]:
        conn.execute(
            "INSERT INTO time_entries (contract_id, employee_id, work_date, hours) VALUES (?,?,?,8)",
            (contract["id"], employee["id"], day),
        )
    conn.commit()
    result = build_payroll(conn, contract["id"], date(2026, 7, 11))
    assert not result.is_zero_activity
    assert len(result.lines) == 1
    ln = result.lines[0]
    # straight: 40 x (20 + 6.10) = 1044.00
    # OT: 8 x (20*1.5 + 6.10) = 8 x 36.10 = 288.80
    assert ln.gross == Decimal("1332.80")
    # FICA 7.65% of 1332.80 = 101.96
    assert ln.fica == Decimal("101.96")
    assert ln.net == Decimal("1230.84")
    assert "OT 8" in ln.explain


def test_zero_activity_week(conn, contract, wage_determination):
    result = build_payroll(conn, contract["id"], date(2026, 7, 11))
    assert result.is_zero_activity
    assert result.lines == []
    assert result.payroll_number == 1


def test_wage_violation_below_base(conn, contract, wage_determination, employee):
    conn.execute(
        """INSERT INTO time_entries (contract_id, employee_id, work_date, hours, base_rate, fringe_rate)
           VALUES (?,?,?,8, 17.00, 6.10)""",
        (contract["id"], employee["id"], "2026-07-06"),
    )
    conn.commit()
    result = build_payroll(conn, contract["id"], date(2026, 7, 11))
    assert len(result.violations) == 1
    assert "BELOW the determination basic rate" in result.violations[0].reason


def test_wage_violation_below_total():
    wd = {"laborer: common": (D("18.25"), D("6.10"))}
    v = check_wage(wd, "Joe", "Laborer: Common", D("18.25"), D("5.00"))
    assert v is not None and "BELOW the required" in v.reason


def test_wage_ok():
    wd = {"laborer: common": (D("18.25"), D("6.10"))}
    assert check_wage(wd, "Joe", "Laborer: Common", D("20.00"), D("6.10")) is None


def test_wage_unknown_classification():
    v = check_wage({}, "Joe", "Pipefitter", D("30"), D("5"))
    assert v is not None and "not found" in v.reason


def test_missing_weeks_and_save(conn, contract, wage_determination):
    # contract started Mon 2026-07-06; as of 2026-07-20 two Saturdays owed
    owed = missing_weeks(conn, contract["id"], date(2026, 7, 20))
    assert owed == [date(2026, 7, 11), date(2026, 7, 18)]
    result = build_payroll(conn, contract["id"], date(2026, 7, 11))
    save_payroll(conn, result, None)
    owed2 = missing_weeks(conn, contract["id"], date(2026, 7, 20))
    assert owed2 == [date(2026, 7, 18)]


def test_payroll_numbers_increment(conn, contract):
    r1 = build_payroll(conn, contract["id"], date(2026, 7, 11))
    save_payroll(conn, r1, None)
    r2 = build_payroll(conn, contract["id"], date(2026, 7, 18))
    assert r2.payroll_number == 2
