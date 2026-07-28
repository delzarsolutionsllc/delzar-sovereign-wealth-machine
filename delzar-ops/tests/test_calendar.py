"""Compliance calendar: deadline creation, OK811 business days,
payment-protection escalation, missing-payroll alerts."""
from datetime import date

from delzar_ops.comply.calendar_rules import (
    add_business_days,
    create_award_events,
    create_completion_events,
    earliest_dig_date,
    upcoming_alerts,
)


def test_add_business_days_skips_weekend():
    # Friday + 2 business days = Tuesday
    assert add_business_days(date(2026, 7, 24), 2) == date(2026, 7, 28)
    # Monday + 2 business days = Wednesday
    assert add_business_days(date(2026, 7, 27), 2) == date(2026, 7, 29)


def test_earliest_dig_date_uses_config():
    assert earliest_dig_date(date(2026, 7, 24)) == date(2026, 7, 28)


def test_award_events_created(conn, contract):
    create_award_events(conn, contract["id"])
    rows = {r["rule_key"]: r for r in conn.execute(
        "SELECT * FROM compliance_events WHERE contract_id = ?", (contract["id"],))}
    # payment protection: award 2026-07-01 + 10 days (FAR 52.228-13)
    assert rows["payment_protection"]["due_date"] == "2026-07-11"
    # debrief: notify 2026-07-01 + 3 days
    assert rows["debrief"]["due_date"] == "2026-07-04"
    # wage determination posting due at start
    assert rows["wd_posting"]["due_date"] == "2026-07-06"


def test_completion_starts_retention_clock(conn, contract):
    conn.execute("UPDATE contracts SET completion_date = '2026-08-15' WHERE id = ?", (contract["id"],))
    conn.commit()
    create_completion_events(conn, contract["id"])
    r = conn.execute(
        "SELECT * FROM compliance_events WHERE rule_key = 'record_retention'").fetchone()
    assert r["due_date"] == "2029-08-15"  # 3 years, 29 CFR 5.5(a)(3)(i)


def test_payment_protection_escalation_days(conn, contract):
    create_award_events(conn, contract["id"])
    # award was 2026-07-01: day 3 = 2026-07-04
    alerts = upcoming_alerts(conn, as_of=date(2026, 7, 4))
    esc = [a for a in alerts if a.rule_key == "payment_protection_escalation"]
    assert len(esc) == 1 and "DAY 3 OF 10" in esc[0].title
    # no escalation on day 4
    alerts = upcoming_alerts(conn, as_of=date(2026, 7, 5))
    assert not [a for a in alerts if a.rule_key == "payment_protection_escalation"]


def test_escalation_stops_when_protection_furnished(conn, contract):
    create_award_events(conn, contract["id"])
    conn.execute(
        "UPDATE compliance_events SET completed_at = datetime('now') WHERE rule_key = 'payment_protection'")
    conn.commit()
    alerts = upcoming_alerts(conn, as_of=date(2026, 7, 4))
    assert not [a for a in alerts if "payment" in a.rule_key]


def test_missing_payroll_weeks_alerted(conn, contract):
    alerts = upcoming_alerts(conn, as_of=date(2026, 7, 20))
    pw = [a for a in alerts if a.rule_key == "payroll_week"]
    assert len(pw) == 2  # weeks ending 07-11 and 07-18 not generated
    assert any("2026-07-11" in a.title for a in pw)


def test_missing_sub_payroll_alerted(conn, contract):
    conn.execute(
        "INSERT INTO sub_payrolls (contract_id, subcontractor, week_ending) VALUES (?, 'DigCo LLC', '2026-07-11')",
        (contract["id"],))
    conn.commit()
    alerts = upcoming_alerts(conn, as_of=date(2026, 7, 15))
    subs = [a for a in alerts if a.rule_key == "sub_payroll"]
    assert len(subs) == 1 and "DigCo" in subs[0].title
