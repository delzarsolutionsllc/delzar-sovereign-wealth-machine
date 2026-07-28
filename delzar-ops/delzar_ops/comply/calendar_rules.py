"""Compliance calendar: hard-coded deadline rules driven by regulatory.json.

Events are created when a contract is registered and listed with
escalating urgency. Missing certified payroll weeks are computed live
(not stored) so they can never silently drift out of date.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import date, timedelta

from ..config import reg
from .payroll import missing_weeks

# Federal holidays are ignored for the OK811 business-day count; the
# operator should call a day early around holidays. Documented in README.


def add_business_days(start: date, n: int) -> date:
    """Return the date n business days (Mon-Fri) after start."""
    d = start
    added = 0
    while added < n:
        d += timedelta(days=1)
        if d.weekday() < 5:
            added += 1
    return d


def earliest_dig_date(locate_request_date: date) -> date:
    """Earliest lawful excavation date after an OKIE811 locate request."""
    return add_business_days(locate_request_date, int(reg().value("ok811_business_days")))


@dataclass
class Alert:
    due_date: date
    title: str
    severity: str          # OVERDUE | URGENT | UPCOMING
    contract_no: str | None
    rule_key: str
    detail: str = ""


def create_award_events(conn: sqlite3.Connection, contract_id: int) -> list[str]:
    """Create the standard deadline events when a contract is awarded."""
    r = reg()
    c = conn.execute("SELECT * FROM contracts WHERE id = ?", (contract_id,)).fetchone()
    created = []

    def add(rule_key: str, title: str, due: date, notes: str = ""):
        conn.execute(
            """INSERT OR IGNORE INTO compliance_events
               (contract_id, rule_key, title, due_date, notes) VALUES (?,?,?,?,?)""",
            (contract_id, rule_key, title, due.isoformat(), notes),
        )
        created.append(f"{due.isoformat()}  {title}")

    if c["award_date"]:
        award = date.fromisoformat(c["award_date"])
        pp = r.get("payment_protection_days")
        add(
            "payment_protection",
            f"Furnish payment protection: 100% of ${c['amount']:,.0f} = ${c['amount']:,.0f}",
            award + timedelta(days=int(pp.value)),
            f"{pp.citation}. Alerts escalate at days 1/3/5/7 after award.",
        )
        add(
            "wd_posting",
            "Post wage determination + WH-1321 poster at the job site",
            date.fromisoformat(c["start_date"]) if c["start_date"] else award,
            "29 CFR 5.5(a)(1); post before work begins, keep posted for duration.",
        )
    if c["notify_date"]:
        notify = date.fromisoformat(c["notify_date"])
        db = r.get("debrief_request_days")
        add(
            "debrief",
            "Request debriefing / brief explanation of award",
            notify + timedelta(days=int(db.value)),
            db.citation,
        )
    conn.commit()
    return created


def create_completion_events(conn: sqlite3.Connection, contract_id: int) -> list[str]:
    r = reg()
    c = conn.execute("SELECT * FROM contracts WHERE id = ?", (contract_id,)).fetchone()
    if not c["completion_date"]:
        return []
    comp = date.fromisoformat(c["completion_date"])
    rr = r.get("record_retention_years")
    due = comp.replace(year=comp.year + int(rr.value))
    conn.execute(
        """INSERT OR IGNORE INTO compliance_events
           (contract_id, rule_key, title, due_date, notes) VALUES (?,?,?,?,?)""",
        (contract_id, "record_retention",
         "Record retention period ends (keep payroll records until this date)",
         due.isoformat(), rr.citation),
    )
    conn.commit()
    return [f"{due.isoformat()}  record retention ends"]


def upcoming_alerts(conn: sqlite3.Connection, as_of: date | None = None,
                    horizon_days: int = 30) -> list[Alert]:
    """All open compliance items: stored events, payment-protection
    escalation, and live-computed missing payroll weeks."""
    as_of = as_of or date.today()
    alerts: list[Alert] = []

    rows = conn.execute(
        """SELECT ce.*, c.contract_no FROM compliance_events ce
           LEFT JOIN contracts c ON ce.contract_id = c.id
           WHERE ce.completed_at IS NULL ORDER BY ce.due_date"""
    ).fetchall()
    for e in rows:
        due = date.fromisoformat(e["due_date"])
        days = (due - as_of).days
        if days < 0:
            sev = "OVERDUE"
        elif days <= 3:
            sev = "URGENT"
        elif days <= horizon_days:
            sev = "UPCOMING"
        else:
            continue
        alerts.append(Alert(due, e["title"], sev, e["contract_no"], e["rule_key"], e["notes"] or ""))

    # payment-protection day 1/3/5/7 escalation
    pp_days = int(reg().value("payment_protection_days"))
    for c in conn.execute(
        "SELECT * FROM contracts WHERE status = 'active' AND award_date IS NOT NULL"
    ):
        open_pp = conn.execute(
            """SELECT 1 FROM compliance_events WHERE contract_id = ? AND
               rule_key = 'payment_protection' AND completed_at IS NULL""",
            (c["id"],),
        ).fetchone()
        if not open_pp:
            continue
        elapsed = (as_of - date.fromisoformat(c["award_date"])).days
        if elapsed in (1, 3, 5, 7):
            alerts.append(Alert(
                date.fromisoformat(c["award_date"]) + timedelta(days=pp_days),
                f"DAY {elapsed} OF {pp_days}: payment protection not yet furnished for {c['contract_no']}",
                "URGENT", c["contract_no"], "payment_protection_escalation",
                reg().get("payment_protection_days").citation,
            ))

    # live missing payroll weeks
    for c in conn.execute("SELECT * FROM contracts WHERE status = 'active'"):
        for wk in missing_weeks(conn, c["id"], as_of):
            days_late = (as_of - wk).days
            sev = "OVERDUE" if days_late > 7 else ("URGENT" if days_late >= 0 else "UPCOMING")
            alerts.append(Alert(
                wk, f"Certified payroll (WH-347) for week ending {wk.isoformat()}",
                sev, c["contract_no"], "payroll_week",
                "Weekly, including zero-work weeks - 29 CFR 5.5(a)(3)(ii). "
                "Run: delzar payroll generate",
            ))

    # missing subcontractor payrolls
    for r_ in conn.execute(
        """SELECT sp.*, c.contract_no FROM sub_payrolls sp
           JOIN contracts c ON sp.contract_id = c.id
           WHERE sp.received_at IS NULL"""
    ):
        wk = date.fromisoformat(r_["week_ending"])
        if wk <= as_of:
            alerts.append(Alert(
                wk, f"Subcontractor payroll NOT RECEIVED: {r_['subcontractor']} week {wk.isoformat()}",
                "OVERDUE" if (as_of - wk).days > 7 else "URGENT",
                r_["contract_no"], "sub_payroll", "You must collect and submit sub payrolls too."))

    sev_rank = {"OVERDUE": 0, "URGENT": 1, "UPCOMING": 2}
    alerts.sort(key=lambda a: (sev_rank[a.severity], a.due_date))
    return alerts
