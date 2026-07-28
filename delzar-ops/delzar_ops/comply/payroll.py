"""Certified payroll: build weekly WH-347 data from time entries.

All money math uses Decimal and rounds to cents. Every computed line
carries an `explain` string so the operator can defend the number.

Conventions:
- Payroll week runs Sunday through Saturday; week_ending is the Saturday.
- Overtime: hours beyond 40 in the week are paid at ot_multiplier x base
  rate (fringe stays at straight rate) per CWHSSA. OT hours are assigned
  to the latest days of the week, matching how they accrue.
- Fringe is assumed paid IN CASH to the employee (typical for a small
  contractor without benefit plans), so hourly pay = base + fringe.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import date, timedelta
from decimal import ROUND_HALF_UP, Decimal

from ..config import reg

CENTS = Decimal("0.01")


def D(x) -> Decimal:
    return Decimal(str(x))


def cents(x: Decimal) -> Decimal:
    return x.quantize(CENTS, rounding=ROUND_HALF_UP)


def week_start(week_ending: date) -> date:
    return week_ending - timedelta(days=6)


def saturdays_between(start: date, end: date) -> list[date]:
    """Every payroll week-ending (Saturday) covering [start, end]."""
    first_sat = start + timedelta(days=(5 - start.weekday()) % 7)
    out = []
    d = first_sat
    while week_start(d) <= end:
        out.append(d)
        d += timedelta(days=7)
    return out


@dataclass
class PayrollLine:
    employee_name: str
    id_last4: str
    withholding_exemptions: int
    classification: str
    base_rate: Decimal
    fringe_rate: Decimal
    day_hours: list[Decimal]      # Sun..Sat straight time
    day_ot_hours: list[Decimal]   # Sun..Sat overtime
    fed_withholding: Decimal = Decimal("0")
    other_deductions: Decimal = Decimal("0")
    other_deductions_note: str = ""
    explain: str = ""

    @property
    def straight_hours(self) -> Decimal:
        return sum(self.day_hours, Decimal("0"))

    @property
    def ot_hours(self) -> Decimal:
        return sum(self.day_ot_hours, Decimal("0"))

    @property
    def hourly_pay(self) -> Decimal:
        """Straight-time cash rate: base + cash fringe."""
        return self.base_rate + self.fringe_rate

    @property
    def ot_hourly_pay(self) -> Decimal:
        mult = D(reg().value("ot_multiplier"))
        return cents(self.base_rate * mult + self.fringe_rate)

    @property
    def gross(self) -> Decimal:
        return cents(
            self.straight_hours * self.hourly_pay
            + self.ot_hours * self.ot_hourly_pay
        )

    @property
    def fica(self) -> Decimal:
        return cents(self.gross * D(reg().value("fica_rate")))

    @property
    def total_deductions(self) -> Decimal:
        return cents(self.fica + self.fed_withholding + self.other_deductions)

    @property
    def net(self) -> Decimal:
        return cents(self.gross - self.total_deductions)

    def build_explain(self) -> str:
        r = reg()
        parts = [
            f"straight {self.straight_hours}h x (${self.base_rate} base + ${self.fringe_rate} cash fringe) = ${cents(self.straight_hours * self.hourly_pay)}"
        ]
        if self.ot_hours:
            parts.append(
                f"OT {self.ot_hours}h x (${self.base_rate} x {r.value('ot_multiplier')} + ${self.fringe_rate} fringe) = ${cents(self.ot_hours * self.ot_hourly_pay)} [{r.get('ot_multiplier').citation}]"
            )
        parts.append(f"gross ${self.gross}")
        parts.append(
            f"FICA {D(r.value('fica_rate')) * 100}% = ${self.fica} [{r.get('fica_rate').citation}]"
        )
        if self.fed_withholding:
            parts.append(f"fed w/h ${self.fed_withholding}")
        if self.other_deductions:
            parts.append(f"other ${self.other_deductions} ({self.other_deductions_note})")
        parts.append(f"net ${self.net}")
        return "; ".join(parts)


@dataclass
class WageViolation:
    employee_name: str
    classification: str
    paid_base: Decimal
    paid_fringe: Decimal
    wd_base: Decimal
    wd_fringe: Decimal
    reason: str


@dataclass
class PayrollResult:
    contract_id: int
    payroll_number: int
    week_ending: date
    lines: list[PayrollLine]
    is_zero_activity: bool
    violations: list[WageViolation] = field(default_factory=list)


def _wd_rates(conn: sqlite3.Connection, contract_id: int) -> dict[str, tuple[Decimal, Decimal]]:
    rows = conn.execute(
        """SELECT wr.classification, wr.base_rate, wr.fringe_rate
           FROM wage_rates wr JOIN wage_determinations wd ON wr.wd_id = wd.id
           WHERE wd.contract_id = ?""",
        (contract_id,),
    ).fetchall()
    return {r["classification"].strip().lower(): (D(r["base_rate"]), D(r["fringe_rate"])) for r in rows}


def check_wage(
    wd: dict[str, tuple[Decimal, Decimal]],
    employee_name: str,
    classification: str,
    base: Decimal,
    fringe: Decimal,
) -> WageViolation | None:
    """Validate a paid rate against the wage determination.

    Two checks, both conservative:
    1. base must meet the WD basic rate (OT is computed on basic rate,
       so undercutting base undercuts OT too);
    2. base + fringe must meet WD base + WD fringe (total prevailing wage).
    """
    key = classification.strip().lower()
    if key not in wd:
        return WageViolation(
            employee_name, classification, base, fringe, D(0), D(0),
            reason=f"Classification '{classification}' not found in the wage determination. "
                   f"Add it with 'delzar payroll wd-add-rate' or request a conformance (SF-1444).",
        )
    wd_base, wd_fringe = wd[key]
    if base < wd_base:
        return WageViolation(
            employee_name, classification, base, fringe, wd_base, wd_fringe,
            reason=f"Base rate ${base} is BELOW the determination basic rate ${wd_base}.",
        )
    if base + fringe < wd_base + wd_fringe:
        return WageViolation(
            employee_name, classification, base, fringe, wd_base, wd_fringe,
            reason=f"Total ${base + fringe} (base+fringe) is BELOW the required "
                   f"${wd_base + wd_fringe} (WD base ${wd_base} + fringe ${wd_fringe}).",
        )
    return None


def split_overtime(day_hours: list[Decimal]) -> tuple[list[Decimal], list[Decimal]]:
    """Split Sun..Sat daily hours into straight-time and OT (over 40/wk).

    OT hours are peeled from the END of the week, since hours worked
    after the 40th cumulative hour are the overtime hours.
    """
    total = sum(day_hours, Decimal("0"))
    ot_total = max(Decimal("0"), total - Decimal("40"))
    straight = list(day_hours)
    ot = [Decimal("0")] * 7
    remaining = ot_total
    for i in range(6, -1, -1):
        if remaining <= 0:
            break
        take = min(straight[i], remaining)
        straight[i] -= take
        ot[i] = take
        remaining -= take
    return straight, ot


def next_payroll_number(conn: sqlite3.Connection, contract_id: int) -> int:
    row = conn.execute(
        "SELECT MAX(payroll_number) AS n FROM payrolls WHERE contract_id = ?",
        (contract_id,),
    ).fetchone()
    return (row["n"] or 0) + 1


def build_payroll(
    conn: sqlite3.Connection, contract_id: int, week_ending: date
) -> PayrollResult:
    """Assemble the week's payroll from time entries.

    If there are no time entries for the week, produces a ZERO-ACTIVITY
    payroll (required for every week of performance - 29 CFR 5.5(a)(3)(ii)).
    """
    start = week_start(week_ending)
    rows = conn.execute(
        """SELECT te.*, e.name, e.id_last4, e.withholding_exemptions,
                  e.default_classification, e.default_base_rate, e.default_fringe_rate
           FROM time_entries te JOIN employees e ON te.employee_id = e.id
           WHERE te.contract_id = ? AND te.work_date >= ? AND te.work_date <= ?
           ORDER BY e.name, te.work_date""",
        (contract_id, start.isoformat(), week_ending.isoformat()),
    ).fetchall()

    wd = _wd_rates(conn, contract_id)
    violations: list[WageViolation] = []

    # group by (employee, classification, base, fringe)
    groups: dict[tuple, dict] = {}
    for r in rows:
        classification = r["classification"] or r["default_classification"] or "Laborer"
        base = D(r["base_rate"] if r["base_rate"] is not None else r["default_base_rate"] or 0)
        fringe = D(r["fringe_rate"] if r["fringe_rate"] is not None else r["default_fringe_rate"] or 0)
        key = (r["name"], classification, base, fringe)
        g = groups.setdefault(
            key,
            {
                "id_last4": r["id_last4"] or "",
                "exemptions": r["withholding_exemptions"] or 0,
                "days": [Decimal("0")] * 7,
            },
        )
        day_idx = (date.fromisoformat(r["work_date"]).weekday() + 1) % 7  # Sun=0..Sat=6
        g["days"][day_idx] += D(r["hours"])

    lines: list[PayrollLine] = []
    for (name, classification, base, fringe), g in groups.items():
        v = check_wage(wd, name, classification, base, fringe)
        if v:
            violations.append(v)
        straight, ot = split_overtime(g["days"])
        line = PayrollLine(
            employee_name=name,
            id_last4=g["id_last4"],
            withholding_exemptions=g["exemptions"],
            classification=classification,
            base_rate=base,
            fringe_rate=fringe,
            day_hours=straight,
            day_ot_hours=ot,
        )
        line.explain = line.build_explain()
        lines.append(line)

    return PayrollResult(
        contract_id=contract_id,
        payroll_number=next_payroll_number(conn, contract_id),
        week_ending=week_ending,
        lines=lines,
        is_zero_activity=not lines,
        violations=violations,
    )


def save_payroll(
    conn: sqlite3.Connection, result: PayrollResult, pdf_path: str | None, is_final: bool = False
) -> int:
    cur = conn.execute(
        """INSERT INTO payrolls (contract_id, payroll_number, week_ending,
                                 is_zero_activity, is_final, pdf_path)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT (contract_id, week_ending) DO UPDATE SET
             is_zero_activity = excluded.is_zero_activity,
             is_final = excluded.is_final,
             pdf_path = excluded.pdf_path,
             generated_at = datetime('now')""",
        (
            result.contract_id,
            result.payroll_number,
            result.week_ending.isoformat(),
            int(result.is_zero_activity),
            int(is_final),
            pdf_path,
        ),
    )
    payroll_id = conn.execute(
        "SELECT id FROM payrolls WHERE contract_id = ? AND week_ending = ?",
        (result.contract_id, result.week_ending.isoformat()),
    ).fetchone()["id"]
    conn.execute("DELETE FROM payroll_lines WHERE payroll_id = ?", (payroll_id,))
    for ln in result.lines:
        conn.execute(
            """INSERT INTO payroll_lines
               (payroll_id, employee_name, id_last4, withholding_exemptions,
                classification, day_hours, day_ot_hours, base_rate, fringe_rate,
                gross, fica, fed_withholding, other_deductions, other_deductions_note, net)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                payroll_id, ln.employee_name, ln.id_last4, ln.withholding_exemptions,
                ln.classification,
                json.dumps([str(h) for h in ln.day_hours]),
                json.dumps([str(h) for h in ln.day_ot_hours]),
                float(ln.base_rate), float(ln.fringe_rate), float(ln.gross),
                float(ln.fica), float(ln.fed_withholding), float(ln.other_deductions),
                ln.other_deductions_note, float(ln.net),
            ),
        )
    conn.commit()
    return payroll_id


def missing_weeks(conn: sqlite3.Connection, contract_id: int, as_of: date) -> list[date]:
    """Payroll weeks owed but not yet generated for a contract."""
    c = conn.execute("SELECT * FROM contracts WHERE id = ?", (contract_id,)).fetchone()
    if not c or not c["start_date"]:
        return []
    start = date.fromisoformat(c["start_date"])
    end = date.fromisoformat(c["completion_date"]) if c["completion_date"] else as_of
    have = {
        r["week_ending"]
        for r in conn.execute(
            "SELECT week_ending FROM payrolls WHERE contract_id = ?", (contract_id,)
        )
    }
    owed = [s for s in saturdays_between(start, end) if s <= as_of]
    return [s for s in owed if s.isoformat() not in have]
