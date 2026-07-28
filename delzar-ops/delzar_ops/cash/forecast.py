"""CASH: working-capital model.

The construction death pattern this prevents: materials and subs are
paid in week 1, the government pays day 30+. Profitable on paper,
insolvent in the bank. Everything here shows its work.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import date, timedelta
from decimal import ROUND_HALF_UP, Decimal

CENTS = Decimal("0.01")


def D(x) -> Decimal:
    return Decimal(str(x))


def cents(x: Decimal) -> Decimal:
    return x.quantize(CENTS, rounding=ROUND_HALF_UP)


# ---------- settings ----------

def get_cash_on_hand(conn: sqlite3.Connection) -> Decimal:
    row = conn.execute("SELECT value FROM cash_settings WHERE key = 'cash_on_hand'").fetchone()
    return D(row["value"]) if row else Decimal("0")


def set_cash_on_hand(conn: sqlite3.Connection, amount: Decimal):
    conn.execute(
        "INSERT INTO cash_settings (key, value) VALUES ('cash_on_hand', ?) "
        "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        (str(amount),),
    )
    conn.commit()


# ---------- receivables aging ----------

def receivables_aging(conn: sqlite3.Connection, as_of: date | None = None) -> list[dict]:
    as_of = as_of or date.today()
    out = []
    for r in conn.execute(
        """SELECT r.*, c.contract_no FROM receivables r
           LEFT JOIN contracts c ON r.contract_id = c.id
           WHERE r.paid_date IS NULL ORDER BY r.invoiced_date"""
    ):
        age = (as_of - date.fromisoformat(r["invoiced_date"])).days
        bucket = "0-30" if age <= 30 else "31-60" if age <= 60 else "61-90" if age <= 90 else "90+"
        out.append({
            "contract_no": r["contract_no"], "invoice_no": r["invoice_no"],
            "amount": D(r["amount"]), "invoiced_date": r["invoiced_date"],
            "age_days": age, "bucket": bucket,
        })
    return out


# ---------- 90-day projection ----------

@dataclass
class WeekProjection:
    week_start: date
    inflows: Decimal
    outflows: Decimal
    ending_cash: Decimal
    events: list[str]


def project_cash(conn: sqlite3.Connection, as_of: date | None = None,
                 weeks: int = 13) -> list[WeekProjection]:
    """Weekly cash projection ~90 days forward from open receivables and
    unpaid outflows. Receivables land on expected_date (default
    invoiced + 30 days if not set)."""
    as_of = as_of or date.today()
    balance = get_cash_on_hand(conn)

    inflow_map: dict[date, list[tuple[Decimal, str]]] = {}
    for r in conn.execute("SELECT * FROM receivables WHERE paid_date IS NULL"):
        exp = (date.fromisoformat(r["expected_date"]) if r["expected_date"]
               else date.fromisoformat(r["invoiced_date"]) + timedelta(days=30))
        exp = max(exp, as_of)  # overdue money still arrives in the future
        inflow_map.setdefault(exp, []).append(
            (D(r["amount"]), f"invoice {r['invoice_no'] or r['id']} ${D(r['amount']):,.2f}"))

    outflow_map: dict[date, list[tuple[Decimal, str]]] = {}
    for o in conn.execute("SELECT * FROM outflows WHERE paid_date IS NULL"):
        due = max(date.fromisoformat(o["due_date"]), as_of)
        outflow_map.setdefault(due, []).append(
            (D(o["amount"]), f"{o['category']}: {o['description'] or ''} ${D(o['amount']):,.2f}"))

    projections = []
    for w in range(weeks):
        ws = as_of + timedelta(days=7 * w)
        we = ws + timedelta(days=6)
        inflows = Decimal("0")
        outflows = Decimal("0")
        events = []
        d = ws
        while d <= we:
            for amt, desc in inflow_map.get(d, []):
                inflows += amt
                events.append(f"+ {desc}")
            for amt, desc in outflow_map.get(d, []):
                outflows += amt
                events.append(f"- {desc}")
            d += timedelta(days=1)
        balance = cents(balance + inflows - outflows)
        projections.append(WeekProjection(ws, cents(inflows), cents(outflows), balance, events))
    return projections


def lowest_point(projections: list[WeekProjection]) -> tuple[date, Decimal]:
    wk = min(projections, key=lambda p: p.ending_cash)
    return wk.week_start, wk.ending_cash


# ---------- instruments outstanding ----------

def instruments_outstanding(conn: sqlite3.Connection) -> Decimal:
    row = conn.execute(
        "SELECT COALESCE(SUM(amount), 0) AS s FROM payment_instruments WHERE released_date IS NULL"
    ).fetchone()
    return D(row["s"])


# ---------- financing math ----------

def factoring_model(invoice_amount: Decimal, advance_rate: Decimal,
                    fee_pct: Decimal, days_early: int) -> dict:
    """Model factoring an invoice.
    advance_rate e.g. 0.85, fee_pct e.g. 0.03 (of face), days_early =
    how many days sooner you get the money vs. waiting for the government.
    """
    advance = cents(invoice_amount * advance_rate)
    fee = cents(invoice_amount * fee_pct)
    reserve_back = cents(invoice_amount - advance - fee)
    net = cents(invoice_amount - fee)
    apr = (fee_pct * D(365) / D(max(days_early, 1))).quantize(Decimal("0.0001"))
    return {
        "invoice": invoice_amount,
        "advance_now": advance,
        "fee": fee,
        "reserve_paid_later": reserve_back,
        "total_net": net,
        "effective_apr": apr,
        "explain": (
            f"Factor ${invoice_amount:,.2f}: get ${advance:,.2f} now ({advance_rate:.0%}), "
            f"fee ${fee:,.2f} ({fee_pct:.1%}), remaining ${reserve_back:,.2f} when the "
            f"government pays. Net ${net:,.2f}. Getting cash {days_early} days early at "
            f"this fee = {apr:.1%} annualized - compare against any credit line first."
        ),
    }


def discount_annualized(discount_pct: Decimal = D("0.02"),
                        discount_days: int = 10, net_days: int = 30) -> dict:
    """Annualized return of taking a supplier early-payment discount
    (e.g. 2/10 net 30). Formula: (d / (1-d)) * (365 / (net - discount days)).
    """
    d = discount_pct
    period = net_days - discount_days
    annual = (d / (1 - d)) * (D(365) / D(period))
    return {
        "discount_pct": d,
        "pay_by_day": discount_days,
        "net_days": net_days,
        "annualized": annual.quantize(Decimal("0.0001")),
        "explain": (
            f"Paying day {discount_days} instead of day {net_days} earns {d:.1%} for "
            f"{period} days of money = {annual:.1%} annualized. Take the discount if "
            f"your cash or credit costs less than that (it almost always does)."
        ),
    }


# ---------- go/no-go gate ----------

GATE_THRESHOLD = Decimal("50000")

GATE_QUESTIONS = [
    ("crew_ok", "Crew available for this job on the required schedule?"),
    ("materials_float_ok", "Materials float available (cash or terms) without starving other jobs?"),
    ("protection_ok", "Payment protection (100% of price) obtainable within 10 days of award?"),
    ("payroll_capacity_ok", "Certified payroll capacity for this PLUS all active contracts, every week?"),
]


def gate_decision(conn: sqlite3.Connection, description: str, amount: Decimal,
                  answers: dict[str, bool], notes: str = "") -> dict:
    all_yes = all(answers.get(k, False) for k, _ in GATE_QUESTIONS)
    recommendation = "accept" if all_yes else "decline"
    conn.execute(
        """INSERT INTO gate_decisions
           (description, amount, crew_ok, materials_float_ok, protection_ok,
            payroll_capacity_ok, recommendation, notes)
           VALUES (?,?,?,?,?,?,?,?)""",
        (description, float(amount),
         int(answers.get("crew_ok", False)),
         int(answers.get("materials_float_ok", False)),
         int(answers.get("protection_ok", False)),
         int(answers.get("payroll_capacity_ok", False)),
         recommendation, notes),
    )
    conn.commit()
    failed = [q for k, q in GATE_QUESTIONS if not answers.get(k, False)]
    return {"recommendation": recommendation, "failed": failed}


def working_capital_check(conn: sqlite3.Connection, new_job_outflow: Decimal,
                          as_of: date | None = None) -> dict:
    """Would this job's early outflows push projected cash below zero?"""
    projections = project_cash(conn, as_of)
    low_date, low_cash = lowest_point(projections)
    after = cents(low_cash - new_job_outflow)
    return {
        "current_low_point": low_cash,
        "low_point_date": low_date,
        "new_job_outflow": new_job_outflow,
        "low_point_after": after,
        "ok": after >= 0,
        "explain": (
            f"Projected low point is ${low_cash:,.2f} (week of {low_date}). This job's "
            f"early outflows of ${new_job_outflow:,.2f} would take that to ${after:,.2f}. "
            + ("OK." if after >= 0 else "DO NOT ACCEPT without financing lined up - "
               "you would run out of cash before the government pays.")
        ),
    }
