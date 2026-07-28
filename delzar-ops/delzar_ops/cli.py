"""DELZAR OPS command line.

Top-level: delzar init | status | dashboard
Modules:   delzar payroll | comply | bid | watch | cash | intel
Every command explains what it did and where any file went.
"""
from __future__ import annotations

import json
from datetime import date, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import typer

from . import COMPANY, __version__
from .config import data_dir, db_path, output_dir, reg
from .db import connect

app = typer.Typer(no_args_is_help=True, help="DELZAR OPS - federal contracting operations for Delzar Solutions LLC")
payroll_app = typer.Typer(no_args_is_help=True, help="Certified payroll (WH-347) - COMPLY module")
comply_app = typer.Typer(no_args_is_help=True, help="Compliance calendar and deadline rules")
bid_app = typer.Typer(no_args_is_help=True, help="LPTA estimator and quotes - BID module")
watch_app = typer.Typer(no_args_is_help=True, help="Solicitation monitor - WATCH module")
cash_app = typer.Typer(no_args_is_help=True, help="Working capital - CASH module")
intel_app = typer.Typer(no_args_is_help=True, help="Competitor / BPA intel - INTEL module")
app.add_typer(payroll_app, name="payroll")
app.add_typer(comply_app, name="comply")
app.add_typer(bid_app, name="bid")
app.add_typer(watch_app, name="watch")
app.add_typer(cash_app, name="cash")
app.add_typer(intel_app, name="intel")


def warn(msg: str):
    typer.secho(msg, fg=typer.colors.RED, bold=True)


def ok(msg: str):
    typer.secho(msg, fg=typer.colors.GREEN)


def info(msg: str):
    typer.echo(msg)


def _contract(conn, contract_no: str):
    row = conn.execute("SELECT * FROM contracts WHERE contract_no = ?", (contract_no,)).fetchone()
    if not row:
        warn(f"No contract '{contract_no}'. Add it: delzar payroll contract-add")
        raise typer.Exit(1)
    return row


# ============================= top level =============================

@app.command()
def version():
    """Show version and data locations."""
    info(f"DELZAR OPS v{__version__}")
    info(f"Data dir:  {data_dir()}")
    info(f"Database:  {db_path()}")
    info(f"Regulatory thresholds last verified: {reg().last_verified}")


@app.command()
def init(seed: bool = typer.Option(False, "--seed", help="Load seed data (materials, competitor/BPA templates)")):
    """Create the database, run migrations, optionally load seed data."""
    conn = connect()
    ok(f"Database ready at {db_path()}")
    if seed:
        from .seed.seed import seed_all
        counts = seed_all(conn)
        ok(f"Seeded: {counts}")
        info("Seed rows marked TEMPLATE are placeholders - edit the CSVs in "
             "delzar_ops/seed/data/ with your research and re-run 'delzar init --seed'.")


@app.command()
def status():
    """One-screen overview: deadlines, contracts, cash, top opportunities."""
    from .comply.calendar_rules import upcoming_alerts
    from .cash.forecast import get_cash_on_hand, instruments_outstanding, lowest_point, project_cash
    conn = connect()

    typer.secho(f"\n=== DELZAR OPS - {date.today().isoformat()} ===", bold=True)
    alerts = upcoming_alerts(conn)
    if alerts:
        typer.secho(f"\nCOMPLIANCE ({len(alerts)} open):", bold=True)
        for a in alerts[:10]:
            color = {"OVERDUE": typer.colors.RED, "URGENT": typer.colors.YELLOW}.get(a.severity)
            typer.secho(f"  [{a.severity:8}] {a.due_date} {a.title}"
                        + (f" ({a.contract_no})" if a.contract_no else ""), fg=color)
    else:
        ok("\nCOMPLIANCE: nothing due. (If you have an active contract, verify payroll weeks are current.)")

    contracts = conn.execute("SELECT * FROM contracts WHERE status = 'active'").fetchall()
    typer.secho(f"\nACTIVE CONTRACTS: {len(contracts)}", bold=True)
    for c in contracts:
        info(f"  {c['contract_no']}  {c['title'][:50]}  ${c['amount']:,.0f}")

    cash = get_cash_on_hand(conn)
    proj = project_cash(conn)
    low_d, low_c = lowest_point(proj)
    inst = instruments_outstanding(conn)
    typer.secho("\nCASH:", bold=True)
    info(f"  On hand: ${cash:,.2f}   90-day low point: ${low_c:,.2f} (week of {low_d})")
    info(f"  Payment protection instruments outstanding: ${inst:,.2f}")

    opps = conn.execute(
        "SELECT * FROM opportunities WHERE archived = 0 ORDER BY score DESC LIMIT 5").fetchall()
    if opps:
        typer.secho("\nTOP OPPORTUNITIES:", bold=True)
        for o in opps:
            info(f"  [{o['score'] or 0:5.1f}] {(o['title'] or '')[:60]} (due {o['response_deadline'] or '?'})")
    info("")


@app.command()
def dashboard(port: int = 8765):
    """Run the local web dashboard (read-only) on localhost."""
    import uvicorn
    from .dashboard.app import create_app
    ok(f"Dashboard: http://127.0.0.1:{port}  (Ctrl-C to stop)")
    uvicorn.run(create_app(), host="127.0.0.1", port=port, log_level="warning")


# ============================= PAYROLL =============================

@payroll_app.command("contract-add")
def contract_add(
    contract_no: str,
    title: str = typer.Option(..., prompt=True),
    amount: float = typer.Option(..., prompt="Contract amount ($)"),
    place: str = typer.Option("", prompt="Place of performance"),
    award_date: str = typer.Option("", prompt="Award date (YYYY-MM-DD, blank if not yet)"),
    notify_date: str = typer.Option("", prompt="Date you were notified (YYYY-MM-DD, blank=same)"),
    start_date: str = typer.Option("", prompt="Work start date (YYYY-MM-DD, blank if unknown)"),
    agency: str = typer.Option("", prompt="Agency/office"),
):
    """Register a contract; creates its compliance deadline events."""
    from .comply.calendar_rules import create_award_events
    conn = connect()
    conn.execute(
        """INSERT INTO contracts (contract_no, title, amount, place_of_performance,
           award_date, notify_date, start_date, agency)
           VALUES (?,?,?,?,?,?,?,?)""",
        (contract_no, title, amount, place or None,
         award_date or None, (notify_date or award_date) or None,
         start_date or None, agency or None),
    )
    conn.commit()
    c = _contract(conn, contract_no)
    events = create_award_events(conn, c["id"])
    ok(f"Contract {contract_no} registered.")
    for e in events:
        info(f"  deadline created: {e}")
    r = reg()
    if amount >= r.value("davis_bacon_threshold"):
        warn(f"  Davis-Bacon applies (>= ${r.value('davis_bacon_threshold'):,.0f}, "
             f"{r.get('davis_bacon_threshold').citation}). Import the wage determination NOW: "
             f"delzar payroll wd-import {contract_no} --wd-number <WD#> --rates-file rates.csv")
    if amount > r.value("miller_act_threshold"):
        warn(f"  Above Miller Act threshold ${r.value('miller_act_threshold'):,.0f} - bonds required "
             f"({r.get('miller_act_threshold').citation}).")


@payroll_app.command("contract-complete")
def contract_complete(contract_no: str, completion_date: str = typer.Option(..., prompt="Completion date (YYYY-MM-DD)")):
    """Mark a contract complete; starts the record-retention clock."""
    from .comply.calendar_rules import create_completion_events
    conn = connect()
    c = _contract(conn, contract_no)
    conn.execute("UPDATE contracts SET completion_date = ?, status = 'completed' WHERE id = ?",
                 (completion_date, c["id"]))
    conn.commit()
    for e in create_completion_events(conn, c["id"]):
        info(f"  deadline created: {e}")
    ok(f"{contract_no} marked complete. Generate the FINAL payroll for the last week: "
       f"delzar payroll generate {contract_no} --final")


@payroll_app.command("wd-import")
def wd_import(
    contract_no: str,
    wd_number: str = typer.Option(..., help="Wage determination number, e.g. OK20240043"),
    rates_file: Path = typer.Option(None, help="CSV: classification,base_rate,fringe_rate"),
    raw_file: Path = typer.Option(None, help="Optional: full WD text file to store for the record"),
):
    """Store the wage determination for a contract and its rates.

    DOL has no free rates API; copy the rates off the WD attached to the
    solicitation into a small CSV (classification,base_rate,fringe_rate).
    """
    import csv as _csv
    conn = connect()
    c = _contract(conn, contract_no)
    raw = raw_file.read_text() if raw_file else None
    cur = conn.execute(
        "INSERT INTO wage_determinations (contract_id, wd_number, source, raw_text) VALUES (?,?,?,?)",
        (c["id"], wd_number, str(rates_file or "manual"), raw),
    )
    wd_id = cur.lastrowid
    n = 0
    if rates_file:
        with open(rates_file, newline="") as f:
            for row in _csv.DictReader(f):
                conn.execute(
                    "INSERT INTO wage_rates (wd_id, classification, base_rate, fringe_rate) VALUES (?,?,?,?)",
                    (wd_id, row["classification"].strip(),
                     float(row["base_rate"]), float(row.get("fringe_rate") or 0)),
                )
                n += 1
    conn.commit()
    ok(f"Wage determination {wd_number} stored for {contract_no} with {n} rates.")
    if not n:
        info(f"Add rates: delzar payroll wd-add-rate {contract_no} --classification 'Laborer: Common' --base 18.25 --fringe 6.10")


@payroll_app.command("wd-add-rate")
def wd_add_rate(contract_no: str, classification: str = typer.Option(...),
                base: float = typer.Option(...), fringe: float = typer.Option(0.0)):
    """Add a single classification rate to the contract's wage determination."""
    conn = connect()
    c = _contract(conn, contract_no)
    wd = conn.execute(
        "SELECT id FROM wage_determinations WHERE contract_id = ? ORDER BY id DESC LIMIT 1",
        (c["id"],)).fetchone()
    if not wd:
        warn(f"No wage determination on file. Run: delzar payroll wd-import {contract_no} --wd-number <WD#>")
        raise typer.Exit(1)
    conn.execute("INSERT INTO wage_rates (wd_id, classification, base_rate, fringe_rate) VALUES (?,?,?,?)",
                 (wd["id"], classification.strip(), base, fringe))
    conn.commit()
    ok(f"Rate stored: {classification} ${base} + ${fringe} fringe")


@payroll_app.command("employee-add")
def employee_add(
    name: str,
    classification: str = typer.Option(..., prompt="Work classification (match the WD wording)"),
    base: float = typer.Option(..., prompt="Base hourly rate ($)"),
    fringe: float = typer.Option(0.0, prompt="Cash fringe per hour ($)"),
    last4: str = typer.Option("", prompt="Last 4 of SSN (for WH-347 column 1, optional)"),
    exemptions: int = typer.Option(0, prompt="Withholding exemptions"),
):
    """Add an employee with default classification and rates."""
    conn = connect()
    conn.execute(
        """INSERT INTO employees (name, default_classification, default_base_rate,
           default_fringe_rate, id_last4, withholding_exemptions) VALUES (?,?,?,?,?,?)""",
        (name, classification, base, fringe, last4 or None, exemptions))
    conn.commit()
    ok(f"Employee {name} added ({classification} ${base}+${fringe}f).")


@payroll_app.command("log")
def payroll_log(contract_no: str, employee: str, work_date: str, hours: float,
                classification: str = typer.Option(None), base: float = typer.Option(None),
                fringe: float = typer.Option(None)):
    """Log hours: delzar payroll log HT75H7-25-P-0123 'Joe Smith' 2026-07-21 8"""
    conn = connect()
    c = _contract(conn, contract_no)
    e = conn.execute("SELECT * FROM employees WHERE name = ?", (employee,)).fetchone()
    if not e:
        warn(f"No employee '{employee}'. Add: delzar payroll employee-add '{employee}'")
        raise typer.Exit(1)
    conn.execute(
        """INSERT INTO time_entries (contract_id, employee_id, work_date, hours,
           classification, base_rate, fringe_rate) VALUES (?,?,?,?,?,?,?)
           ON CONFLICT (contract_id, employee_id, work_date, classification)
           DO UPDATE SET hours = excluded.hours""",
        (c["id"], e["id"], work_date, hours, classification, base, fringe))
    conn.commit()
    ok(f"Logged {hours}h for {employee} on {work_date} ({contract_no}).")


@payroll_app.command("generate")
def payroll_generate(
    contract_no: str,
    week_ending: str = typer.Option(None, help="Saturday YYYY-MM-DD; default = most recent owed week"),
    final: bool = typer.Option(False, "--final", help="Mark as FINAL payroll"),
    signatory: str = typer.Option("", help="Name of person signing the Statement of Compliance"),
):
    """Generate the WH-347 PDF for a week. No hours logged = zero-activity payroll (still required!)."""
    from .comply.payroll import build_payroll, missing_weeks, save_payroll
    from .comply.wh347_pdf import render_wh347
    conn = connect()
    c = _contract(conn, contract_no)

    if week_ending:
        we = date.fromisoformat(week_ending)
        if we.weekday() != 5:
            warn(f"{week_ending} is not a Saturday - payroll weeks end Saturday. Using it anyway.")
    else:
        owed = missing_weeks(conn, c["id"], date.today())
        if not owed:
            ok(f"No payroll weeks owed for {contract_no}. Nothing to generate.")
            raise typer.Exit(0)
        we = owed[0]
        info(f"Generating oldest owed week: week ending {we.isoformat()}")

    result = build_payroll(conn, c["id"], we)

    if result.violations:
        warn("=" * 70)
        warn("WAGE DETERMINATION VIOLATIONS - DO NOT SUBMIT THIS PAYROLL AS-IS")
        for v in result.violations:
            warn(f"  {v.employee_name} ({v.classification}): {v.reason}")
        warn("Underpaying Davis-Bacon wages triggers withholding and can support")
        warn("termination and debarment. Fix the rates, then re-generate.")
        warn("=" * 70)

    pdf = output_dir() / f"WH347-{contract_no.replace('/', '-')}-{we.isoformat()}.pdf"
    result_final = result
    if final:
        result_final.is_final = True  # type: ignore[attr-defined]
    render_wh347(result, dict(c), pdf, signatory_name=signatory)
    save_payroll(conn, result, str(pdf), is_final=final)

    kind = "ZERO-ACTIVITY payroll (no hours logged - still must be submitted)" if result.is_zero_activity \
        else f"payroll with {len(result.lines)} line(s)"
    ok(f"Payroll #{result.payroll_number} ({kind}) for week ending {we.isoformat()}")
    ok(f"PDF: {pdf}")
    for ln in result.lines:
        info(f"  {ln.employee_name}: {ln.explain}")
    remaining = missing_weeks(conn, c["id"], date.today())
    if remaining:
        warn(f"Still owed: {len(remaining)} more week(s): {', '.join(d.isoformat() for d in remaining)}")


@payroll_app.command("status")
def payroll_status():
    """Which payroll weeks are owed on every active contract."""
    from .comply.payroll import missing_weeks
    conn = connect()
    rows = conn.execute("SELECT * FROM contracts WHERE status = 'active'").fetchall()
    if not rows:
        info("No active contracts.")
    for c in rows:
        owed = missing_weeks(conn, c["id"], date.today())
        if owed:
            warn(f"{c['contract_no']}: {len(owed)} week(s) OWED: {', '.join(d.isoformat() for d in owed)}")
        else:
            ok(f"{c['contract_no']}: current.")


@payroll_app.command("sub-expect")
def sub_expect(contract_no: str, subcontractor: str, week_ending: str):
    """Record that a subcontractor owes a payroll for a week."""
    conn = connect()
    c = _contract(conn, contract_no)
    conn.execute(
        """INSERT OR IGNORE INTO sub_payrolls (contract_id, subcontractor, week_ending)
           VALUES (?,?,?)""", (c["id"], subcontractor, week_ending))
    conn.commit()
    ok(f"Expecting {subcontractor} payroll for week ending {week_ending}.")


@payroll_app.command("sub-received")
def sub_received(contract_no: str, subcontractor: str, week_ending: str):
    """Log receipt of a subcontractor's certified payroll."""
    conn = connect()
    c = _contract(conn, contract_no)
    conn.execute(
        """INSERT INTO sub_payrolls (contract_id, subcontractor, week_ending, received_at)
           VALUES (?,?,?,datetime('now'))
           ON CONFLICT (contract_id, subcontractor, week_ending)
           DO UPDATE SET received_at = datetime('now')""",
        (c["id"], subcontractor, week_ending))
    conn.commit()
    ok(f"Received: {subcontractor} week ending {week_ending}.")


# ============================= COMPLY =============================

@comply_app.command("calendar")
def comply_calendar(horizon: int = typer.Option(30, help="Days ahead to show")):
    """All open compliance deadlines, most urgent first."""
    from .comply.calendar_rules import upcoming_alerts
    conn = connect()
    alerts = upcoming_alerts(conn, horizon_days=horizon)
    if not alerts:
        ok("Nothing due. Stay ready.")
        return
    for a in alerts:
        color = {"OVERDUE": typer.colors.RED, "URGENT": typer.colors.YELLOW}.get(a.severity)
        typer.secho(f"[{a.severity:8}] {a.due_date}  {a.title}"
                    + (f"  ({a.contract_no})" if a.contract_no else ""), fg=color, bold=a.severity == "OVERDUE")
        if a.detail:
            info(f"           {a.detail}")


@comply_app.command("done")
def comply_done(rule_key: str, contract_no: str = typer.Option(None)):
    """Mark a compliance event complete, e.g.: delzar comply done payment_protection --contract-no X"""
    conn = connect()
    q = "UPDATE compliance_events SET completed_at = datetime('now') WHERE rule_key = ? AND completed_at IS NULL"
    params: list = [rule_key]
    if contract_no:
        c = _contract(conn, contract_no)
        q += " AND contract_id = ?"
        params.append(c["id"])
    n = conn.execute(q, params).rowcount
    conn.commit()
    ok(f"Marked {n} event(s) '{rule_key}' complete.")


@comply_app.command("dig-date")
def dig_date(locate_request_date: str = typer.Option(None, help="Date you call OKIE811 (default today)")):
    """Earliest lawful dig date after an OKIE811 locate request."""
    from .comply.calendar_rules import earliest_dig_date
    d = date.fromisoformat(locate_request_date) if locate_request_date else date.today()
    r = reg().get("ok811_business_days")
    e = earliest_dig_date(d)
    ok(f"Call OKIE811 (dial 811) on {d.isoformat()} -> earliest dig: {e.isoformat()}")
    info(f"Rule: {int(r.value)} business days ({r.citation}). Around state holidays, call a day early.")


@comply_app.command("thresholds")
def thresholds():
    """Show every regulatory threshold, its citation, and last-verified date."""
    r = reg()
    info(f"Last verified: {r.last_verified}  (update delzar_ops/regulatory.json when re-checked)")
    for t in r.all().values():
        info(f"  {t.key:42} {t.value:>12,.4g}  {t.citation}")
    for k, v in r.policy_notes.items():
        info(f"  NOTE {k}: {v}")


# ============================= BID =============================

def _print_models(models: dict, est, bid_price: Decimal | None = None):
    from .bid.estimator import turnkey_vs_dayrate_delta
    typer.secho(f"\n{'':24}{'BROKER':>14}{'HYBRID':>14}{'SELF-PERFORM':>14}", bold=True)
    rows = [
        ("direct cost", [m.direct_cost for m in models.values()]),
        ("contingency", [m.contingency for m in models.values()]),
        ("overhead", [m.overhead for m in models.values()]),
        ("cost total", [m.cost_total for m in models.values()]),
        ("suggested price", [m.suggested_price for m in models.values()]),
        ("margin @ suggested", [f"{m.margin_at_suggested:.1%}" for m in models.values()]),
    ]
    for label, vals in rows:
        cells = "".join(f"{v:>14,.2f}" if isinstance(v, Decimal) else f"{v:>14}" for v in vals)
        info(f"{label:24}{cells}")
    if bid_price:
        cells = "".join(f"{m.margin_at(bid_price):>14.1%}" for m in models.values())
        info(f"{'margin @ your price':24}{cells}")
        for name, m in models.items():
            if m.below_direct_cost(bid_price):
                warn(f"  BELOW DIRECT COST under the {name.upper()} model "
                     f"(${bid_price:,.2f} < ${m.direct_cost:,.2f}). You would lose cash on every foot.")
    delta = turnkey_vs_dayrate_delta(est)
    typer.secho("\nTHE MARGIN LEVER:", bold=True)
    info(f"  {delta['explain']}")


@bid_app.command("demo")
def bid_demo(export: bool = typer.Option(True, help="Also export the demo quote PDF")):
    """Acceptance demo: price a 200-ft water service line, all three models, quote PDF."""
    from .bid.estimator import demo_estimate, run_models
    from .bid.quote_pdf import render_quote
    est = demo_estimate()
    models = run_models(est)
    typer.secho(f"ESTIMATE: {est.title}", bold=True)
    _print_models(models, est)
    chosen = models["hybrid"]
    price = chosen.suggested_price
    if export:
        pdf = output_dir() / "quote-demo-200ft-water-line.pdf"
        render_quote(est, chosen, price, pdf)
        ok(f"\nQuote PDF (hybrid model @ ${price:,.2f}): {pdf}")
        warn("Reminder: attach the IEE Representation form (HHSAR 352.226-7) to every IHS quote.")


@bid_app.command("template")
def bid_template(path: Path = typer.Argument(Path("estimate.json"))):
    """Write an example estimate JSON you can edit and price with 'delzar bid new'."""
    from dataclasses import asdict
    from .bid.estimator import demo_estimate
    est = demo_estimate()
    d = asdict(est)
    path.write_text(json.dumps(d, indent=2, default=str))
    ok(f"Template written: {path}. Edit quantities/prices, then: delzar bid new --from-file {path}")


@bid_app.command("new")
def bid_new(
    from_file: Path = typer.Option(..., help="Estimate JSON (start from 'delzar bid template')"),
    price: float = typer.Option(None, help="Your intended bid price, to see margin at each model"),
):
    """Price an estimate: three models side by side, stored for win-rate tracking."""
    from .bid.estimator import run_models
    raw = json.loads(from_file.read_text())
    est = _parse_estimate(raw)
    models = run_models(est)
    typer.secho(f"ESTIMATE: {est.title}", bold=True)
    bid_price = Decimal(str(price)) if price else None
    _print_models(models, est, bid_price)

    conn = connect()
    payload = {"input": raw, "models": {
        k: {"direct": str(m.direct_cost), "cost_total": str(m.cost_total),
            "suggested": str(m.suggested_price), "explain": m.explain}
        for k, m in models.items()}}
    cur = conn.execute(
        """INSERT INTO bids (solicitation_no, title, estimate_json, bid_price, total_direct_cost)
           VALUES (?,?,?,?,?)""",
        (est.solicitation_no, est.title, json.dumps(payload),
         float(bid_price) if bid_price else None,
         float(min(m.direct_cost for m in models.values()))))
    conn.commit()
    ok(f"\nStored as bid #{cur.lastrowid}. Record the result later: "
       f"delzar bid outcome {cur.lastrowid} won|lost --winning-price N")


@bid_app.command("quote")
def bid_quote(
    bid_id: int,
    model: str = typer.Option("hybrid", help="broker | hybrid | self"),
    price: float = typer.Option(..., help="Firm fixed price for the quote"),
    delivery_days: int = typer.Option(30),
):
    """Export the submittable quote PDF for a stored bid."""
    from .bid.estimator import run_models
    from .bid.quote_pdf import render_quote
    conn = connect()
    row = conn.execute("SELECT * FROM bids WHERE id = ?", (bid_id,)).fetchone()
    if not row:
        warn(f"No bid #{bid_id}.")
        raise typer.Exit(1)
    raw = json.loads(row["estimate_json"])["input"]
    est = _parse_estimate(raw)
    models = run_models(est)
    if model not in models:
        warn("model must be broker, hybrid, or self")
        raise typer.Exit(1)
    m = models[model]
    p = Decimal(str(price))
    if m.below_direct_cost(p):
        warn(f"Price ${p:,.2f} is BELOW direct cost ${m.direct_cost:,.2f} for the {model} model. Not exporting.")
        raise typer.Exit(1)
    pdf = output_dir() / f"quote-{(est.solicitation_no or bid_id)}.pdf"
    render_quote(est, m, p, pdf, delivery_days=delivery_days)
    conn.execute("UPDATE bids SET model_chosen = ?, bid_price = ? WHERE id = ?", (model, float(p), bid_id))
    conn.commit()
    ok(f"Quote PDF: {pdf} ({model} model @ ${p:,.2f}, margin {m.margin_at(p):.1%})")
    warn("Attach the IEE Representation form (HHSAR 352.226-7). Do NOT offer a prompt payment discount.")


def _parse_estimate(raw: dict):
    """Shared estimate-JSON parser (same shape as 'delzar bid template')."""
    from .bid.estimator import EquipmentItem, EstimateInput, LaborItem, LineItem
    D_ = Decimal
    return EstimateInput(
        title=raw["title"], solicitation_no=raw.get("solicitation_no", ""),
        materials=[LineItem(m["description"], D_(str(m["qty"])), m["unit"], D_(str(m["unit_cost"])))
                   for m in raw.get("materials", [])],
        labor=[LaborItem(l["classification"], D_(str(l["hours"])), D_(str(l["base_rate"])), D_(str(l["fringe_rate"])))
               for l in raw.get("labor", [])],
        equipment=[EquipmentItem(e["name"], D_(str(e["day_rate"])), D_(str(e["days"])), e.get("owned", False))
                   for e in raw.get("equipment", [])],
        sub_turnkey_price=D_(str(raw.get("sub_turnkey_price", 0))),
        sub_day_rate=D_(str(raw.get("sub_day_rate", 0))),
        sub_days=D_(str(raw.get("sub_days", 0))),
        mobilization_miles=D_(str(raw.get("mobilization_miles", 0))),
        mobilization_rate=D_(str(raw.get("mobilization_rate", "2.50"))),
        mobilization_trips=D_(str(raw.get("mobilization_trips", 1))),
        permits_fees=[LineItem(p["description"], D_(str(p["qty"])), p["unit"], D_(str(p["unit_cost"])))
                      for p in raw.get("permits_fees", [])],
        payment_protection_cost=D_(str(raw.get("payment_protection_cost", 0))),
        contingency_pct=D_(str(raw.get("contingency_pct", "0.10"))),
        overhead_pct=D_(str(raw.get("overhead_pct", "0.10"))),
        profit_pct=D_(str(raw.get("profit_pct", "0.10"))),
    )


@bid_app.command("outcome")
def bid_outcome(bid_id: int, outcome: str, winning_price: float = typer.Option(None)):
    """Record won/lost and (if known) the winning price."""
    if outcome not in ("won", "lost", "no_bid"):
        warn("outcome must be won, lost, or no_bid")
        raise typer.Exit(1)
    conn = connect()
    conn.execute("UPDATE bids SET outcome = ?, winning_price = ? WHERE id = ?",
                 (outcome, winning_price, bid_id))
    conn.commit()
    ok(f"Bid #{bid_id}: {outcome}" + (f", winner at ${winning_price:,.2f}" if winning_price else ""))


@bid_app.command("stats")
def bid_stats():
    """Win rate and average delta from the winner (needs 5+ decided bids)."""
    from .bid.estimator import win_rate_report
    conn = connect()
    bids = [dict(r) for r in conn.execute("SELECT * FROM bids")]
    rep = win_rate_report(bids)
    if not rep:
        info(f"Only {len([b for b in bids if b['outcome'] in ('won', 'lost')])} decided bid(s); "
             "stats unlock at 5. Keep recording outcomes.")
        return
    ok(f"Decided: {rep['decided']}  Won: {rep['won']}  Win rate: {rep['win_rate']:.0%}")
    if rep["avg_delta_from_winner"] is not None:
        info(f"On losses, you averaged {rep['avg_delta_from_winner']:+.1%} vs the winning price.")


@bid_app.command("materials")
def bid_materials():
    """Show the maintained materials price list."""
    conn = connect()
    for r in conn.execute("SELECT * FROM materials_prices ORDER BY item"):
        info(f"  {r['item']:45} {r['unit']:4} ${r['unit_cost']:>9,.2f}  ({r['source'] or ''}, {r['updated_at'][:10]})")


@bid_app.command("materials-set")
def bid_materials_set(item: str, unit_cost: float, unit: str = typer.Option(None), source: str = typer.Option("manual update")):
    """Update (or add) a materials price."""
    conn = connect()
    existing = conn.execute("SELECT * FROM materials_prices WHERE item = ?", (item,)).fetchone()
    conn.execute(
        """INSERT INTO materials_prices (item, unit, unit_cost, source) VALUES (?,?,?,?)
           ON CONFLICT (item) DO UPDATE SET unit_cost = excluded.unit_cost,
             unit = COALESCE(?, materials_prices.unit), source = excluded.source,
             updated_at = datetime('now')""",
        (item, unit or (existing["unit"] if existing else "EA"), unit_cost, source, unit))
    conn.commit()
    ok(f"{item}: ${unit_cost:,.2f}")


# ============================= WATCH =============================

@watch_app.command("poll")
def watch_poll(days_back: int = typer.Option(3, help="How many posted-days to sweep")):
    """Poll SAM.gov, dedupe, detect amendments, rescore, write the digest."""
    from .watch.notify import build_digest_text, desktop_notify, write_digest
    from .watch.sam_adapter import SamKeyMissing, fetch_opportunities, upsert_opportunities
    from .watch.scoring import ranked_digest, rescore_all
    conn = connect()
    try:
        opps = fetch_opportunities(days_back=days_back)
    except SamKeyMissing as e:
        warn(str(e))
        raise typer.Exit(1)
    except Exception as e:
        warn(f"SAM.gov fetch failed ({e}). Yesterday's data is still in the database; "
             "run 'delzar watch digest' to see it. Try again later.")
        raise typer.Exit(1)
    stats = upsert_opportunities(conn, opps)
    rescore_all(conn)
    ranked = ranked_digest(conn)
    text = build_digest_text(ranked, stats)
    p = write_digest(text)
    ok(f"Poll done: {stats}. Digest: {p}")
    if stats["new"] or stats["amended"]:
        desktop_notify("DELZAR OPS", f"{stats['new']} new, {stats['amended']} amended solicitations")
    typer.echo(text)


@watch_app.command("digest")
def watch_digest(limit: int = 15):
    """Ranked digest from stored opportunities (works offline)."""
    from .watch.notify import build_digest_text
    from .watch.scoring import ranked_digest, rescore_all
    conn = connect()
    rescore_all(conn)
    typer.echo(build_digest_text(ranked_digest(conn, limit)))


@watch_app.command("why")
def watch_why(notice_id: str):
    """Show the full score breakdown for one opportunity."""
    conn = connect()
    r = conn.execute("SELECT * FROM opportunities WHERE notice_id = ? OR solicitation_no = ?",
                     (notice_id, notice_id)).fetchone()
    if not r:
        warn("Not found.")
        raise typer.Exit(1)
    info(f"{r['title']}  [score {r['score']}]")
    if r["piid_type"]:
        info(f"Instrument: {r['piid_type']}")
    for k, v in json.loads(r["score_breakdown"] or "{}").items():
        info(f"  {k}: {v}")


@watch_app.command("piid")
def watch_piid(piid: str):
    """Decode a contract number's instrument type (position 9)."""
    from .watch.piid import decode_piid
    d = decode_piid(piid)
    info(f"{piid} -> [{d['type_code']}] {d['instrument']}")
    if d["channel_note"]:
        typer.secho(f"  {d['channel_note']}", fg=typer.colors.YELLOW)


@watch_app.command("daemon")
def watch_daemon(hour: int = 6, minute: int = 30):
    """Run the daily poll on a schedule (keep this terminal open)."""
    from apscheduler.schedulers.blocking import BlockingScheduler

    def _run_poll():
        try:
            watch_poll(days_back=3)
        except typer.Exit:
            pass  # fetch failure already reported; try again tomorrow

    sched = BlockingScheduler()
    sched.add_job(_run_poll, "cron", hour=hour, minute=minute)
    ok(f"Polling SAM.gov daily at {hour:02d}:{minute:02d}. Ctrl-C to stop.")
    try:
        sched.start()
    except (KeyboardInterrupt, SystemExit):
        info("Stopped.")


# ============================= CASH =============================

@cash_app.command("set-balance")
def cash_set_balance(amount: float):
    """Set current cash on hand."""
    from .cash.forecast import set_cash_on_hand
    conn = connect()
    set_cash_on_hand(conn, Decimal(str(amount)))
    ok(f"Cash on hand: ${amount:,.2f}")


@cash_app.command("invoice-add")
def cash_invoice_add(contract_no: str, amount: float,
                     invoiced_date: str = typer.Option(..., prompt="Invoice date (YYYY-MM-DD)"),
                     invoice_no: str = typer.Option(None),
                     expected_date: str = typer.Option(None, help="Default: invoiced + 30 days")):
    """Record an invoice to the government."""
    conn = connect()
    c = _contract(conn, contract_no)
    exp = expected_date or (date.fromisoformat(invoiced_date) + timedelta(days=30)).isoformat()
    conn.execute(
        "INSERT INTO receivables (contract_id, invoice_no, amount, invoiced_date, expected_date) VALUES (?,?,?,?,?)",
        (c["id"], invoice_no, amount, invoiced_date, exp))
    conn.commit()
    ok(f"Invoice ${amount:,.2f} recorded; payment expected {exp}.")


@cash_app.command("invoice-paid")
def cash_invoice_paid(invoice_id: int, paid_date: str = typer.Option(None)):
    """Mark a receivable paid."""
    conn = connect()
    conn.execute("UPDATE receivables SET paid_date = ? WHERE id = ?",
                 (paid_date or date.today().isoformat(), invoice_id))
    conn.commit()
    ok(f"Receivable #{invoice_id} marked paid.")


@cash_app.command("outflow-add")
def cash_outflow_add(category: str, amount: float, due_date: str,
                     contract_no: str = typer.Option(None), desc: str = typer.Option("")):
    """Record a planned/unpaid outflow: materials, subcontractor, equipment, overhead, other."""
    conn = connect()
    cid = _contract(conn, contract_no)["id"] if contract_no else None
    conn.execute(
        "INSERT INTO outflows (contract_id, category, description, amount, due_date) VALUES (?,?,?,?,?)",
        (cid, category, desc, amount, due_date))
    conn.commit()
    ok(f"Outflow ${amount:,.2f} ({category}) due {due_date} recorded.")


@cash_app.command("outflow-paid")
def cash_outflow_paid(outflow_id: int, paid_date: str = typer.Option(None)):
    conn = connect()
    conn.execute("UPDATE outflows SET paid_date = ? WHERE id = ?",
                 (paid_date or date.today().isoformat(), outflow_id))
    conn.commit()
    ok(f"Outflow #{outflow_id} marked paid.")


@cash_app.command("aging")
def cash_aging():
    """Outstanding receivables by age bucket."""
    from .cash.forecast import receivables_aging
    conn = connect()
    rows = receivables_aging(conn)
    if not rows:
        info("No open receivables.")
        return
    total = sum(r["amount"] for r in rows)
    for r in rows:
        flag = "" if r["bucket"] == "0-30" else "  <-- FOLLOW UP"
        info(f"  {r['contract_no'] or '?':22} {r['invoice_no'] or '-':12} "
             f"${r['amount']:>10,.2f}  {r['age_days']:>3}d [{r['bucket']}]{flag}")
    info(f"  TOTAL OUTSTANDING: ${total:,.2f}")


@cash_app.command("project")
def cash_project(weeks: int = 13):
    """90-day forward cash projection, week by week."""
    from .cash.forecast import get_cash_on_hand, lowest_point, project_cash
    conn = connect()
    proj = project_cash(conn, weeks=weeks)
    info(f"Starting cash: ${get_cash_on_hand(conn):,.2f}")
    for p in proj:
        marker = "  <-- NEGATIVE" if p.ending_cash < 0 else ""
        info(f"  wk {p.week_start}  in ${p.inflows:>10,.2f}  out ${p.outflows:>10,.2f}  "
             f"end ${p.ending_cash:>11,.2f}{marker}")
        for e in p.events:
            info(f"      {e}")
    d, c = lowest_point(proj)
    (warn if c < 0 else ok)(f"Low point: ${c:,.2f} in week of {d}")


@cash_app.command("instrument-add")
def cash_instrument_add(contract_no: str, instrument_type: str, amount: float,
                        issued_date: str = typer.Option(None)):
    """Track a payment protection instrument (they STACK across contracts)."""
    from .cash.forecast import instruments_outstanding
    conn = connect()
    c = _contract(conn, contract_no)
    conn.execute(
        "INSERT INTO payment_instruments (contract_id, instrument_type, amount, issued_date) VALUES (?,?,?,?)",
        (c["id"], instrument_type, amount, issued_date or date.today().isoformat()))
    conn.commit()
    total = instruments_outstanding(conn)
    ok(f"Instrument recorded. TOTAL outstanding across all contracts: ${total:,.2f}")
    info("Five concurrent $20k jobs = $100k of instruments simultaneously. Watch this number.")


@cash_app.command("instrument-release")
def cash_instrument_release(instrument_id: int, released_date: str = typer.Option(None)):
    conn = connect()
    conn.execute("UPDATE payment_instruments SET released_date = ? WHERE id = ?",
                 (released_date or date.today().isoformat(), instrument_id))
    conn.commit()
    ok(f"Instrument #{instrument_id} released.")


@cash_app.command("gate")
def cash_gate(description: str, amount: float,
              early_outflow: float = typer.Option(0, help="Cash you must spend before the government pays")):
    """Go/no-go gate: required before accepting any award over $50,000."""
    from .cash.forecast import GATE_QUESTIONS, GATE_THRESHOLD, gate_decision, working_capital_check
    conn = connect()
    amt = Decimal(str(amount))
    if amt < GATE_THRESHOLD:
        info(f"Under ${GATE_THRESHOLD:,.0f} - gate optional, but answering keeps you honest.")
    if early_outflow:
        wc = working_capital_check(conn, Decimal(str(early_outflow)))
        (ok if wc["ok"] else warn)(wc["explain"])
    answers = {}
    for key, q in GATE_QUESTIONS:
        answers[key] = typer.confirm(q)
    result = gate_decision(conn, description, amt, answers)
    if result["recommendation"] == "accept":
        ok(f"GATE: four yeses. Recommendation: ACCEPT. Decision logged.")
    else:
        warn("GATE RECOMMENDS DECLINING. Failed checks:")
        for f in result["failed"]:
            warn(f"  - {f}")
        warn("Decision logged. Overriding a failed gate is how contractors die - "
             "fix the failed item first or pass on this one.")


@cash_app.command("factoring")
def cash_factoring(invoice_amount: float, advance_rate: float = 0.85,
                   fee_pct: float = 0.03, days_early: int = 25):
    """Model factoring an invoice: advance, fee, net, effective APR."""
    from .cash.forecast import factoring_model
    m = factoring_model(Decimal(str(invoice_amount)), Decimal(str(advance_rate)),
                        Decimal(str(fee_pct)), days_early)
    info(m["explain"])


@cash_app.command("discount")
def cash_discount(pct: float = 0.02, discount_days: int = 10, net_days: int = 30):
    """Annualized value of taking a supplier's early-payment discount (default 2/10 net 30)."""
    from .cash.forecast import discount_annualized
    m = discount_annualized(Decimal(str(pct)), discount_days, net_days)
    info(m["explain"])
    warn("This is about SUPPLIER terms you TAKE. Never OFFER the government a prompt "
         "payment discount - not evaluated at this office, pure margin giveaway.")


# ============================= INTEL =============================

@intel_app.command("grid")
def intel_grid():
    """The BPA holder grid: field office x service type."""
    from .intel.tracker import bpa_grid
    conn = connect()
    grid = bpa_grid(conn)
    if not grid:
        info("Grid empty. Seed it: delzar init --seed, then edit delzar_ops/seed/data/bpa_grid.csv")
    for office, services in grid.items():
        typer.secho(office, bold=True)
        for svc, holders in services.items():
            info(f"  {svc}: {', '.join(holders)}")


@intel_app.command("waves")
def intel_waves():
    """BPA establishment waves and the predicted next window."""
    from .intel.tracker import wave_analysis
    conn = connect()
    w = wave_analysis(conn)
    if not w:
        info("Not enough establishment dates on record. Fill bpa_grid.csv and re-seed.")
        return
    for i, wave in enumerate(w["waves"], 1):
        info(f"  wave {i}: {wave[0]} .. {wave[-1]} ({len(wave)} holders)")
    if w.get("predicted_next"):
        ok(f"Predicted next wave: ~{w['predicted_next']} (window {w['window']}, "
           f"avg gap {w['avg_gap_days']}d)")
        info(w["note"])


@intel_app.command("recompetes")
def intel_recompetes():
    """Known BPA expirations, soonest first."""
    from .intel.tracker import recompete_calendar
    conn = connect()
    rows = recompete_calendar(conn)
    if not rows:
        info("No expiration dates on record.")
    for r in rows:
        info(f"  {r['expires']} ({r['days_out']:>4}d)  {r['holder']} - {r['field_office']} / {r['service_type']}")


@intel_app.command("thin-cells")
def intel_thin_cells():
    """Categories with the fewest average bidders = best odds."""
    from .intel.tracker import thin_cells
    conn = connect()
    rows = thin_cells(conn)
    if not rows:
        info("No award/bid-count data yet. Record with: delzar intel award-add")
    for r in rows:
        info(f"  {r['category']:30} awards {r['awards']:>3}  avg bidders {r['avg_bids']}")


@intel_app.command("competitors")
def intel_competitors():
    conn = connect()
    for r in conn.execute("SELECT * FROM competitors ORDER BY name"):
        n = conn.execute("SELECT COUNT(*) AS n FROM competitor_awards WHERE competitor_id = ?",
                         (r["id"],)).fetchone()["n"]
        info(f"  {r['name']:50} {r['location'] or '':20} awards on file: {n}")


@intel_app.command("award-add")
def intel_award_add(competitor: str, piid: str = typer.Option(None), amount: float = typer.Option(None),
                    award_date: str = typer.Option(None), category: str = typer.Option(None),
                    bid_count: int = typer.Option(None), description: str = typer.Option("")):
    """Record a competitor award (with bid count if known - feeds thin-cell analysis)."""
    from .watch.piid import decode_piid
    conn = connect()
    comp = conn.execute("SELECT * FROM competitors WHERE name = ?", (competitor,)).fetchone()
    if not comp:
        conn.execute("INSERT INTO competitors (name) VALUES (?)", (competitor,))
        comp = conn.execute("SELECT * FROM competitors WHERE name = ?", (competitor,)).fetchone()
    ptype = decode_piid(piid)["type_code"] if piid else None
    conn.execute(
        """INSERT INTO competitor_awards (competitor_id, piid, piid_type, amount,
           award_date, category, bid_count, description) VALUES (?,?,?,?,?,?,?,?)""",
        (comp["id"], piid, ptype, amount, award_date, category, bid_count, description))
    conn.commit()
    ok(f"Award recorded for {competitor}" + (f" [{ptype}]" if ptype else ""))


@intel_app.command("awards-pull")
def intel_awards_pull(competitor: str, naics: str = typer.Option("237110")):
    """Pull a competitor's recent awards from USAspending.gov (no key needed)."""
    from .watch.usaspending import search_awards_by_recipient
    try:
        awards = search_awards_by_recipient(competitor, naics=naics)
    except Exception as e:
        warn(f"USAspending fetch failed ({e}). Try again later.")
        raise typer.Exit(1)
    if not awards:
        info("No awards found for that name/NAICS.")
        return
    for a in awards:
        info(f"  {a['start_date']}  {(a['piid'] or '?'):<18}  ${a['amount'] or 0:>12,.0f}  "
             f"{a['sub_agency'] or a['agency'] or ''}")
        if a["description"]:
            info(f"      {a['description'][:90]}")


if __name__ == "__main__":
    app()
