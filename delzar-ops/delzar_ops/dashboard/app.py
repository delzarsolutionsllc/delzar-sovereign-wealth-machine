"""Read-only local dashboard: FastAPI + Jinja. No auth (single operator,
localhost only). Shows the same data the CLI shows, at a glance."""
from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader

from ..db import connect

TEMPLATES = Path(__file__).parent / "templates"


def create_app() -> FastAPI:
    app = FastAPI(title="DELZAR OPS")
    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=True)

    def render(name: str, **ctx) -> HTMLResponse:
        ctx.setdefault("today", date.today().isoformat())
        ctx.setdefault("active", name.removesuffix(".html"))
        return HTMLResponse(env.get_template(name).render(**ctx))

    @app.get("/", response_class=HTMLResponse)
    def home():
        from ..comply.calendar_rules import upcoming_alerts
        from ..cash.forecast import get_cash_on_hand, instruments_outstanding, lowest_point, project_cash
        conn = connect()
        alerts = upcoming_alerts(conn)
        contracts = conn.execute("SELECT * FROM contracts WHERE status = 'active'").fetchall()
        proj = project_cash(conn)
        low_d, low_c = lowest_point(proj)
        opps = conn.execute(
            "SELECT * FROM opportunities WHERE archived = 0 ORDER BY score DESC LIMIT 10"
        ).fetchall()
        return render(
            "home.html",
            alerts=alerts,
            contracts=[dict(c) for c in contracts],
            cash=get_cash_on_hand(conn),
            low_point=(low_d, low_c),
            instruments=instruments_outstanding(conn),
            opportunities=[dict(o) for o in opps],
        )

    @app.get("/payroll", response_class=HTMLResponse)
    def payroll():
        from ..comply.payroll import missing_weeks
        conn = connect()
        contracts = []
        for c in conn.execute("SELECT * FROM contracts ORDER BY status, contract_no"):
            owed = missing_weeks(conn, c["id"], date.today()) if c["status"] == "active" else []
            payrolls = conn.execute(
                "SELECT * FROM payrolls WHERE contract_id = ? ORDER BY week_ending DESC", (c["id"],)
            ).fetchall()
            contracts.append({"c": dict(c), "owed": owed, "payrolls": [dict(p) for p in payrolls]})
        return render("payroll.html", contracts=contracts)

    @app.get("/bids", response_class=HTMLResponse)
    def bids():
        conn = connect()
        rows = [dict(r) for r in conn.execute("SELECT * FROM bids ORDER BY created_at DESC")]
        from ..bid.estimator import win_rate_report
        return render("bids.html", bids=rows, stats=win_rate_report(rows))

    @app.get("/cash", response_class=HTMLResponse)
    def cash():
        from ..cash.forecast import get_cash_on_hand, project_cash, receivables_aging
        conn = connect()
        return render(
            "cash.html",
            cash=get_cash_on_hand(conn),
            aging=receivables_aging(conn),
            projections=project_cash(conn),
        )

    @app.get("/intel", response_class=HTMLResponse)
    def intel():
        from ..intel.tracker import bpa_grid, recompete_calendar, thin_cells, wave_analysis
        conn = connect()
        return render(
            "intel.html",
            grid=bpa_grid(conn),
            waves=wave_analysis(conn),
            recompetes=recompete_calendar(conn),
            cells=thin_cells(conn),
        )

    @app.get("/opportunity/{notice_id}", response_class=HTMLResponse)
    def opportunity(notice_id: str):
        conn = connect()
        r = conn.execute("SELECT * FROM opportunities WHERE notice_id = ?", (notice_id,)).fetchone()
        breakdown = json.loads(r["score_breakdown"]) if r and r["score_breakdown"] else {}
        return render("opportunity.html", o=dict(r) if r else None, breakdown=breakdown)

    return app
