"""INTEL: surface changes, not analysis. Deliberately minimal.

- competitor list + award history
- BPA holder grid by field office x service type
- BPA establishment wave analysis -> predicted next window
- recompete calendar from expiration dates
- bid-count distribution -> thin cells worth targeting
"""
from __future__ import annotations

import sqlite3
from datetime import date, timedelta
from statistics import mean


def wave_analysis(conn: sqlite3.Connection) -> dict | None:
    """Group BPA establishment dates into waves (gaps > 45 days start a
    new wave) and predict the next window from the mean inter-wave gap."""
    dates = sorted(
        date.fromisoformat(r["established_date"])
        for r in conn.execute(
            "SELECT established_date FROM bpa_holders WHERE established_date IS NOT NULL"
        )
    )
    if len(dates) < 2:
        return None
    waves: list[list[date]] = [[dates[0]]]
    for d in dates[1:]:
        if (d - waves[-1][-1]).days > 45:
            waves.append([d])
        else:
            waves[-1].append(d)
    starts = [w[0] for w in waves]
    if len(starts) < 2:
        return {"waves": [[d.isoformat() for d in w] for w in waves],
                "predicted_next": None,
                "note": "Only one wave on record - need more history to predict."}
    gaps = [(starts[i + 1] - starts[i]).days for i in range(len(starts) - 1)]
    avg_gap = int(mean(gaps))
    predicted = starts[-1] + timedelta(days=avg_gap)
    return {
        "waves": [[d.isoformat() for d in w] for w in waves],
        "wave_count": len(waves),
        "avg_gap_days": avg_gap,
        "last_wave": starts[-1].isoformat(),
        "predicted_next": predicted.isoformat(),
        "window": f"{(predicted - timedelta(days=30)).isoformat()} to {(predicted + timedelta(days=30)).isoformat()}",
        "note": "Watch for BPA RFQs in the predicted window; get on the next wave.",
    }


def recompete_calendar(conn: sqlite3.Connection, as_of: date | None = None) -> list[dict]:
    as_of = as_of or date.today()
    out = []
    for r in conn.execute(
        """SELECT holder, field_office, service_type, bpa_piid, expiration_date
           FROM bpa_holders WHERE expiration_date IS NOT NULL ORDER BY expiration_date"""
    ):
        exp = date.fromisoformat(r["expiration_date"])
        out.append({
            "holder": r["holder"], "field_office": r["field_office"],
            "service_type": r["service_type"], "piid": r["bpa_piid"],
            "expires": r["expiration_date"], "days_out": (exp - as_of).days,
        })
    return out


def thin_cells(conn: sqlite3.Connection) -> list[dict]:
    """Categories with few known bidders = best odds. Uses recorded
    bid counts from competitor awards, grouped by category."""
    rows = conn.execute(
        """SELECT category, COUNT(*) AS awards, AVG(bid_count) AS avg_bids
           FROM competitor_awards WHERE category IS NOT NULL
           GROUP BY category ORDER BY avg_bids ASC"""
    ).fetchall()
    return [
        {"category": r["category"], "awards": r["awards"],
         "avg_bids": round(r["avg_bids"], 1) if r["avg_bids"] is not None else None}
        for r in rows
    ]


def bpa_grid(conn: sqlite3.Connection) -> dict:
    """The grid: field offices x service types -> holders."""
    grid: dict[str, dict[str, list[str]]] = {}
    for r in conn.execute(
        "SELECT holder, field_office, service_type FROM bpa_holders ORDER BY field_office, service_type"
    ):
        grid.setdefault(r["field_office"], {}).setdefault(r["service_type"], []).append(r["holder"])
    return grid
