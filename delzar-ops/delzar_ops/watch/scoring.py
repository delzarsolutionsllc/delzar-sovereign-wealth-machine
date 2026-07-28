"""Opportunity scoring: rank by fit for Delzar Solutions, Tulsa 74129.

Score 0-100, weighted:
  40  distance from Tulsa (this business lives or dies on drive time)
  25  set-aside eligibility (ISBEE/IEE best; SDVOSB/WOSB = INELIGIBLE)
  15  dollar band fit (sweet spot $1,700-$22,000; workable to $150k pre-bonding)
  10  days until deadline (enough time to quote)
  10  scope licensing fit (NAICS on the watch list = licensed scope)

Every score stores a JSON breakdown - the operator can always see WHY
something ranked where it did.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import date, datetime
from decimal import Decimal

from .piid import decode_piid

# Road-mile distances from Tulsa 74129 to recurring places of performance.
# Rough highway miles; unknown places fall back by state.
CITY_MILES: dict[str, int] = {
    "tulsa": 5, "sand springs": 15, "sapulpa": 18, "claremore": 28,
    "okmulgee": 40, "muskogee": 50, "tahlequah": 66, "bartlesville": 47,
    "vinita": 60, "salina": 60, "jay": 75, "miami": 90, "stilwell": 85,
    "sallisaw": 95, "wagoner": 45, "pryor": 44, "nowata": 45,
    "pawhuska": 60, "hominy": 40, "cleveland": 35, "stillwater": 65,
    "oklahoma city": 105, "el reno": 130, "shawnee": 95, "ada": 125,
    "anadarko": 150, "lawton": 190, "clinton": 175, "watonga": 150,
    "pawnee": 55, "perkins": 75, "wewoka": 100, "holdenville": 110,
    "mcalester": 90, "talihina": 130, "poteau": 115, "hugo": 175,
    "durant": 155, "ardmore": 175, "tishomingo": 150, "enid": 115,
    "ponca city": 75, "white eagle": 80, "elgin": 180, "carnegie": 165,
    "wichita": 175, "kansas city": 250, "topeka": 215, "lawrence": 230,
    "holton": 240, "horton": 245, "mayetta": 225, "haskell": 230,
}
STATE_FALLBACK_MILES = {"OK": 160, "KS": 240}
OUT_OF_REGION_MILES = 320

# Set-aside eligibility for a Cherokee Nation citizen-owned small business
SET_ASIDE_SCORES: dict[str, tuple[int, str]] = {
    "ISBEE": (25, "Indian Small Business Economic Enterprise - best lane"),
    "IEE": (25, "Indian Economic Enterprise - best lane"),
    "BICiv": (25, "Buy Indian - best lane"),
    "SBA": (18, "Total small business set-aside - eligible"),
    "SBP": (18, "Partial small business - eligible"),
    "NONE": (12, "Unrestricted - eligible but open competition"),
    "8A": (0, "8(a) - NOT currently certified; INELIGIBLE unless certified"),
    "8AN": (0, "8(a) sole source - INELIGIBLE"),
    "HZC": (0, "HUBZone - INELIGIBLE unless certified"),
    "SDVOSBC": (0, "SDVOSB - INELIGIBLE"),
    "SDVOSBS": (0, "SDVOSB sole source - INELIGIBLE"),
    "VSA": (0, "Veteran-owned - INELIGIBLE"),
    "WOSB": (0, "WOSB - INELIGIBLE"),
    "EDWOSB": (0, "EDWOSB - INELIGIBLE"),
}

LICENSED_NAICS = {"237110", "238910", "238110", "221310"}


def distance_miles(city: str | None, state: str | None) -> tuple[int, str]:
    key = (city or "").strip().lower()
    if key in CITY_MILES:
        return CITY_MILES[key], f"known city {city}"
    st = (state or "").strip().upper()
    if st in STATE_FALLBACK_MILES:
        return STATE_FALLBACK_MILES[st], f"unknown city in {st}, state fallback"
    return OUT_OF_REGION_MILES, "outside OK/KS"


def _distance_points(miles: int) -> float:
    # 40 pts at 0 mi, linear to 0 pts at 320 mi
    return max(0.0, 40.0 * (1 - miles / 320))


def _dollar_points(amount: Decimal | None) -> tuple[float, str]:
    if amount is None:
        return 8.0, "value unknown - neutral 8/15"
    a = float(amount)
    if 1700 <= a <= 22000:
        return 15.0, "in the sweet spot ($1.7k-$22k)"
    if a < 1700:
        return 6.0, "below sweet spot - may not cover mobilization"
    if a <= 150000:
        return 10.0, "workable, under Miller Act bonding threshold"
    return 3.0, "above bonding threshold - bonding required"


def _deadline_points(deadline: str | None, as_of: date) -> tuple[float, str]:
    if not deadline:
        return 5.0, "no deadline given - neutral 5/10"
    try:
        d = datetime.fromisoformat(deadline.replace("Z", "+00:00")).date()
    except ValueError:
        try:
            d = date.fromisoformat(deadline[:10])
        except ValueError:
            return 5.0, "unparseable deadline - neutral"
    days = (d - as_of).days
    if days < 0:
        return 0.0, f"deadline passed {-days}d ago"
    if days <= 2:
        return 3.0, f"only {days}d left - tight"
    if days <= 14:
        return 10.0, f"{days}d left - normal window"
    return 8.0, f"{days}d left - plenty of time"


def score_opportunity(opp: dict, as_of: date | None = None,
                      estimated_value: Decimal | None = None) -> tuple[float, dict]:
    """Returns (score, breakdown). opp uses the normalized/DB column names."""
    as_of = as_of or date.today()
    breakdown = {}

    miles, why = distance_miles(opp.get("place_city"), opp.get("place_state"))
    dp = round(_distance_points(miles), 1)
    breakdown["distance"] = {"points": dp, "max": 40, "miles": miles, "why": why}

    sa_raw = (opp.get("set_aside") or "NONE").strip()
    sa_points, sa_why = SET_ASIDE_SCORES.get(sa_raw, (10, f"unrecognized set-aside '{sa_raw}' - verify manually"))
    breakdown["set_aside"] = {"points": sa_points, "max": 25, "code": sa_raw, "why": sa_why}
    ineligible = sa_points == 0

    dollar_pts, dollar_why = _dollar_points(estimated_value)
    breakdown["dollar_band"] = {"points": dollar_pts, "max": 15, "why": dollar_why}

    dl_pts, dl_why = _deadline_points(opp.get("response_deadline"), as_of)
    breakdown["deadline"] = {"points": dl_pts, "max": 10, "why": dl_why}

    naics = (opp.get("naics") or "").strip()
    lic_pts = 10.0 if naics in LICENSED_NAICS else 3.0
    breakdown["licensing"] = {
        "points": lic_pts, "max": 10,
        "why": "watched NAICS - in-scope" if lic_pts == 10 else f"NAICS {naics} outside core scope - verify licensing",
    }

    total = dp + sa_points + dollar_pts + dl_pts + lic_pts
    if ineligible:
        total = min(total, 10.0)  # hard cap: never rank an ineligible job high
        breakdown["ineligible_cap"] = {"why": "set-aside makes this INELIGIBLE - capped at 10"}
    return round(total, 1), breakdown


def rescore_all(conn: sqlite3.Connection, as_of: date | None = None) -> int:
    n = 0
    for row in conn.execute("SELECT * FROM opportunities WHERE archived = 0"):
        opp = dict(row)
        score, breakdown = score_opportunity(opp, as_of)
        piid = decode_piid(opp.get("solicitation_no") or "")
        conn.execute(
            "UPDATE opportunities SET score = ?, score_breakdown = ?, piid_type = ? WHERE id = ?",
            (score, json.dumps(breakdown),
             f"{piid['type_code']}: {piid['instrument']}" if piid["type_code"] else None,
             row["id"]),
        )
        n += 1
    conn.commit()
    return n


def ranked_digest(conn: sqlite3.Connection, limit: int = 15) -> list[dict]:
    rows = conn.execute(
        """SELECT * FROM opportunities WHERE archived = 0
           ORDER BY score DESC, response_deadline ASC LIMIT ?""",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]
