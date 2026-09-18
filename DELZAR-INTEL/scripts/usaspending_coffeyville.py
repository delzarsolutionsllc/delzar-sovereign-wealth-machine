#!/usr/bin/env python3
"""Multi-query USAspending pull for Coffeyville, KS and surrounding counties.

USAspending is award/obligation history, not a live SAM bid board.
Run: python3 usaspending_coffeyville.py
"""
from __future__ import annotations

import csv
import json
import time
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

API = "https://api.usaspending.gov"
OUT = Path(__file__).resolve().parent.parent / "outputs" / "coffeyville-usaspending"
OUT.mkdir(parents=True, exist_ok=True)

TODAY = date.today().isoformat()
TIME_PERIOD = [{"start_date": "2022-10-01", "end_date": TODAY}]

POP_LOCS = [
    {"country": "USA", "state": "KS", "city": "Coffeyville"},
    {"country": "USA", "state": "KS", "city": "Independence"},
    {"country": "USA", "state": "KS", "city": "Cherryvale"},
    {"country": "USA", "state": "KS", "city": "Caney"},
    {"country": "USA", "state": "KS", "city": "Parsons"},
    {"country": "USA", "state": "KS", "city": "Neodesha"},
    {"country": "USA", "state": "KS", "city": "Fredonia"},
    {"country": "USA", "state": "OK", "city": "Bartlesville"},
    {"country": "USA", "state": "OK", "city": "Nowata"},
    {"country": "USA", "state": "OK", "city": "South Coffeyville"},
    {"country": "USA", "state": "OK", "city": "Dewey"},
    {"country": "USA", "state": "OK", "city": "Miami"},
]
COUNTY_LOCS = [
    {"country": "USA", "state": "KS", "county": "Montgomery"},
    {"country": "USA", "state": "KS", "county": "Labette"},
    {"country": "USA", "state": "KS", "county": "Chautauqua"},
    {"country": "USA", "state": "KS", "county": "Wilson"},
    {"country": "USA", "state": "OK", "county": "Nowata"},
    {"country": "USA", "state": "OK", "county": "Washington"},
    {"country": "USA", "state": "OK", "county": "Craig"},
]

AWARD_FIELDS = [
    "Award ID", "Recipient Name", "Recipient DUNS", "Award Amount", "Total Outlays",
    "Description", "Awarding Agency", "Awarding Sub Agency", "Award Type",
    "Start Date", "End Date", "Place of Performance City Name",
    "Place of Performance State Code", "Place of Performance County Name",
    "NAICS", "PSC", "COVID-19 Obligations", "Infrastructure Obligations",
]
CONTRACT_TYPES = ["A", "B", "C", "D", "IDV_A", "IDV_B", "IDV_C", "IDV_D", "IDV_E"]
ASSIST_TYPES = ["02", "03", "04", "05", "06", "07", "08", "09", "10", "11"]


def post(path, payload, retries=4):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        API + path, data=data,
        headers={"Content-Type": "application/json", "User-Agent": "DelzarIntel/1.0"},
        method="POST",
    )
    last = None
    for i in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=90) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            last = e
            body = e.read().decode(errors="replace")
            if e.code in (429, 500, 502, 503, 504):
                time.sleep(2 ** i)
                continue
            raise RuntimeError(f"HTTP {e.code} {path}: {body[:500]}") from e
        except Exception as e:
            last = e
            time.sleep(2 ** i)
    raise RuntimeError(f"failed {path}: {last}")


def paged_awards(label, extra_filters, award_type_codes):
    rows = []
    page = 1
    while True:
        payload = {
            "filters": {
                "time_period": TIME_PERIOD,
                "award_type_codes": award_type_codes,
                **extra_filters,
            },
            "fields": AWARD_FIELDS,
            "limit": 100,
            "page": page,
            "sort": "Award Amount",
            "order": "desc",
        }
        data = post("/api/v2/search/spending_by_award/", payload)
        results = data.get("results") or []
        rows.extend(results)
        print(f"  {label} page {page}: {len(results)} (running {len(rows)})")
        meta = data.get("page_metadata") or {}
        if not results or not meta.get("hasNext"):
            break
        page += 1
        if page > 20:
            print("  stop at 20 pages")
            break
        time.sleep(0.4)
    return rows


def write_csv(name, rows):
    path = OUT / name
    if not rows:
        path.write_text("")
        return
    keys = []
    for r in rows:
        for k in r:
            if k not in keys:
                keys.append(k)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {path} ({len(rows)} rows)")


def main():
    summary = {
        "generated": TODAY,
        "note": "USAspending = historical obligations. Open solicitations live on SAM.gov.",
        "queries": {},
    }
    queries = {
        "contracts_pop_counties": ({"place_of_performance_locations": COUNTY_LOCS}, CONTRACT_TYPES),
        "contracts_pop_cities": ({"place_of_performance_locations": POP_LOCS}, CONTRACT_TYPES),
        "contracts_recipient_counties": ({"recipient_locations": COUNTY_LOCS}, CONTRACT_TYPES),
        "assistance_pop_counties": ({"place_of_performance_locations": COUNTY_LOCS}, ASSIST_TYPES),
        "assistance_recipient_counties": ({"recipient_locations": COUNTY_LOCS}, ASSIST_TYPES),
    }
    all_contracts = []
    for name, (filt, types) in queries.items():
        print("QUERY", name)
        rows = paged_awards(name, filt, types)
        write_csv(f"{name}.csv", rows)
        amounts = [float(r.get("Award Amount") or 0) for r in rows]
        summary["queries"][name] = {"count": len(rows), "award_amount_sum": round(sum(amounts), 2)}
        if name.startswith("contracts_"):
            all_contracts.extend(rows)
        time.sleep(0.5)
    seen = {}
    for r in all_contracts:
        aid = r.get("Award ID")
        if aid and aid not in seen:
            seen[aid] = r
    uniq = list(seen.values())
    write_csv("contracts_deduped.csv", uniq)
    open_rows = []
    for r in uniq:
        end = (r.get("End Date") or "")[:10]
        if end >= TODAY:
            open_rows.append(r)
    write_csv("contracts_pop_still_open.csv", open_rows)
    agencies, naics, recips = {}, {}, {}
    for r in uniq:
        amt = float(r.get("Award Amount") or 0)
        agencies[r.get("Awarding Agency") or "UNK"] = agencies.get(r.get("Awarding Agency") or "UNK", 0) + amt
        naics[r.get("NAICS") or "UNK"] = naics.get(r.get("NAICS") or "UNK", 0) + amt
        recips[r.get("Recipient Name") or "UNK"] = recips.get(r.get("Recipient Name") or "UNK", 0) + amt
    def top(d, n=15):
        return sorted(d.items(), key=lambda x: x[1], reverse=True)[:n]
    summary["deduped_contracts"] = len(uniq)
    summary["open_pop_contracts"] = len(open_rows)
    summary["top_agencies"] = top(agencies)
    summary["top_naics"] = top(naics)
    summary["top_recipients"] = top(recips)
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
