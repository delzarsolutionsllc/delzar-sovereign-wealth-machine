#!/usr/bin/env python3
"""BIA/BIE contract pull from USAspending with facilities keep + NAICS drop filters.

Subtier 1450 is BIA and BIE together. This is award history, not a live SAM board.

Examples:
  python3 usaspending_bie_facilities.py
  python3 usaspending_bie_facilities.py --from-csv bie_bia_contracts_fy25_26.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import time
from pathlib import Path

import requests

URL = "https://api.usaspending.gov/api/v2/search/spending_by_award/"
START = "2024-10-01"
END = "2026-09-17"

FIELDS = [
    "Award ID",
    "Recipient Name",
    "Recipient UEI",
    "Award Amount",
    "Start Date",
    "End Date",
    "Awarding Agency",
    "Awarding Sub Agency",
    "Awarding Office",
    "Place of Performance State Code",
    "Place of Performance City Name",
    "NAICS",
    "PSC",
    "Description",
]

KEEP_NAICS_PREFIXES = ("236", "237", "238", "5616")
DROP_NAICS_PREFIXES = (
    "2211",  # electric power
    "2212",  # natural gas
    "2213",  # water/sewer
    "311",   # food manufacturing
    "445",   # food stores
    "484",   # trucking
    "517",   # telecom
    "522",   # credit
    "523",   # securities / intermediation
    "524",   # insurance
    "611",   # education services / curriculum
    "622",   # hospitals
    "623",   # nursing / residential care
    "624",   # social assistance
    "722",   # food service
    "8111",  # auto repair
    "9221",  # justice / fire protection public
)
NEEDLES = (
    "FIRE ALARM",
    "FIRE-ALARM",
    "SPRINKLER",
    "LIFE SAFETY",
    "LIFE-SAFETY",
    "HVAC",
    "GENERATOR",
    "ELECTRICAL",
    "CONSTRUCT",
    "ROOF",
    "PLUMB",
    "BOILER",
    "HASKELL",
    "RIVERSIDE INDIAN",
    "HINU",
)

OUT_DIR = Path(__file__).resolve().parent


def naics_code(value) -> str:
    if isinstance(value, dict):
        return str(value.get("code") or "")
    return str(value or "")


def psc_code(value) -> str:
    if isinstance(value, dict):
        return str(value.get("code") or "")
    return str(value or "")


def flatten(row: dict) -> dict:
    naics = row.get("NAICS")
    psc = row.get("PSC")
    naics_d = naics if isinstance(naics, dict) else {}
    psc_d = psc if isinstance(psc, dict) else {}
    return {
        "Award ID": row.get("Award ID"),
        "Recipient Name": row.get("Recipient Name"),
        "Recipient UEI": row.get("Recipient UEI"),
        "Award Amount": row.get("Award Amount"),
        "Start Date": row.get("Start Date"),
        "End Date": row.get("End Date"),
        "Awarding Agency": row.get("Awarding Agency"),
        "Awarding Sub Agency": row.get("Awarding Sub Agency"),
        "Awarding Office": row.get("Awarding Office"),
        "Place of Performance State Code": row.get("Place of Performance State Code"),
        "Place of Performance City Name": row.get("Place of Performance City Name"),
        "NAICS": naics_code(naics),
        "NAICS Description": naics_d.get("description") or "",
        "PSC": psc_code(psc),
        "PSC Description": psc_d.get("description") or "",
        "Description": row.get("Description") or "",
        "generated_internal_id": row.get("generated_internal_id") or "",
    }


def dropped_naics(code: str) -> bool:
    return any(code.startswith(p) for p in DROP_NAICS_PREFIXES)


def kept_naics(code: str) -> bool:
    return any(code.startswith(p) for p in KEEP_NAICS_PREFIXES)


def is_facilities(row: dict) -> bool:
    code = str(row.get("NAICS") or "")
    if dropped_naics(code):
        return False
    blob = " ".join(str(row.get(k) or "") for k in row).upper()
    if kept_naics(code):
        return True
    return any(n in blob for n in NEEDLES)


def fetch_page(page: int) -> dict:
    body = {
        "filters": {
            "time_period": [{"start_date": START, "end_date": END}],
            "award_type_codes": ["A", "B", "C", "D"],
            "agencies": [
                {
                    "type": "awarding",
                    "tier": "subtier",
                    "name": "Bureau of Indian Affairs and Bureau of Indian Education",
                }
            ],
        },
        "fields": FIELDS,
        "limit": 100,
        "page": page,
    }
    r = requests.post(URL, json=body, timeout=90)
    r.raise_for_status()
    return r.json()


def pull_api() -> list[dict]:
    rows: list[dict] = []
    page = 1
    while True:
        data = fetch_page(page)
        batch = data.get("results") or []
        rows.extend(flatten(r) for r in batch)
        print(f"page {page}: +{len(batch)} total={len(rows)}")
        if not data.get("page_metadata", {}).get("hasNext") or not batch:
            break
        page += 1
        if page > 80:
            print("stop at 80 pages")
            break
        time.sleep(0.25)
    return rows


def load_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as f:
        return [flatten(r) for r in csv.DictReader(f)]


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        path.write_text("")
        return
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--from-csv", type=Path, help="Re-filter an existing all-rows dump")
    args = p.parse_args()

    if args.from_csv:
        all_rows = load_csv(args.from_csv)
        all_path = args.from_csv
    else:
        all_rows = pull_api()
        all_path = OUT_DIR / "bie_bia_contracts_fy25_26.csv"
        write_csv(all_path, all_rows)

    fac = [r for r in all_rows if is_facilities(r)]
    dropped = [r for r in all_rows if dropped_naics(str(r.get("NAICS") or ""))]
    fac_path = OUT_DIR / "bie_facilities_awards.csv"
    write_csv(fac_path, fac)

    print(f"{len(all_rows)} BIA/BIE rows")
    print(f"{len(dropped)} dropped by NAICS prefix")
    print(f"{len(fac)} facilities-like after keep+drop")
    print(f"wrote {all_path}")
    print(f"wrote {fac_path}")


if __name__ == "__main__":
    main()
