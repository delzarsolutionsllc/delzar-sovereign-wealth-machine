#!/usr/bin/env python3
"""Classify Coffeyville-ring firms into WINNER / SAM_IDLE / DARK / BUYER."""
from __future__ import annotations

import csv
import json
import urllib.request
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEED = ROOT / "config" / "coffeyville_firms_seed.csv"
OUT = ROOT / "outputs" / "coffeyville-usaspending"
OUT.mkdir(parents=True, exist_ok=True)


def lookup_uei(uei: str) -> dict:
    if not uei:
        return {}
    url = f"https://api.usaspending.gov/api/v2/recipient/{uei}/"
    req = urllib.request.Request(url, headers={"User-Agent": "DelzarIntel/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"error": str(e)}


def main() -> None:
    rows = list(csv.DictReader(SEED.open(encoding="utf-8")))
    by_bucket = Counter(r["bucket"] for r in rows)
    live = []
    for r in rows:
        info = {"name": r["name"], "bucket": r["bucket"], "uei": r.get("uei", "")}
        if r.get("uei"):
            rec = lookup_uei(r["uei"])
            info["live_usaspending"] = {
                "error": rec.get("error"),
                "name": rec.get("name"),
            }
        live.append(info)
    summary = {
        "seed_rows": len(rows),
        "buckets": dict(by_bucket),
        "idle_or_dark": [r["name"] for r in rows if r["bucket"] in ("SAM_IDLE", "DARK")],
        "winners": [r["name"] for r in rows if r["bucket"] == "WINNER"],
        "live": live,
    }
    (OUT / "gap_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: summary[k] for k in ("seed_rows", "buckets", "idle_or_dark", "winners")}, indent=2))


if __name__ == "__main__":
    main()
