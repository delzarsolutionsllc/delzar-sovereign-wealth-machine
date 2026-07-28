"""Thin adapter around the USAspending.gov API (no key required).

Used by INTEL to pull award history for competitors and offices.
Docs: https://api.usaspending.gov/docs/endpoints
Only this file knows the USAspending schema.
"""
from __future__ import annotations

import httpx

BASE = "https://api.usaspending.gov/api/v2"


def search_awards_by_recipient(
    recipient_name: str,
    naics: str | None = None,
    limit: int = 25,
    client: httpx.Client | None = None,
) -> list[dict]:
    own = client is None
    client = client or httpx.Client(timeout=30)
    try:
        filters: dict = {
            "recipient_search_text": [recipient_name],
            "award_type_codes": ["A", "B", "C", "D"],
        }
        if naics:
            filters["naics_codes"] = [naics]
        resp = client.post(
            f"{BASE}/search/spending_by_award/",
            json={
                "filters": filters,
                "fields": ["Award ID", "Recipient Name", "Award Amount",
                           "Start Date", "End Date", "Awarding Agency",
                           "Awarding Sub Agency", "Description"],
                "limit": limit,
                "order": "desc",
                "sort": "Start Date",
            },
        )
        resp.raise_for_status()
        out = []
        for r in resp.json().get("results", []):
            out.append({
                "piid": r.get("Award ID"),
                "recipient": r.get("Recipient Name"),
                "amount": r.get("Award Amount"),
                "start_date": r.get("Start Date"),
                "end_date": r.get("End Date"),
                "agency": r.get("Awarding Agency"),
                "sub_agency": r.get("Awarding Sub Agency"),
                "description": r.get("Description"),
            })
        return out
    finally:
        if own:
            client.close()
