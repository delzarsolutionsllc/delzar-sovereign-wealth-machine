"""Thin adapter around the SAM.gov Get Opportunities API v2.

Endpoint verified 2026-07-28:
    GET https://api.sam.gov/opportunities/v2/search
Docs: https://open.gsa.gov/api/get-opportunities-public-api/

Key facts encoded here:
- Free API key from your SAM.gov Account Details page (env SAM_API_KEY).
- Rate limit: ~10 requests/day for public keys; 1,000/day once your
  entity registration is linked. Either way: poll ONCE daily, cache all.
- postedFrom/postedTo are REQUIRED, format MM/dd/yyyy, max 1-year span.
- Response 'description' field is a URL needing a second call - we do
  NOT fetch it (burns request budget); the notice URL is stored instead.

Everything downstream consumes the normalized dict from _normalize(),
so a SAM schema change only ever breaks this one file.
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import date, datetime, timedelta

import httpx

BASE_URL = "https://api.sam.gov/opportunities/v2/search"

# Default watch list per operations plan
DEFAULT_NAICS = ["237110", "238910", "238110", "221310"]
DEFAULT_STATES = ["OK", "KS"]
DEFAULT_OFFICES = ["75H711", "75H701", "W912BV"]  # IHS OKC, IHS, USACE Tulsa


class SamKeyMissing(Exception):
    pass


def api_key() -> str:
    key = os.environ.get("SAM_API_KEY", "").strip()
    if not key:
        raise SamKeyMissing(
            "No SAM.gov API key found. Get a free key: log in at SAM.gov -> "
            "Account Details -> API Key, then:  export SAM_API_KEY=yourkey  "
            "(or put it in ~/.delzar/env). The rest of DELZAR OPS works fine "
            "without it; only live polling needs the key."
        )
    return key


def fetch_opportunities(
    naics: list[str] | None = None,
    states: list[str] | None = None,
    days_back: int = 3,
    limit: int = 200,
    client: httpx.Client | None = None,
) -> list[dict]:
    """One conservative API call per NAICS code; returns normalized dicts."""
    naics = naics or DEFAULT_NAICS
    states = states or DEFAULT_STATES
    posted_to = date.today()
    posted_from = posted_to - timedelta(days=days_back)
    own_client = client is None
    client = client or httpx.Client(timeout=30)
    results: list[dict] = []
    try:
        for code in naics:
            params = {
                "api_key": api_key(),
                "postedFrom": posted_from.strftime("%m/%d/%Y"),
                "postedTo": posted_to.strftime("%m/%d/%Y"),
                "ncode": code,
                "limit": str(limit),
                "ptype": "o,k,p,r,s",  # solicitations, combined synopsis, presol, sources sought, SS
            }
            resp = client.get(BASE_URL, params=params)
            resp.raise_for_status()
            data = resp.json()
            for opp in data.get("opportunitiesData", []):
                norm = _normalize(opp)
                if not states or (norm["place_state"] or "").upper() in states or not norm["place_state"]:
                    results.append(norm)
    finally:
        if own_client:
            client.close()
    return results


def _normalize(opp: dict) -> dict:
    """Map a raw SAM v2 record to our stable internal shape."""
    pop = opp.get("placeOfPerformance") or {}
    city = (pop.get("city") or {})
    state = (pop.get("state") or {})
    poc_list = opp.get("pointOfContact") or []
    poc = poc_list[0] if poc_list else {}
    return {
        "notice_id": opp.get("noticeId"),
        "solicitation_no": opp.get("solicitationNumber"),
        "title": opp.get("title"),
        "agency": opp.get("department") or opp.get("fullParentPathName", "").split(".")[0],
        "office": opp.get("officeAddress", {}).get("city") if isinstance(opp.get("officeAddress"), dict) else opp.get("subTier"),
        "set_aside": opp.get("typeOfSetAside") or opp.get("typeOfSetAsideDescription"),
        "naics": opp.get("naicsCode"),
        "psc": opp.get("classificationCode"),
        "place_city": city.get("name") if isinstance(city, dict) else str(city or ""),
        "place_state": state.get("code") if isinstance(state, dict) else str(state or ""),
        "place_zip": pop.get("zip"),
        "posted_date": opp.get("postedDate"),
        "response_deadline": opp.get("responseDeadLine"),
        "attachment_count": len(opp.get("resourceLinks") or []),
        "poc_name": poc.get("fullName"),
        "poc_email": poc.get("email"),
        "url": opp.get("uiLink"),
        "raw": opp,
    }


def upsert_opportunities(conn: sqlite3.Connection, opps: list[dict]) -> dict:
    """Dedupe across polls by notice_id; detect amendments via changed
    deadline/title. Returns counts."""
    new, amended, seen = 0, 0, 0
    now = datetime.now().isoformat(timespec="seconds")
    for o in opps:
        if not o["notice_id"]:
            continue
        row = conn.execute(
            "SELECT * FROM opportunities WHERE notice_id = ?", (o["notice_id"],)
        ).fetchone()
        if row is None:
            conn.execute(
                """INSERT INTO opportunities
                   (notice_id, solicitation_no, title, agency, office, set_aside,
                    naics, psc, place_city, place_state, place_zip, posted_date,
                    response_deadline, attachment_count, poc_name, poc_email, url,
                    last_seen, raw_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (o["notice_id"], o["solicitation_no"], o["title"], o["agency"],
                 o["office"], o["set_aside"], o["naics"], o["psc"], o["place_city"],
                 o["place_state"], o["place_zip"], o["posted_date"],
                 o["response_deadline"], o["attachment_count"], o["poc_name"],
                 o["poc_email"], o["url"], now, json.dumps(o["raw"])),
            )
            new += 1
        else:
            changed = (
                (o["response_deadline"] or "") != (row["response_deadline"] or "")
                or (o["title"] or "") != (row["title"] or "")
                or (o["attachment_count"] or 0) != (row["attachment_count"] or 0)
            )
            conn.execute(
                """UPDATE opportunities SET last_seen = ?, response_deadline = ?,
                   title = ?, attachment_count = ?, amended_at = CASE WHEN ? THEN ? ELSE amended_at END
                   WHERE notice_id = ?""",
                (now, o["response_deadline"], o["title"], o["attachment_count"],
                 int(changed), now, o["notice_id"]),
            )
            if changed:
                amended += 1
            else:
                seen += 1
    conn.commit()
    return {"new": new, "amended": amended, "unchanged": seen}
