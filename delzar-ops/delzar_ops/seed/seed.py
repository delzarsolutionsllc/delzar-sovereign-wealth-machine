"""Seed the database from the editable CSVs in seed/data.

These files are TEMPLATES. The operator replaces placeholder rows with
real research and re-runs `delzar init --seed` (idempotent upserts).
"""
from __future__ import annotations

import csv
import sqlite3
from pathlib import Path

DATA = Path(__file__).parent / "data"


def seed_all(conn: sqlite3.Connection) -> dict:
    counts = {
        "materials": _seed_materials(conn),
        "competitors": _seed_competitors(conn),
        "bpa_holders": _seed_bpa(conn),
    }
    conn.commit()
    return counts


def _rows(name: str) -> list[dict]:
    with open(DATA / name, newline="") as f:
        return list(csv.DictReader(f))


def _seed_materials(conn: sqlite3.Connection) -> int:
    n = 0
    for r in _rows("materials.csv"):
        conn.execute(
            """INSERT INTO materials_prices (item, unit, unit_cost, source)
               VALUES (?,?,?,?)
               ON CONFLICT (item) DO UPDATE SET unit = excluded.unit,
                 unit_cost = excluded.unit_cost, source = excluded.source,
                 updated_at = datetime('now')""",
            (r["item"], r["unit"], float(r["unit_cost"]), r["source"]),
        )
        n += 1
    return n


def _seed_competitors(conn: sqlite3.Connection) -> int:
    n = 0
    for r in _rows("competitors.csv"):
        conn.execute(
            """INSERT INTO competitors (name, uei, location, notes) VALUES (?,?,?,?)
               ON CONFLICT (name) DO UPDATE SET uei = excluded.uei,
                 location = excluded.location, notes = excluded.notes""",
            (r["name"], r["uei"] or None, r["location"], r["notes"]),
        )
        n += 1
    return n


def _seed_bpa(conn: sqlite3.Connection) -> int:
    n = 0
    for r in _rows("bpa_grid.csv"):
        conn.execute(
            """INSERT INTO bpa_holders
               (holder, field_office, service_type, bpa_piid, established_date,
                expiration_date, notes)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT (holder, field_office, service_type) DO UPDATE SET
                 bpa_piid = excluded.bpa_piid,
                 established_date = excluded.established_date,
                 expiration_date = excluded.expiration_date,
                 notes = excluded.notes""",
            (r["holder"], r["field_office"], r["service_type"],
             r["bpa_piid"] or None, r["established_date"] or None,
             r["expiration_date"] or None, r["notes"]),
        )
        n += 1
    return n
