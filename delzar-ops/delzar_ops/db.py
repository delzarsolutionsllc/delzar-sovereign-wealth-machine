"""SQLite connection and migration runner.

Migrations are numbered .sql files in delzar_ops/migrations, applied in
order exactly once, tracked in schema_migrations.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from .config import db_path

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def connect(path: Path | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(path or db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    migrate(conn)
    return conn


def migrate(conn: sqlite3.Connection) -> list[str]:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations "
        "(name TEXT PRIMARY KEY, applied_at TEXT DEFAULT (datetime('now')))"
    )
    applied = {r["name"] for r in conn.execute("SELECT name FROM schema_migrations")}
    ran = []
    for sql_file in sorted(MIGRATIONS_DIR.glob("*.sql")):
        if sql_file.name in applied:
            continue
        conn.executescript(sql_file.read_text())
        conn.execute("INSERT INTO schema_migrations (name) VALUES (?)", (sql_file.name,))
        conn.commit()
        ran.append(sql_file.name)
    return ran
