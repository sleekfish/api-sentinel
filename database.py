"""SQLite database helpers using the stdlib sqlite3 module."""
from __future__ import annotations

import sqlite3
import os

DB_PATH = os.getenv("DB_PATH", "./sentinel.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db() -> None:
    """Create tables and run any pending column migrations."""
    with get_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url  TEXT    NOT NULL,
                status      TEXT    NOT NULL DEFAULT 'pending',
                created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
                finished_at TEXT
            );

            CREATE TABLE IF NOT EXISTS findings (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id      INTEGER NOT NULL REFERENCES scans(id),
                severity     TEXT    NOT NULL,
                category     TEXT    NOT NULL,
                title        TEXT    NOT NULL,
                description  TEXT    NOT NULL,
                remediation  TEXT    NOT NULL,
                affected_url TEXT    NOT NULL DEFAULT '',
                evidence     TEXT    NOT NULL DEFAULT '',
                confidence   TEXT    NOT NULL DEFAULT 'high'
            );
            """
        )
        # Non-destructive migration: add new columns to existing DBs that
        # were created before the extended schema.
        _add_column_if_missing(conn, "findings", "affected_url", "TEXT NOT NULL DEFAULT ''")
        _add_column_if_missing(conn, "findings", "evidence",     "TEXT NOT NULL DEFAULT ''")
        _add_column_if_missing(conn, "findings", "confidence",   "TEXT NOT NULL DEFAULT 'high'")


def _add_column_if_missing(
    conn: sqlite3.Connection, table: str, column: str, definition: str
) -> None:
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


# ── Write helpers ─────────────────────────────────────────────────────────────

def create_scan(target_url: str) -> int:
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO scans (target_url, status) VALUES (?, 'running')",
            (target_url,),
        )
        return cur.lastrowid


def finish_scan(scan_id: int) -> None:
    with get_connection() as conn:
        conn.execute(
            "UPDATE scans SET status='done', finished_at=datetime('now') WHERE id=?",
            (scan_id,),
        )


def fail_scan(scan_id: int) -> None:
    with get_connection() as conn:
        conn.execute(
            "UPDATE scans SET status='failed', finished_at=datetime('now') WHERE id=?",
            (scan_id,),
        )


def save_findings(scan_id: int, findings: list[dict]) -> None:
    rows = []
    for f in findings:
        rows.append({
            "scan_id":     scan_id,
            "severity":    f["severity"],
            "category":    f["category"],
            "title":       f["title"],
            "description": f["description"],
            "remediation": f["remediation"],
            "affected_url": f.get("affected_url", ""),
            "evidence":    f.get("evidence", ""),
            "confidence":  f.get("confidence", "high"),
        })
    with get_connection() as conn:
        conn.executemany(
            """INSERT INTO findings
               (scan_id, severity, category, title, description, remediation,
                affected_url, evidence, confidence)
               VALUES (:scan_id, :severity, :category, :title, :description,
                       :remediation, :affected_url, :evidence, :confidence)""",
            rows,
        )


# ── Read helpers ──────────────────────────────────────────────────────────────

def get_scan(scan_id: int) -> sqlite3.Row | None:
    with get_connection() as conn:
        return conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()


def get_findings(scan_id: int) -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            """SELECT * FROM findings WHERE scan_id=?
               ORDER BY CASE severity
                 WHEN 'critical' THEN 0
                 WHEN 'high'     THEN 1
                 WHEN 'medium'   THEN 2
                 WHEN 'low'      THEN 3
                 ELSE 4 END""",
            (scan_id,),
        ).fetchall()


def list_scans() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT 50"
        ).fetchall()


def count_findings(scan_id: int) -> int:
    with get_connection() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM findings WHERE scan_id=?", (scan_id,)
        ).fetchone()[0]
