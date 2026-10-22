
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "aishield.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                total_tests INTEGER NOT NULL,
                passed INTEGER NOT NULL,
                failed INTEGER NOT NULL,
                review INTEGER NOT NULL,
                errors INTEGER NOT NULL,
                score REAL,
                attack_success_rate REAL,
                results_json TEXT NOT NULL
            )
        """)


def save_scan(scan_data):
    timestamp = datetime.now(timezone.utc).isoformat()

    with get_connection() as conn:
        cursor = conn.execute("""
            INSERT INTO scans (
                model, timestamp, total_tests,
                passed, failed, review, errors,
                score, attack_success_rate, results_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_data["model"],
            timestamp,
            scan_data["total_tests"],
            scan_data["passed"],
            scan_data["failed"],
            scan_data["review"],
            scan_data["errors"],
            scan_data["score"],
            scan_data["attack_success_rate"],
            json.dumps(scan_data),
        ))

        scan_id = cursor.lastrowid

    return scan_id, timestamp


def get_scans():
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT
                id, model, timestamp, total_tests,
                passed, failed, review, errors,
                score, attack_success_rate
            FROM scans
            ORDER BY id DESC
            LIMIT 100
        """).fetchall()

    return [dict(row) for row in rows]


def get_scan_by_id(scan_id):
    with get_connection() as conn:
        row = conn.execute("""
            SELECT id, timestamp, results_json
            FROM scans
            WHERE id = ?
        """, (scan_id,)).fetchone()

    if row is None:
        return None

    scan = json.loads(row["results_json"])
    scan["scan_id"] = row["id"]
    scan["timestamp"] = row["timestamp"]

    return scan
