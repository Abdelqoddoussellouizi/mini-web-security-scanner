import json
import sqlite3
from pathlib import Path
from typing import Any

DATABASE_PATH = Path(__file__).resolve().parent.parent / "scanner.db"


def initialize_database(database_path: Path = DATABASE_PATH) -> None:
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target_url TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                http_status INTEGER,
                status TEXT NOT NULL,
                findings_json TEXT NOT NULL
            )
            """
        )


def save_scan(database_path: Path, scan: dict[str, Any]) -> None:
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO scans (id, target_url, scanned_at, http_status, status, findings_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                scan["id"],
                scan["url"],
                scan["scanned_at"],
                scan["http_status"],
                scan["status"],
                json.dumps(scan["findings"]),
            ),
        )


def list_scans(database_path: Path, limit: int) -> list[dict[str, Any]]:
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT id, target_url, scanned_at, http_status, status
            FROM scans
            ORDER BY scanned_at DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [_row_to_scan(row) for row in rows]


def get_scan(database_path: Path, scan_id: str) -> dict[str, Any] | None:
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT id, target_url, scanned_at, http_status, status, findings_json
            FROM scans
            WHERE id = ?
            """,
            (scan_id,),
        ).fetchone()
    if row is None:
        return None
    scan = _row_to_scan(row)
    scan["findings"] = json.loads(row["findings_json"])
    return scan


def _row_to_scan(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "url": row["target_url"],
        "scanned_at": row["scanned_at"],
        "http_status": row["http_status"],
        "status": row["status"],
    }
