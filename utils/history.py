"""Phase 17 — SQLite history: store runs, compare against previous run."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import datetime
from typing import Any

from utils.config import get

logger = logging.getLogger("sentinelaudit.history")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    hostname TEXT NOT NULL,
    score INTEGER NOT NULL,
    band TEXT,
    results_json TEXT NOT NULL
);
"""


def _db_path() -> str:
    path = (get("database") or {}).get("path", "database/history.db")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    return path


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path())
    conn.executescript(_SCHEMA)
    return conn


def save_run(hostname: str, score: int, band: str, results: dict[str, Any]) -> int:
    """Persist a run; returns the new run id."""
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO runs (timestamp, hostname, score, band, results_json) VALUES (?,?,?,?,?)",
            (datetime.now().isoformat(timespec="seconds"), hostname, score, band,
             json.dumps(results, default=str)),
        )
        return int(cur.lastrowid or 0)


def get_last_run(exclude_id: int | None = None) -> dict[str, Any] | None:
    """Fetch the most recent prior run (optionally excluding a run id)."""
    with _connect() as conn:
        if exclude_id is not None:
            row = conn.execute(
                "SELECT id, timestamp, hostname, score, band, results_json FROM runs "
                "WHERE id != ? ORDER BY id DESC LIMIT 1", (exclude_id,),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT id, timestamp, hostname, score, band, results_json FROM runs "
                "ORDER BY id DESC LIMIT 1",
            ).fetchone()
    if not row:
        return None
    return {
        "id": row[0],
        "timestamp": row[1],
        "hostname": row[2],
        "score": row[3],
        "band": row[4],
        "results": json.loads(row[5]),
    }


def list_runs(limit: int = 20) -> list[dict[str, Any]]:
    """List recent runs (no full JSON)."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, timestamp, hostname, score, band FROM runs ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [
        {"id": r[0], "timestamp": r[1], "hostname": r[2], "score": r[3], "band": r[4]}
        for r in rows
    ]


def _finding_keys(results: dict[str, Any]) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    for module, res in (results or {}).items():
        if not isinstance(res, dict):
            continue
        for f in res.get("findings", []):
            keys.add((module, f.get("title", "")))
    return keys


def _finding_map(results: dict[str, Any]) -> dict[tuple[str, str], dict]:
    out: dict[tuple[str, str], dict] = {}
    for module, res in (results or {}).items():
        if not isinstance(res, dict):
            continue
        for f in res.get("findings", []):
            out[(module, f.get("title", ""))] = {**f, "module": module}
    return out


def compare(current_results: dict[str, Any], current_score: int,
            previous: dict[str, Any] | None) -> dict[str, Any]:
    """Diff current run against a previous stored run."""
    if previous is None:
        return {
            "previous_timestamp": None,
            "previous_score": None,
            "score_delta": 0,
            "new_findings": [],
            "resolved_findings": [],
            "first_run": True,
        }
    prev_map = _finding_map(previous["results"])
    cur_map = _finding_map(current_results)
    new = [cur_map[k] for k in cur_map.keys() - prev_map.keys()]
    resolved = [prev_map[k] for k in prev_map.keys() - cur_map.keys()]
    return {
        "previous_timestamp": previous["timestamp"],
        "previous_score": previous["score"],
        "score_delta": current_score - int(previous["score"]),
        "new_findings": new,
        "resolved_findings": resolved,
        "first_run": False,
    }
