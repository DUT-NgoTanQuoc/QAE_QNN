import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone

import pandas as pd

from .config import ROOT

DB_PATH = ROOT / "data" / "traffic.sqlite3"


@dataclass(frozen=True)
class TrafficRun:
    id: int
    name: str
    kind: str
    created_at: str
    packet_count: int
    elapsed_s: float


@contextmanager
def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS traffic_runs (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                kind TEXT NOT NULL CHECK (kind IN ('analysis', 'replay')),
                created_at TEXT NOT NULL,
                packet_count INTEGER NOT NULL,
                elapsed_s REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS traffic_windows (
                run_id INTEGER NOT NULL REFERENCES traffic_runs(id),
                position INTEGER NOT NULL,
                result TEXT NOT NULL,
                PRIMARY KEY (run_id, position)
            );
        """)
        with connection:
            yield connection
    finally:
        connection.close()


def save_windows(name, kind, packet_count, elapsed_s, rows, *, run_id=None, offset=0):
    records = rows.to_dict(orient="records")
    with _connect() as connection:
        if run_id is None:
            run_id = connection.execute(
                "INSERT INTO traffic_runs (name, kind, created_at, packet_count, elapsed_s) "
                "VALUES (?, ?, ?, ?, ?)",
                (name, kind, datetime.now(timezone.utc).isoformat(), packet_count, elapsed_s),
            ).lastrowid
        else:
            connection.execute("UPDATE traffic_runs SET elapsed_s = ? WHERE id = ?", (elapsed_s, run_id))
        connection.executemany(
            "INSERT INTO traffic_windows (run_id, position, result) VALUES (?, ?, ?)",
            ((run_id, position, json.dumps(record, allow_nan=False))
             for position, record in enumerate(records, start=offset)),
        )
    return run_id


def list_runs():
    with _connect() as connection:
        runs = connection.execute(
            "SELECT id, name, kind, created_at, packet_count, elapsed_s FROM traffic_runs ORDER BY id DESC"
        ).fetchall()
    return [TrafficRun(*run) for run in runs]


def load_windows(run_id):
    with _connect() as connection:
        results = connection.execute(
            "SELECT result FROM traffic_windows WHERE run_id = ? ORDER BY position", (run_id,)
        ).fetchall()
    return pd.DataFrame.from_records(json.loads(result) for (result,) in results)
