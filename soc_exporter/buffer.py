"""Persistent local event buffer backed by SQLite.

Events are stored until confirmed delivered to the API.
Thread-safe via a connection-per-call pattern with WAL mode.

Also stores runtime metadata (last heartbeat, last send, last error)
so `soc-exporter status` can read state even when the service is stopped.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Generator

from . import logger as _logger

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    payload     TEXT    NOT NULL,
    queued_at   REAL    NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    next_retry  REAL    NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_next_retry ON events(next_retry);

CREATE TABLE IF NOT EXISTS metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class Buffer:
    def __init__(self, db_path: str):
        self._db_path = db_path
        self._log = _logger.get()
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        with self._conn() as conn:
            conn.executescript(_SCHEMA)
        self._log.info("Buffer initialised at %s", db_path)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def push(self, event: dict) -> None:
        """Persist a single event."""
        now = time.time()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO events (payload, queued_at, next_retry) VALUES (?, ?, ?)",
                (json.dumps(event, ensure_ascii=False), now, now),
            )

    def push_batch(self, events: list[dict]) -> None:
        """Persist multiple events in one transaction."""
        now = time.time()
        rows = [(json.dumps(e, ensure_ascii=False), now, now) for e in events]
        with self._conn() as conn:
            conn.executemany(
                "INSERT INTO events (payload, queued_at, next_retry) VALUES (?, ?, ?)",
                rows,
            )

    def fetch_ready(self, limit: int = 100) -> list[tuple[int, dict]]:
        """Return up to *limit* (id, payload) pairs whose next_retry <= now."""
        now = time.time()
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, payload FROM events WHERE next_retry <= ? ORDER BY id LIMIT ?",
                (now, limit),
            ).fetchall()
        return [(row[0], json.loads(row[1])) for row in rows]

    def ack(self, ids: list[int]) -> None:
        """Remove successfully delivered events."""
        if not ids:
            return
        placeholders = ",".join("?" * len(ids))
        with self._conn() as conn:
            conn.execute(f"DELETE FROM events WHERE id IN ({placeholders})", ids)

    def nack(self, ids: list[int], base_delay: float, max_delay: float) -> None:
        """Increment attempt counter and schedule next retry with exponential backoff."""
        if not ids:
            return
        now = time.time()
        placeholders = ",".join("?" * len(ids))
        with self._conn() as conn:
            rows = conn.execute(
                f"SELECT id, attempts FROM events WHERE id IN ({placeholders})", ids
            ).fetchall()
            updates = []
            for event_id, attempts in rows:
                attempts += 1
                delay = min(base_delay * (2 ** (attempts - 1)), max_delay)
                updates.append((attempts, now + delay, event_id))
            conn.executemany(
                "UPDATE events SET attempts = ?, next_retry = ? WHERE id = ?",
                updates,
            )

    def pending_count(self) -> int:
        with self._conn() as conn:
            return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def oldest_queued_at(self) -> float | None:
        with self._conn() as conn:
            row = conn.execute("SELECT MIN(queued_at) FROM events").fetchone()
            return row[0] if row else None

    # ------------------------------------------------------------------
    # Metadata (runtime state for status command)
    # ------------------------------------------------------------------

    def set_meta(self, key: str, value: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                (key, value),
            )

    def get_meta(self, key: str) -> str | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT value FROM metadata WHERE key = ?", (key,)
            ).fetchone()
            return row[0] if row else None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
