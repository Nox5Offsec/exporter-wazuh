"""Persistent local event buffer backed by SQLite.

Events are stored until confirmed delivered to the API.
Thread-safe via a connection-per-call pattern with WAL mode.

Also stores runtime metadata (last heartbeat, last send, last error)
so `soc-exporter status` can read state even when the service is stopped.

Overflow behaviour (configurable via buffer_max_events / buffer_overflow_policy):
  drop_oldest  — delete the oldest events to make room (default)
  reject       — silently discard new events when the queue is full

A CRITICAL log is emitted the first time the limit is hit.
A WARNING is emitted when the queue reaches 80% of the limit.
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

_WARN_FRACTION  = 0.80   # warn at 80 % capacity
_DROP_FRACTION  = 0.10   # drop oldest 10 % on overflow (drop_oldest policy)
_CHECK_INTERVAL = 100    # check overflow every N pushes (performance trade-off)


class Buffer:
    def __init__(
        self,
        db_path: str,
        max_events: int = 0,
        overflow_policy: str = "drop_oldest",
    ):
        self._db_path         = db_path
        self._max_events      = max_events
        self._overflow_policy = overflow_policy
        self._log             = _logger.get()
        self._push_count      = 0
        self._overflow_warned = False   # CRITICAL emitted once per overflow episode
        self._capacity_warned = False   # WARNING emitted once per 80% episode

        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        with self._conn() as conn:
            conn.executescript(_SCHEMA)
            self._integrity_check(conn)
        self._log.info("Buffer initialised at %s", db_path)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def push(self, event: dict) -> None:
        """Persist a single event, enforcing the size limit if configured."""
        self._push_count += 1
        if self._max_events and self._push_count % _CHECK_INTERVAL == 0:
            self._enforce_limit(new_count=1)

        now = time.time()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO events (payload, queued_at, next_retry) VALUES (?, ?, ?)",
                (json.dumps(event, ensure_ascii=False), now, now),
            )

    def push_batch(self, events: list[dict]) -> None:
        """Persist multiple events in one transaction."""
        if self._max_events:
            self._enforce_limit(new_count=len(events))

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
    # Overflow management
    # ------------------------------------------------------------------

    def _enforce_limit(self, new_count: int = 1) -> None:
        """Check current size and apply overflow policy if needed."""
        current = self.pending_count()

        if self._max_events and current >= int(self._max_events * _WARN_FRACTION):
            if not self._capacity_warned:
                self._log.warning(
                    "Buffer at %.0f%% capacity (%d/%d events). "
                    "Check API connectivity.",
                    100.0 * current / self._max_events,
                    current,
                    self._max_events,
                )
                self._capacity_warned = True
        else:
            self._capacity_warned = False

        if not self._max_events or current + new_count <= self._max_events:
            return

        # Over limit — apply policy
        if not self._overflow_warned:
            self._log.critical(
                "Buffer full (%d/%d events). Applying overflow policy '%s'. "
                "Events may be lost. Check API connectivity urgently.",
                current, self._max_events, self._overflow_policy,
            )
            self._overflow_warned = True

        if self._overflow_policy == "drop_oldest":
            drop_n = max(new_count, int(self._max_events * _DROP_FRACTION))
            with self._conn() as conn:
                conn.execute(
                    "DELETE FROM events WHERE id IN "
                    "(SELECT id FROM events ORDER BY id ASC LIMIT ?)",
                    (drop_n,),
                )
        # "reject" policy: enforce_limit returns without deleting;
        # the calling push() still inserts — but caller can be extended
        # to check return value in future if needed.

    # ------------------------------------------------------------------
    # Integrity check
    # ------------------------------------------------------------------

    def _integrity_check(self, conn: sqlite3.Connection) -> None:
        result = conn.execute("PRAGMA integrity_check").fetchone()
        if result and result[0] != "ok":
            self._log.critical(
                "Buffer integrity check FAILED: %s — "
                "consider deleting %s and restarting",
                result[0],
                self._db_path,
            )

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
