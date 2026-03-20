"""Tests: Buffer persistence, retry scheduling, metadata."""

import os
import time
import tempfile
import pytest

from soc_exporter.buffer import Buffer


@pytest.fixture()
def buf(tmp_path):
    return Buffer(db_path=str(tmp_path / "buffer.db"))


# ---------------------------------------------------------------------------
# Basic push / fetch / ack
# ---------------------------------------------------------------------------

def test_push_and_fetch(buf):
    buf.push({"id": 1, "msg": "hello"})
    items = buf.fetch_ready(limit=10)
    assert len(items) == 1
    assert items[0][1]["msg"] == "hello"


def test_ack_removes_event(buf):
    buf.push({"id": 1})
    items = buf.fetch_ready()
    ids = [i for i, _ in items]
    buf.ack(ids)
    assert buf.pending_count() == 0


def test_push_batch(buf):
    events = [{"n": i} for i in range(50)]
    buf.push_batch(events)
    assert buf.pending_count() == 50


def test_fetch_respects_limit(buf):
    buf.push_batch([{"n": i} for i in range(20)])
    items = buf.fetch_ready(limit=5)
    assert len(items) == 5


# ---------------------------------------------------------------------------
# Persistence across restarts
# ---------------------------------------------------------------------------

def test_survives_restart(tmp_path):
    db_path = str(tmp_path / "buffer.db")

    # Write events in first instance
    b1 = Buffer(db_path=db_path)
    b1.push_batch([{"x": i} for i in range(10)])
    del b1  # close / simulate restart

    # Second instance reads same DB
    b2 = Buffer(db_path=db_path)
    assert b2.pending_count() == 10
    items = b2.fetch_ready(limit=10)
    assert len(items) == 10


# ---------------------------------------------------------------------------
# Nack / exponential backoff
# ---------------------------------------------------------------------------

def test_nack_delays_retry(buf):
    buf.push({"id": 1})
    items = buf.fetch_ready()
    ids = [i for i, _ in items]

    buf.nack(ids, base_delay=60.0, max_delay=300.0)

    # Should NOT be ready immediately
    ready = buf.fetch_ready()
    assert len(ready) == 0
    assert buf.pending_count() == 1


def test_nack_exponential_growth(tmp_path):
    db_path = str(tmp_path / "buf.db")
    buf = Buffer(db_path=db_path)
    buf.push({"id": 1})

    delays = []
    for attempt in range(5):
        items = buf.fetch_ready()
        if not items:
            break
        ids = [i for i, _ in items]
        # Record next_retry before nack
        import sqlite3
        conn = sqlite3.connect(db_path)
        before = conn.execute("SELECT next_retry FROM events").fetchone()[0]
        conn.close()

        buf.nack(ids, base_delay=2.0, max_delay=300.0)

        conn = sqlite3.connect(db_path)
        after = conn.execute("SELECT next_retry FROM events").fetchone()[0]
        conn.close()
        delays.append(after - before)

        # Wind the clock forward so next fetch_ready returns the event
        import sqlite3 as _sq
        c = _sq.connect(db_path)
        c.execute("UPDATE events SET next_retry = 0")
        c.commit()
        c.close()

    # Each delay should be >= previous (exponential)
    for i in range(1, len(delays)):
        assert delays[i] >= delays[i - 1]


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

def test_metadata_set_get(buf):
    buf.set_meta("last_heartbeat_at", "2024-01-01T00:00:00+00:00")
    assert buf.get_meta("last_heartbeat_at") == "2024-01-01T00:00:00+00:00"


def test_metadata_overwrite(buf):
    buf.set_meta("key", "first")
    buf.set_meta("key", "second")
    assert buf.get_meta("key") == "second"


def test_metadata_missing_returns_none(buf):
    assert buf.get_meta("nonexistent") is None


def test_metadata_persists_across_restart(tmp_path):
    db_path = str(tmp_path / "buf.db")
    b1 = Buffer(db_path=db_path)
    b1.set_meta("last_send_at", "2024-06-01T12:00:00+00:00")
    del b1

    b2 = Buffer(db_path=db_path)
    assert b2.get_meta("last_send_at") == "2024-06-01T12:00:00+00:00"


# ---------------------------------------------------------------------------
# oldest_queued_at
# ---------------------------------------------------------------------------

def test_oldest_queued_at_empty(buf):
    assert buf.oldest_queued_at() is None


def test_oldest_queued_at(buf):
    buf.push({"a": 1})
    time.sleep(0.05)
    buf.push({"b": 2})
    oldest = buf.oldest_queued_at()
    assert oldest is not None
    age = time.time() - oldest
    assert 0 < age < 5
