"""Tests: Collector rotation scenarios and event parsing."""

import json
import os
import threading
import time

import pytest

from soc_exporter.collector import Collector


@pytest.fixture()
def alerts_path(tmp_path):
    return str(tmp_path / "alerts.json")


def _make_collector(alerts_path, collected, stop):
    c = Collector(
        alerts_path=alerts_path,
        installation_id="test-inst",
        on_event=collected.append,
        stop_event=stop,
    )
    # Speed up "file not found" retry for tests (default is 10s)
    c._missing_file_retry = 0.5
    return c


def _write_alert(path, rule_id=1000):
    alert = {"rule": {"id": rule_id, "description": "test"}}
    with open(path, "a") as f:
        f.write(json.dumps(alert) + "\n")


def _wait_for(condition, timeout=5.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(interval)
    return False


def _stop_collector(c, stop):
    stop.set()
    c.join(timeout=3)


# ---------------------------------------------------------------------------
# Basic collection
# ---------------------------------------------------------------------------

def test_collects_new_events(alerts_path):
    collected = []
    stop = threading.Event()
    open(alerts_path, "w").close()

    c = _make_collector(alerts_path, collected, stop)
    c.start()
    time.sleep(0.15)  # let collector reach tail position

    _write_alert(alerts_path, rule_id=1001)
    _write_alert(alerts_path, rule_id=1002)

    assert _wait_for(lambda: len(collected) >= 2), "Events not collected in time"
    _stop_collector(c, stop)

    rule_ids = [e["raw"]["rule"]["id"] for e in collected]
    assert 1001 in rule_ids
    assert 1002 in rule_ids


def test_event_enrichment(alerts_path):
    collected = []
    stop = threading.Event()
    open(alerts_path, "w").close()

    c = _make_collector(alerts_path, collected, stop)
    c.start()
    time.sleep(0.15)

    _write_alert(alerts_path)
    assert _wait_for(lambda: len(collected) >= 1)
    _stop_collector(c, stop)

    event = collected[0]
    assert "raw" in event
    assert event["installation_id"] == "test-inst"
    assert "hostname" in event
    assert "sent_at" in event


def test_skips_old_events_on_start(alerts_path):
    """Collector must NOT replay events already in the file at startup."""
    _write_alert(alerts_path, rule_id=9999)

    collected = []
    stop = threading.Event()
    c = _make_collector(alerts_path, collected, stop)
    c.start()
    time.sleep(0.15)

    assert len(collected) == 0

    _write_alert(alerts_path, rule_id=1111)
    assert _wait_for(lambda: len(collected) >= 1)
    _stop_collector(c, stop)

    assert collected[0]["raw"]["rule"]["id"] == 1111


# ---------------------------------------------------------------------------
# File not present at startup
# ---------------------------------------------------------------------------

def test_waits_for_file_creation(tmp_path):
    missing_path = str(tmp_path / "alerts.json")
    collected = []
    stop = threading.Event()

    c = _make_collector(missing_path, collected, stop)
    c.start()
    time.sleep(0.3)  # collector is in wait loop

    # Create the file — collector will notice within _missing_file_retry (0.5s)
    open(missing_path, "w").close()
    time.sleep(0.7)  # wait for collector to pick up the new file

    _write_alert(missing_path, rule_id=2000)
    assert _wait_for(lambda: len(collected) >= 1, timeout=5), \
        "Should collect after file creation"
    _stop_collector(c, stop)


# ---------------------------------------------------------------------------
# Rotation: rename (mv alerts.json → alerts.json.1; new file created)
# ---------------------------------------------------------------------------

def test_rename_rotation(alerts_path):
    collected = []
    stop = threading.Event()
    open(alerts_path, "w").close()

    c = _make_collector(alerts_path, collected, stop)
    c.start()
    time.sleep(0.15)

    # Write one event before rotation — collect it
    _write_alert(alerts_path, rule_id=5000)
    assert _wait_for(lambda: len(collected) >= 1)

    # Simulate rename rotation
    os.rename(alerts_path, alerts_path + ".1")
    open(alerts_path, "w").close()  # new empty file

    # Give collector one full poll cycle to detect rotation and re-open
    time.sleep(0.5)

    # Write to new file — collector reads from pos 0 after rotation
    _write_alert(alerts_path, rule_id=5001)
    assert _wait_for(lambda: len(collected) >= 2, timeout=5), \
        "Should collect from new file after rename rotation"

    _stop_collector(c, stop)
    rule_ids = [e["raw"]["rule"]["id"] for e in collected]
    assert 5001 in rule_ids


# ---------------------------------------------------------------------------
# Rotation: copytruncate (same inode, file truncated to 0)
# ---------------------------------------------------------------------------

def test_copytruncate_rotation(alerts_path):
    collected = []
    stop = threading.Event()
    open(alerts_path, "w").close()

    c = _make_collector(alerts_path, collected, stop)
    c.start()
    time.sleep(0.15)

    _write_alert(alerts_path, rule_id=6000)
    assert _wait_for(lambda: len(collected) >= 1)

    # Simulate copytruncate (truncate in place, same inode)
    with open(alerts_path, "w") as f:
        f.truncate(0)

    # Wait for collector to detect shrink and re-open
    time.sleep(0.5)

    _write_alert(alerts_path, rule_id=6001)
    assert _wait_for(lambda: len(collected) >= 2, timeout=5), \
        "Should collect from truncated file after copytruncate"

    _stop_collector(c, stop)
    rule_ids = [e["raw"]["rule"]["id"] for e in collected]
    assert 6001 in rule_ids


# ---------------------------------------------------------------------------
# Malformed JSON lines
# ---------------------------------------------------------------------------

def test_skips_invalid_json(alerts_path):
    collected = []
    stop = threading.Event()
    open(alerts_path, "w").close()

    c = _make_collector(alerts_path, collected, stop)
    c.start()
    time.sleep(0.15)

    with open(alerts_path, "a") as f:
        f.write("this is not json\n")
        f.write(json.dumps({"rule": {"id": 7000}}) + "\n")

    assert _wait_for(lambda: len(collected) >= 1)
    _stop_collector(c, stop)

    assert collected[0]["raw"]["rule"]["id"] == 7000
    assert c.get_stats()["parse_errors"] == 1
