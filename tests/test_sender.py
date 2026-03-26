"""Tests: Sender retry logic, auth failure, 5xx backoff, no token leakage,
and agent_groups feature flag."""

import threading
import time
from unittest.mock import MagicMock, patch, call

import pytest

from soc_exporter.api_client import (
    AuthError,
    NetworkError,
    PayloadError,
    APIError,
)
from soc_exporter.buffer import Buffer
from soc_exporter.config import Config
from soc_exporter.sender import Sender


def _make_config(**overrides):
    data = {
        "installation_id": "inst-test",
        "ingestion_token": "secret-token-abc",
        "api_url": "https://soc-api.example.com",
        "send_batch_size": 10,
        "send_interval": 1,
        "retry_base_delay": 0.1,
        "retry_max_delay": 1.0,
    }
    data.update(overrides)
    return Config(data)


@pytest.fixture()
def buf(tmp_path):
    return Buffer(db_path=str(tmp_path / "buf.db"))


@pytest.fixture()
def cfg():
    return _make_config()


@pytest.fixture()
def mock_client():
    return MagicMock()


def _run_sender_once(buf, cfg, mock_client, group_cache=None):
    """Create a Sender, let it flush once, then stop it."""
    stop = threading.Event()
    sender = Sender(
        client=mock_client,
        buffer=buf,
        config=cfg,
        stop_event=stop,
        agent_group_cache=group_cache,
    )
    sender._flush()  # call directly for deterministic tests
    return sender


# ---------------------------------------------------------------------------
# Successful send
# ---------------------------------------------------------------------------

def test_successful_send_acks_events(buf, cfg, mock_client):
    mock_client.ingest_events.return_value = {}
    buf.push_batch([{"n": i} for i in range(5)])

    sender = _run_sender_once(buf, cfg, mock_client)

    assert buf.pending_count() == 0
    assert sender.get_stats()["sent"] == 5
    mock_client.ingest_events.assert_called_once()


def test_successful_send_clears_error_meta(buf, cfg, mock_client):
    mock_client.ingest_events.return_value = {}
    buf.push({"x": 1})
    buf.set_meta("last_send_error", "previous error")

    _run_sender_once(buf, cfg, mock_client)

    assert buf.get_meta("last_send_error") == ""


# ---------------------------------------------------------------------------
# Network failure — retry
# ---------------------------------------------------------------------------

def test_network_error_nacks_events(buf, cfg, mock_client):
    mock_client.ingest_events.side_effect = NetworkError("connection refused")
    buf.push_batch([{"n": i} for i in range(3)])

    sender = _run_sender_once(buf, cfg, mock_client)

    # Events stay in buffer but are scheduled for later retry
    assert buf.pending_count() == 3
    # Not yet ready (they have a future next_retry)
    ready = buf.fetch_ready()
    assert len(ready) == 0
    assert sender.get_stats()["retried"] == 3


# ---------------------------------------------------------------------------
# 5xx — retry with backoff
# ---------------------------------------------------------------------------

def test_5xx_nacks_events(buf, cfg, mock_client):
    mock_client.ingest_events.side_effect = APIError(500, "internal error")
    buf.push({"a": 1})

    sender = _run_sender_once(buf, cfg, mock_client)

    assert buf.pending_count() == 1
    assert sender.get_stats()["retried"] == 1


def test_429_retried(buf, cfg, mock_client):
    mock_client.ingest_events.side_effect = APIError(429, "rate limited")
    buf.push({"a": 1})

    sender = _run_sender_once(buf, cfg, mock_client)

    assert buf.pending_count() == 1
    assert sender.get_stats()["retried"] == 1


# ---------------------------------------------------------------------------
# Auth failure (401 / 403) — do NOT retry
# ---------------------------------------------------------------------------

def test_auth_401_suspends_sender(buf, cfg, mock_client):
    mock_client.ingest_events.side_effect = AuthError(401, "unauthorized")
    buf.push({"a": 1})

    sender = _run_sender_once(buf, cfg, mock_client)

    assert sender._auth_failed is True
    # Event is nacked but sender will stop sending further batches
    assert buf.pending_count() == 1

    # Second flush should be a no-op (latch is set)
    mock_client.ingest_events.reset_mock()
    sender._flush()
    mock_client.ingest_events.assert_not_called()


def test_auth_403_suspends_sender(buf, cfg, mock_client):
    mock_client.ingest_events.side_effect = AuthError(403, "forbidden")
    buf.push({"a": 1})

    sender = _run_sender_once(buf, cfg, mock_client)

    assert sender._auth_failed is True


def test_auth_failure_writes_meta(buf, cfg, mock_client):
    mock_client.ingest_events.side_effect = AuthError(401, "unauthorized")
    buf.push({"a": 1})

    _run_sender_once(buf, cfg, mock_client)

    err = buf.get_meta("last_send_error")
    assert err and "AUTH_FAILURE" in err


# ---------------------------------------------------------------------------
# Payload error (400 / 422) — drop, do NOT retry
# ---------------------------------------------------------------------------

def test_payload_400_drops_events(buf, cfg, mock_client):
    mock_client.ingest_events.side_effect = PayloadError(400, "bad request")
    buf.push_batch([{"x": i} for i in range(3)])

    sender = _run_sender_once(buf, cfg, mock_client)

    assert buf.pending_count() == 0
    assert sender.get_stats()["dropped"] == 3


def test_payload_422_drops_events(buf, cfg, mock_client):
    mock_client.ingest_events.side_effect = PayloadError(422, "unprocessable")
    buf.push({"x": 1})

    sender = _run_sender_once(buf, cfg, mock_client)

    assert buf.pending_count() == 0


# ---------------------------------------------------------------------------
# No token leakage in logs
# ---------------------------------------------------------------------------

def test_no_token_in_logs(buf, cfg, mock_client, caplog):
    """The ingestion token must never appear in log output."""
    import logging
    mock_client.ingest_events.side_effect = AuthError(401, "unauthorized")
    buf.push({"a": 1})

    with caplog.at_level(logging.DEBUG, logger="soc_exporter"):
        _run_sender_once(buf, cfg, mock_client)

    token = cfg.ingestion_token
    for record in caplog.records:
        assert token not in record.getMessage(), (
            f"Token found in log: {record.getMessage()}"
        )


def test_no_token_in_network_error_logs(buf, cfg, mock_client, caplog):
    import logging
    mock_client.ingest_events.side_effect = NetworkError(
        f"Connection failed: token={cfg.ingestion_token}"
    )
    buf.push({"a": 1})

    with caplog.at_level(logging.DEBUG, logger="soc_exporter"):
        _run_sender_once(buf, cfg, mock_client)

    token = cfg.ingestion_token
    for record in caplog.records:
        assert token not in record.getMessage()


# ---------------------------------------------------------------------------
# agent_groups feature
# ---------------------------------------------------------------------------

def _make_config_with_groups(**overrides):
    data = {
        "installation_id": "inst-test",
        "ingestion_token": "secret-token-abc",
        "api_url": "https://soc-api.example.com",
        "send_batch_size": 10,
        "send_interval": 1,
        "retry_base_delay": 0.1,
        "retry_max_delay": 1.0,
        "send_agent_groups": True,
    }
    data.update(overrides)
    return Config(data)


def _enriched_event(agent_name: str) -> dict:
    return {"raw": {"agent": {"name": agent_name}}, "hostname": "manager"}


def test_agent_groups_included_when_cache_populated(buf, mock_client):
    mock_client.ingest_events.return_value = {}
    cfg = _make_config_with_groups()

    group_cache = MagicMock()
    group_cache.get_for_batch.return_value = [
        {"agent_name": "AGENT-A", "group_name": "nox5-tecnica"}
    ]

    buf.push(_enriched_event("AGENT-A"))
    _run_sender_once(buf, cfg, mock_client, group_cache=group_cache)

    _, kwargs = mock_client.ingest_events.call_args
    assert kwargs["agent_groups"] == [
        {"agent_name": "AGENT-A", "group_name": "nox5-tecnica"}
    ]


def test_agent_groups_omitted_when_feature_flag_false(buf, mock_client):
    mock_client.ingest_events.return_value = {}
    cfg = _make_config_with_groups(send_agent_groups=False)

    group_cache = MagicMock()

    buf.push(_enriched_event("AGENT-A"))
    _run_sender_once(buf, cfg, mock_client, group_cache=group_cache)

    group_cache.get_for_batch.assert_not_called()
    _, kwargs = mock_client.ingest_events.call_args
    assert kwargs.get("agent_groups") is None


def test_agent_groups_omitted_when_no_cache(buf, mock_client):
    mock_client.ingest_events.return_value = {}
    cfg = _make_config_with_groups()

    buf.push(_enriched_event("AGENT-A"))
    _run_sender_once(buf, cfg, mock_client, group_cache=None)

    _, kwargs = mock_client.ingest_events.call_args
    assert kwargs.get("agent_groups") is None


def test_agent_groups_omitted_when_cache_returns_empty(buf, mock_client):
    """Empty list from cache → agent_groups not sent (avoids empty [] in payload)."""
    mock_client.ingest_events.return_value = {}
    cfg = _make_config_with_groups()

    group_cache = MagicMock()
    group_cache.get_for_batch.return_value = []

    buf.push(_enriched_event("UNKNOWN-AGENT"))
    _run_sender_once(buf, cfg, mock_client, group_cache=group_cache)

    _, kwargs = mock_client.ingest_events.call_args
    assert kwargs.get("agent_groups") is None


def test_agent_groups_does_not_affect_retry_on_network_error(buf, mock_client):
    """Network failure still nacks events; groups don't interfere."""
    mock_client.ingest_events.side_effect = NetworkError("timeout")
    cfg = _make_config_with_groups()

    group_cache = MagicMock()
    group_cache.get_for_batch.return_value = [
        {"agent_name": "AGENT-A", "group_name": "g1"}
    ]

    buf.push(_enriched_event("AGENT-A"))
    sender = _run_sender_once(buf, cfg, mock_client, group_cache=group_cache)

    assert buf.pending_count() == 1
    assert sender.get_stats()["retried"] == 1
