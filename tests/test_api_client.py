"""Tests: APIClient error taxonomy and request_id extraction."""

import pytest
import responses as resp_lib

from soc_exporter.api_client import (
    APIClient,
    APIError,
    AuthError,
    NetworkError,
    PayloadError,
)


BASE = "https://soc-api.example.com"


@pytest.fixture()
def client():
    return APIClient(api_url=BASE, token="test-token")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _register_post(path, status, body=None, json=None, headers=None):
    resp_lib.add(
        resp_lib.POST,
        BASE + path,
        status=status,
        json=json or body or {},
        headers=headers or {},
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_ingest_success(client):
    _register_post("/v1/ingest/wazuh", 200, json={"ok": True})
    result = client.ingest_events("inst-1", [{"x": 1}])
    assert result.get("ok") is True


@resp_lib.activate
def test_request_id_extracted(client):
    resp_lib.add(
        resp_lib.POST,
        BASE + "/v1/ingest/wazuh",
        status=200,
        json={},
        headers={"X-Request-Id": "req-abc-123"},
    )
    result = client.ingest_events("inst-1", [{"x": 1}])
    assert result.get("_request_id") == "req-abc-123"


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_401_raises_auth_error(client):
    _register_post("/v1/ingest/wazuh", 401, body={"error": "unauthorized"})
    with pytest.raises(AuthError) as exc_info:
        client.ingest_events("inst-1", [{}])
    assert exc_info.value.status_code == 401
    assert not exc_info.value.is_retryable()


@resp_lib.activate
def test_403_raises_auth_error(client):
    _register_post("/v1/ingest/wazuh", 403, body={"error": "forbidden"})
    with pytest.raises(AuthError):
        client.ingest_events("inst-1", [{}])


@resp_lib.activate
def test_400_raises_payload_error(client):
    _register_post("/v1/ingest/wazuh", 400, body={"error": "bad request"})
    with pytest.raises(PayloadError) as exc_info:
        client.ingest_events("inst-1", [{}])
    assert not exc_info.value.is_retryable()


@resp_lib.activate
def test_422_raises_payload_error(client):
    _register_post("/v1/ingest/wazuh", 422, body={"error": "validation"})
    with pytest.raises(PayloadError):
        client.ingest_events("inst-1", [{}])


@resp_lib.activate
def test_500_raises_api_error_retryable(client):
    _register_post("/v1/ingest/wazuh", 500, body={"error": "internal"})
    with pytest.raises(APIError) as exc_info:
        client.ingest_events("inst-1", [{}])
    assert exc_info.value.is_retryable()


@resp_lib.activate
def test_503_retryable(client):
    _register_post("/v1/ingest/wazuh", 503, body={})
    with pytest.raises(APIError) as exc_info:
        client.ingest_events("inst-1", [{}])
    assert exc_info.value.is_retryable()


@resp_lib.activate
def test_404_not_retryable(client):
    _register_post("/v1/ingest/wazuh", 404, body={})
    with pytest.raises(APIError) as exc_info:
        client.ingest_events("inst-1", [{}])
    assert not exc_info.value.is_retryable()


# ---------------------------------------------------------------------------
# Network errors
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_connection_error_raises_network_error(client):
    import requests.exceptions
    resp_lib.add(
        resp_lib.POST,
        BASE + "/v1/ingest/wazuh",
        body=requests.exceptions.ConnectionError("refused"),
    )
    with pytest.raises(NetworkError):
        client.ingest_events("inst-1", [{}])


# ---------------------------------------------------------------------------
# Auth on request_id in error response
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_request_id_in_auth_error(client):
    resp_lib.add(
        resp_lib.POST,
        BASE + "/v1/ingest/wazuh",
        status=401,
        json={"error": "unauthorized"},
        headers={"X-Request-Id": "rid-999"},
    )
    with pytest.raises(AuthError) as exc_info:
        client.ingest_events("inst-1", [{}])
    assert exc_info.value.request_id == "rid-999"
