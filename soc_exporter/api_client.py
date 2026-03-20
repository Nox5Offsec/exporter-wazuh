"""HTTP client for the SOC API.

Handles authentication, timeouts, and surface-level error reporting.
Does NOT implement retry logic — that lives in sender.py / heartbeat.py.

Error taxonomy:
  NetworkError  — transient; safe to retry (connection refused, timeout)
  APIError      — non-2xx; check is_retryable() for 5xx/429
  AuthError     — 401 or 403; do NOT retry blindly (bad token)
  PayloadError  — 400 or 422; malformed payload, do not retry
"""

from __future__ import annotations

import socket
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import logger as _logger

_CONNECT_TIMEOUT = 10   # seconds
_READ_TIMEOUT = 30      # seconds


def _build_session() -> requests.Session:
    session = requests.Session()
    # Low-level TCP retry (not our business-level retry)
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


class APIClient:
    def __init__(self, api_url: str, token: str | None = None):
        self._base = api_url.rstrip("/")
        self._token = token
        self._session = _build_session()
        self._log = _logger.get()

    # ------------------------------------------------------------------
    # Registration (no auth required)
    # ------------------------------------------------------------------

    def register_agent(self, activation_key: str, name: str, environment: str) -> dict:
        """POST /v1/agents/register — returns {installation_id, ingestion_token}."""
        payload = {
            "activation_key": activation_key,
            "name": name,
            "environment": environment,
            "hostname": socket.gethostname(),
        }
        return self._post("/v1/agents/register", json=payload, auth=False)

    # ------------------------------------------------------------------
    # Heartbeat
    # ------------------------------------------------------------------

    def heartbeat(self, installation_id: str, stats: dict | None = None) -> dict:
        """POST /v1/agents/heartbeat."""
        payload = {
            "installation_id": installation_id,
            "hostname": socket.gethostname(),
            "stats": stats or {},
        }
        return self._post("/v1/agents/heartbeat", json=payload)

    # ------------------------------------------------------------------
    # Ingest
    # ------------------------------------------------------------------

    def ingest_events(self, installation_id: str, events: list[dict]) -> dict:
        """POST /v1/ingest/wazuh — batch of events."""
        payload = {
            "installation_id": installation_id,
            "events": events,
        }
        return self._post("/v1/ingest/wazuh", json=payload)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _post(self, path: str, json: Any, auth: bool = True) -> dict:
        url = self._base + path
        headers = {"Content-Type": "application/json"}
        if auth and self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        try:
            resp = self._session.post(
                url,
                json=json,
                headers=headers,
                timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT),
            )
            request_id = resp.headers.get("X-Request-Id") or resp.headers.get("X-Request-ID")
            resp.raise_for_status()
            data = resp.json() if resp.content else {}
            if request_id:
                data["_request_id"] = request_id
            return data

        except requests.exceptions.ConnectionError as exc:
            raise NetworkError(f"Connection failed to {url}: {exc}") from exc
        except requests.exceptions.Timeout as exc:
            raise NetworkError(f"Timeout calling {url}: {exc}") from exc
        except requests.exceptions.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else 0
            body = exc.response.text[:300] if exc.response is not None else ""
            request_id = (
                exc.response.headers.get("X-Request-Id")
                if exc.response is not None
                else None
            )
            if status in (401, 403):
                raise AuthError(status, body, request_id) from exc
            if status in (400, 422):
                raise PayloadError(status, body, request_id) from exc
            raise APIError(status, body, request_id) from exc


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------

class NetworkError(Exception):
    """Transient network failure — safe to retry."""


class APIError(Exception):
    """Non-2xx HTTP response that is retryable (5xx, 429)."""

    def __init__(self, status_code: int, body: str, request_id: str | None = None):
        self.status_code = status_code
        self.body = body
        self.request_id = request_id
        rid = f" [rid={request_id}]" if request_id else ""
        super().__init__(f"HTTP {status_code}{rid}: {body}")

    def is_retryable(self) -> bool:
        return self.status_code in (429, 500, 502, 503, 504)


class AuthError(APIError):
    """401 or 403 — token is invalid or revoked. Do NOT retry blindly."""

    def is_retryable(self) -> bool:
        return False


class PayloadError(APIError):
    """400 or 422 — malformed payload. Do not retry."""

    def is_retryable(self) -> bool:
        return False
