"""Periodic heartbeat to the SOC API."""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

_TZ_SAO_PAULO = ZoneInfo("America/Sao_Paulo")

from .api_client import APIClient, AuthError, NetworkError, APIError
from .buffer import Buffer
from .config import Config
from . import logger as _logger


class Heartbeat(threading.Thread):
    def __init__(
        self,
        client: APIClient,
        config: Config,
        buffer: Buffer,
        stats_fn=None,
        stop_event: threading.Event | None = None,
    ):
        super().__init__(name="heartbeat", daemon=True)
        self._client = client
        self._cfg = config
        self._buffer = buffer
        self._stats_fn = stats_fn or (lambda: {})
        self._stop = stop_event or threading.Event()
        self._log = _logger.get()

    def run(self) -> None:
        interval = self._cfg.heartbeat_interval
        inst = self._cfg.installation_id
        self._log.info("[%s] Heartbeat starting (interval=%ds)", inst, interval)
        while not self._stop.is_set():
            self._send()
            self._stop.wait(interval)

    def _send(self) -> None:
        inst = self._cfg.installation_id
        try:
            stats = self._stats_fn()
            self._client.heartbeat(inst, stats)
            now = datetime.now(_TZ_SAO_PAULO).isoformat()
            self._buffer.set_meta("last_heartbeat_at", now)
            self._buffer.set_meta("last_heartbeat_ok", "true")
            self._log.debug("[%s] Heartbeat sent.", inst)
        except AuthError as exc:
            self._log.critical(
                "[%s] Heartbeat AUTH FAILURE (HTTP %d) — token may be revoked.",
                inst,
                exc.status_code,
            )
            self._buffer.set_meta("last_heartbeat_ok", "false")
        except (NetworkError, APIError) as exc:
            self._log.warning("[%s] Heartbeat failed: %s", inst, exc)
            self._buffer.set_meta("last_heartbeat_ok", "false")
        except Exception as exc:
            self._log.error("[%s] Unexpected heartbeat error: %s", inst, exc)
