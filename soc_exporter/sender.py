"""Event sender with exponential-backoff retry.

Reads batches from the buffer and ships them to the API.
On failure it calls buffer.nack() so events are rescheduled automatically.

Error handling strategy:
  NetworkError / 5xx / 429  → nack + retry with backoff (events preserved)
  AuthError (401/403)        → nack + log CRITICAL, pause 60s (avoid storm)
  PayloadError (400/422)     → ack + drop (bad payload will never succeed)
  Other APIError             → ack + drop
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone

from .api_client import APIClient, APIError, AuthError, NetworkError, PayloadError
from .buffer import Buffer
from .config import Config
from . import logger as _logger

# After an auth failure, pause this long before retrying to avoid
# hammering the API with invalid tokens.
_AUTH_PAUSE_SECONDS = 60


class Sender(threading.Thread):
    """Background thread that drains the event buffer."""

    def __init__(
        self,
        client: APIClient,
        buffer: Buffer,
        config: Config,
        stop_event: threading.Event,
    ):
        super().__init__(name="sender", daemon=True)
        self._client = client
        self._buffer = buffer
        self._cfg = config
        self._stop = stop_event
        self._log = _logger.get()
        self._stats = {
            "sent": 0,
            "failed_batches": 0,
            "retried": 0,
            "dropped": 0,
        }
        self._auth_failed = False  # latch: stops retrying on 401/403

    # ------------------------------------------------------------------
    # Thread entry
    # ------------------------------------------------------------------

    def run(self) -> None:
        inst = self._cfg.installation_id
        self._log.info(
            "[%s] Sender starting (batch=%d, interval=%ds)",
            inst,
            self._cfg.send_batch_size,
            self._cfg.send_interval,
        )
        while not self._stop.is_set():
            try:
                self._flush()
            except Exception as exc:
                self._log.error("[%s] Unexpected error in sender loop: %s", inst, exc)
            self._stop.wait(self._cfg.send_interval)

    # ------------------------------------------------------------------
    # Flush logic
    # ------------------------------------------------------------------

    def _flush(self) -> None:
        """Send one batch. Called in a loop by run()."""
        if self._auth_failed:
            return  # stay silent until operator intervenes

        items = self._buffer.fetch_ready(limit=self._cfg.send_batch_size)
        if not items:
            return

        ids = [i for i, _ in items]
        events = [e for _, e in items]
        inst = self._cfg.installation_id
        pending = self._buffer.pending_count()

        self._log.info(
            "[%s] Sending batch of %d events (queue=%d)",
            inst,
            len(events),
            pending,
        )

        try:
            result = self._client.ingest_events(inst, events)
            self._buffer.ack(ids)
            self._stats["sent"] += len(ids)

            request_id = result.get("_request_id", "")
            rid_tag = f" rid={request_id}" if request_id else ""
            self._log.info(
                "[%s] Sent %d events%s (total_sent=%d)",
                inst,
                len(ids),
                rid_tag,
                self._stats["sent"],
            )
            self._write_meta(last_error=None)

        except AuthError as exc:
            # Token is invalid — do not retry, alert operator.
            self._auth_failed = True
            self._stats["failed_batches"] += 1
            msg = (
                f"[{inst}] AUTH FAILURE (HTTP {exc.status_code}) — "
                "ingestion token is invalid or revoked. "
                "Run 'soc-exporter init' to re-register. "
                "Sending is SUSPENDED."
            )
            self._log.critical(msg)
            self._buffer.nack(
                ids,
                base_delay=_AUTH_PAUSE_SECONDS,
                max_delay=_AUTH_PAUSE_SECONDS,
            )
            self._write_meta(last_error=f"AUTH_FAILURE HTTP {exc.status_code}")

        except PayloadError as exc:
            # Malformed payload — drop to avoid infinite loop.
            self._buffer.ack(ids)
            self._stats["dropped"] += len(ids)
            self._log.error(
                "[%s] Payload rejected (HTTP %d) — dropping %d events. "
                "Check Wazuh alert format. rid=%s",
                inst,
                exc.status_code,
                len(ids),
                exc.request_id or "n/a",
            )
            self._write_meta(last_error=f"PAYLOAD_REJECTED HTTP {exc.status_code}")

        except (NetworkError, APIError) as exc:
            retryable = isinstance(exc, NetworkError) or exc.is_retryable()
            if retryable:
                self._buffer.nack(
                    ids,
                    base_delay=self._cfg.retry_base_delay,
                    max_delay=self._cfg.retry_max_delay,
                )
                self._stats["retried"] += len(ids)
                self._log.warning(
                    "[%s] Send failed (%s) — %d events rescheduled for retry. queue=%d",
                    inst,
                    exc,
                    len(ids),
                    pending,
                )
                self._write_meta(last_error=str(exc)[:120])
            else:
                self._buffer.ack(ids)
                self._stats["failed_batches"] += 1
                self._log.error(
                    "[%s] Non-retryable error %s — dropping %d events.",
                    inst,
                    exc,
                    len(ids),
                )
                self._write_meta(last_error=f"NON_RETRYABLE HTTP {getattr(exc, 'status_code', '?')}")

    # ------------------------------------------------------------------
    # State persistence (readable by `soc-exporter status`)
    # ------------------------------------------------------------------

    def _write_meta(self, last_error: str | None) -> None:
        now = datetime.now(timezone.utc).isoformat()
        try:
            self._buffer.set_meta("last_send_at", now)
            if last_error is not None:
                self._buffer.set_meta("last_send_error", last_error)
            elif self._buffer.get_meta("last_send_error"):
                # Clear error on success
                self._buffer.set_meta("last_send_error", "")
        except Exception:
            pass  # never crash the sender over metadata writes

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        return {**self._stats, "auth_failed": self._auth_failed}
