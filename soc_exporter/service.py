"""Main service orchestrator.

Wires together: Collector → Buffer → Sender + Heartbeat.
Handles SIGTERM/SIGINT for graceful shutdown.
"""

from __future__ import annotations

import signal
import sys
import threading
import time

from .api_client import APIClient
from .buffer import Buffer
from .collector import Collector
from .config import Config
from .heartbeat import Heartbeat
from .sender import Sender
from . import logger as _logger


class Service:
    def __init__(self, config: Config):
        self._cfg = config
        self._log = _logger.setup(config.log_level)
        self._stop = threading.Event()

    def run(self) -> None:
        cfg = self._cfg
        log = self._log

        if not cfg.is_registered():
            log.error("Agent not registered. Run 'soc-exporter init' first.")
            sys.exit(1)

        log.info(
            "Starting SOC Exporter v%s  installation=%s",
            _version(),
            cfg.installation_id,
        )

        # Core components
        client = APIClient(api_url=cfg.api_url, token=cfg.ingestion_token)
        buffer = Buffer(db_path=cfg.buffer_db_path)

        # Worker threads
        collector = Collector(
            alerts_path=cfg.wazuh_alerts_path,
            installation_id=cfg.installation_id,
            on_event=buffer.push,
            stop_event=self._stop,
        )
        sender = Sender(
            client=client,
            buffer=buffer,
            config=cfg,
            stop_event=self._stop,
        )

        def _combined_stats() -> dict:
            return {
                "collector": collector.get_stats(),
                "sender": sender.get_stats(),
                "buffer_pending": buffer.pending_count(),
            }

        heartbeat = Heartbeat(
            client=client,
            config=cfg,
            buffer=buffer,
            stats_fn=_combined_stats,
            stop_event=self._stop,
        )

        # Graceful shutdown on SIGTERM / SIGINT
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        collector.start()
        sender.start()
        heartbeat.start()

        log.info("All workers started. Watching %s", cfg.wazuh_alerts_path)

        # Block main thread until stopped
        try:
            while not self._stop.is_set():
                self._stop.wait(timeout=5)
                self._health_check(collector, sender, heartbeat, buffer)
        finally:
            self._shutdown(collector, sender, heartbeat)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _handle_signal(self, signum, _frame) -> None:
        self._log.info("Received signal %s — shutting down…", signum)
        self._stop.set()

    def _health_check(
        self,
        collector: Collector,
        sender: Sender,
        heartbeat: Heartbeat,
        buffer: Buffer,
    ) -> None:
        pending = buffer.pending_count()
        if pending > 0:
            self._log.info("Buffer pending: %d events", pending)

    def _shutdown(self, *workers) -> None:
        self._log.info("Waiting for workers to finish…")
        for w in workers:
            w.join(timeout=10)
        self._log.info("SOC Exporter stopped.")


def _version() -> str:
    try:
        from . import __version__
        return __version__
    except Exception:
        return "unknown"
