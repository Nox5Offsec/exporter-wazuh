"""Main service orchestrator.

Wires together: Collector → Buffer → Sender + Heartbeat.
Handles SIGTERM/SIGINT for graceful shutdown.
"""

from __future__ import annotations

import os
import signal
import sys
import threading

from .agent_groups import AgentGroupCache
from .api_client import APIClient
from .buffer import Buffer
from .collector import Collector
from .config import Config
from .heartbeat import Heartbeat
from .sender import Sender
from . import logger as _logger

# Warn in health-check when buffer exceeds this fraction of its limit
_BUFFER_WARN_FRACTION = 0.80


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

        # Validate config and environment before starting any thread
        self._startup_checks(cfg)

        log.info(
            "Starting SOC Exporter v%s  installation=%s",
            _version(),
            cfg.installation_id,
        )

        # Core components
        client = APIClient(api_url=cfg.api_url, token=cfg.ingestion_token)
        buffer = Buffer(
            db_path=cfg.buffer_db_path,
            max_events=cfg.get("buffer_max_events", 0),
            overflow_policy=cfg.get("buffer_overflow_policy", "drop_oldest"),
        )

        # Agent-group cache (optional feature — disabled via send_agent_groups: false)
        group_cache: AgentGroupCache | None = None
        if cfg.get("send_agent_groups", True):
            group_cache = AgentGroupCache(
                refresh_interval=cfg.get("agent_groups_refresh", 300),
                wazuh_api_url=cfg.get("wazuh_api_url", "https://localhost:55000"),
                wazuh_api_user=cfg.get("wazuh_api_user"),
                wazuh_api_password=cfg.get("wazuh_api_password"),
                wazuh_ca_bundle=cfg.get("wazuh_ca_bundle"),
                stop_event=self._stop,
            )
            group_cache.load_once()

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
            agent_group_cache=group_cache,
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
        if group_cache is not None:
            group_cache.start()

        log.info("All workers started. Watching %s", cfg.wazuh_alerts_path)

        # Block main thread until stopped
        try:
            while not self._stop.is_set():
                self._stop.wait(timeout=5)
                self._health_check(buffer, cfg)
        finally:
            workers = [collector, sender, heartbeat]
            if group_cache is not None:
                workers.append(group_cache)
            self._shutdown(*workers)

    # ------------------------------------------------------------------
    # Startup self-check
    # ------------------------------------------------------------------

    def _startup_checks(self, cfg: Config) -> None:
        log = self._log
        fatal = False

        # 1. Config field validation
        errors = cfg.validate()
        for err in errors:
            log.error("Config error: %s", err)
            fatal = True

        # 2. Alert file accessibility
        alerts_path = cfg.wazuh_alerts_path
        if not os.path.exists(alerts_path):
            log.warning(
                "Wazuh alerts file not found: %s — "
                "collector will wait for it to appear",
                alerts_path,
            )
        elif not os.access(alerts_path, os.R_OK):
            log.error(
                "Wazuh alerts file is not readable: %s — "
                "add soc-exporter to the wazuh group: "
                "sudo usermod -aG wazuh soc-exporter",
                alerts_path,
            )
            fatal = True

        # 3. Buffer directory writeable
        buf_dir = os.path.dirname(cfg.buffer_db_path)
        if not os.access(buf_dir, os.W_OK):
            log.error("Buffer directory is not writable: %s", buf_dir)
            fatal = True

        # 4. Warn if SSL verification is disabled for the Wazuh API
        if cfg.get("send_agent_groups", True) and not cfg.get("wazuh_ca_bundle"):
            log.warning(
                "Wazuh API SSL verification disabled (verify=False). "
                "Set wazuh_ca_bundle=/path/to/ca.pem to enable it."
            )

        if fatal:
            log.error("Startup checks failed — aborting.")
            sys.exit(1)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _handle_signal(self, signum, _frame) -> None:
        self._log.info("Received signal %s — shutting down…", signum)
        self._stop.set()

    def _health_check(self, buffer: Buffer, cfg: Config) -> None:
        pending = buffer.pending_count()
        if pending > 0:
            self._log.info("Buffer pending: %d events", pending)
        max_events = cfg.get("buffer_max_events", 0)
        if max_events and pending >= int(max_events * _BUFFER_WARN_FRACTION):
            self._log.warning(
                "Buffer near capacity: %d/%d events (%.0f%%). "
                "Check API connectivity.",
                pending, max_events, 100.0 * pending / max_events,
            )

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
