"""Wazuh alert collector.

Follows alerts.json like `tail -F`, parsing each newline-delimited JSON
object and placing it into the buffer. Handles log rotation transparently.

=== Rotation strategy ===

Wazuh uses logrotate with two common configurations:

1. rename (default):   logrotate renames alerts.json → alerts.json.1 and
                        creates a new empty alerts.json.
   Detection:          inode of the path changes → re-open from start of
                        the new file.

2. copytruncate:        logrotate copies the file then truncates it in place
                        (same inode, same path, file shrinks to 0).
   Detection:          st_size < current file position → re-open from 0.

3. File removed:        path disappears entirely (unusual but handled).
   Detection:          FileNotFoundError on os.stat() → wait and re-open.

4. File does not exist at startup:
   Detection:          os.path.exists() loop → warn every 10s until created.

In all cases the collector thread returns from _tail_file() and run()
immediately re-enters it, opening the file from the correct offset.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Callable

from . import logger as _logger

_MAX_LINE_BYTES = 2 * 1024 * 1024   # 2 MB — max size of a single Wazuh alert
_POLL_INTERVAL = 0.2                 # seconds between read attempts when idle
_MISSING_FILE_RETRY = 10             # seconds between retries when file not found


class Collector(threading.Thread):
    """Background thread that tails the Wazuh alerts file."""

    def __init__(
        self,
        alerts_path: str,
        installation_id: str,
        on_event: Callable[[dict], None],
        stop_event: threading.Event,
    ):
        super().__init__(name="collector", daemon=True)
        self._path = alerts_path
        self._installation_id = installation_id
        self._on_event = on_event
        self._stop_event = stop_event
        self._log = _logger.get()
        self._hostname = socket.gethostname()
        self._stats = {"collected": 0, "parse_errors": 0}
        # Overridable in tests to avoid 10-second waits
        self._missing_file_retry = _MISSING_FILE_RETRY
        # On first open we skip to EOF to avoid replaying history.
        # After rotation we read from the start so nothing is missed.
        self._rotated = False

    # ------------------------------------------------------------------
    # Thread entry
    # ------------------------------------------------------------------

    def run(self) -> None:
        self._log.info("[%s] Collector starting, watching %s",
                       self._installation_id, self._path)
        while not self._stop_event.is_set():
            try:
                self._tail_file()
            except Exception as exc:
                self._log.error(
                    "[%s] Collector crashed, restarting in 5s: %s",
                    self._installation_id, exc,
                )
                self._stop_event.wait(5)

    # ------------------------------------------------------------------
    # Core tail logic
    # ------------------------------------------------------------------

    def _tail_file(self) -> None:
        # Phase 1: wait for the file to exist (handles missing-at-boot case)
        while not os.path.exists(self._path):
            self._log.warning(
                "[%s] Alerts file not found: %s — retrying in 10s",
                self._installation_id, self._path,
            )
            if self._stop_event.wait(self._missing_file_retry):
                return

        with open(self._path, "rb") as fh:
            if self._rotated:
                # After rotation: read from start so no events are missed
                fh.seek(0, os.SEEK_SET)
                self._rotated = False
            else:
                # First open: skip to end to avoid replaying historical alerts
                fh.seek(0, os.SEEK_END)
            initial_inode = os.fstat(fh.fileno()).st_ino
            self._log.info(
                "[%s] Tailing %s (inode=%d, pos=%d)",
                self._installation_id, self._path, initial_inode, fh.tell(),
            )

            partial = b""
            while not self._stop_event.is_set():
                chunk = fh.read(65536)

                if not chunk:
                    # --- Idle: check for rotation ---
                    try:
                        st = os.stat(self._path)
                    except FileNotFoundError:
                        self._log.info(
                            "[%s] Alerts file removed (rename rotation). Re-opening.",
                            self._installation_id,
                        )
                        self._rotated = True
                        return  # run() will re-enter _tail_file immediately

                    if st.st_ino != initial_inode:
                        # rename rotation: path now points to a new file
                        self._log.info(
                            "[%s] Inode changed (%d → %d): rename rotation detected.",
                            self._installation_id, initial_inode, st.st_ino,
                        )
                        self._rotated = True
                        return

                    if st.st_size < fh.tell():
                        # copytruncate rotation: same inode, file shrank
                        self._log.info(
                            "[%s] File shrank (%d → %d): copytruncate rotation detected.",
                            self._installation_id, fh.tell(), st.st_size,
                        )
                        self._rotated = True
                        return

                    self._stop_event.wait(_POLL_INTERVAL)
                    continue

                partial += chunk

                # Safety guard: prevent OOM from a runaway partial line
                if len(partial) > _MAX_LINE_BYTES * 10:
                    self._log.error(
                        "[%s] Read buffer overflow — dropping partial data to recover.",
                        self._installation_id,
                    )
                    # Try to salvage by jumping to the last newline
                    last_nl = partial.rfind(b"\n")
                    partial = partial[last_nl + 1:] if last_nl >= 0 else b""

                partial = self._process_lines(partial)

    def _process_lines(self, buf: bytes) -> bytes:
        """Parse complete newline-terminated JSON objects from the buffer."""
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                self._on_event(self._enrich(event))
                self._stats["collected"] += 1
            except json.JSONDecodeError as exc:
                self._stats["parse_errors"] += 1
                self._log.warning(
                    "[%s] JSON parse error (skipping line): %s",
                    self._installation_id, exc,
                )
        return buf

    # ------------------------------------------------------------------
    # Enrichment
    # ------------------------------------------------------------------

    def _enrich(self, event: dict) -> dict:
        return {
            "raw": event,
            "hostname": self._hostname,
            "installation_id": self._installation_id,
            "sent_at": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        return dict(self._stats)
