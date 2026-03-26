"""Agent-to-group mapping cache.

Reads Wazuh's local state to build an in-memory dict of
{agent_name: [group, ...]} without needing the Wazuh REST API.

=== Sources (read-only, no write) ===

Primary — Wazuh 4.x (global.db):
  /var/ossec/var/db/global.db

  Two query strategies are tried in order:
    1. belongs + "group" tables  — used when the agent belongs to one or more
       groups and Wazuh has populated the relational tables (standard 4.x).
    2. agent."group" column      — legacy fallback if the belongs table is
       absent or empty (older schema / fresh install with no groups set).

Fallback — older Wazuh / dev environment (filesystem):
  /var/ossec/etc/client.keys         — id → name
  /var/ossec/queue/agent-groups/{id} — group(s) per agent id

The filesystem fallback is used only when global.db does not exist.

=== Permissions ===

global.db is owned by wazuh:wazuh (mode 660).
Add soc-exporter to the wazuh group — no other permission change needed:

  sudo usermod -aG wazuh soc-exporter

The DB is opened in read-only URI mode (mode=ro), so the process can never
write to it even if file permissions were misconfigured.

Verify access before starting the service:
  sudo -u soc-exporter sqlite3 /var/ossec/var/db/global.db \
    "SELECT name FROM agent WHERE id > 0 LIMIT 5;"

=== Group name normalisation ===

Group names are normalised on ingest:
  strip()  — removes surrounding whitespace
  lower()  — canonical lower-case

Multi-group agents produce one entry per group.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from typing import Optional

from . import logger as _logger

_GLOBAL_DB_PATH   = "/var/ossec/var/db/global.db"
_CLIENT_KEYS_PATH = "/var/ossec/etc/client.keys"       # filesystem fallback
_AGENT_GROUPS_DIR = "/var/ossec/queue/agent-groups"    # filesystem fallback

# SQL: multi-group via relational tables (standard Wazuh 4.x)
_SQL_BELONGS = """
    SELECT a.name, g.name AS group_name
    FROM   agent a
    JOIN   belongs b  ON a.id  = b.id_agent
    JOIN   "group"  g ON g.id  = b.id_group
    WHERE  a.id > 0
    ORDER  BY a.name, g.name
"""

# SQL: single-group via agent."group" column (fallback / older schema)
_SQL_AGENT_GROUP = """
    SELECT name, "group"
    FROM   agent
    WHERE  id > 0
      AND  "group" IS NOT NULL
      AND  "group" != ''
"""


class AgentGroupCache(threading.Thread):
    """Background thread that keeps an in-memory agent→groups map fresh.

    Usage::

        cache = AgentGroupCache(refresh_interval=300, stop_event=stop)
        cache.load_once()   # synchronous first load before threads start
        cache.start()       # background refresh every refresh_interval seconds

        # In Sender, per-batch:
        agent_groups = cache.get_for_batch(events)
    """

    def __init__(
        self,
        refresh_interval: int = 300,
        global_db_path: str = _GLOBAL_DB_PATH,
        client_keys_path: str = _CLIENT_KEYS_PATH,
        agent_groups_dir: str = _AGENT_GROUPS_DIR,
        stop_event: Optional[threading.Event] = None,
    ):
        super().__init__(name="agent-group-cache", daemon=True)
        self._interval    = refresh_interval
        self._db_path     = global_db_path
        self._keys_path   = client_keys_path
        self._groups_dir  = agent_groups_dir
        self._stop        = stop_event or threading.Event()
        self._log         = _logger.get()
        self._lock        = threading.RLock()
        # {agent_name: [normalised_group, ...]}
        self._cache: dict[str, list[str]] = {}

    # ------------------------------------------------------------------
    # Thread entry
    # ------------------------------------------------------------------

    def run(self) -> None:
        self._log.info(
            "[agent-groups] Cache starting (refresh every %ds)", self._interval
        )
        while not self._stop.is_set():
            try:
                self._refresh()
            except Exception as exc:
                self._log.warning("[agent-groups] Refresh failed: %s", exc)
            self._stop.wait(self._interval)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_once(self) -> None:
        """Synchronous initial load — call before starting the background thread."""
        try:
            self._refresh()
        except Exception as exc:
            self._log.warning("[agent-groups] Initial load failed: %s", exc)

    def get_for_batch(self, events: list[dict]) -> list[dict]:
        """Return deduplicated agent_groups entries for agents present in *events*.

        Each entry is ``{"agent_name": str, "group_name": str}``.
        A (agent_name, group_name) pair appears at most once per call.
        Agents not found in the cache are silently omitted.

        Args:
            events: enriched event dicts as produced by Collector._enrich()
                    (shape: ``{"raw": {..., "agent": {"name": "..."}}, ...}``).
        """
        agent_names: set[str] = set()
        for event in events:
            try:
                name = event["raw"]["agent"]["name"]
                if name:
                    agent_names.add(name)
            except (KeyError, TypeError):
                continue

        result: list[dict] = []
        seen: set[tuple[str, str]] = set()

        with self._lock:
            for name in sorted(agent_names):  # sorted for deterministic output
                for group in self._cache.get(name) or []:
                    pair = (name, group)
                    if pair not in seen:
                        seen.add(pair)
                        result.append({"agent_name": name, "group_name": group})

        return result

    # ------------------------------------------------------------------
    # Internal — refresh orchestration
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        if os.path.exists(self._db_path):
            new_cache = self._read_from_global_db()
            source = "global.db"
        else:
            new_cache = self._read_from_filesystem()
            source = "filesystem (fallback)"

        with self._lock:
            self._cache = new_cache

        self._log.debug(
            "[agent-groups] Cache refreshed via %s: %d agents loaded",
            source,
            len(new_cache),
        )

    # ------------------------------------------------------------------
    # Primary: global.db (Wazuh 4.x)
    # ------------------------------------------------------------------

    def _read_from_global_db(self) -> dict[str, list[str]]:
        """Read agent→groups from global.db.

        Opens the database in read-only URI mode.  Tries the belongs+group
        relational tables first; falls back to the agent."group" column if
        those tables do not exist or are empty.
        """
        uri = f"file:{self._db_path}?mode=ro"
        try:
            conn = sqlite3.connect(uri, uri=True, timeout=5)
        except sqlite3.OperationalError as exc:
            self._log.warning(
                "[agent-groups] Cannot open %s (is soc-exporter in the wazuh group?): %s",
                self._db_path,
                exc,
            )
            return {}

        try:
            result = self._query_belongs_table(conn)
            if result:
                return result
            # belongs table exists but is empty — try agent."group" column
            return self._query_agent_group_column(conn)
        except sqlite3.OperationalError:
            # belongs or "group" table absent — try agent."group" column
            try:
                return self._query_agent_group_column(conn)
            except sqlite3.OperationalError as exc:
                self._log.warning(
                    "[agent-groups] Cannot query global.db: %s", exc
                )
                return {}
        finally:
            conn.close()

    def _query_belongs_table(self, conn: sqlite3.Connection) -> dict[str, list[str]]:
        """Query belongs + "group" tables → {agent_name: [group, ...]}."""
        result: dict[str, list[str]] = {}
        for agent_name, group_name in conn.execute(_SQL_BELONGS).fetchall():
            norm = group_name.strip().lower()
            if not norm:
                continue
            result.setdefault(agent_name, [])
            if norm not in result[agent_name]:
                result[agent_name].append(norm)
        return result

    def _query_agent_group_column(self, conn: sqlite3.Connection) -> dict[str, list[str]]:
        """Query agent."group" column → {agent_name: [group, ...]}."""
        result: dict[str, list[str]] = {}
        for agent_name, group_col in conn.execute(_SQL_AGENT_GROUP).fetchall():
            groups = [g.strip().lower() for g in group_col.split(",") if g.strip()]
            if groups:
                result[agent_name] = groups
        return result

    # ------------------------------------------------------------------
    # Fallback: filesystem (older Wazuh / dev)
    # ------------------------------------------------------------------

    def _read_from_filesystem(self) -> dict[str, list[str]]:
        """Read agent→groups from client.keys + queue/agent-groups/{id}."""
        agent_ids = self._read_client_keys()
        result: dict[str, list[str]] = {}
        for agent_id, agent_name in agent_ids.items():
            groups = self._read_agent_groups_file(agent_id)
            if groups:
                result[agent_name] = groups
        return result

    def _read_client_keys(self) -> dict[str, str]:
        """Parse client.keys → {agent_id: agent_name}.

        Format per line: ``<id> <name> <ip> <key>``
        Lines starting with ``#`` and id ``000`` (manager) are skipped.
        """
        result: dict[str, str] = {}
        try:
            with open(self._keys_path) as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    agent_id, agent_name = parts[0], parts[1]
                    if agent_id == "000":
                        continue
                    result[agent_id] = agent_name
        except FileNotFoundError:
            self._log.debug(
                "[agent-groups] client.keys not found at %s", self._keys_path
            )
        except OSError as exc:
            self._log.warning("[agent-groups] Cannot read client.keys: %s", exc)
        return result

    def _read_agent_groups_file(self, agent_id: str) -> list[str]:
        """Read queue/agent-groups/{id} → normalised group list."""
        path = os.path.join(self._groups_dir, agent_id)
        try:
            with open(path) as fh:
                raw = fh.read()
        except FileNotFoundError:
            return []
        except OSError as exc:
            self._log.debug(
                "[agent-groups] Cannot read groups for agent %s: %s",
                agent_id,
                exc,
            )
            return []
        return [g.strip().lower() for g in raw.split(",") if g.strip()]
