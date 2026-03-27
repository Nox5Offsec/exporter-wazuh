"""Agent-to-group mapping cache.

Builds an in-memory dict of {agent_name: [group, ...]} and refreshes it
periodically in a background thread.

=== Sources (tried in order) ===

1. Wazuh REST API  — primary when wazuh_api_user + wazuh_api_password are set.
   GET /agents?select=name,group  (requires Wazuh 4.x, JWT auth)
   This is the definitive source: group assignments are always up-to-date.

2. global.db  — fallback when API credentials are not configured.
   /var/ossec/var/db/global.db  (Wazuh 4.x SQLite, read-only)
   Two sub-strategies: belongs+"group" tables → agent."group" column.

3. Filesystem  — last-resort fallback (older Wazuh / dev environments).
   /var/ossec/etc/client.keys + /var/ossec/queue/agent-groups/{id}

=== Wazuh API auth ===

Uses JWT tokens.  Flow:
  POST {wazuh_api_url}/security/user/authenticate  (Basic auth)
  → {"data": {"token": "<JWT>"}}

  GET  {wazuh_api_url}/agents?select=name,group&limit=500
  → {"data": {"affected_items": [{"name": "...", "group": ["..."]}, ...]}}

Tokens are cached and refreshed 60 s before expiry (_TOKEN_EXPIRY_BUFFER).

=== TLS verification ===

By default verify=False because Wazuh ships with a self-signed certificate.
To enable verification supply the path to a CA bundle via wazuh_ca_bundle.
A one-time WARNING is logged whenever verify=False is in use.

=== Group name normalisation ===

strip() + lower() on all group names.
Multi-group agents produce one entry per group.

=== Permissions ===

For global.db fallback, add soc-exporter to the wazuh group:
  sudo usermod -aG wazuh soc-exporter
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from typing import Optional

import requests
import urllib3

from . import logger as _logger

# Do NOT suppress InsecureRequestWarning globally — we do it conditionally
# on first use when verify=False is actually in effect.

_GLOBAL_DB_PATH   = "/var/ossec/var/db/global.db"
_CLIENT_KEYS_PATH = "/var/ossec/etc/client.keys"
_AGENT_GROUPS_DIR = "/var/ossec/queue/agent-groups"

# Re-authenticate this many seconds before the JWT actually expires
_TOKEN_EXPIRY_BUFFER = 60

# Wazuh API pagination limit (500 covers virtually all environments)
_AGENTS_PAGE_LIMIT = 500

_SQL_BELONGS = """
    SELECT a.name, g.name AS group_name
    FROM   agent a
    JOIN   belongs b  ON a.id  = b.id_agent
    JOIN   "group"  g ON g.id  = b.id_group
    WHERE  a.id > 0
    ORDER  BY a.name, g.name
"""

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

        cache = AgentGroupCache(
            wazuh_api_url="https://localhost:55000",
            wazuh_api_user="wazuh-wui",
            wazuh_api_password="<password>",
            refresh_interval=300,
            stop_event=stop,
        )
        cache.load_once()
        cache.start()

        agent_groups = cache.get_for_batch(events)
    """

    def __init__(
        self,
        refresh_interval: int = 300,
        wazuh_api_url: str = "https://localhost:55000",
        wazuh_api_user: Optional[str] = None,
        wazuh_api_password: Optional[str] = None,
        wazuh_ca_bundle: Optional[str] = None,
        global_db_path: str = _GLOBAL_DB_PATH,
        client_keys_path: str = _CLIENT_KEYS_PATH,
        agent_groups_dir: str = _AGENT_GROUPS_DIR,
        stop_event: Optional[threading.Event] = None,
    ):
        super().__init__(name="agent-group-cache", daemon=True)
        self._interval        = refresh_interval
        self._api_url         = wazuh_api_url.rstrip("/")
        self._api_user        = wazuh_api_user
        self._api_password    = wazuh_api_password
        self._db_path         = global_db_path
        self._keys_path       = client_keys_path
        self._groups_dir      = agent_groups_dir
        self._stop            = stop_event or threading.Event()
        self._log             = _logger.get()
        self._lock            = threading.RLock()
        self._cache: dict[str, list[str]] = {}
        # JWT token cache
        self._jwt_token: Optional[str] = None
        self._jwt_expires_at: float = 0.0
        # TLS: use CA bundle when provided; fall back to verify=False with a warning
        self._ssl_verify: str | bool = wazuh_ca_bundle if wazuh_ca_bundle else False
        self._ssl_warned = False
        if self._ssl_verify is False and (wazuh_api_user or wazuh_api_password):
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            self._log.warning(
                "[agent-groups] Wazuh API SSL verification DISABLED (verify=False). "
                "Set wazuh_ca_bundle in config to enable certificate verification."
            )
            self._ssl_warned = True

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
        """Synchronous first load — call before starting the background thread."""
        try:
            self._refresh()
        except Exception as exc:
            self._log.warning("[agent-groups] Initial load failed: %s", exc)

    def get_for_batch(self, events: list[dict]) -> list[dict]:  # noqa: ARG002
        """Return all cached agent_groups entries.

        Sends the full agent→group map on every batch so the backend always
        has a complete picture regardless of which agents are active in a
        given time window.

        Each entry is ``{"agent_name": str, "group_name": str}``.
        """
        result: list[dict] = []
        with self._lock:
            for name in sorted(self._cache):
                for group in self._cache[name]:
                    result.append({"agent_name": name, "group_name": group})
        return result

    # ------------------------------------------------------------------
    # Refresh orchestration
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        if self._api_user and self._api_password:
            new_cache, source = self._read_from_wazuh_api(), "wazuh-api"
        elif os.path.exists(self._db_path):
            new_cache, source = self._read_from_global_db(), "global.db"
        else:
            new_cache, source = self._read_from_filesystem(), "filesystem"

        with self._lock:
            self._cache = new_cache

        self._log.debug(
            "[agent-groups] Cache refreshed via %s: %d agents loaded",
            source,
            len(new_cache),
        )

    # ------------------------------------------------------------------
    # Source 1: Wazuh REST API
    # ------------------------------------------------------------------

    def _read_from_wazuh_api(self) -> dict[str, list[str]]:
        """Fetch agent→groups from GET /agents?select=name,group."""
        token = self._get_jwt()
        if not token:
            return {}

        url    = f"{self._api_url}/agents"
        params = {"select": "name,group", "limit": _AGENTS_PAGE_LIMIT, "offset": 0}
        headers = {"Authorization": f"Bearer {token}"}

        try:
            resp = requests.get(
                url, params=params, headers=headers,
                verify=self._ssl_verify, timeout=10,
            )
        except requests.exceptions.RequestException as exc:
            self._log.warning("[agent-groups] Wazuh API request failed: %s", exc)
            return {}

        if resp.status_code == 401:
            # Token may have expired mid-cycle — invalidate and retry once
            self._jwt_token = None
            self._jwt_expires_at = 0.0
            token = self._get_jwt()
            if not token:
                return {}
            headers["Authorization"] = f"Bearer {token}"
            try:
                resp = requests.get(
                    url, params=params, headers=headers,
                    verify=self._ssl_verify, timeout=10,
                )
            except requests.exceptions.RequestException as exc:
                self._log.warning("[agent-groups] Wazuh API retry failed: %s", exc)
                return {}

        if not resp.ok:
            self._log.warning(
                "[agent-groups] Wazuh API returned HTTP %d", resp.status_code
            )
            return {}

        try:
            items = resp.json()["data"]["affected_items"]
        except (KeyError, ValueError) as exc:
            self._log.warning("[agent-groups] Unexpected Wazuh API response: %s", exc)
            return {}

        result: dict[str, list[str]] = {}
        for item in items:
            name   = item.get("name")
            groups = item.get("group") or []
            if not name or not groups:
                continue
            normed = [g.strip().lower() for g in groups if g.strip()]
            if normed:
                result[name] = normed

        total = resp.json().get("data", {}).get("total_affected_items", 0)
        if total > _AGENTS_PAGE_LIMIT:
            self._log.warning(
                "[agent-groups] %d agents in Wazuh but only %d fetched — "
                "increase agent_groups_page_limit if needed",
                total, _AGENTS_PAGE_LIMIT,
            )

        return result

    def _get_jwt(self) -> Optional[str]:
        """Return a valid JWT token, re-authenticating if necessary."""
        if self._jwt_token and time.time() < self._jwt_expires_at:
            return self._jwt_token

        url = f"{self._api_url}/security/user/authenticate"
        try:
            resp = requests.post(
                url,
                auth=(self._api_user, self._api_password),
                verify=self._ssl_verify,
                timeout=10,
            )
        except requests.exceptions.RequestException as exc:
            self._log.warning(
                "[agent-groups] Wazuh API authentication failed: %s", exc
            )
            return None

        if not resp.ok:
            self._log.warning(
                "[agent-groups] Wazuh API authentication returned HTTP %d — "
                "check wazuh_api_user / wazuh_api_password in config",
                resp.status_code,
            )
            return None

        try:
            token = resp.json()["data"]["token"]
        except (KeyError, ValueError) as exc:
            self._log.warning(
                "[agent-groups] Unexpected auth response from Wazuh API: %s", exc
            )
            return None

        # Wazuh JWT tokens last 900 s by default; refresh _TOKEN_EXPIRY_BUFFER s early
        self._jwt_token      = token
        self._jwt_expires_at = time.time() + 900 - _TOKEN_EXPIRY_BUFFER
        return token

    # ------------------------------------------------------------------
    # Source 2: global.db (Wazuh 4.x SQLite)
    # ------------------------------------------------------------------

    def _read_from_global_db(self) -> dict[str, list[str]]:
        uri = f"file:{self._db_path}?mode=ro"
        try:
            conn = sqlite3.connect(uri, uri=True, timeout=5)
        except sqlite3.OperationalError as exc:
            self._log.warning(
                "[agent-groups] Cannot open %s (is soc-exporter in the wazuh group?): %s",
                self._db_path, exc,
            )
            return {}

        try:
            result = self._query_belongs_table(conn)
            if result:
                return result
            return self._query_agent_group_column(conn)
        except sqlite3.OperationalError:
            try:
                return self._query_agent_group_column(conn)
            except sqlite3.OperationalError as exc:
                self._log.warning("[agent-groups] Cannot query global.db: %s", exc)
                return {}
        finally:
            conn.close()

    def _query_belongs_table(self, conn: sqlite3.Connection) -> dict[str, list[str]]:
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
        result: dict[str, list[str]] = {}
        for agent_name, group_col in conn.execute(_SQL_AGENT_GROUP).fetchall():
            groups = [g.strip().lower() for g in group_col.split(",") if g.strip()]
            if groups:
                result[agent_name] = groups
        return result

    # ------------------------------------------------------------------
    # Source 3: filesystem (older Wazuh / dev)
    # ------------------------------------------------------------------

    def _read_from_filesystem(self) -> dict[str, list[str]]:
        agent_ids = self._read_client_keys()
        result: dict[str, list[str]] = {}
        for agent_id, agent_name in agent_ids.items():
            groups = self._read_agent_groups_file(agent_id)
            if groups:
                result[agent_name] = groups
        return result

    def _read_client_keys(self) -> dict[str, str]:
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
        path = os.path.join(self._groups_dir, agent_id)
        try:
            with open(path) as fh:
                raw = fh.read()
        except FileNotFoundError:
            return []
        except OSError as exc:
            self._log.debug(
                "[agent-groups] Cannot read groups for agent %s: %s", agent_id, exc
            )
            return []
        return [g.strip().lower() for g in raw.split(",") if g.strip()]
