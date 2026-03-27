"""Configuration management.

Config is stored at /etc/soc-exporter/config.json with mode 640 (root:soc-exporter).

Secret override via environment variables (never written back to disk):
  SOC_INGESTION_TOKEN   — overrides ingestion_token
  SOC_WAZUH_PASSWORD    — overrides wazuh_api_password
"""

import grp
import json
import logging
import os
import stat

CONFIG_DIR = "/etc/soc-exporter"
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")

# Sensitive fields that can be supplied via environment variable instead of
# being stored in the config file.  Values from env are never written to disk.
_ENV_OVERRIDES: dict[str, str] = {
    "ingestion_token":    "SOC_INGESTION_TOKEN",
    "wazuh_api_password": "SOC_WAZUH_PASSWORD",
}

_DEFAULTS = {
    "api_url": None,
    "installation_id": None,
    "ingestion_token": None,
    "agent_name": None,
    "environment": "prod",
    "wazuh_alerts_path": "/var/ossec/logs/alerts/alerts.json",
    "heartbeat_interval": 60,        # seconds
    "send_batch_size": 100,          # events per request
    "send_interval": 5,              # seconds between flush attempts
    "retry_max_attempts": 10,
    "retry_base_delay": 2.0,         # seconds (doubled each attempt)
    "retry_max_delay": 300.0,        # seconds
    "buffer_db_path": "/var/lib/soc-exporter/buffer.db",
    "buffer_max_events": 500_000,    # max events in SQLite queue (0 = unlimited)
    "buffer_overflow_policy": "drop_oldest",  # "drop_oldest" | "reject"
    "log_level": "INFO",
    "send_agent_groups": True,       # include agent_groups in ingest payload
    "agent_groups_refresh": 300,     # seconds between cache refreshes
    "wazuh_api_url": "https://localhost:55000",  # Wazuh REST API base URL
    "wazuh_api_user": None,          # set to enable API source (e.g. "wazuh-wui")
    "wazuh_api_password": None,      # set to enable API source
    "wazuh_ca_bundle": None,         # path to CA bundle for Wazuh TLS verification
}


class Config:
    def __init__(self, data: dict):
        self._data = {**_DEFAULTS, **data}

    # -----------------------------------------------------------------
    # Accessors — env vars take precedence over file values for secrets
    # -----------------------------------------------------------------

    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)
        # Env var override for sensitive fields (never touches the config file)
        if name in _ENV_OVERRIDES:
            env_val = os.environ.get(_ENV_OVERRIDES[name])
            if env_val:
                return env_val
        try:
            return self._data[name]
        except KeyError:
            raise AttributeError(f"Config has no attribute '{name}'") from None

    def get(self, key: str, default=None):
        # Also honour env var overrides when accessed via get()
        if key in _ENV_OVERRIDES:
            env_val = os.environ.get(_ENV_OVERRIDES[key])
            if env_val:
                return env_val
        return self._data.get(key, default)

    def as_dict(self) -> dict:
        return dict(self._data)

    # -----------------------------------------------------------------
    # Validation — call at startup to catch misconfiguration early
    # -----------------------------------------------------------------

    def validate(self) -> list[str]:
        """Return a list of human-readable error strings (empty = OK)."""
        errors: list[str] = []

        api_url = self._data.get("api_url") or ""
        if not api_url.startswith("https://"):
            errors.append(
                f"api_url '{api_url}' must use HTTPS"
            )

        wazuh_url = self._data.get("wazuh_api_url") or ""
        if wazuh_url and not wazuh_url.startswith("https://"):
            errors.append(
                f"wazuh_api_url '{wazuh_url}' must use HTTPS"
            )

        for key, min_val in [
            ("heartbeat_interval", 5),
            ("send_interval", 1),
            ("send_batch_size", 1),
        ]:
            val = self._data.get(key)
            if val is not None and val < min_val:
                errors.append(f"'{key}' = {val} is below minimum ({min_val})")

        ca_bundle = self._data.get("wazuh_ca_bundle")
        if ca_bundle and not os.path.isfile(ca_bundle):
            errors.append(
                f"wazuh_ca_bundle '{ca_bundle}' does not exist or is not a file"
            )

        return errors

    # -----------------------------------------------------------------
    # Persistence
    # -----------------------------------------------------------------

    def save(self) -> None:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        tmp = CONFIG_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self._data, f, indent=2)
        os.replace(tmp, CONFIG_FILE)
        os.chmod(CONFIG_FILE, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)  # 0o640
        try:
            gid = grp.getgrnam("soc-exporter").gr_gid
            os.chown(CONFIG_FILE, 0, gid)  # root:soc-exporter
        except KeyError:
            pass  # group not present (dev environment)

    @classmethod
    def load(cls) -> "Config":
        if not os.path.exists(CONFIG_FILE):
            raise FileNotFoundError(
                f"Config not found at {CONFIG_FILE}. Run 'soc-exporter init' first."
            )
        _check_config_permissions(CONFIG_FILE)
        with open(CONFIG_FILE) as f:
            data = json.load(f)
        return cls(data)

    @classmethod
    def load_or_default(cls) -> "Config":
        try:
            return cls.load()
        except FileNotFoundError:
            return cls({})

    def is_registered(self) -> bool:
        # Use __getattr__ so env var overrides are respected
        return bool(
            self._data.get("installation_id") and
            (self._data.get("ingestion_token") or os.environ.get("SOC_INGESTION_TOKEN"))
        )

    def update(self, **kwargs) -> None:
        self._data.update(kwargs)


# -----------------------------------------------------------------
# Permission guard
# -----------------------------------------------------------------

def _check_config_permissions(path: str) -> None:
    """Log a CRITICAL warning if the config file is too permissive."""
    log = logging.getLogger("soc_exporter")
    try:
        mode = os.stat(path).st_mode & 0o777
        if mode & 0o002:
            raise PermissionError(
                f"SECURITY: {path} is world-writable (mode {mode:04o}). "
                "Refusing to start — fix with: chmod 640 " + path
            )
        if mode & 0o004:
            log.critical(
                "SECURITY: %s is world-readable (mode %04o). "
                "This exposes credentials. Fix immediately: chmod 640 %s",
                path, mode, path,
            )
        if mode & 0o040 and mode & 0o004:
            pass  # already warned above
    except FileNotFoundError:
        pass
