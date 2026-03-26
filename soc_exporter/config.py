"""Configuration management.

Config is stored at /etc/soc-exporter/config.json with mode 640 (root:soc-exporter).
"""

import grp
import json
import os
import stat

CONFIG_DIR = "/etc/soc-exporter"
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")

_DEFAULTS = {
    "api_url": "https://soc-api.nox5.com.br",
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
    "log_level": "INFO",
    "send_agent_groups": True,       # include agent_groups in ingest payload
    "agent_groups_refresh": 300,     # seconds between cache refreshes
    "wazuh_api_url": "https://localhost:55000",  # Wazuh REST API base URL
    "wazuh_api_user": None,          # set to enable API source (e.g. "wazuh-wui")
    "wazuh_api_password": None,      # set to enable API source
}


class Config:
    def __init__(self, data: dict):
        self._data = {**_DEFAULTS, **data}

    # -----------------------------------------------------------------
    # Accessors
    # -----------------------------------------------------------------

    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)
        try:
            return self._data[name]
        except KeyError:
            raise AttributeError(f"Config has no attribute '{name}'") from None

    def get(self, key: str, default=None):
        return self._data.get(key, default)

    def as_dict(self) -> dict:
        return dict(self._data)

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
        return bool(self._data.get("installation_id") and self._data.get("ingestion_token"))

    def update(self, **kwargs) -> None:
        self._data.update(kwargs)
