"""Agent registration flow (used by `soc-exporter init`)."""

from __future__ import annotations

import getpass
import sys

from .api_client import APIClient, APIError, NetworkError
from .config import Config
from . import logger as _logger


def run_interactive() -> None:
    """Prompt the user, register the agent, and write the config file."""
    log = _logger.get()

    print("\n=== SOC Exporter — Initial Setup ===\n")

    api_url = _prompt("API URL", default="https://soc-api.nox5.com.br")
    activation_key = _prompt_secret("Activation Key")
    name = _prompt("Installation name (e.g. client-prod-01)", default=None)
    environment = _prompt("Environment", choices=["prod", "hml"], default="prod")

    print("\nConnecting to the API...")
    client = APIClient(api_url=api_url)

    try:
        result = client.register_agent(
            activation_key=activation_key,
            name=name,
            environment=environment,
        )
    except NetworkError as exc:
        print(f"\n[ERROR] Could not reach the API: {exc}")
        sys.exit(1)
    except APIError as exc:
        print(f"\n[ERROR] Registration failed (HTTP {exc.status_code}): {exc.body}")
        sys.exit(1)

    # API may wrap the payload in a "data" envelope
    payload = result.get("data", result)

    installation_id = payload.get("installation_id")
    ingestion_token = payload.get("ingestion_token")

    if not installation_id or not ingestion_token:
        print(f"\n[ERROR] Unexpected API response: {result}")
        sys.exit(1)

    cfg = Config({
        "api_url": api_url,
        "installation_id": installation_id,
        "ingestion_token": ingestion_token,
        "agent_name": name,
        "environment": environment,
    })
    cfg.save()

    print(f"\n[OK] Registered successfully!")
    print(f"     Installation ID : {installation_id}")
    print(f"     Config saved to : {Config.__module__}")
    print(f"\nRun 'soc-exporter start' or 'systemctl start soc-exporter' to begin.\n")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _prompt(label: str, default: str | None = None, choices: list[str] | None = None) -> str:
    hint = ""
    if choices:
        hint = f" [{'/'.join(choices)}]"
    if default:
        hint += f" (default: {default})"

    while True:
        value = input(f"{label}{hint}: ").strip()
        if not value:
            if default is not None:
                return default
            print("  This field is required.")
            continue
        if choices and value not in choices:
            print(f"  Choose one of: {', '.join(choices)}")
            continue
        return value


def _prompt_secret(label: str) -> str:
    while True:
        value = getpass.getpass(f"{label}: ").strip()
        if value:
            return value
        print("  This field is required.")
