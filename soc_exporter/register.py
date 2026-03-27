"""Agent registration flow (used by `soc-exporter init`)."""

from __future__ import annotations

import getpass
import sys

import warnings

import requests
import urllib3

from .api_client import APIClient, APIError, NetworkError
from .config import Config
from . import logger as _logger


def run_interactive() -> None:
    """Prompt the user, register the agent, and write the config file."""
    log = _logger.get()

    print("\n=== SOC Exporter — Initial Setup ===\n")

    # ------------------------------------------------------------------
    # Step 1: SOC API
    # ------------------------------------------------------------------
    print("--- [1/2] SOC API ---\n")

    api_url        = _prompt("API URL", default="https://soc-api.nox5.com.br")
    activation_key = _prompt_secret("Activation Key")
    name           = _prompt("Installation name (e.g. client-prod-01)", default=None)
    environment    = _prompt("Environment", choices=["prod", "hml"], default="prod")

    # ------------------------------------------------------------------
    # Step 2: Wazuh API (agent group detection)
    # ------------------------------------------------------------------
    print("\n--- [2/2] Wazuh API — detecção de grupos de agentes ---\n")
    print("  Necessário para enviar agent_groups junto com os alertas.")
    print("  Usuário recomendado: wazuh-wui  (já existe no Wazuh por padrão)\n")

    wazuh_api_url  = _prompt("Wazuh API URL", default="https://localhost:55000")
    wazuh_api_user = _prompt("Wazuh API user", default="wazuh-wui")
    wazuh_api_password = _prompt_secret("Wazuh API password")

    print("\n  Testando conexão com a API Wazuh...")
    wazuh_ok = _test_wazuh_api(wazuh_api_url, wazuh_api_user, wazuh_api_password)
    if wazuh_ok:
        print("  [OK] Autenticado com sucesso — grupos serão enviados nos batches.")
    else:
        print("  [WARN] Falha na autenticação. Verifique user/senha após a instalação.")
        print("         O exporter vai iniciar normalmente; grupos serão enviados assim")
        print("         que a conexão for reestabelecida.")

    # ------------------------------------------------------------------
    # Register with the SOC API
    # ------------------------------------------------------------------
    print("\nRegistrando agente na API central...")
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

    payload = result.get("data", result)

    installation_id = payload.get("installation_id")
    ingestion_token = payload.get("ingestion_token")

    if not installation_id or not ingestion_token:
        print(f"\n[ERROR] Unexpected API response: {result}")
        sys.exit(1)

    # ------------------------------------------------------------------
    # Save config
    # ------------------------------------------------------------------
    cfg = Config({
        "api_url":            api_url,
        "installation_id":    installation_id,
        "ingestion_token":    ingestion_token,
        "agent_name":         name,
        "environment":        environment,
        "wazuh_api_url":      wazuh_api_url,
        "wazuh_api_user":     wazuh_api_user,
        "wazuh_api_password": wazuh_api_password,
    })
    cfg.save()

    print(f"\n[OK] Registrado com sucesso!")
    print(f"     Installation ID : {installation_id}")
    print(f"     Config salvo em : /etc/soc-exporter/config.json")
    print(f"\nPróximos passos:")
    print(f"  systemctl start soc-exporter")
    print(f"  soc-exporter status\n")


# ---------------------------------------------------------------------------
# Wazuh API connection test
# ---------------------------------------------------------------------------

def _test_wazuh_api(api_url: str, user: str, password: str) -> bool:
    """Try to authenticate against the Wazuh API. Returns True on success.

    Uses verify=False because Wazuh ships with a self-signed certificate.
    The InsecureRequestWarning is suppressed only for this specific call.
    """
    url = api_url.rstrip("/") + "/security/user/authenticate"
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)
            resp = requests.post(
                url,
                auth=(user, password),
                verify=False,
                timeout=8,
            )
        return resp.ok and "token" in resp.json().get("data", {})
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Prompt helpers
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
