"""CLI entry point.

Commands:
  soc-exporter init    — interactive registration wizard
  soc-exporter start   — start the forwarder in the foreground
  soc-exporter status  — show current status and buffer stats
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

from . import __version__
from . import logger as _logger

_OK   = "\033[32m OK \033[0m"
_WARN = "\033[33mWARN\033[0m"
_ERR  = "\033[31mFAIL\033[0m"
_NA   = "  — "


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="soc-exporter",
        description="SOC Exporter — Wazuh event forwarder",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Register this agent with the SOC API")
    sub.add_parser("start", help="Start the event forwarder (blocking)")
    sub.add_parser("status", help="Show agent status and buffer statistics")

    args = parser.parse_args()

    if args.command == "init":
        _cmd_init()
    elif args.command == "start":
        _cmd_start()
    elif args.command == "status":
        _cmd_status()


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def _cmd_init() -> None:
    from .register import run_interactive
    run_interactive()


def _cmd_start() -> None:
    from .config import Config
    from .service import Service

    try:
        cfg = Config.load()
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)

    _logger.setup(cfg.log_level)
    Service(cfg).run()


def _cmd_status() -> None:
    from .config import Config, CONFIG_FILE
    from .buffer import Buffer

    print(f"\n=== SOC Exporter  v{__version__} ===\n")

    # ---- Config -------------------------------------------------------
    if not os.path.exists(CONFIG_FILE):
        _row("Configured", _ERR, "run 'soc-exporter init'")
        print()
        return

    try:
        cfg = Config.load()
    except Exception as exc:
        _row("Config", _ERR, str(exc))
        print()
        return

    # Verify config permissions
    try:
        mode = oct(os.stat(CONFIG_FILE).st_mode & 0o777)
        perm_ok = mode == "0o600"
        _row("Config file", _OK if perm_ok else _WARN,
             f"{CONFIG_FILE}  (mode {mode}{'  ← should be 600' if not perm_ok else ''})")
    except Exception:
        _row("Config file", _NA, CONFIG_FILE)

    _row("Installation ID", _NA, cfg.installation_id or "not set")
    _row("Agent name",      _NA, cfg.agent_name or "not set")
    _row("Environment",     _NA, cfg.environment)
    _row("API URL",         _NA, cfg.api_url)

    # ---- Alerts file --------------------------------------------------
    alerts_path = cfg.wazuh_alerts_path
    alerts_ok = os.path.exists(alerts_path)
    _row(
        "Alerts file",
        _OK if alerts_ok else _WARN,
        f"{alerts_path}{'  ← NOT FOUND' if not alerts_ok else ''}",
    )

    # ---- Buffer -------------------------------------------------------
    print()
    try:
        buf = Buffer(db_path=cfg.buffer_db_path)
        pending = buf.pending_count()
        oldest  = buf.oldest_queued_at()

        status = _OK if pending == 0 else (_WARN if pending < 1000 else _ERR)
        detail = f"{pending} events pending"
        if oldest and pending > 0:
            age = int(time.time() - oldest)
            detail += f"  (oldest {_fmt_duration(age)} ago)"
        _row("Buffer", status, detail)

        # Last heartbeat
        hb_at = buf.get_meta("last_heartbeat_at")
        hb_ok = buf.get_meta("last_heartbeat_ok")
        if hb_at:
            hb_age = _iso_age(hb_at)
            hb_status = _OK if hb_ok == "true" else _WARN
            _row("Last heartbeat", hb_status, f"{hb_at}  ({hb_age} ago)")
        else:
            _row("Last heartbeat", _NA, "no heartbeat recorded yet")

        # Last send attempt
        send_at = buf.get_meta("last_send_at")
        last_err = buf.get_meta("last_send_error") or ""
        if send_at:
            send_age = _iso_age(send_at)
            send_status = _ERR if last_err else _OK
            _row("Last send", send_status, f"{send_at}  ({send_age} ago)")
            if last_err:
                _row("Last error", _ERR, last_err)
        else:
            _row("Last send", _NA, "no send recorded yet")

    except Exception as exc:
        _row("Buffer", _ERR, f"unavailable — {exc}")

    # ---- systemd ------------------------------------------------------
    print()
    svc_active = _systemd_is_active("soc-exporter")
    _row("systemd service", _OK if svc_active else _WARN,
         "RUNNING" if svc_active else "STOPPED  (systemctl start soc-exporter)")

    print()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _row(label: str, status: str, detail: str) -> None:
    print(f"  [{status}]  {label:<20} {detail}")


def _fmt_duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    h = seconds // 3600
    m = (seconds % 3600) // 60
    return f"{h}h {m}m"


def _iso_age(iso: str) -> str:
    try:
        from datetime import datetime, timezone
        ts = datetime.fromisoformat(iso)
        age = int((datetime.now(timezone.utc) - ts).total_seconds())
        return _fmt_duration(max(age, 0))
    except Exception:
        return "?"


def _systemd_is_active(service: str) -> bool:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "--quiet", service],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False
