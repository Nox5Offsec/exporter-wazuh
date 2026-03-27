"""Logging setup. Never logs tokens or secrets."""

import logging
import logging.handlers
import os
import re
import sys

# Bearer tokens and raw token fields (expanded charset covers JWT base64url + standard base64)
_BEARER_PATTERN = re.compile(
    r"(bearer\s+)[A-Za-z0-9\-_\.+/=]+",
    re.IGNORECASE,
)
# token=..., token: ..., "token": "..."
_TOKEN_FIELD_PATTERN = re.compile(
    r"(token['\"]?\s*[:=]\s*)[A-Za-z0-9\-_\.+/=]+",
    re.IGNORECASE,
)
# password=..., password: ..., "password": "...", passwd=...
_PASSWORD_PATTERN = re.compile(
    r"(passwords?['\"]?\s*[:=]\s*)\S+",
    re.IGNORECASE,
)
# https://user:secret@host or http://user:secret@host
_URL_CREDS_PATTERN = re.compile(
    r"(https?://[^:@/\s]+:)[^@\s]+(@)",
    re.IGNORECASE,
)
# Authorization: Basic <base64>
_BASIC_AUTH_PATTERN = re.compile(
    r"(basic\s+)[A-Za-z0-9+/=]+",
    re.IGNORECASE,
)

_PATTERNS = [
    (_BEARER_PATTERN,    r"\1[REDACTED]"),
    (_TOKEN_FIELD_PATTERN, r"\1[REDACTED]"),
    (_PASSWORD_PATTERN,  r"\1[REDACTED]"),
    (_URL_CREDS_PATTERN, r"\1[REDACTED]\2"),
    (_BASIC_AUTH_PATTERN, r"\1[REDACTED]"),
]

LOG_DIR = "/var/log/soc-exporter"
LOG_FILE = os.path.join(LOG_DIR, "soc-exporter.log")


class _SanitizeFilter(logging.Filter):
    """Strip tokens and secrets from log records before any handler writes them."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = _redact(str(record.msg))
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: _redact(v) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            else:
                record.args = tuple(
                    _redact(str(a)) if isinstance(a, (str, Exception)) else a
                    for a in record.args
                )
        return True


def _redact(text: str) -> str:
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def setup(level: str = "INFO") -> logging.Logger:
    numeric = getattr(logging, level.upper(), logging.INFO)

    logger = logging.getLogger("soc_exporter")
    logger.setLevel(numeric)

    if logger.handlers:
        return logger

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    sanitize = _SanitizeFilter()

    # Add filter at logger level so ALL destinations (incl. pytest caplog) are covered
    logger.addFilter(sanitize)

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    logger.addHandler(console)

    # Rotating file handler (10 MB × 5 files)
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            LOG_FILE,
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
        )
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)
    except PermissionError:
        logger.warning("Cannot write to %s, logging to console only.", LOG_DIR)

    return logger


def get() -> logging.Logger:
    return logging.getLogger("soc_exporter")
