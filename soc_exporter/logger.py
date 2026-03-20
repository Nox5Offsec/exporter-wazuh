"""Logging setup. Never logs tokens or secrets."""

import logging
import logging.handlers
import os
import re
import sys


_TOKEN_PATTERN = re.compile(
    r"(bearer\s+|token['\"]?\s*[:=]\s*)[A-Za-z0-9\-_\.]+",
    re.IGNORECASE,
)

LOG_DIR = "/var/log/soc-exporter"
LOG_FILE = os.path.join(LOG_DIR, "soc-exporter.log")


class _SanitizeFilter(logging.Filter):
    """Strip tokens and secrets from log records."""

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
    return _TOKEN_PATTERN.sub(r"\1[REDACTED]", text)


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
