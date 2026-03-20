"""Tests: Logger sanitization — tokens must never appear in output."""

import logging
import pytest

from soc_exporter import logger as _logger


@pytest.fixture(autouse=True)
def reset_logger():
    """Remove handlers between tests to avoid cross-test pollution."""
    log = logging.getLogger("soc_exporter")
    log.handlers.clear()
    yield
    log.handlers.clear()


def _get_log_output(message: str, level=logging.WARNING) -> str:
    """Set up logger with a string stream and capture output."""
    import io
    buf = io.StringIO()
    log = _logger.setup("DEBUG")
    # Replace handlers with a single StringIO handler
    log.handlers.clear()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(logging.Formatter("%(message)s"))
    from soc_exporter.logger import _SanitizeFilter
    handler.addFilter(_SanitizeFilter())
    log.addHandler(handler)
    log.log(level, message)
    return buf.getvalue()


def test_bearer_token_redacted():
    out = _get_log_output("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
    assert "eyJhbG" not in out
    assert "[REDACTED]" in out


def test_token_key_value_redacted():
    out = _get_log_output("token=supersecretvalue123")
    assert "supersecretvalue123" not in out
    assert "[REDACTED]" in out


def test_normal_message_passes_through():
    out = _get_log_output("Sending 42 events to the API")
    assert "Sending 42 events" in out


def test_installation_id_not_redacted():
    out = _get_log_output("installation_id=inst-abc123")
    # installation_id is not a token pattern — must not be redacted
    assert "inst-abc123" in out
