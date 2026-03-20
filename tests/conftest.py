"""Shared pytest fixtures and configuration."""

import logging
import pytest

# Silence noisy loggers during tests
logging.getLogger("soc_exporter").setLevel(logging.CRITICAL)
logging.getLogger("urllib3").setLevel(logging.CRITICAL)
