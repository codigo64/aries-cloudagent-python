"""Entrypoint."""

import os
from typing import Any, Mapping

from .logging import LoggingConfigurator


def common_config(settings: Mapping[str, Any]):
    """Perform common app configuration."""
    # Set up logging
    log_config = settings.get("log.config")
    log_level = settings.get("log.level") or os.getenv("LOG_LEVEL")
    log_file = settings.get("log.file")
    LoggingConfigurator.configure(log_config, log_level, log_file)
