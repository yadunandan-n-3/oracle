"""
Structured Logging Service
==========================

Built on structlog for structured, production-grade logging.
Supports JSON output, correlation IDs, and context propagation.
"""

from __future__ import annotations

import structlog
import logging
from typing import Any
from uuid import uuid4

from core.config import settings


def setup_logging() -> None:
    """Configure structured logging for the entire ORACLE system."""
    timestamper = structlog.processors.TimeStamper(fmt="ISO")

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            timestamper,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
            if settings.is_production
            else structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Set root logger level
    root_logger = logging.getLogger()
    root_logger.setLevel(settings.log_level)

    # Quiet noisy libraries
    for name in ["uvicorn", "uvicorn.access", "httpx", "neo4j"]:
        logging.getLogger(name).setLevel(logging.WARNING)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """
    Get a structured logger instance.

    Args:
        name: Logger name (typically __name__ of calling module)

    Returns:
        A bound logger with automatic context enrichment.
    """
    return structlog.get_logger(name or __name__)


def with_correlation_id(logger: structlog.stdlib.BoundLogger, correlation_id: str | None = None) -> structlog.stdlib.BoundLogger:
    """
    Bind a correlation ID to a logger for request tracing.

    Args:
        logger: The logger to bind to
        correlation_id: Optional existing ID, generates one if not provided

    Returns:
        Logger with correlation_id bound
    """
    return logger.bind(correlation_id=correlation_id or str(uuid4()))


from core.logging.mission_logger import MissionLogger, get_mission_logger, set_mission_logger, MISSION_LOG_EVENTS, LogEntry

__all__ = [
    "setup_logging",
    "get_logger",
    "with_correlation_id",
    "MissionLogger",
    "get_mission_logger",
    "set_mission_logger",
    "MISSION_LOG_EVENTS",
    "LogEntry",
]
