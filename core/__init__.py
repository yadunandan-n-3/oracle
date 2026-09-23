"""
ORACLE Core Package
===================

Shared infrastructure for the ORACLE OS.

Every component imports from `core`, never the other way around.
"""

from core.logging import get_logger, setup_logging
from core.config import OracleSettings, Environment, settings
from core.events import OracleEvent, EventEnvelope, EventType
from core.exceptions import (
    OracleError,
    ConfigurationError,
    ResourceNotFoundError,
    ValidationError,
    AuthenticationError,
    AuthorizationError,
    TimeoutError,
    IntegrationError,
    PolicyViolationError,
    RateLimitError,
    ToolUnavailableError,
    InvalidStateError,
)
from core.interfaces import (
    OracleAgent,
    Capability,
    AgentStatus,
    CapabilityCategory,
    Evidence,
    SecurityTool,
    OraclePlugin,
    Repository,
)
from core.telemetry import TelemetryClient, telemetry
from core.tool_manager import ToolManager, get_tool_manager

__all__ = [
    # Logging
    "get_logger",
    "setup_logging",
    # Config
    "OracleSettings",
    "Environment",
    "settings",
    # Events
    "OracleEvent",
    "EventEnvelope",
    "EventType",
    # Exceptions
    "OracleError",
    "ConfigurationError",
    "ResourceNotFoundError",
    "ValidationError",
    "AuthenticationError",
    "AuthorizationError",
    "TimeoutError",
    "IntegrationError",
    "PolicyViolationError",
    "RateLimitError",
    "ToolUnavailableError",
    "InvalidStateError",
    # Interfaces
    "OracleAgent",
    "Capability",
    "AgentStatus",
    "CapabilityCategory",
    "Evidence",
    "SecurityTool",
    "OraclePlugin",
    "Repository",
    # Telemetry
    "TelemetryClient",
    "telemetry",
    # Tool Manager
    "ToolManager",
    "get_tool_manager",
]
