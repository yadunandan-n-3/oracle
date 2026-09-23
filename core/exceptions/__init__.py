"""
ORACLE Exception Hierarchy
===========================

Domain-specific exceptions for the ORACLE system.
Every error is typed, traceable, and serializable.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class OracleError(Exception):
    """
    Base exception for all ORACLE errors.

    Every exception in the system extends this class,
    ensuring consistent error handling and serialization.
    """

    def __init__(
        self,
        message: str = "An ORACLE error occurred",
        code: str = "INTERNAL_ERROR",
        details: Optional[Dict[str, Any]] = None,
        status_code: int = 500,
    ) -> None:
        self.message = message
        self.code = code
        self.details = details or {}
        self.status_code = status_code
        super().__init__(self.message)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the error to a dictionary for API responses."""
        return {
            "error": True,
            "code": self.code,
            "message": self.message,
            "details": self.details,
        }


class ConfigurationError(OracleError):
    """Raised when system configuration is invalid or missing."""

    def __init__(
        self,
        message: str = "Invalid configuration",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            message=message,
            code="CONFIGURATION_ERROR",
            details=details,
            status_code=500,
        )


class ResourceNotFoundError(OracleError):
    """Raised when a requested resource does not exist."""

    def __init__(
        self,
        resource_type: str = "resource",
        resource_id: str = "",
        message: str = "",
    ) -> None:
        msg = message or f"{resource_type} not found: {resource_id}"
        super().__init__(
            message=msg,
            code="RESOURCE_NOT_FOUND",
            details={"resource_type": resource_type, "resource_id": resource_id},
            status_code=404,
        )


class ValidationError(OracleError):
    """Raised when input data fails validation."""

    def __init__(
        self,
        message: str = "Validation failed",
        field: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            message=message,
            code="VALIDATION_ERROR",
            details={**(details or {}), "field": field},
            status_code=422,
        )


class AuthenticationError(OracleError):
    """Raised when authentication fails."""

    def __init__(
        self,
        message: str = "Authentication failed",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            message=message,
            code="AUTHENTICATION_ERROR",
            details=details,
            status_code=401,
        )


class AuthorizationError(OracleError):
    """Raised when the user lacks permission for an action."""

    def __init__(
        self,
        message: str = "Not authorized",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            message=message,
            code="AUTHORIZATION_ERROR",
            details=details,
            status_code=403,
        )


class TimeoutError(OracleError):
    """Raised when an operation exceeds its timeout."""

    def __init__(
        self,
        operation: str = "operation",
        timeout_seconds: int = 0,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            message=f"{operation} timed out after {timeout_seconds}s",
            code="TIMEOUT_ERROR",
            details={**(details or {}), "operation": operation, "timeout_seconds": timeout_seconds},
            status_code=504,
        )


class IntegrationError(OracleError):
    """Raised when an external integration fails."""

    def __init__(
        self,
        message: str = "External integration failed",
        service: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            message=message,
            code="INTEGRATION_ERROR",
            details={**(details or {}), "service": service},
            status_code=502,
        )


class PolicyViolationError(OracleError):
    """Raised when an action violates a security policy."""

    def __init__(
        self,
        message: str = "Policy violation",
        policy_name: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            message=message,
            code="POLICY_VIOLATION",
            details={**(details or {}), "policy_name": policy_name},
            status_code=403,
        )


class RateLimitError(OracleError):
    """Raised when rate limit is exceeded."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            message=message,
            code="RATE_LIMIT_ERROR",
            details=details,
            status_code=429,
        )


class ToolUnavailableError(OracleError):
    """Raised when a required tool is not available on the system."""

    def __init__(
        self,
        tool_name: str = "",
        message: str = "",
    ) -> None:
        msg = message or f"Tool not available: {tool_name}"
        super().__init__(
            message=msg,
            code="TOOL_UNAVAILABLE",
            details={"tool_name": tool_name},
            status_code=503,
        )


class InvalidStateError(OracleError):
    """Raised when an operation is attempted in an invalid state."""

    def __init__(
        self,
        message: str = "Invalid state for operation",
        current_state: str = "",
        expected_state: str = "",
    ) -> None:
        super().__init__(
            message=message,
            code="INVALID_STATE",
            details={
                "current_state": current_state,
                "expected_state": expected_state,
            },
            status_code=409,
        )


__all__ = [
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
]
