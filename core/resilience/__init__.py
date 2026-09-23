"""
Resilience Package
==================

Provides circuit breakers, degraded mode management, and failure policies
for graceful dependency failure handling.

Policies:
- PostgreSQL: Retry, then continue in degraded mode if unavailable
- Neo4j: Skip graph persistence, continue mission
- Nmap: Mark task failed, continue remaining tasks if possible
- Redis: Fall back to local scheduling where feasible
"""

from __future__ import annotations

from core.resilience.circuit_breaker import (
    CircuitBreaker,
    CircuitState,
    CircuitBreakerRegistry,
    CircuitOpenError,
    get_circuit_breaker,
)
from core.resilience.degraded_mode import (
    DegradedModeManager,
    FailurePolicy,
    DependencyStatus,
    get_degraded_mode_manager,
)

__all__ = [
    "CircuitBreaker",
    "CircuitState",
    "CircuitBreakerRegistry",
    "CircuitOpenError",
    "get_circuit_breaker",
    "DegradedModeManager",
    "FailurePolicy",
    "DependencyStatus",
    "get_degraded_mode_manager",
]

