"""
Circuit Breaker
===============

Implements the Circuit Breaker pattern for external dependency resilience.

States:
- CLOSED: Normal operation, requests pass through
- OPEN: Failures exceeded threshold, requests are rejected immediately
- HALF_OPEN: Testing if the dependency has recovered

Transitions:
    CLOSED → OPEN (when failure threshold exceeded)
    OPEN → HALF_OPEN (after recovery timeout)
    HALF_OPEN → CLOSED (on successful probe)
    HALF_OPEN → OPEN (on failed probe)
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Optional, TypeVar

from core.logging import get_logger
from core.telemetry import telemetry

logger = get_logger(__name__)

T = TypeVar("T")


class CircuitState(str, Enum):
    """State of a circuit breaker."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(Exception):
    """Raised when a circuit breaker is open and rejects a request."""

    def __init__(self, circuit_name: str, message: str = "") -> None:
        self.circuit_name = circuit_name
        msg = message or f"Circuit '{circuit_name}' is OPEN. Request rejected."
        super().__init__(msg)


@dataclass
class CircuitBreakerConfig:
    """Configuration for a circuit breaker."""

    failure_threshold: int = 5
    recovery_timeout_seconds: float = 30.0
    half_open_max_requests: int = 3
    consecutive_success_threshold: int = 2
    name: str = "default"


@dataclass
class CircuitStats:
    """Statistics for a circuit breaker."""

    total_calls: int = 0
    total_successes: int = 0
    total_failures: int = 0
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    last_failure_time: Optional[float] = None
    last_success_time: Optional[float] = None
    state_change_count: int = 0
    open_count: int = 0


class CircuitBreaker:
    """
    Circuit breaker for protecting external dependencies.

    Usage:
        breaker = CircuitBreaker(config=CircuitBreakerConfig(name="postgres"))
        async with breaker.protect():
            result = await db.query(...)
    """

    def __init__(self, config: Optional[CircuitBreakerConfig] = None) -> None:
        self._config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._stats = CircuitStats()
        self._half_open_tasks: int = 0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def stats(self) -> CircuitStats:
        return self._stats

    @property
    def name(self) -> str:
        return self._config.name

    async def call(self, func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """
        Execute a function through the circuit breaker.

        If the circuit is OPEN, raises CircuitOpenError.
        If the circuit is HALF_OPEN, allows limited requests through.

        Args:
            func: The function to execute
            *args: Positional arguments for the function
            **kwargs: Keyword arguments for the function

        Returns:
            The result of the function call

        Raises:
            CircuitOpenError: If the circuit is OPEN
        """
        async with self._lock:
            if self._state == CircuitState.OPEN:
                if self._recovery_timeout_elapsed():
                    self._transition_to(CircuitState.HALF_OPEN)
                else:
                    self._stats.total_calls += 1
                    telemetry.increment_counter(
                        "circuit_breaker.rejected",
                        attributes={"circuit": self._config.name, "state": self._state.value},
                    )
                    raise CircuitOpenError(
                        self._config.name,
                        f"Circuit '{self._config.name}' is OPEN. "
                        f"Retry after {self._remaining_timeout():.0f}s.",
                    )

            if self._state == CircuitState.HALF_OPEN:
                if self._half_open_tasks >= self._config.half_open_max_requests:
                    self._stats.total_calls += 1
                    raise CircuitOpenError(
                        self._config.name,
                        f"Circuit '{self._config.name}' is HALF_OPEN and at capacity.",
                    )
                self._half_open_tasks += 1

        try:
            result = await func(*args, **kwargs) if asyncio.iscoroutinefunction(func) else func(*args, **kwargs)
            await self._on_success()
            return result  # type: ignore
        except Exception as e:
            await self._on_failure(e)
            raise

    async def _on_success(self) -> None:
        """Handle a successful call."""
        async with self._lock:
            self._stats.total_calls += 1
            self._stats.total_successes += 1
            self._stats.consecutive_successes += 1
            self._stats.consecutive_failures = 0
            self._stats.last_success_time = time.monotonic()

            if self._state == CircuitState.HALF_OPEN:
                self._half_open_tasks -= 1
                if self._stats.consecutive_successes >= self._config.consecutive_success_threshold:
                    self._transition_to(CircuitState.CLOSED)

    async def _on_failure(self, error: Exception) -> None:
        """Handle a failed call."""
        async with self._lock:
            self._stats.total_calls += 1
            self._stats.total_failures += 1
            self._stats.consecutive_failures += 1
            self._stats.consecutive_successes = 0
            self._stats.last_failure_time = time.monotonic()

            if self._state == CircuitState.HALF_OPEN:
                self._half_open_tasks -= 1
                self._transition_to(CircuitState.OPEN)
            elif self._state == CircuitState.CLOSED:
                if self._stats.consecutive_failures >= self._config.failure_threshold:
                    self._transition_to(CircuitState.OPEN)

    def _transition_to(self, new_state: CircuitState) -> None:
        """Transition to a new state."""
        old_state = self._state
        self._state = new_state
        self._stats.state_change_count += 1

        if new_state == CircuitState.OPEN:
            self._stats.open_count += 1

        telemetry.increment_counter(
            "circuit_breaker.state_change",
            attributes={
                "circuit": self._config.name,
                "from": old_state.value,
                "to": new_state.value,
            },
        )

        logger.info(
            "circuit_breaker.state_change",
            name=self._config.name,
            from_state=old_state.value,
            to_state=new_state.value,
            consecutive_failures=self._stats.consecutive_failures,
        )

    def _recovery_timeout_elapsed(self) -> bool:
        """Check if the recovery timeout has elapsed since the last failure."""
        if self._stats.last_failure_time is None:
            return True
        return (time.monotonic() - self._stats.last_failure_time) >= self._config.recovery_timeout_seconds

    def _remaining_timeout(self) -> float:
        """Get remaining time before recovery timeout."""
        if self._stats.last_failure_time is None:
            return 0.0
        elapsed = time.monotonic() - self._stats.last_failure_time
        return max(0.0, self._config.recovery_timeout_seconds - elapsed)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize breaker state for observability."""
        return {
            "name": self._config.name,
            "state": self._state.value,
            "stats": {
                "total_calls": self._stats.total_calls,
                "total_successes": self._stats.total_successes,
                "total_failures": self._stats.total_failures,
                "consecutive_failures": self._stats.consecutive_failures,
                "consecutive_successes": self._stats.consecutive_successes,
                "state_changes": self._stats.state_change_count,
                "open_count": self._stats.open_count,
            },
            "config": {
                "failure_threshold": self._config.failure_threshold,
                "recovery_timeout_seconds": self._config.recovery_timeout_seconds,
                "half_open_max_requests": self._config.half_open_max_requests,
            },
        }


class CircuitBreakerRegistry:
    """Registry of named circuit breakers."""

    def __init__(self) -> None:
        self._breakers: Dict[str, CircuitBreaker] = {}

    def get_or_create(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None,
    ) -> CircuitBreaker:
        """Get an existing circuit breaker or create a new one."""
        if name not in self._breakers:
            cfg = config or CircuitBreakerConfig(name=name)
            self._breakers[name] = CircuitBreaker(cfg)
        return self._breakers[name]

    def get(self, name: str) -> Optional[CircuitBreaker]:
        """Get a circuit breaker by name."""
        return self._breakers.get(name)

    def all_health(self) -> Dict[str, Dict[str, Any]]:
        """Get health status of all circuit breakers."""
        return {name: breaker.to_dict() for name, breaker in self._breakers.items()}

    def reset(self, name: str) -> None:
        """Reset a circuit breaker to CLOSED state."""
        breaker = self._breakers.get(name)
        if breaker:
            # Re-create to reset stats
            self._breakers[name] = CircuitBreaker(breaker._config)


# Global registry
_registry: Optional[CircuitBreakerRegistry] = None


def get_circuit_breaker(name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
    """Get or create a circuit breaker from the global registry."""
    global _registry
    if _registry is None:
        _registry = CircuitBreakerRegistry()
    return _registry.get_or_create(name, config)


def get_breaker_registry() -> CircuitBreakerRegistry:
    """Get the global circuit breaker registry."""
    global _registry
    if _registry is None:
        _registry = CircuitBreakerRegistry()
    return _registry


__all__ = [
    "CircuitBreaker",
    "CircuitBreakerConfig",
    "CircuitBreakerRegistry",
    "CircuitState",
    "CircuitOpenError",
    "CircuitStats",
    "get_circuit_breaker",
    "get_breaker_registry",
]

