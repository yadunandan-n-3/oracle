"""
Degraded Mode Manager
=====================

Manages graceful degradation of ORACLE functionality when
external dependencies become unavailable.

Failure Policies:
| Dependency | Runtime behavior                                       |
| ---------- | ------------------------------------------------------ |
| PostgreSQL | Retry, then continue in degraded mode if unavailable   |
| Neo4j      | Skip graph persistence, continue mission               |
| Nmap       | Mark task failed, continue remaining tasks if possible |
| Redis      | Fall back to local scheduling where feasible           |
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from core.logging import get_logger, get_mission_logger
from core.telemetry import telemetry

logger = get_logger(__name__)
mission_logger = get_mission_logger()


class DependencyStatus(str, Enum):
    """Operational status of an external dependency."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class FailurePolicy(str, Enum):
    """Failure handling policy for a dependency."""

    RETRY_THEN_DEGRADE = "retry_then_degrade"
    SKIP_AND_CONTINUE = "skip_and_continue"
    FAIL_TASK_ONLY = "fail_task_only"
    FALLBACK_LOCAL = "fallback_local"


@dataclass
class DependencyConfig:
    """Configuration for a managed dependency."""

    name: str
    policy: FailurePolicy
    critical: bool = False
    max_retries: int = 3
    timeout_seconds: int = 30
    health_check_interval: int = 60


# Default dependency configurations
DEFAULT_DEPENDENCIES = [
    DependencyConfig(
        name="postgresql",
        policy=FailurePolicy.RETRY_THEN_DEGRADE,
        critical=False,
        max_retries=3,
        timeout_seconds=30,
    ),
    DependencyConfig(
        name="neo4j",
        policy=FailurePolicy.SKIP_AND_CONTINUE,
        critical=False,
        max_retries=2,
        timeout_seconds=10,
    ),
    DependencyConfig(
        name="nmap",
        policy=FailurePolicy.FAIL_TASK_ONLY,
        critical=False,
        max_retries=1,
        timeout_seconds=600,
    ),
    DependencyConfig(
        name="redis",
        policy=FailurePolicy.FALLBACK_LOCAL,
        critical=False,
        max_retries=2,
        timeout_seconds=5,
    ),
]


class DegradedModeManager:
    """
    Manages degraded mode for ORACLE dependencies.

    Tracks which dependencies are available and provides
    decision-making about what operations to skip or modify
    when dependencies are unavailable.
    """

    def __init__(self) -> None:
        self._dependencies: Dict[str, DependencyConfig] = {}
        self._statuses: Dict[str, DependencyStatus] = {}
        self._degraded_features: Set[str] = set()

        # Register default dependencies
        for dep in DEFAULT_DEPENDENCIES:
            self.register_dependency(dep)

    def register_dependency(self, config: DependencyConfig) -> None:
        """Register a dependency for degraded mode management."""
        self._dependencies[config.name] = config
        self._statuses[config.name] = DependencyStatus.UNKNOWN

    def update_status(self, name: str, status: DependencyStatus) -> None:
        """Update the status of a dependency."""
        old_status = self._statuses.get(name, DependencyStatus.UNKNOWN)
        self._statuses[name] = status

        if old_status != status:
            telemetry.increment_counter(
                "degraded_mode.dependency_status_change",
                attributes={
                    "dependency": name,
                    "from": old_status.value,
                    "to": status.value,
                },
            )

            mission_logger.log(
                f"persistence.{name}_{status.value}",
                status=status.value,
                details={"dependency": name, "from": old_status.value, "to": status.value},
            )

            logger.info(
                "degraded_mode.status_change",
                dependency=name,
                from_status=old_status.value,
                to_status=status.value,
            )

            if status in (DependencyStatus.DEGRADED, DependencyStatus.UNAVAILABLE):
                self._degraded_features.add(name)
            else:
                self._degraded_features.discard(name)

    def get_status(self, name: str) -> DependencyStatus:
        """Get the status of a dependency."""
        return self._statuses.get(name, DependencyStatus.UNKNOWN)

    def get_policy(self, name: str) -> FailurePolicy:
        """Get the failure policy for a dependency."""
        dep = self._dependencies.get(name)
        return dep.policy if dep else FailurePolicy.FAIL_TASK_ONLY

    def is_available(self, name: str) -> bool:
        """Check if a dependency is available."""
        status = self._statuses.get(name, DependencyStatus.UNKNOWN)
        return status == DependencyStatus.HEALTHY

    def is_critical(self, name: str) -> bool:
        """Check if a dependency is marked as critical."""
        dep = self._dependencies.get(name)
        return dep.critical if dep else False

    @property
    def is_degraded(self) -> bool:
        """Check if the system is in degraded mode."""
        return len(self._degraded_features) > 0

    @property
    def degraded_features(self) -> Set[str]:
        """Get the set of features currently degraded."""
        return set(self._degraded_features)

    def should_skip_operation(self, dependency: str, operation: str) -> bool:
        """
        Determine if an operation should be skipped based on dependency policy.

        Args:
            dependency: The dependency name (e.g., "neo4j")
            operation: The operation description for logging

        Returns:
            True if the operation should be skipped
        """
        status = self._statuses.get(dependency, DependencyStatus.UNKNOWN)

        if status == DependencyStatus.HEALTHY:
            return False

        policy = self.get_policy(dependency)

        if policy == FailurePolicy.SKIP_AND_CONTINUE:
            logger.warning(
                "degraded_mode.skipping_operation",
                dependency=dependency,
                operation=operation,
                status=status.value,
            )
            return True

        if policy == FailurePolicy.FAIL_TASK_ONLY:
            # Don't skip silently — let the caller handle failure
            return False

        if policy == FailurePolicy.RETRY_THEN_DEGRADE:
            if status == DependencyStatus.UNAVAILABLE:
                logger.warning(
                    "degraded_mode.skipping_operation",
                    dependency=dependency,
                    operation=operation,
                    status=status.value,
                )
                return True

        return False

    def get_health_summary(self) -> Dict[str, Any]:
        """Get a summary of all dependency health statuses."""
        return {
            "degraded": self.is_degraded,
            "dependencies": {
                name: {
                    "status": status.value,
                    "policy": self._dependencies[name].policy.value if name in self._dependencies else "unknown",
                    "critical": self._dependencies[name].critical if name in self._dependencies else False,
                }
                for name, status in self._statuses.items()
            },
            "degraded_features": list(self._degraded_features),
        }


# Global singleton
_degraded_manager: Optional[DegradedModeManager] = None


def get_degraded_mode_manager() -> DegradedModeManager:
    """Get or create the global DegradedModeManager singleton."""
    global _degraded_manager
    if _degraded_manager is None:
        _degraded_manager = DegradedModeManager()
    return _degraded_manager


__all__ = [
    "DegradedModeManager",
    "DependencyStatus",
    "FailurePolicy",
    "DependencyConfig",
    "get_degraded_mode_manager",
]

