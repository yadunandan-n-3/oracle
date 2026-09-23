"""
Resource Manager
================

Manages compute resources, tool instances, and rate limiting for ORACLE.

Ensures that:
- No single mission consumes all resources
- API rate limits are respected for external tools
- Tool instances are properly sandboxed
- Resource usage is tracked for telemetry
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from uuid import UUID

from core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ResourceQuota:
    """Resource quota for a mission or agent."""

    max_concurrent_tools: int = 3
    max_memory_mb: int = 1024
    max_cpu_percent: float = 50.0
    max_duration_minutes: int = 120
    rate_limit_per_minute: int = 30


@dataclass
class ResourceUsage:
    """Current resource usage snapshot."""

    active_tools: int = 0
    memory_used_mb: float = 0.0
    cpu_percent: float = 0.0
    duration_minutes: float = 0.0
    requests_this_minute: int = 0


class ResourceManager:
    """
    Manages resource allocation and rate limiting.

    Features:
    - Per-mission resource quotas
    - Rate limiting for tool execution
    - Resource tracking for telemetry
    - Concurrent execution limits
    """

    def __init__(self) -> None:
        self._quotas: Dict[str, ResourceQuota] = {}
        self._usage: Dict[str, ResourceUsage] = {}
        self._rate_limit_windows: Dict[str, List[datetime]] = {}
        self._semaphores: Dict[str, asyncio.Semaphore] = {}

    def set_quota(self, resource_id: str, quota: ResourceQuota) -> None:
        """Set a resource quota for a mission or agent."""
        self._quotas[resource_id] = quota
        self._semaphores[resource_id] = asyncio.Semaphore(quota.max_concurrent_tools)
        self._usage[resource_id] = ResourceUsage()
        self._rate_limit_windows[resource_id] = []

    def get_quota(self, resource_id: str) -> Optional[ResourceQuota]:
        """Get the quota for a resource."""
        return self._quotas.get(resource_id)

    def get_usage(self, resource_id: str) -> Optional[ResourceUsage]:
        """Get current usage for a resource."""
        return self._usage.get(resource_id)

    async def acquire_tool_slot(self, resource_id: str) -> bool:
        """
        Acquire a slot for tool execution.

        Waits if all slots are busy.

        Args:
            resource_id: The resource identifier

        Returns:
            True if slot acquired
        """
        semaphore = self._semaphores.get(resource_id)
        if not semaphore:
            logger.warning("resource.no_quota", resource_id=resource_id)
            return False

        try:
            await asyncio.wait_for(semaphore.acquire(), timeout=30.0)
            usage = self._usage.get(resource_id)
            if usage:
                usage.active_tools += 1
            return True
        except asyncio.TimeoutError:
            logger.warning("resource.timeout", resource_id=resource_id)
            return False

    def release_tool_slot(self, resource_id: str) -> None:
        """Release a tool execution slot."""
        semaphore = self._semaphores.get(resource_id)
        if semaphore:
            semaphore.release()
            usage = self._usage.get(resource_id)
            if usage and usage.active_tools > 0:
                usage.active_tools -= 1

    def check_rate_limit(self, resource_id: str) -> bool:
        """
        Check if the resource has exceeded its rate limit.

        Args:
            resource_id: The resource identifier

        Returns:
            True if rate limit allows another request
        """
        quota = self._quotas.get(resource_id)
        if not quota:
            return True

        now = datetime.now(timezone.utc)
        window = self._rate_limit_windows.setdefault(resource_id, [])

        # Remove entries older than 1 minute
        cutoff = now - timedelta(minutes=1)
        window[:] = [t for t in window if t > cutoff]

        # Check limit
        if len(window) >= quota.rate_limit_per_minute:
            return False

        window.append(now)
        usage = self._usage.get(resource_id)
        if usage:
            usage.requests_this_minute = len(window)
        return True

    def track_duration(self, resource_id: str, minutes: float) -> None:
        """Track execution duration for a resource."""
        usage = self._usage.get(resource_id)
        if usage:
            usage.duration_minutes += minutes

    def get_resource_summary(self, resource_id: str) -> Optional[Dict[str, Any]]:
        """Get a summary of resource usage."""
        usage = self._usage.get(resource_id)
        quota = self._quotas.get(resource_id)
        if not usage or not quota:
            return None

        return {
            "resource_id": resource_id,
            "active_tools": usage.active_tools,
            "max_concurrent_tools": quota.max_concurrent_tools,
            "requests_this_minute": usage.requests_this_minute,
            "rate_limit_per_minute": quota.rate_limit_per_minute,
            "duration_minutes": usage.duration_minutes,
            "max_duration_minutes": quota.max_duration_minutes,
            "utilization_percent": (usage.active_tools / quota.max_concurrent_tools) * 100 if quota.max_concurrent_tools > 0 else 0,
        }

    def get_all_resource_summaries(self) -> List[Dict[str, Any]]:
        """Get summaries for all tracked resources."""
        return [
            summary
            for resource_id in self._quotas
            if (summary := self.get_resource_summary(resource_id))
        ]


__all__ = ["ResourceManager", "ResourceQuota", "ResourceUsage"]
