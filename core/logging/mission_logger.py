"""
Mission Logger
==============

Structured logging for the ORACLE mission lifecycle.

Produces standardized JSON log entries that include:
- mission_id, task_id, agent, tool, event, duration_ms, status, error

Every mission produces a consistent log trail:
    Mission Created
    Planner Started
    Task Created
    Discovery Started
    Nmap Started
    Nmap Finished
    Evidence Created
    Evidence Validated
    Evidence Stored
    Mission Completed
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from core.logging import get_logger

# Standard log event types for the mission lifecycle
MISSION_LOG_EVENTS = {
    # Mission lifecycle
    "mission.created": "Mission Created",
    "mission.planner_started": "Planner Started",
    "mission.planned": "Mission Planned",
    "mission.started": "Mission Started",
    "mission.executing": "Mission Executing",
    "mission.completed": "Mission Completed",
    "mission.failed": "Mission Failed",
    "mission.cancelled": "Mission Cancelled",
    # Task lifecycle
    "task.created": "Task Created",
    "task.assigned": "Task Assigned",
    "task.started": "Task Started",
    "task.completed": "Task Completed",
    "task.failed": "Task Failed",
    "task.skipped": "Task Skipped",
    # Agent lifecycle
    "agent.started": "Agent Started",
    "agent.completed": "Agent Completed",
    "agent.failed": "Agent Failed",
    # Tool lifecycle
    "tool.started": "Tool Started",
    "tool.completed": "Tool Completed",
    "tool.failed": "Tool Failed",
    # Discovery
    "discovery.started": "Discovery Started",
    "discovery.completed": "Discovery Completed",
    # Scan lifecycle
    "scan.started": "Scan Started",
    "scan.completed": "Scan Completed",
    "scan.failed": "Scan Failed",
    # Nmap lifecycle
    "nmap.started": "Nmap Started",
    "nmap.completed": "Nmap Finished",
    "nmap.failed": "Nmap Failed",
    "nmap.parsing": "Nmap Parsing",
    "nmap.parsed": "Nmap Parsed",
    # Evidence lifecycle
    "evidence.created": "Evidence Created",
    "evidence.validated": "Evidence Validated",
    "evidence.stored_db": "Evidence Stored (PostgreSQL)",
    "evidence.stored_graph": "Evidence Stored (Neo4j)",
    "evidence.stored": "Evidence Stored",
    "evidence.failed": "Evidence Failed",
    # Persistence
    "persistence.db_connected": "Database Connected",
    "persistence.graph_connected": "Graph Database Connected",
    "persistence.db_disconnected": "Database Disconnected",
    "persistence.graph_disconnected": "Graph Database Disconnected",
    "persistence.write_started": "Persistence Write Started",
    "persistence.write_completed": "Persistence Write Completed",
    "persistence.write_failed": "Persistence Write Failed",
    # Validation
    "validation.started": "Validation Started",
    "validation.completed": "Validation Completed",
    "validation.failed": "Validation Failed",
    # Policy
    "policy.checking": "Policy Checking",
    "policy.passed": "Policy Check Passed",
    "policy.blocked": "Policy Blocked",
    # System
    "system.startup": "System Startup",
    "system.shutdown": "System Shutdown",
    "system.health": "System Health Check",
}


@dataclass
class LogEntry:
    """A single structured log entry for a mission event."""

    event: str
    mission_id: Optional[str] = None
    task_id: Optional[str] = None
    agent: str = ""
    tool: str = ""
    status: str = "success"
    duration_ms: Optional[float] = None
    error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class MissionLogger:
    """
    Structured mission logger.

    Produces standardized log entries for every stage of a mission's lifecycle.
    Each log entry includes context fields for tracing and debugging.

    Usage:
        logger = MissionLogger()
        logger.log("mission.created", mission_id=str(mission.id))
        logger.log("nmap.started", mission_id=str(mission.id), tool="nmap",
                   details={"target": "192.168.1.1", "ports": "1-1000"})
    """

    def __init__(self, name: str = "oracle.mission") -> None:
        self._logger = get_logger(name)
        self._timers: Dict[str, float] = {}

    def log(
        self,
        event: str,
        mission_id: Optional[str] = None,
        task_id: Optional[str] = None,
        agent: str = "",
        tool: str = "",
        status: str = "success",
        duration_ms: Optional[float] = None,
        error: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log a structured mission event.

        Args:
            event: The event type (e.g., "mission.created", "nmap.started")
            mission_id: UUID of the mission
            task_id: UUID of the task
            agent: Name of the agent
            tool: Name of the tool
            status: "success", "failure", "started", "completed"
            duration_ms: Duration of the operation in milliseconds
            error: Error message if status is "failure"
            details: Additional structured data
        """
        human_readable = MISSION_LOG_EVENTS.get(event, event.replace("_", " ").title())

        log_data: Dict[str, Any] = {
            "event_type": event,
            "message": human_readable,
            "mission_id": mission_id or "",
            "task_id": task_id or "",
            "agent": agent,
            "tool": tool,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if duration_ms is not None:
            log_data["duration_ms"] = round(duration_ms, 1)

        if error:
            log_data["error"] = error
            log_data["status"] = "failure"

        if details:
            # Merge details at top level for structured logging
            for key, value in details.items():
                if key not in log_data:
                    log_data[key] = value

        # Log at appropriate level — structlog uses the first positional arg as event name
        if status == "failure" or error:
            self._logger.error(event, **log_data)
        elif status == "started":
            self._logger.info(event, **log_data)
        elif status == "completed":
            self._logger.info(event, **log_data)
        elif status == "warning":
            self._logger.warning(event, **log_data)
        else:
            self._logger.info(event, **log_data)

    # ─── Timer helpers ────────────────────────────────────────────────────

    def start_timer(self, timer_id: str) -> None:
        """Start a named timer for measuring duration."""
        self._timers[timer_id] = time.monotonic()

    def elapsed_ms(self, timer_id: str) -> Optional[float]:
        """Get elapsed milliseconds for a named timer."""
        start = self._timers.get(timer_id)
        if start is None:
            return None
        return (time.monotonic() - start) * 1000.0

    def stop_timer(self, timer_id: str) -> Optional[float]:
        """Stop a named timer and return elapsed milliseconds."""
        elapsed = self.elapsed_ms(timer_id)
        self._timers.pop(timer_id, None)
        return elapsed

    # ─── Convenience methods ──────────────────────────────────────────────

    @contextmanager
    def timed_log(
        self,
        event: str,
        mission_id: Optional[str] = None,
        task_id: Optional[str] = None,
        agent: str = "",
        tool: str = "",
        details: Optional[Dict[str, Any]] = None,
    ):
        """
        Context manager that logs start/end with timing.

        Usage:
            with mission_logger.timed_log("nmap.started", mission_id=mid, tool="nmap"):
                result = await nmap.execute(targets)
        """
        timer_id = f"{event}_{mission_id}_{task_id}"
        self.start_timer(timer_id)
        self.log(
            event=event,
            mission_id=mission_id,
            task_id=task_id,
            agent=agent,
            tool=tool,
            status="started",
            details=details,
        )
        try:
            yield
            duration = self.stop_timer(timer_id)
            self.log(
                event=event.replace(".started", ".completed").replace(".started", ".completed"),
                mission_id=mission_id,
                task_id=task_id,
                agent=agent,
                tool=tool,
                status="completed",
                duration_ms=duration,
                details=details,
            )
        except Exception as e:
            duration = self.stop_timer(timer_id)
            self.log(
                event=event.replace(".started", ".failed"),
                mission_id=mission_id,
                task_id=task_id,
                agent=agent,
                tool=tool,
                status="failure",
                duration_ms=duration,
                error=str(e),
                details=details,
            )
            raise

    def log_mission_created(self, mission_id: str, mission_type: str, name: str, goal_count: int) -> None:
        """Log a mission creation event."""
        self.log(
            event="mission.created",
            mission_id=mission_id,
            status="success",
            details={
                "mission_type": mission_type,
                "mission_name": name,
                "goal_count": goal_count,
            },
        )

    def log_mission_completed(self, mission_id: str, total_tasks: int, total_evidence: int, duration_ms: float) -> None:
        """Log a mission completion event."""
        self.log(
            event="mission.completed",
            mission_id=mission_id,
            status="success",
            duration_ms=duration_ms,
            details={
                "total_tasks": total_tasks,
                "total_evidence": total_evidence,
            },
        )

    def log_mission_failed(self, mission_id: str, error: str, duration_ms: float) -> None:
        """Log a mission failure event."""
        self.log(
            event="mission.failed",
            mission_id=mission_id,
            status="failure",
            error=error,
            duration_ms=duration_ms,
        )

    def log_task_created(self, mission_id: str, task_id: str, capability: str, priority: str) -> None:
        """Log a task creation event."""
        self.log(
            event="task.created",
            mission_id=mission_id,
            task_id=task_id,
            status="success",
            details={
                "capability": capability,
                "priority": priority,
            },
        )

    def log_evidence_flow(
        self,
        mission_id: str,
        evidence_id: str,
        evidence_type: str,
        asset_value: str,
        tool: str = "",
        confidence: float = 0.0,
    ) -> None:
        """Log the evidence creation and validation flow."""
        self.log(
            event="evidence.created",
            mission_id=mission_id,
            tool=tool,
            status="success",
            details={
                "evidence_id": evidence_id,
                "evidence_type": evidence_type,
                "asset_value": asset_value,
                "confidence": confidence,
            },
        )

    def log_evidence_validated(
        self,
        mission_id: str,
        evidence_id: str,
        confidence: float,
        status: str,
        validation_method: str,
    ) -> None:
        """Log evidence validation."""
        self.log(
            event="evidence.validated",
            mission_id=mission_id,
            status=status,
            details={
                "evidence_id": evidence_id,
                "confidence": confidence,
                "validation_method": validation_method,
            },
        )

    def log_persistence(
        self,
        mission_id: str,
        target: str,
        status: str,
        duration_ms: float,
        error: Optional[str] = None,
    ) -> None:
        """Log a persistence operation."""
        self.log(
            event=f"persistence.write_{status}",
            mission_id=mission_id,
            status=status,
            duration_ms=duration_ms,
            error=error,
            details={"target": target},
        )


# Global MissionLogger singleton
_mission_logger: Optional[MissionLogger] = None


def get_mission_logger() -> MissionLogger:
    """Get or create the global MissionLogger singleton."""
    global _mission_logger
    if _mission_logger is None:
        _mission_logger = MissionLogger()
    return _mission_logger


def set_mission_logger(logger: MissionLogger) -> None:
    """Set the global MissionLogger (useful for testing)."""
    global _mission_logger
    _mission_logger = logger


__all__ = [
    "MissionLogger",
    "LogEntry",
    "MISSION_LOG_EVENTS",
    "get_mission_logger",
    "set_mission_logger",
]

