"""
Event Definitions and Types
===========================

Standard event types for the ORACLE Event Bus.
All events in the system conform to these definitions.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class EventType(str, Enum):
    """All event types in the ORACLE system."""

    # --- System Events ---
    SYSTEM_STARTUP = "system.startup"
    SYSTEM_SHUTDOWN = "system.shutdown"
    SYSTEM_ERROR = "system.error"

    # --- Mission Events ---
    MISSION_CREATED = "mission.created"
    MISSION_PLANNED = "mission.planned"
    MISSION_STARTED = "mission.started"
    MISSION_PAUSED = "mission.paused"
    MISSION_RESUMED = "mission.resumed"
    MISSION_COMPLETED = "mission.completed"
    MISSION_FAILED = "mission.failed"
    MISSION_CANCELLED = "mission.cancelled"
    MISSION_UPDATED = "mission.updated"
    MISSION_DELETED = "mission.deleted"

    # --- Task Events ---
    MISSION_TASK_CREATED = "mission.task.created"
    MISSION_TASK_ASSIGNED = "mission.task.assigned"
    MISSION_TASK_STARTED = "mission.task.started"
    MISSION_TASK_COMPLETED = "mission.task.completed"
    MISSION_TASK_FAILED = "mission.task.failed"
    MISSION_TASK_SKIPPED = "mission.task.skipped"
    MISSION_TASK_BLOCKED = "mission.task.blocked"

    # --- Goal Events ---
    GOAL_CREATED = "goal.created"
    GOAL_COMPLETED = "goal.completed"
    GOAL_FAILED = "goal.failed"

    # --- Asset Events ---
    ASSET_DISCOVERED = "asset.discovered"
    ASSET_UPDATED = "asset.updated"
    ASSET_REMOVED = "asset.removed"
    ASSET_RELATIONSHIP_CREATED = "asset.relationship.created"

    # --- Evidence Events ---
    EVIDENCE_COLLECTED = "evidence.collected"
    EVIDENCE_VALIDATED = "evidence.validated"
    EVIDENCE_CORRELATED = "evidence.correlated"
    EVIDENCE_DISPUTED = "evidence.disputed"
    EVIDENCE_CONFIRMED = "evidence.confirmed"

# --- Finding Events ---
    FINDING_CREATED = "finding.created"
    FINDING_VALIDATED = "finding.validated"
    FINDING_UPDATED = "finding.updated"
    FINDING_RESOLVED = "finding.resolved"
    FINDING_ACCEPTED = "finding.accepted"
    FINDING_FALSE_POSITIVE = "finding.false_positive"
    FINDING_ENRICHED = "finding.enriched"
    FINDING_CORRELATED = "finding.correlated"

    # --- Risk Events ---
    RISK_ASSESSED = "risk.assessed"
    RISK_UPDATED = "risk.updated"
    RISK_THRESHOLD_EXCEEDED = "risk.threshold.exceeded"

    # --- Scan Events ---
    SCAN_STARTED = "scan.started"
    SCAN_PROGRESS = "scan.progress"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"

    # --- Tool Events ---
    TOOL_EXECUTION_STARTED = "tool.execution.started"
    TOOL_EXECUTION_COMPLETED = "tool.execution.completed"
    TOOL_EXECUTION_FAILED = "tool.execution.failed"
    TOOL_REGISTERED = "tool.registered"
    TOOL_UNREGISTERED = "tool.unregistered"

    # --- Agent Events ---
    AGENT_STARTED = "agent.started"
    AGENT_COMPLETED = "agent.completed"
    AGENT_FAILED = "agent.failed"
    AGENT_STATUS_CHANGE = "agent.status.change"

    # --- Policy Events ---
    POLICY_CHECK_PASSED = "policy.check.passed"
    POLICY_CHECK_FAILED = "policy.check.failed"
    POLICY_VIOLATION = "policy.violation"
    POLICY_CREATED = "policy.created"
    POLICY_UPDATED = "policy.updated"

    # --- Knowledge Graph Events ---
    GRAPH_NODE_CREATED = "graph.node.created"
    GRAPH_RELATIONSHIP_CREATED = "graph.relationship.created"
    GRAPH_QUERY_EXECUTED = "graph.query.executed"

    # --- Report Events ---
    REPORT_GENERATED = "report.generated"
    REPORT_EXPORTED = "report.exported"

    # --- Notification Events ---
    NOTIFICATION_SENT = "notification.sent"
    ALERT_TRIGGERED = "alert.triggered"


class OracleEvent(BaseModel):
    """
    Standard event payload for the ORACLE Event Bus.

    Every event in the system conforms to this structure.
    """

    id: UUID = Field(default_factory=uuid4)
    event_type: EventType
    source: str = ""
    mission_id: Optional[UUID] = None
    goal_id: Optional[UUID] = None
    task_id: Optional[UUID] = None
    asset_id: Optional[UUID] = None
    evidence_id: Optional[UUID] = None
    finding_id: Optional[UUID] = None
    correlation_id: Optional[str] = None
    data: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    version: str = "1.0"

    model_config = {"extra": "allow"}


class EventEnvelope(BaseModel):
    """
    Wrapper for events sent through the Event Bus.

    Contains routing metadata and delivery information.
    """

    event: OracleEvent
    priority: int = 0
    ttl_seconds: int = 300
    delivered: bool = False
    delivery_attempts: int = 0
    last_error: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = {"extra": "allow"}


__all__ = [
    "EventType",
    "OracleEvent",
    "EventEnvelope",
]
