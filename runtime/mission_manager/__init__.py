"""
Mission Manager
===============

ORACLE's defining concept.

Users never click "Run Nmap".
They create Missions. The Mission Manager plans and orchestrates everything.

Mission lifecycle:
1. CREATE — User defines mission scope and goals
2. PLAN — Mission Manager invokes Planner to break goals into tasks
3. EXECUTE — Scheduler dispatches tasks to agents
4. MONITOR — State Manager tracks progress
5. COMPLETE — Report generated and mission closed
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from core.events import EventType, OracleEvent
from core.exceptions import InvalidStateError, OracleError, ResourceNotFoundError, ValidationError
from core.logging import get_logger
from core.telemetry import telemetry
from domain.mission import Mission, MissionGoal, MissionStatus, MissionTarget, MissionType, MISSION_TEMPLATES
from runtime.event_bus import get_event_bus

logger = get_logger(__name__)


class MissionManager:
    """
    Manages the full lifecycle of ORACLE missions.

    Services:
    - Create, read, update, cancel missions
    - Start mission execution
    - Track mission progress
    - Handle mission completion/failure
    """

    def __init__(self) -> None:
        self._missions: Dict[UUID, Mission] = {}
        self._event_bus = get_event_bus()

    # ─── Mission Lifecycle ─────────────────────────────────────────────────

    async def create_mission(
        self,
        name: str,
        mission_type: MissionType,
        target: MissionTarget,
        description: str = "",
        goals: Optional[List[str]] = None,
        priority: str = "medium",
        created_by: Optional[str] = None,
        organization_id: Optional[UUID] = None,
        project_id: Optional[UUID] = None,
    ) -> Mission:
        """
        Create a new mission.

        Validates the mission parameters and publishes MISSION_CREATED event.
        """
        # Validate target
        if not target.domains and not target.ip_ranges and not target.urls:
            raise ValidationError(
                "Mission target must specify at least one domain, IP range, or URL",
                field="target",
            )

        # Build goals from defaults if not specified
        mission_goals = []
        if goals:
            for g in goals:
                mission_goals.append(MissionGoal(description=g))
        else:
            # Use template defaults
            for template in MISSION_TEMPLATES:
                if template.mission_type == mission_type:
                    for default_goal in template.default_goals:
                        mission_goals.append(MissionGoal(description=default_goal))
                    break
            if not mission_goals:
                mission_goals.append(MissionGoal(description=f"Execute {mission_type.value} assessment"))

        # Create mission
        mission = Mission(
            name=name,
            description=description,
            mission_type=mission_type,
            priority=priority,  # type: ignore
            target=target,
            goals=mission_goals,
            status=MissionStatus.DRAFT,
            created_by=created_by,
            organization_id=organization_id,
            project_id=project_id,
        )

        self._missions[mission.id] = mission

        # Publish event
        await self._event_bus.publish(OracleEvent(
            event_type=EventType.MISSION_CREATED,
            source="mission_manager",
            mission_id=mission.id,
            data={
                "mission_id": str(mission.id),
                "mission_type": mission_type.value,
                "name": name,
                "goal_count": len(mission_goals),
            },
        ))

        logger.info(
            "mission.created",
            mission_id=str(mission.id),
            mission_type=mission_type.value,
            goal_count=len(mission_goals),
        )

        telemetry.increment_counter(
            "mission.created",
            attributes={"mission_type": mission_type.value},
        )

        return mission

    async def start_mission(self, mission_id: UUID) -> Mission:
        """
        Start executing a mission.

        Transitions from DRAFT/PENDING to PLANNING, then IN_PROGRESS.
        """
        mission = self._get_mission(mission_id)

        if mission.status not in {MissionStatus.DRAFT, MissionStatus.PENDING, MissionStatus.PAUSED}:
            raise InvalidStateError(
                message=f"Cannot start mission in status: {mission.status.value}",
                current_state=mission.status.value,
                expected_state="draft, pending, or paused",
            )

        mission.status = MissionStatus.PLANNING
        mission.started_at = datetime.now(timezone.utc)
        mission.updated_at = datetime.now(timezone.utc)

        await self._event_bus.publish(OracleEvent(
            event_type=EventType.MISSION_STARTED,
            source="mission_manager",
            mission_id=mission.id,
            data={"mission_id": str(mission.id)},
        ))

        logger.info("mission.started", mission_id=str(mission_id))
        return mission

    async def complete_mission(self, mission_id: UUID) -> Mission:
        """Mark a mission as completed successfully."""
        mission = self._get_mission(mission_id)
        mission.status = MissionStatus.COMPLETED
        mission.completed_at = datetime.now(timezone.utc)
        mission.updated_at = datetime.now(timezone.utc)

        await self._event_bus.publish(OracleEvent(
            event_type=EventType.MISSION_COMPLETED,
            source="mission_manager",
            mission_id=mission.id,
            data={
                "mission_id": str(mission.id),
                "total_assets": mission.total_assets_discovered,
                "total_findings": mission.total_findings,
            },
        ))

        telemetry.record_histogram(
            "mission.duration_seconds",
            value=(mission.completed_at - mission.started_at).total_seconds()
            if mission.started_at else 0,
            attributes={"mission_type": mission.mission_type.value},
        )

        logger.info("mission.completed", mission_id=str(mission_id))
        return mission

    async def fail_mission(self, mission_id: UUID, error: str) -> Mission:
        """Mark a mission as failed."""
        mission = self._get_mission(mission_id)
        mission.status = MissionStatus.FAILED
        mission.completed_at = datetime.now(timezone.utc)
        mission.updated_at = datetime.now(timezone.utc)
        mission.metadata["failure_reason"] = error

        await self._event_bus.publish(OracleEvent(
            event_type=EventType.MISSION_FAILED,
            source="mission_manager",
            mission_id=mission.id,
            data={"mission_id": str(mission.id), "error": error},
        ))

        logger.error("mission.failed", mission_id=str(mission_id), error=error)
        return mission

    async def cancel_mission(self, mission_id: UUID) -> Mission:
        """Cancel a running mission."""
        mission = self._get_mission(mission_id)
        mission.status = MissionStatus.CANCELLED
        mission.updated_at = datetime.now(timezone.utc)

        await self._event_bus.publish(OracleEvent(
            event_type=EventType.MISSION_CANCELLED,
            source="mission_manager",
            mission_id=mission.id,
            data={"mission_id": str(mission.id)},
        ))

        logger.info("mission.cancelled", mission_id=str(mission_id))
        return mission

    # ─── Mission Queries ───────────────────────────────────────────────────

    def get_mission(self, mission_id: UUID) -> Optional[Mission]:
        """Get a mission by ID."""
        return self._missions.get(mission_id)

    def list_missions(
        self,
        organization_id: Optional[UUID] = None,
        project_id: Optional[UUID] = None,
        status: Optional[MissionStatus] = None,
        mission_type: Optional[MissionType] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Mission]:
        """List missions with optional filtering."""
        missions = list(self._missions.values())

        if organization_id:
            missions = [m for m in missions if m.organization_id == organization_id]
        if project_id:
            missions = [m for m in missions if m.project_id == project_id]
        if status:
            missions = [m for m in missions if m.status == status]
        if mission_type:
            missions = [m for m in missions if m.mission_type == mission_type]

        # Sort by created_at descending
        missions.sort(key=lambda m: m.created_at, reverse=True)

        return missions[offset : offset + limit]

    def get_mission_templates(self) -> list:
        """Get available mission templates."""
        return [
            {
                "id": str(t.id),
                "name": t.name,
                "description": t.description,
                "mission_type": t.mission_type.value,
                "default_goals": t.default_goals,
                "estimated_duration_minutes": t.estimated_duration_minutes,
            }
            for t in MISSION_TEMPLATES
        ]

    # ─── Progress Tracking ─────────────────────────────────────────────────

    async def update_progress(
        self,
        mission_id: UUID,
        assets_discovered: int = 0,
        findings: int = 0,
        critical: int = 0,
        high: int = 0,
        medium: int = 0,
        low: int = 0,
    ) -> None:
        """Update mission progress counters."""
        mission = self._get_mission(mission_id)
        mission.total_assets_discovered += assets_discovered
        mission.total_findings += findings
        mission.critical_findings += critical
        mission.high_findings += high
        mission.medium_findings += medium
        mission.low_findings += low
        mission.updated_at = datetime.now(timezone.utc)

    async def mark_goal_completed(self, mission_id: UUID, goal_id: UUID) -> None:
        """Mark a mission goal as completed."""
        mission = self._get_mission(mission_id)
        for goal in mission.goals:
            if goal.id == goal_id:
                goal.completed = True
                goal.completed_at = datetime.now(timezone.utc)
                break

    # ─── Internal ──────────────────────────────────────────────────────────

    def _get_mission(self, mission_id: UUID) -> Mission:
        """Get mission or raise."""
        mission = self._missions.get(mission_id)
        if mission is None:
            raise ResourceNotFoundError("Mission", str(mission_id))
        return mission


__all__ = ["MissionManager"]
