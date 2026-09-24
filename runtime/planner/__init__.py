"""
Planner
=======

Breaks mission goals into executable tasks.

The Planner is like the Kubernetes Scheduler for AI agents.
It analyzes the mission, determines required capabilities,
and creates an ordered task graph for execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from core.events import EventType, OracleEvent
from core.interfaces import Capability, CapabilityCategory
from core.logging import get_logger
from domain.mission import Mission, MissionGoal, MissionType
from runtime.event_bus import get_event_bus

logger = get_logger(__name__)


class TaskStatus(str, Enum):
    """Status of a planned task."""

    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class TaskPriority(int, Enum):
    """Priority levels for tasks."""

    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3


@dataclass
class Task:
    """A single executable task produced by the Planner."""

    mission_id: UUID
    id: UUID = field(default_factory=uuid4)
    goal_id: Optional[UUID] = None
    name: str = ""
    description: str = ""
    priority: TaskPriority = TaskPriority.MEDIUM
    status: TaskStatus = TaskStatus.PENDING

    # Capability requirements
    capability: str = ""
    required_capabilities: List[str] = field(default_factory=list)
    required_tools: List[str] = field(default_factory=list)

    # Canonical execution input.  A task may address one explicit target or
    # use the target collections in ``config`` for capability-wide work.
    target: Optional[str] = None
    params: Dict[str, Any] = field(default_factory=dict)
    required: bool = True

    # Dependencies
    depends_on: List[UUID] = field(default_factory=list)

    # Execution config
    config: Dict[str, Any] = field(default_factory=dict)
    timeout_seconds: int = 300
    retry_on_failure: bool = True
    max_retries: int = 3

    # Results
    evidence_ids: List[UUID] = field(default_factory=list)
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        """Keep the singular capability and compatibility list in sync."""
        if self.capability and not self.required_capabilities:
            self.required_capabilities = [self.capability]
        elif not self.capability and self.required_capabilities:
            self.capability = self.required_capabilities[0]


@dataclass
class Plan:
    """A complete execution plan for a mission."""

    mission_id: UUID
    id: UUID = field(default_factory=uuid4)
    tasks: List[Task] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    total_tasks: int = 0
    estimated_duration_minutes: int = 0


class Planner:
    """
    Mission Planner.

    Responsible for:
    - Analyzing mission goals
    - Determining required capabilities
    - Creating task dependency graph
    - Ordering tasks for optimal execution
    - Estimating duration
    """

    # Mapping from mission types to capability chains
    MISSION_CAPABILITY_MAP: Dict[MissionType, List[List[str]]] = {
        MissionType.EXTERNAL_ATTACK_SURFACE: [
            ["subdomain_enumeration", "dns_resolution"],
            ["port_scanning", "service_discovery"],
            ["technology_detection", "banner_grabbing"],
            ["ssl_analysis", "certificate_inspection"],
            ["web_crawling", "endpoint_discovery"],
            ["vulnerability_scanning", "misconfiguration_check"],
            ["risk_assessment", "reporting"],
        ],
        MissionType.API_SECURITY_ASSESSMENT: [
            ["api_discovery", "endpoint_enumeration"],
            ["authentication_testing", "authorization_testing"],
            ["input_validation", "fuzzing"],
            ["business_logic_analysis", "rate_limit_testing"],
            ["data_exposure_check", "vulnerability_scanning"],
            ["risk_assessment", "reporting"],
        ],
        MissionType.CLOUD_AUDIT: [
            ["cloud_resource_enumeration"],
            ["iam_analysis", "permission_review"],
            ["storage_audit", "exposure_check"],
            ["network_security_review", "encryption_audit"],
            ["compliance_checking", "benchmark_evaluation"],
            ["risk_assessment", "reporting"],
        ],
        MissionType.INCIDENT_INVESTIGATION: [
            ["evidence_collection", "log_acquisition"],
            ["ioc_extraction", "indicator_analysis"],
            ["timeline_reconstruction", "kill_chain_mapping"],
            ["malware_analysis", "artifacts_examination"],
            ["scope_assessment", "impact_analysis"],
            ["remediation_planning", "reporting"],
        ],
    }

    def __init__(self) -> None:
        self._plans: Dict[UUID, Plan] = {}
        self._event_bus = get_event_bus()

    async def create_plan(self, mission: Mission) -> Plan:
        """
        Create an execution plan for a mission.

        Analyzes the mission type and goals, then generates
        an ordered task graph with dependencies.
        """
        tasks: List[Task] = []
        goal_map: Dict[UUID, MissionGoal] = {g.id: g for g in mission.goals}

        # Get capability chain for this mission type
        capability_chains = self.MISSION_CAPABILITY_MAP.get(
            mission.mission_type,
            [["reconnaissance"], ["analysis"], ["reporting"]],
        )

        # Create tasks from capability chains
        previous_task_ids: List[UUID] = []
        for group_idx, capability_group in enumerate(capability_chains):
            group_tasks = []

            for cap_idx, capability in enumerate(capability_group):
                # Find matching goal
                matching_goal = None
                for gid, goal in goal_map.items():
                    if any(word in goal.description.lower() for word in capability.split("_")):
                        matching_goal = gid
                        break

                task = Task(
                    mission_id=mission.id,
                    goal_id=matching_goal,
                    name=f"{capability.replace('_', ' ').title()}",
                    description=f"Execute {capability} on mission targets",
                    # Capability chains can contain more stages than the four
                    # supported priority levels. Later stages remain LOW
                    # priority instead of constructing an invalid enum value.
                    priority=TaskPriority(min(group_idx, TaskPriority.LOW.value)),
                    status=TaskStatus.PENDING,
                    capability=capability,
                    required_capabilities=[capability],
                    depends_on=list(previous_task_ids),
                    config={
                        "target_domains": [d for d in mission.target.domains],
                        "target_ips": [ip for ip in mission.target.ip_ranges],
                        "target_urls": [u for u in mission.target.urls],
                        "goal_evidence": [],
                    },
                )
                group_tasks.append(task)

            tasks.extend(group_tasks)
            previous_task_ids = [t.id for t in group_tasks]

        # If no goals were matched, create generic tasks
        if not tasks:
            for idx, goal in enumerate(mission.goals):
                task = Task(
                    mission_id=mission.id,
                    goal_id=goal.id,
                    name=f"Goal {idx + 1}: {goal.description[:50]}",
                    description=goal.description,
                    priority=TaskPriority(min(idx, TaskPriority.LOW.value)),
                    required_capabilities=["analysis"],
                    depends_on=previous_task_ids[-1:] if previous_task_ids else [],
                    config={"goal_description": goal.description},
                )
                tasks.append(task)
                previous_task_ids = [task.id]

        # Create the plan
        plan = Plan(
            mission_id=mission.id,
            tasks=tasks,
            total_tasks=len(tasks),
            estimated_duration_minutes=len(tasks) * 15,  # Rough estimate
        )

        self._plans[plan.id] = plan

        # Mark first wave as ready
        self._update_ready_tasks(plan)

        # Publish event
        await self._event_bus.publish(OracleEvent(
            event_type=EventType.MISSION_PLANNED,
            source="planner",
            mission_id=mission.id,
            data={
                "plan_id": str(plan.id),
                "total_tasks": plan.total_tasks,
                "estimated_minutes": plan.estimated_duration_minutes,
            },
        ))

        logger.info(
            "plan.created",
            mission_id=str(mission.id),
            total_tasks=len(tasks),
            estimated_minutes=plan.estimated_duration_minutes,
        )

        return plan

    def get_plan(self, plan_id: UUID) -> Optional[Plan]:
        """Get a plan by ID."""
        return self._plans.get(plan_id)

    def register_plan(self, plan: Plan) -> None:
        """Register an externally constructed plan for workflow execution."""
        self._plans[plan.id] = plan

    def get_mission_plan(self, mission_id: UUID) -> Optional[Plan]:
        """Get the plan for a specific mission."""
        for plan in self._plans.values():
            if plan.mission_id == mission_id:
                return plan
        return None

    def get_ready_tasks(self, plan_id: UUID) -> List[Task]:
        """Get all tasks that are ready to execute."""
        plan = self._plans.get(plan_id)
        if not plan:
            return []
        return [t for t in plan.tasks if t.status == TaskStatus.READY]

    async def update_task_status(
        self,
        plan_id: UUID,
        task_id: UUID,
        status: TaskStatus,
        error: Optional[str] = None,
    ) -> List[Task]:
        """Update a task and return tasks newly unblocked by the change."""
        plan = self._plans.get(plan_id)
        if not plan:
            return []

        for task in plan.tasks:
            if task.id == task_id:
                task.status = status
                if status == TaskStatus.RUNNING:
                    task.started_at = datetime.now(timezone.utc)
                elif status in {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.SKIPPED}:
                    task.completed_at = datetime.now(timezone.utc)
                if error:
                    task.error = error
                break

        # Update ready tasks after dependency completion
        if status == TaskStatus.COMPLETED:
            return self._update_ready_tasks(plan)
        return []

    def _update_ready_tasks(self, plan: Plan) -> List[Task]:
        """Mark and return tasks whose dependencies have just completed."""
        newly_ready: List[Task] = []
        for task in plan.tasks:
            if task.status != TaskStatus.PENDING:
                continue

            # Check if all dependencies are completed
            deps_met = True
            for dep_id in task.depends_on:
                dep_task = next((t for t in plan.tasks if t.id == dep_id), None)
                if dep_task and dep_task.status != TaskStatus.COMPLETED:
                    deps_met = False
                    break

            if deps_met and not task.depends_on:
                # No dependencies — always ready
                task.status = TaskStatus.READY
                newly_ready.append(task)
            elif deps_met:
                task.status = TaskStatus.READY
                newly_ready.append(task)

        return newly_ready


__all__ = ["Planner", "Plan", "Task", "TaskStatus", "TaskPriority"]
