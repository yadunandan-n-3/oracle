"""Mission workflow orchestration.

The workflow owns the terminal completion primitive for a plan. Enqueuing a
task is not completion: ``execute_plan`` returns only after every required task
has completed or the workflow reaches a terminal failure/cancellation/timeout.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
from uuid import UUID

from core.logging import get_logger
from domain.mission import Mission
from runtime.event_bus import get_event_bus
from runtime.planner import Plan, Planner, Task, TaskStatus
from runtime.scheduler import Scheduler
from runtime.state_manager import StateManager

logger = get_logger(__name__)


class WorkflowStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


@dataclass
class WorkflowResult:
    """Terminal, downstream-consumable result of one plan execution."""

    mission_id: UUID
    plan_id: UUID
    status: WorkflowStatus
    total_tasks: int
    completed_tasks: int
    failed_tasks: int
    skipped_tasks: int
    error: Optional[str] = None
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def succeeded(self) -> bool:
        return self.status == WorkflowStatus.SUCCESS


class MissingTaskHandlerError(RuntimeError):
    """Raised when a required capability has no registered implementation."""


class WorkflowEngine:
    """Execute planner dependency graphs through the scheduler."""

    def __init__(
        self,
        scheduler: Scheduler,
        state_manager: StateManager,
        planner: Optional[Planner] = None,
    ) -> None:
        self._scheduler = scheduler
        self._state_manager = state_manager
        self._planner = planner or Planner()
        self._event_bus = get_event_bus()
        self._active_workflows: Dict[UUID, Plan] = {}
        self._completion_futures: Dict[UUID, asyncio.Future[WorkflowResult]] = {}
        self._scheduled_tasks: Dict[UUID, Set[UUID]] = {}
        self._workflow_started_at: Dict[UUID, datetime] = {}
        self._task_handlers: Dict[str, Callable[[Task], Any]] = {}

        # Install callbacks before the scheduler can dispatch anything.
        self._scheduler.set_executor(self._execute_task)
        self._scheduler.set_failure_handler(self._fail_task)

    async def execute_plan(
        self,
        plan: Plan,
        mission: Mission,
        timeout_seconds: Optional[float] = None,
    ) -> WorkflowResult:
        """Execute and await a plan's actual terminal result without polling."""
        if mission.id in self._active_workflows:
            raise RuntimeError(f"Mission {mission.id} already has an active workflow")

        started_at = datetime.now(timezone.utc)
        logger.info(
            "workflow.starting",
            mission_id=str(mission.id),
            plan_id=str(plan.id),
            task_count=plan.total_tasks,
        )

        await self._state_manager.initialize_mission_state(mission, plan)
        self._planner.register_plan(plan)
        self._active_workflows[mission.id] = plan
        self._scheduled_tasks[mission.id] = set()
        self._workflow_started_at[mission.id] = started_at
        future: asyncio.Future[WorkflowResult] = asyncio.get_running_loop().create_future()
        self._completion_futures[mission.id] = future

        ready_tasks = [task for task in plan.tasks if task.status == TaskStatus.READY]
        if not plan.tasks:
            self._resolve_workflow(mission.id, WorkflowStatus.SUCCESS)
        elif not ready_tasks:
            self._resolve_workflow(
                mission.id,
                WorkflowStatus.FAILED,
                "Plan has tasks but no dependency-free task is ready",
            )
        else:
            await self._schedule_tasks(plan, ready_tasks)

        logger.info(
            "workflow.started",
            mission_id=str(mission.id),
            plan_id=str(plan.id),
            ready_tasks=len(ready_tasks),
        )

        try:
            if timeout_seconds is None:
                return await asyncio.shield(future)
            return await asyncio.wait_for(asyncio.shield(future), timeout=timeout_seconds)
        except asyncio.TimeoutError:
            error = f"Workflow timed out after {timeout_seconds} seconds"
            await self._terminate_unfinished(mission.id, error, WorkflowStatus.TIMED_OUT)
            return await asyncio.shield(future)
        except asyncio.CancelledError:
            await self._terminate_unfinished(
                mission.id,
                "Workflow execution was cancelled",
                WorkflowStatus.CANCELLED,
            )
            raise
        finally:
            self._completion_futures.pop(mission.id, None)

    async def _schedule_tasks(self, plan: Plan, tasks: List[Task]) -> None:
        scheduled = self._scheduled_tasks.setdefault(plan.mission_id, set())
        fresh = [task for task in tasks if task.id not in scheduled]
        if not fresh:
            return

        logger.info(
            "workflow.dependency_wave_ready",
            mission_id=str(plan.mission_id),
            plan_id=str(plan.id),
            task_ids=[str(task.id) for task in fresh],
            task_names=[task.name for task in fresh],
        )
        for task in fresh:
            scheduled.add(task.id)
            await self._scheduler.schedule_task(task, plan.id)

    async def _execute_task(self, task: Task) -> Any:
        """Dispatch the canonical task to its registered capability handler."""
        await self._state_manager.register_active_task(task.mission_id, task)

        capabilities = task.required_capabilities or ([task.capability] if task.capability else [])
        handler = next(
            (self._task_handlers[cap] for cap in capabilities if cap in self._task_handlers),
            None,
        )
        if handler is None:
            task.retry_on_failure = False
            logger.error(
                "workflow.missing_handler",
                mission_id=str(task.mission_id),
                task_id=str(task.id),
                task_name=task.name,
                required_capabilities=capabilities,
            )
            raise MissingTaskHandlerError(
                f"No handler registered for required capabilities: {capabilities}"
            )

        result = await handler(task)
        await self._complete_task(task)
        return result

    async def _complete_task(self, task: Task) -> None:
        """Persist completion, advance dependencies, and check the workflow."""
        plan = self._active_workflows.get(task.mission_id)
        if plan is None:
            return

        newly_ready = await self._planner.update_task_status(
            plan.id,
            task.id,
            TaskStatus.COMPLETED,
        )
        await self._state_manager.complete_task(task.mission_id, task)
        logger.info(
            "workflow.task_completed",
            mission_id=str(task.mission_id),
            task_id=str(task.id),
            task_name=task.name,
        )

        if newly_ready:
            await self._schedule_tasks(plan, newly_ready)
        await self._check_workflow_completion(task.mission_id)

    async def _fail_task(self, task: Task, error: str) -> None:
        """Handle terminal task failure after scheduler retries are exhausted."""
        plan = self._active_workflows.get(task.mission_id)
        if plan is None:
            return

        await self._planner.update_task_status(plan.id, task.id, TaskStatus.FAILED, error)
        await self._state_manager.fail_task(task.mission_id, task)
        logger.error(
            "workflow.task_failed",
            mission_id=str(task.mission_id),
            task_id=str(task.id),
            task_name=task.name,
            error=error,
        )

        if task.required:
            await self._scheduler.cancel_mission(task.mission_id, exclude_task_id=task.id)
            self._mark_remaining_tasks(plan, TaskStatus.SKIPPED)
            self._resolve_workflow(task.mission_id, WorkflowStatus.FAILED, error)
        else:
            await self._check_workflow_completion(task.mission_id)

    async def _check_workflow_completion(self, mission_id: UUID) -> None:
        plan = self._active_workflows.get(mission_id)
        if plan is None:
            return

        if any(task.required and task.status == TaskStatus.FAILED for task in plan.tasks):
            failed = next(task for task in plan.tasks if task.required and task.status == TaskStatus.FAILED)
            self._resolve_workflow(mission_id, WorkflowStatus.FAILED, failed.error)
            return

        if all(task.status == TaskStatus.COMPLETED for task in plan.tasks):
            self._resolve_workflow(mission_id, WorkflowStatus.SUCCESS)

    async def _terminate_unfinished(
        self,
        mission_id: UUID,
        error: str,
        status: WorkflowStatus,
    ) -> None:
        plan = self._active_workflows.get(mission_id)
        if plan:
            await self._scheduler.cancel_mission(mission_id)
            self._mark_remaining_tasks(plan, TaskStatus.SKIPPED)
        self._resolve_workflow(mission_id, status, error)

    def _mark_remaining_tasks(self, plan: Plan, status: TaskStatus) -> None:
        for task in plan.tasks:
            if task.status not in {TaskStatus.COMPLETED, TaskStatus.FAILED}:
                task.status = status
                task.completed_at = datetime.now(timezone.utc)

    def _resolve_workflow(
        self,
        mission_id: UUID,
        status: WorkflowStatus,
        error: Optional[str] = None,
    ) -> None:
        plan = self._active_workflows.pop(mission_id, None)
        future = self._completion_futures.get(mission_id)
        if plan is None or future is None or future.done():
            return

        result = WorkflowResult(
            mission_id=mission_id,
            plan_id=plan.id,
            status=status,
            total_tasks=len(plan.tasks),
            completed_tasks=sum(t.status == TaskStatus.COMPLETED for t in plan.tasks),
            failed_tasks=sum(t.status == TaskStatus.FAILED for t in plan.tasks),
            skipped_tasks=sum(t.status == TaskStatus.SKIPPED for t in plan.tasks),
            error=error,
            started_at=self._workflow_started_at.pop(mission_id),
        )
        future.set_result(result)
        self._scheduled_tasks.pop(mission_id, None)

        log = logger.info if result.succeeded else logger.error
        log(
            "workflow.completed" if result.succeeded else "workflow.failed",
            mission_id=str(mission_id),
            plan_id=str(plan.id),
            status=result.status.value,
            completed_tasks=result.completed_tasks,
            failed_tasks=result.failed_tasks,
            skipped_tasks=result.skipped_tasks,
            error=error,
        )

    async def cancel_workflow(self, mission_id: UUID) -> Optional[WorkflowResult]:
        """Cancel a workflow and resolve its waiter with a terminal result."""
        future = self._completion_futures.get(mission_id)
        if not future:
            return None
        await self._terminate_unfinished(
            mission_id,
            "Workflow cancelled by operator",
            WorkflowStatus.CANCELLED,
        )
        return await asyncio.shield(future)

    def register_handler(self, capability: str, handler: Callable[[Task], Any]) -> None:
        self._task_handlers[capability] = handler
        logger.debug("workflow.handler_registered", capability=capability)

    def has_handler(self, capability: str) -> bool:
        return capability in self._task_handlers

    def get_active_workflows(self) -> List[Dict[str, Any]]:
        return [
            {
                "mission_id": str(mid),
                "plan_id": str(plan.id),
                "task_count": len(plan.tasks),
                "status": "running",
            }
            for mid, plan in self._active_workflows.items()
        ]


__all__ = [
    "MissingTaskHandlerError",
    "WorkflowEngine",
    "WorkflowResult",
    "WorkflowStatus",
]
