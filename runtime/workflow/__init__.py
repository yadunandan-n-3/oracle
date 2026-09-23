"""
Workflow Engine
===============

Orchestrates multi-step, multi-agent workflows in ORACLE.

The Workflow Engine manages the execution flow:
1. Accepts a plan from the Planner
2. Coordinates agent execution through the Scheduler
3. Handles branching, parallel execution, and conditional logic
4. Manages workflow state and transitions
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Set
from uuid import UUID

from core.events import EventType, OracleEvent
from core.logging import get_logger
from domain.asset import Asset
from domain.evidence import Evidence
from domain.mission import Mission
from runtime.event_bus import EventBus, get_event_bus
from runtime.planner import Plan, Task, TaskStatus
from runtime.scheduler import Scheduler
from runtime.state_manager import StateManager

logger = get_logger(__name__)


class WorkflowEngine:
    """
    Coordinates the execution of mission plans.

    The Workflow Engine:
    - Receives a plan from the Planner
    - Dispatches tasks to the Scheduler
    - Monitors task completion
    - Triggers downstream tasks when dependencies resolve
    - Handles workflow-level errors and recovery
    """

    def __init__(
        self,
        scheduler: Scheduler,
        state_manager: StateManager,
    ) -> None:
        self._scheduler = scheduler
        self._state_manager = state_manager
        self._event_bus = get_event_bus()
        self._active_workflows: Dict[UUID, Plan] = {}
        self._task_handlers: Dict[str, Callable] = {}

    async def execute_plan(
        self,
        plan: Plan,
        mission: Mission,
    ) -> None:
        """
        Execute a complete plan for a mission.

        This is the main entry point for mission execution.

        Args:
            plan: The plan to execute
            mission: The mission this plan belongs to
        """
        logger.info(
            "workflow.starting",
            mission_id=str(mission.id),
            task_count=plan.total_tasks,
        )

        # Initialize state
        await self._state_manager.initialize_mission_state(mission, plan)
        self._active_workflows[mission.id] = plan

        # Register task handlers for common capabilities
        self._register_default_handlers()

        # Schedule all ready tasks
        await self._scheduler.schedule_plan(plan)

        # Set the executor function on the scheduler
        self._scheduler.set_executor(self._execute_task)

        logger.info(
            "workflow.started",
            mission_id=str(mission.id),
            ready_tasks=len(self._scheduler.get_queue_stats()),
        )

    async def _execute_task(self, task: Task) -> Any:
        """
        Execute a single task within the workflow.

        This dispatches to the appropriate handler based on
        the task's required capabilities.

        Args:
            task: The task to execute

        Returns:
            Task execution result
        """
        # Register the task as active
        await self._state_manager.register_active_task(task.mission_id, task)

        # Find the first matching handler
        for capability in task.required_capabilities:
            handler = self._task_handlers.get(capability)
            if handler:
                try:
                    result = await handler(task)
                    await self._complete_task(task)
                    return result
                except Exception as e:
                    await self._fail_task(task, str(e))
                    raise

        # No handler found — mark as completed with warning
        logger.warning(
            "workflow.no_handler",
            task_id=str(task.id),
            capabilities=task.required_capabilities,
        )
        await self._complete_task(task)
        return None

    async def _complete_task(self, task: Task) -> None:
        """Handle task completion in the workflow."""
        task.status = TaskStatus.COMPLETED
        await self._state_manager.complete_task(task.mission_id, task)

        # Check if all tasks are done
        await self._check_workflow_completion(task.mission_id)

    async def _fail_task(self, task: Task, error: str) -> None:
        """Handle task failure in the workflow."""
        task.status = TaskStatus.FAILED
        task.error = error
        await self._state_manager.fail_task(task.mission_id, task)

        # Check if workflow should stop
        await self._check_workflow_completion(task.mission_id)

    async def _check_workflow_completion(self, mission_id: UUID) -> None:
        """Check if all tasks are complete and finalize if so."""
        plan = self._active_workflows.get(mission_id)
        if not plan:
            return

        all_done = all(
            task.status in {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.SKIPPED}
            for task in plan.tasks
        )

        if all_done:
            logger.info(
                "workflow.completed",
                mission_id=str(mission_id),
                total_tasks=plan.total_tasks,
            )
            self._active_workflows.pop(mission_id, None)

    def _register_default_handlers(self) -> None:
        """Register default task handlers for standard capabilities."""
        # These are placeholder handlers — real implementations
        # are registered by the AI layer and tool plugins
        pass

    def register_handler(
        self,
        capability: str,
        handler: Callable,
    ) -> None:
        """
        Register a handler for a specific capability.

        Args:
            capability: The capability name (e.g., "port_scanning")
            handler: Async function that handles tasks with this capability
        """
        self._task_handlers[capability] = handler
        logger.debug(
            "workflow.handler_registered",
            capability=capability,
        )

    def get_active_workflows(self) -> List[Dict[str, Any]]:
        """Get summary of all active workflows."""
        return [
            {
                "mission_id": str(mid),
                "task_count": len(plan.tasks),
                "status": "running",
            }
            for mid, plan in self._active_workflows.items()
        ]


__all__ = ["WorkflowEngine"]
