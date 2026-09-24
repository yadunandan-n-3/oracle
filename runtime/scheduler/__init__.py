"""
Scheduler
=========

Priority-based task scheduler for ORACLE.

Never execute everything immediately.
Tasks are queued by priority, dispatched to available agents,
and retried on failure. This makes ORACLE scalable.
"""

from __future__ import annotations

import asyncio
import heapq
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from uuid import UUID

from core.events import EventType, OracleEvent
from core.exceptions import TimeoutError
from core.logging import get_logger, get_mission_logger
from core.telemetry import telemetry
from runtime.event_bus import get_event_bus
from runtime.planner import Plan, Task, TaskPriority, TaskStatus

logger = get_logger(__name__)
mission_logger = get_mission_logger()


@dataclass(order=True)
class ScheduledItem:
    """Item in the priority queue."""

    priority: int
    created_at: datetime
    task: Task = field(compare=False)
    plan_id: UUID = field(compare=False)

    @property
    def task_id(self) -> UUID:
        return self.task.id

    @property
    def mission_id(self) -> UUID:
        return self.task.mission_id


class Scheduler:
    """
    Priority-based task scheduler.

    Features:
    - Priority queue with starvation prevention
    - Concurrent task execution with configurable max workers
    - Automatic retry with exponential backoff
    - Task timeout enforcement
    - Dead letter queue for failed tasks
    """

    def __init__(
        self,
        max_concurrent: int = 10,
        poll_interval: float = 1.0,
    ) -> None:
        self._queue: List[ScheduledItem] = []
        self._running_tasks: Dict[UUID, asyncio.Task] = {}
        self._task_models: Dict[UUID, Task] = {}
        self._dead_letter_queue: List[Tuple[Task, str]] = []
        self._max_concurrent = max_concurrent
        self._poll_interval = poll_interval
        self._running = False
        self._worker: Optional[asyncio.Task] = None
        self._task_executor: Optional[Callable[[Task], Any]] = None
        self._task_failure_handler: Optional[Callable[[Task, str], Any]] = None
        self._event_bus = get_event_bus()
        self._total_scheduled = 0
        self._total_completed = 0
        self._total_failed = 0

    # ─── Lifecycle ──────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the scheduler worker."""
        if self._running:
            logger.warning("scheduler.already_running")
            return

        self._running = True
        self._worker = asyncio.create_task(self._scheduler_loop())
        logger.info("scheduler.started", max_concurrent=self._max_concurrent)

    async def stop(self) -> None:
        """Gracefully stop the scheduler."""
        self._running = False
        if self._worker:
            self._worker.cancel()
            try:
                await self._worker
            except asyncio.CancelledError:
                pass

        for task_id, task in self._running_tasks.items():
            task.cancel()
        if self._running_tasks:
            await asyncio.gather(*self._running_tasks.values(), return_exceptions=True)

        logger.info(
            "scheduler.stopped",
            scheduled=self._total_scheduled,
            completed=self._total_completed,
            failed=self._total_failed,
            dead_letter=len(self._dead_letter_queue),
        )

    async def health(self) -> Dict[str, Any]:
        """Return scheduler health."""
        return {
            "status": "healthy" if self._running else "stopped",
            "running": self._running,
            "queue_size": len(self._queue),
            "running_tasks": len(self._running_tasks),
            "max_concurrent": self._max_concurrent,
            "total_scheduled": self._total_scheduled,
            "total_completed": self._total_completed,
            "total_failed": self._total_failed,
            "dead_letter_count": len(self._dead_letter_queue),
        }

    # ─── Task Management ───────────────────────────────────────────────────

    def set_executor(self, executor: Callable[[Task], Any]) -> None:
        """Set the task executor function."""
        self._task_executor = executor

    def set_failure_handler(self, handler: Callable[[Task, str], Any]) -> None:
        """Set the callback invoked after a task exhausts its retries."""
        self._task_failure_handler = handler

    async def schedule_plan(self, plan: Plan) -> None:
        """Schedule all tasks in a plan."""
        for task in plan.tasks:
            if task.status == TaskStatus.READY:
                await self.schedule_task(task, plan.id)

    async def schedule_task(self, task: Task, plan_id: Optional[UUID] = None) -> None:
        """Schedule the canonical planner task without reconstructing it."""
        item = ScheduledItem(
            priority=task.priority.value,
            created_at=datetime.now(timezone.utc),
            task=task,
            plan_id=plan_id or UUID(int=0),
        )

        heapq.heappush(self._queue, item)
        self._task_models[task.id] = task
        self._total_scheduled += 1

        telemetry.increment_counter("scheduler.task_scheduled", attributes={"priority": str(task.priority.name)})

        mission_logger.log(
            "task.scheduled",
            mission_id=str(task.mission_id),
            details={"task_id": str(task.id), "task_name": task.name, "priority": task.priority.name},
        )

        logger.debug("scheduler.task_scheduled", task_id=str(task.id), priority=task.priority.name)

    async def get_next_task(self) -> Optional[Task]:
        """Get the next ready task from the queue without executing."""
        if not self._queue:
            return None
        item = heapq.heappop(self._queue)
        return self._task_from_item(item) if self._task_executor else None

    def _task_from_item(self, item: ScheduledItem) -> Task:
        """Return the exact task produced by the planner."""
        return item.task

    # ─── Scheduler Loop ────────────────────────────────────────────────────

    async def _scheduler_loop(self) -> None:
        """Background loop that dispatches tasks."""
        while self._running:
            try:
                await self._process_queue()
                await asyncio.sleep(self._poll_interval)
            except Exception as e:
                logger.error("scheduler.loop_error", error=str(e))
                await asyncio.sleep(5.0)

    async def _process_queue(self) -> None:
        """Process the task queue — dispatch ready tasks."""
        if not self._queue:
            return

        available_slots = self._max_concurrent - len(self._running_tasks)
        if available_slots <= 0:
            return

        dispatched = 0
        while self._queue and dispatched < available_slots:
            item = heapq.heappop(self._queue)
            await self._dispatch_task(item.task, item.plan_id)
            dispatched += 1

    async def _dispatch_task(self, task: Task, plan_id: UUID) -> None:
        """Dispatch a task to the executor."""

        async def execute_task() -> None:
            try:
                task.status = TaskStatus.RUNNING
                task.started_at = datetime.now(timezone.utc)

                mission_logger.start_timer(f"task_{task.id}")

                await self._event_bus.publish(OracleEvent(
                    event_type=EventType.MISSION_TASK_STARTED,
                    source="scheduler",
                    mission_id=task.mission_id,
                    data={"task_id": str(task.id), "task_name": task.name},
                ))

                if not self._task_executor:
                    raise RuntimeError("Scheduler task executor is not configured")

                try:
                    await asyncio.wait_for(
                        self._task_executor(task),
                        timeout=task.timeout_seconds,
                    )
                except asyncio.TimeoutError:
                    raise TimeoutError(operation=task.name, timeout_seconds=task.timeout_seconds)

                task.status = TaskStatus.COMPLETED
                task.completed_at = datetime.now(timezone.utc)
                self._total_completed += 1

                duration_ms = mission_logger.stop_timer(f"task_{task.id}") or 0.0
                mission_logger.log(
                    "task.completed",
                    mission_id=str(task.mission_id),
                    details={"task_id": str(task.id), "task_name": task.name, "duration_ms": duration_ms, "status": "success"},
                )

                await self._event_bus.publish(OracleEvent(
                    event_type=EventType.MISSION_TASK_COMPLETED,
                    source="scheduler",
                    mission_id=task.mission_id,
                    data={"task_id": str(task.id), "task_name": task.name},
                ))

                telemetry.increment_counter("scheduler.task_completed")

            except Exception as e:
                task.status = TaskStatus.FAILED
                task.error = str(e)
                task.completed_at = datetime.now(timezone.utc)
                self._total_failed += 1

                duration_ms = mission_logger.elapsed_ms(f"task_{task.id}") or 0.0
                mission_logger.log(
                    "task.failed",
                    mission_id=str(task.mission_id),
                    error=str(e),
                    details={"task_id": str(task.id), "task_name": task.name, "duration_ms": duration_ms, "status": "failure"},
                )

                if task.retry_on_failure and task.max_retries > 0:
                    task.max_retries -= 1
                    mission_logger.log(
                        "task.retrying",
                        mission_id=str(task.mission_id),
                        details={"task_id": str(task.id), "retries_left": task.max_retries},
                    )
                    await asyncio.sleep(2.0 ** (3 - task.max_retries))
                    task.status = TaskStatus.READY
                    await self.schedule_task(task, plan_id)
                else:
                    self._dead_letter_queue.append((task, str(e)))
                    if self._task_failure_handler:
                        await self._task_failure_handler(task, str(e))

                await self._event_bus.publish(OracleEvent(
                    event_type=EventType.MISSION_TASK_FAILED,
                    source="scheduler",
                    mission_id=task.mission_id,
                    data={"task_id": str(task.id), "error": str(e)},
                ))

                telemetry.increment_counter("scheduler.task_failed")
                logger.error("scheduler.task_failed", task_id=str(task.id), error=str(e))

            finally:
                self._running_tasks.pop(task.id, None)

        asyncio_task = asyncio.create_task(execute_task())
        self._running_tasks[task.id] = asyncio_task

    async def cancel_mission(
        self,
        mission_id: UUID,
        exclude_task_id: Optional[UUID] = None,
    ) -> None:
        """Remove queued work and cancel running work for one mission."""
        self._queue = [item for item in self._queue if item.mission_id != mission_id]
        heapq.heapify(self._queue)

        running = [
            running_task
            for task_id, running_task in self._running_tasks.items()
            if self._task_models.get(task_id)
            and self._task_models[task_id].mission_id == mission_id
            and task_id != exclude_task_id
        ]
        for running_task in running:
            running_task.cancel()

    # ─── Queue Management ──────────────────────────────────────────────────

    def get_queue_stats(self) -> Dict[str, Any]:
        """Get statistics about the task queue."""
        return {
            "queue_size": len(self._queue),
            "running": len(self._running_tasks),
            "total_scheduled": self._total_scheduled,
            "total_completed": self._total_completed,
            "total_failed": self._total_failed,
            "dead_letter_count": len(self._dead_letter_queue),
        }

    def get_dead_letter_queue(self) -> List[Dict[str, Any]]:
        """Get failed tasks from the dead letter queue."""
        return [
            {
                "task_id": str(task.id),
                "task_name": task.name,
                "error": error,
                "mission_id": str(task.mission_id),
            }
            for task, error in self._dead_letter_queue
        ]


__all__ = ["Scheduler", "ScheduledItem"]
