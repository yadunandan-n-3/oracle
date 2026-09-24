"""Regression coverage for ORACLE's P0 execution contract."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest

from domain.mission import MissionStatus, MissionTarget, MissionType
from runtime.planner import Plan, Planner, Task, TaskPriority, TaskStatus
from runtime.runtime import OracleRuntime
from runtime.scheduler import Scheduler
from runtime.state_manager import StateManager
from runtime.workflow import WorkflowEngine, WorkflowStatus
from tests.conftest import make_mission


def make_plan_task(
    mission_id: UUID,
    name: str = "task",
    capability: str = "test_capability",
    *,
    status: TaskStatus = TaskStatus.READY,
    depends_on: list[UUID] | None = None,
) -> Task:
    return Task(
        mission_id=mission_id,
        name=name,
        description=f"Execute {name}",
        capability=capability,
        status=status,
        depends_on=depends_on or [],
        retry_on_failure=False,
        max_retries=0,
        timeout_seconds=2,
    )


def make_plan(mission_id: UUID, tasks: list[Task]) -> Plan:
    return Plan(mission_id=mission_id, tasks=tasks, total_tasks=len(tasks))


async def make_running_engine() -> tuple[Scheduler, Planner, WorkflowEngine]:
    scheduler = Scheduler(max_concurrent=20, poll_interval=0.001)
    planner = Planner()
    engine = WorkflowEngine(scheduler, StateManager(), planner)
    await scheduler.start()
    return scheduler, planner, engine


@pytest.mark.asyncio
async def test_execute_plan_waits_for_completion(event_bus: Any) -> None:
    scheduler, _, engine = await make_running_engine()
    mission = make_mission(domains=["wait.oracle.test"])
    task = make_plan_task(mission.id)
    started = asyncio.Event()
    release = asyncio.Event()

    async def handler(_: Task) -> None:
        started.set()
        await release.wait()

    engine.register_handler(task.capability, handler)
    execution = asyncio.create_task(engine.execute_plan(make_plan(mission.id, [task]), mission))
    try:
        await asyncio.wait_for(started.wait(), timeout=1)
        await asyncio.sleep(0)
        assert not execution.done()

        release.set()
        result = await asyncio.wait_for(execution, timeout=1)
        assert result.status == WorkflowStatus.SUCCESS
        assert task.status == TaskStatus.COMPLETED
    finally:
        release.set()
        await scheduler.stop()


@pytest.mark.asyncio
async def test_scheduler_preserves_task_metadata(event_bus: Any) -> None:
    scheduler = Scheduler(max_concurrent=1, poll_interval=0.001)
    captured: list[Task] = []
    executed = asyncio.Event()
    dependency_id = uuid4()
    goal_id = uuid4()
    task = Task(
        mission_id=uuid4(),
        goal_id=goal_id,
        name="metadata",
        description="Preserve every execution field",
        priority=TaskPriority.HIGH,
        status=TaskStatus.READY,
        capability="metadata_capability",
        required_capabilities=["metadata_capability", "fallback_capability"],
        required_tools=["fake_tool"],
        target="metadata.oracle.test",
        params={"depth": 3},
        config={"mode": "safe"},
        depends_on=[dependency_id],
        timeout_seconds=17,
        retry_on_failure=False,
        max_retries=4,
    )

    async def executor(received: Task) -> None:
        captured.append(received)
        executed.set()

    scheduler.set_executor(executor)
    await scheduler.start()
    try:
        await scheduler.schedule_task(task, uuid4())
        await asyncio.wait_for(executed.wait(), timeout=1)
        assert captured == [task]
        assert captured[0] is task
        assert captured[0].id == task.id
        assert captured[0].name == "metadata"
        assert captured[0].goal_id == goal_id
        assert captured[0].capability == "metadata_capability"
        assert captured[0].required_capabilities == [
            "metadata_capability",
            "fallback_capability",
        ]
        assert captured[0].required_tools == ["fake_tool"]
        assert captured[0].target == "metadata.oracle.test"
        assert captured[0].params == {"depth": 3}
        assert captured[0].config == {"mode": "safe"}
        assert captured[0].depends_on == [dependency_id]
        assert captured[0].timeout_seconds == 17
        assert captured[0].retry_on_failure is False
        assert captured[0].max_retries == 4
    finally:
        await scheduler.stop()


@pytest.mark.asyncio
async def test_missing_handler_does_not_complete_task(event_bus: Any) -> None:
    scheduler, _, engine = await make_running_engine()
    mission = make_mission(domains=["missing-handler.oracle.test"])
    task = make_plan_task(mission.id, capability="not_registered")
    try:
        result = await asyncio.wait_for(
            engine.execute_plan(make_plan(mission.id, [task]), mission),
            timeout=1,
        )
        assert result.status == WorkflowStatus.FAILED
        assert task.status == TaskStatus.FAILED
        assert "No handler registered" in (result.error or "")
    finally:
        await scheduler.stop()


@pytest.mark.asyncio
async def test_dependency_wave_advances(event_bus: Any) -> None:
    scheduler, _, engine = await make_running_engine()
    mission = make_mission(domains=["waves.oracle.test"])
    first = make_plan_task(mission.id, name="first")
    second = make_plan_task(
        mission.id,
        name="second",
        status=TaskStatus.PENDING,
        depends_on=[first.id],
    )
    order: list[str] = []

    async def handler(task: Task) -> None:
        order.append(task.name)

    engine.register_handler("test_capability", handler)
    try:
        result = await engine.execute_plan(make_plan(mission.id, [first, second]), mission)
        assert result.status == WorkflowStatus.SUCCESS
        assert order == ["first", "second"]
        assert second.started_at is not None
        assert first.completed_at is not None
    finally:
        await scheduler.stop()


@pytest.mark.asyncio
async def test_mission_does_not_complete_before_workflow(event_bus: Any) -> None:
    runtime = OracleRuntime()
    runtime.scheduler._poll_interval = 0.001
    mission = await runtime.mission_manager.create_mission(
        name="Completion ordering",
        mission_type=MissionType.CUSTOM,
        target=MissionTarget(domains=["ordering.oracle.test"]),
    )
    task = make_plan_task(mission.id, capability="controlled")
    plan = make_plan(mission.id, [task])
    runtime.planner.create_plan = AsyncMock(return_value=plan)
    started = asyncio.Event()
    release = asyncio.Event()

    async def handler(_: Task) -> None:
        started.set()
        await release.wait()

    runtime.register_capability_handler("controlled", handler)
    await runtime.scheduler.start()
    execution = asyncio.create_task(runtime.execute_mission(mission.id))
    try:
        await asyncio.wait_for(started.wait(), timeout=1)
        assert mission.status == MissionStatus.IN_PROGRESS
        assert mission.completed_at is None
        assert not execution.done()

        release.set()
        result = await asyncio.wait_for(execution, timeout=1)
        assert result is not None and result.succeeded
        assert mission.status == MissionStatus.COMPLETED
        assert mission.completed_at is not None
        assert task.status == TaskStatus.COMPLETED
        assert not runtime.workflow_engine.get_active_workflows()
    finally:
        release.set()
        await runtime.scheduler.stop()


@pytest.mark.asyncio
async def test_planner_failure_marks_mission_failed(event_bus: Any) -> None:
    runtime = OracleRuntime()
    mission = await runtime.mission_manager.create_mission(
        name="Planner failure",
        mission_type=MissionType.CUSTOM,
        target=MissionTarget(domains=["planner-failure.oracle.test"]),
    )

    async def fail_planning(_: Any) -> Plan:
        raise RuntimeError("planner exploded")

    runtime.planner.create_plan = fail_planning
    with pytest.raises(RuntimeError, match="planner exploded"):
        await runtime.execute_mission(mission.id)

    assert mission.status == MissionStatus.FAILED
    assert mission.metadata["failure_reason"] == "planner exploded"


@pytest.mark.asyncio
async def test_task_failure_marks_workflow_failed(event_bus: Any) -> None:
    scheduler, _, engine = await make_running_engine()
    mission = make_mission(domains=["task-failure.oracle.test"])
    task = make_plan_task(mission.id, capability="failing")

    async def handler(_: Task) -> None:
        raise RuntimeError("handler exploded")

    engine.register_handler("failing", handler)
    try:
        result = await engine.execute_plan(make_plan(mission.id, [task]), mission)
        assert result.status == WorkflowStatus.FAILED
        assert result.failed_tasks == 1
        assert result.error == "handler exploded"
    finally:
        await scheduler.stop()


@pytest.mark.asyncio
async def test_workflow_timeout_marks_failure(event_bus: Any) -> None:
    scheduler, _, engine = await make_running_engine()
    mission = make_mission(domains=["timeout.oracle.test"])
    task = make_plan_task(mission.id, capability="blocking")
    blocked = asyncio.Event()

    async def handler(_: Task) -> None:
        await blocked.wait()

    engine.register_handler("blocking", handler)
    try:
        result = await engine.execute_plan(
            make_plan(mission.id, [task]),
            mission,
            timeout_seconds=0.03,
        )
        assert result.status == WorkflowStatus.TIMED_OUT
        assert task.status == TaskStatus.SKIPPED
        assert not engine.get_active_workflows()
    finally:
        blocked.set()
        await scheduler.stop()


@pytest.mark.asyncio
async def test_handler_registration_before_dispatch(event_bus: Any) -> None:
    scheduler = Scheduler(max_concurrent=1, poll_interval=0.001)
    engine = WorkflowEngine(scheduler, StateManager(), Planner())
    mission = make_mission(domains=["registration.oracle.test"])
    task = make_plan_task(mission.id, capability="registered_first")
    called = asyncio.Event()

    async def handler(_: Task) -> None:
        called.set()

    engine.register_handler("registered_first", handler)
    assert engine.has_handler("registered_first")
    assert scheduler._task_executor is not None

    await scheduler.start()
    try:
        result = await engine.execute_plan(make_plan(mission.id, [task]), mission)
        assert result.succeeded
        assert called.is_set()
    finally:
        await scheduler.stop()


@pytest.mark.asyncio
async def test_concurrent_missions_isolate_agent_state(
    event_bus: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ai.agents.discovery_agent import DiscoveryAgent

    runtime = OracleRuntime()
    seen_agents: dict[UUID, int] = {}

    async def fake_execute(self: Any, context: dict[str, Any]) -> Any:
        mission_id = context["mission_id"]
        self._discovered_assets[str(mission_id)] = object()
        seen_agents[mission_id] = id(self)
        await asyncio.sleep(0)
        if False:
            yield None

    monkeypatch.setattr(DiscoveryAgent, "execute", fake_execute)
    runtime._register_capability_handlers()
    handler = runtime._registered_handlers["port_scanning"]
    first = make_plan_task(uuid4(), capability="port_scanning")
    second = make_plan_task(uuid4(), capability="port_scanning")
    first.target = "first.oracle.test"
    second.target = "second.oracle.test"

    await asyncio.gather(handler(first), handler(second))

    assert seen_agents[first.mission_id] != seen_agents[second.mission_id]
    assert set(runtime._discovery_agents) == {first.mission_id, second.mission_id}
    assert str(second.mission_id) not in runtime._discovery_agents[first.mission_id]._discovered_assets
    assert str(first.mission_id) not in runtime._discovery_agents[second.mission_id]._discovered_assets


@pytest.mark.asyncio
async def test_full_external_attack_surface_plan_execution(event_bus: Any) -> None:
    scheduler, planner, engine = await make_running_engine()
    mission = make_mission(
        mission_type=MissionType.EXTERNAL_ATTACK_SURFACE,
        domains=["full-plan.oracle.test"],
    )
    plan = await planner.create_plan(mission)
    handled: list[UUID] = []

    async def handler(task: Task) -> None:
        handled.append(task.id)

    for capability in {task.capability for task in plan.tasks}:
        engine.register_handler(capability, handler)

    try:
        result = await asyncio.wait_for(engine.execute_plan(plan, mission), timeout=2)
        assert result.status == WorkflowStatus.SUCCESS
        assert result.completed_tasks == len(plan.tasks)
        assert len(handled) == len(plan.tasks)
        assert all(task.status == TaskStatus.COMPLETED for task in plan.tasks)
        assert not engine.get_active_workflows()
    finally:
        await scheduler.stop()
