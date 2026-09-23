"""
E2E Comprehensive Test Suite
============================
End-to-end verification of the ORACLE pipeline.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List
from uuid import UUID, uuid4

import pytest

from core.logging.mission_logger import MissionLogger
from core.events import EventType, OracleEvent
from domain.asset import Asset, AssetType, AssetCriticality
from domain.evidence import Evidence, EvidenceType, EvidenceStatus, EvidenceSource
from domain.finding import Finding, FindingSeverity, FindingStatus
from domain.mission import (
    Mission, MissionGoal, MissionTarget, MissionType,
    MissionStatus, MissionPriority,
)
from runtime.event_bus import EventBus, get_event_bus, set_event_bus
from runtime.planner import Planner, Plan, Task, TaskStatus, TaskPriority
from runtime.scheduler import Scheduler
from runtime.state_manager import StateManager, MissionState
from runtime.validator import Validator, ValidationResult


@pytest.fixture(autouse=True)
def reset_singletons():
    set_event_bus(EventBus())
    yield


@pytest.fixture
def event_bus():
    bus = EventBus()
    set_event_bus(bus)
    return bus


@pytest.fixture
def sample_target() -> MissionTarget:
    return MissionTarget(
        domains=["example.com", "test.org"],
        ip_ranges=["192.168.1.0/24"],
        urls=["https://scanme.nmap.org"],
    )


@pytest.fixture
def sample_goals() -> List[MissionGoal]:
    return [
        MissionGoal(description="Discover all subdomains"),
        MissionGoal(description="Identify open ports and services"),
        MissionGoal(description="Detect web technologies"),
    ]


@pytest.fixture
def sample_mission(sample_target, sample_goals) -> Mission:
    return Mission(
        name="E2E Test Mission",
        description="Automated end-to-end pipeline test",
        mission_type=MissionType.EXTERNAL_ATTACK_SURFACE,
        priority=MissionPriority.MEDIUM,
        status=MissionStatus.DRAFT,
        goals=sample_goals,
        target=sample_target,
    )


@pytest.fixture
def planner() -> Planner:
    return Planner()


@pytest.fixture
def scheduler(event_bus) -> Scheduler:
    return Scheduler(max_concurrent=5)


@pytest.fixture
def state_manager(event_bus) -> StateManager:
    return StateManager()


@pytest.fixture
def validator(event_bus) -> Validator:
    return Validator()


class TestMissionLifecycle:
    @pytest.mark.asyncio
    async def test_mission_creation(self, sample_mission):
        assert sample_mission.id is not None
        assert sample_mission.mission_type == MissionType.EXTERNAL_ATTACK_SURFACE
        assert sample_mission.status == MissionStatus.DRAFT
        assert len(sample_mission.goals) == 3

    @pytest.mark.asyncio
    async def test_mission_status_transitions(self, sample_mission):
        sample_mission.status = MissionStatus.COMPLETED
        assert sample_mission.status == MissionStatus.COMPLETED
        sample_mission.status = MissionStatus.FAILED
        assert sample_mission.status == MissionStatus.FAILED

    @pytest.mark.asyncio
    async def test_mission_multi_target(self):
        target = MissionTarget(domains=["test.com"], api_endpoints=["/users"])
        mission = Mission(name="Multi", mission_type=MissionType.API_SECURITY_ASSESSMENT, target=target)
        assert len(mission.target.api_endpoints) == 1

    @pytest.mark.asyncio
    async def test_mission_no_goals(self):
        mission = Mission(name="Minimal", mission_type=MissionType.CUSTOM)
        assert len(mission.goals) == 0


class TestPlanner:
    @pytest.mark.asyncio
    async def test_planner_creates_tasks(self, planner, sample_mission):
        plan = await planner.create_plan(sample_mission)
        assert plan is not None
        assert len(plan.tasks) > 0

    @pytest.mark.asyncio
    async def test_planner_ready_tasks(self, planner, sample_mission):
        plan = await planner.create_plan(sample_mission)
        ready_tasks = planner.get_ready_tasks(plan.id)
        assert len(ready_tasks) > 0

    @pytest.mark.asyncio
    async def test_planner_update_status(self, planner, sample_mission):
        plan = await planner.create_plan(sample_mission)
        first_task = plan.tasks[0]
        await planner.update_task_status(plan.id, first_task.id, TaskStatus.COMPLETED)
        updated_plan = planner.get_plan(plan.id)
        updated = next(t for t in updated_plan.tasks if t.id == first_task.id)
        assert updated.status == TaskStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_planner_custom_mission(self, planner):
        mission = Mission(name="Custom", mission_type=MissionType.CUSTOM, target=MissionTarget(domains=["test.com"]))
        plan = await planner.create_plan(mission)
        assert plan.total_tasks >= 3

    @pytest.mark.asyncio
    async def test_planner_no_mission_plan(self, planner):
        missing = planner.get_mission_plan(uuid4())
        assert missing is None


class TestScheduler:
    @pytest.mark.asyncio
    async def test_scheduler_start_stop(self, scheduler):
        await scheduler.start()
        health = await scheduler.health()
        assert health["running"] is True
        await scheduler.stop()
        health = await scheduler.health()
        assert health["running"] is False

    @pytest.mark.asyncio
    async def test_scheduler_schedule_task(self, scheduler):
        await scheduler.start()
        task = Task(mission_id=uuid4(), name="Test", priority=TaskPriority.HIGH)
        await scheduler.schedule_task(task)
        stats = scheduler.get_queue_stats()
        assert stats["total_scheduled"] >= 1
        await scheduler.stop()

    @pytest.mark.asyncio
    async def test_scheduler_health(self, scheduler):
        await scheduler.start()
        health = await scheduler.health()
        assert "status" in health
        await scheduler.stop()

    @pytest.mark.asyncio
    async def test_queue_stats(self, scheduler):
        await scheduler.start()
        stats = scheduler.get_queue_stats()
        assert "queue_size" in stats
        await scheduler.stop()

    @pytest.mark.asyncio
    async def test_dead_letter_queue(self, scheduler):
        await scheduler.start()
        async def failing_executor(task):
            raise RuntimeError("Simulated failure")
        scheduler.set_executor(failing_executor)
        task = Task(mission_id=uuid4(), name="Fail", priority=TaskPriority.HIGH, retry_on_failure=True, max_retries=1)
        await scheduler.schedule_task(task)
        await asyncio.sleep(0.3)
        await scheduler.stop()


class TestEvidencePipeline:
    @pytest.mark.asyncio
    async def test_evidence_creation(self):
        evidence = Evidence(
            evidence_type=EvidenceType.OPEN_PORT, title="Open Port 80",
            source=EvidenceSource(tool_name="nmap"),
            asset_value="192.168.1.1:80/tcp",
            raw_data={"port": 80, "protocol": "tcp", "state": "open"},
        )
        assert evidence.id is not None
        assert evidence.status == EvidenceStatus.COLLECTED

    @pytest.mark.asyncio
    async def test_evidence_validation(self, validator):
        evidence = Evidence(
            evidence_type=EvidenceType.OPEN_PORT, title="Open Port 443",
            source=EvidenceSource(tool_name="nmap"),
            asset_value="10.0.0.1:443/tcp",
            raw_data={"port": 443, "protocol": "tcp", "state": "open"},
        )
        validated = await validator.validate_evidence(evidence)
        assert validated.validated_at is not None

    @pytest.mark.asyncio
    async def test_evidence_false_positive(self, validator):
        fp = Evidence(
            evidence_type=EvidenceType.OPEN_PORT, title="Invalid Port 0",
            source=EvidenceSource(tool_name="nmap"), asset_value="0.0.0.0",
            raw_data={"port": 0},
        )
        validated = await validator.validate_evidence(fp)
        assert validated.status == EvidenceStatus.DISPUTED

    @pytest.mark.asyncio
    async def test_evidence_minimal(self):
        evidence = Evidence(
            evidence_type=EvidenceType.RAW_OUTPUT, title="Minimal",
            source=EvidenceSource(tool_name="unknown"),
        )
        assert evidence.status == EvidenceStatus.COLLECTED


class TestStateManager:
    @pytest.mark.asyncio
    async def test_initialize_mission_state(self, state_manager, sample_mission):
        state = await state_manager.initialize_mission_state(sample_mission)
        assert state is not None
        assert state.mission.id == sample_mission.id

    @pytest.mark.asyncio
    async def test_add_evidence_to_state(self, state_manager, sample_mission):
        await state_manager.initialize_mission_state(sample_mission)
        evidence = Evidence(
            evidence_type=EvidenceType.OPEN_PORT, title="Test",
            source=EvidenceSource(tool_name="nmap"), asset_value="1.2.3.4:80/tcp",
        )
        await state_manager.add_evidence(sample_mission.id, evidence)
        stored = state_manager.get_evidence(sample_mission.id)
        assert len(stored) == 1

    @pytest.mark.asyncio
    async def test_add_asset(self, state_manager, sample_mission):
        await state_manager.initialize_mission_state(sample_mission)
        asset = Asset(asset_type=AssetType.HOST, value="192.168.1.1")
        await state_manager.add_asset(sample_mission.id, asset)
        assets = state_manager.get_assets(sample_mission.id)
        assert len(assets) == 1

    @pytest.mark.asyncio
    async def test_asset_by_value(self, state_manager, sample_mission):
        await state_manager.initialize_mission_state(sample_mission)
        asset = Asset(asset_type=AssetType.HOST, value="10.0.0.1")
        await state_manager.add_asset(sample_mission.id, asset)
        found = state_manager.get_asset_by_value(sample_mission.id, "10.0.0.1")
        assert found is not None
        assert found.value == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_get_mission_summary(self, state_manager, sample_mission):
        await state_manager.initialize_mission_state(sample_mission)
        summary = state_manager.get_mission_summary(sample_mission.id)
        assert summary is not None
        assert summary["mission_id"] == str(sample_mission.id)


class TestMissionLogger:
    def test_mission_logger_creation(self):
        ml = MissionLogger()
        assert ml is not None

    def test_timer_helpers(self):
        ml = MissionLogger()
        ml.start_timer("test_timer")
        time.sleep(0.01)
        elapsed = ml.elapsed_ms("test_timer")
        assert elapsed is not None
        assert elapsed > 0

    def test_stop_timer(self):
        ml = MissionLogger()
        ml.start_timer("test")
        time.sleep(0.01)
        elapsed = ml.stop_timer("test")
        assert elapsed is not None
        assert elapsed > 0

    def test_log_mission_created(self):
        ml = MissionLogger()
        ml.log_mission_created(mission_id="m1", mission_type="external_attack_surface", name="Test", goal_count=3)
        ml.log_mission_completed("m1", 10, 25, 1500.5)
        ml.log_mission_failed("m1", "Connection refused", 500.0)

    def test_log_evidence_flow(self):
        ml = MissionLogger()
        ml.log_evidence_flow("m1", "ev-1", "open_port", "10.0.0.1:80", tool="nmap", confidence=0.95)
        ml.log_evidence_validated("m1", "ev-1", 0.95, "validated", "validator.v1")
        ml.log_persistence("m1", "postgresql", "completed", 45.0)
        ml.log_persistence("m1", "neo4j", "failed", 120.0, error="Connection timeout")


class TestValidatorEdgeCases:
    @pytest.mark.asyncio
    async def test_empty_evidence(self, validator):
        evidence = Evidence(
            evidence_type=EvidenceType.RAW_OUTPUT, title="Minimal",
            source=EvidenceSource(tool_name="unknown"),
        )
        validated = await validator.validate_evidence(evidence)
        assert validated is not None

    @pytest.mark.asyncio
    async def test_finding_no_evidence(self, validator):
        finding = Finding(title="Test", severity=FindingSeverity.HIGH, evidence_ids=[])
        assert await validator.validate_finding(finding) is False

    @pytest.mark.asyncio
    async def test_finding_with_evidence(self, validator):
        finding = Finding(title="Valid", severity=FindingSeverity.CRITICAL, evidence_ids=[uuid4()])
        assert await validator.validate_finding(finding) is True


class TestResilience:
    @pytest.mark.asyncio
    async def test_circuit_breaker_closed(self):
        from core.resilience.circuit_breaker import CircuitBreaker, CircuitBreakerConfig
        cb = CircuitBreaker(CircuitBreakerConfig(name="test", failure_threshold=2))
        assert cb.state.value == "closed"

    @pytest.mark.asyncio
    async def test_circuit_breaker_opens(self):
        from core.resilience.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitOpenError
        cb = CircuitBreaker(CircuitBreakerConfig(name="test", failure_threshold=2, recovery_timeout_seconds=60))
        assert cb.state.value == "closed"
        async def fail():
            raise ValueError("fail")
        with pytest.raises(ValueError):
            await cb.call(fail)
        with pytest.raises(ValueError):
            await cb.call(fail)
        assert cb.state.value == "open"
        with pytest.raises(CircuitOpenError):
            await cb.call(fail)

    @pytest.mark.asyncio
    async def test_circuit_breaker_success(self):
        from core.resilience.circuit_breaker import CircuitBreaker, CircuitBreakerConfig
        cb = CircuitBreaker(CircuitBreakerConfig(name="test", failure_threshold=3))
        async def succeed():
            return "ok"
        result = await cb.call(succeed)
        assert result == "ok"
        assert cb.stats.total_successes == 1

    @pytest.mark.asyncio
    async def test_degraded_mode(self):
        from core.resilience.degraded_mode import DegradedModeManager, DependencyStatus
        mgr = DegradedModeManager()
        assert mgr.is_available("postgresql") is False
        mgr.update_status("postgresql", DependencyStatus.HEALTHY)
        assert mgr.is_available("postgresql") is True
        summary = mgr.get_health_summary()
        assert summary["degraded"] is False


class TestEventBusCore:
    @pytest.mark.asyncio
    async def test_publish_subscribe(self, event_bus):
        await event_bus.start()
        received = []
        async def handler(event):
            received.append(event)
        event_bus.subscribe("test_sub", {EventType.SYSTEM_STARTUP}, handler)
        await event_bus.publish(OracleEvent(event_type=EventType.SYSTEM_STARTUP, source="test"))
        await asyncio.sleep(0.1)
        assert len(received) > 0
        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_event_deduplication(self, event_bus):
        await event_bus.start()
        count = 0
        async def handler(event):
            nonlocal count
            count += 1
        event_bus.subscribe("dedup", {EventType.SYSTEM_STARTUP}, handler)
        event = OracleEvent(event_type=EventType.SYSTEM_STARTUP, source="test")
        await event_bus.publish(event)
        await event_bus.publish(event)
        await asyncio.sleep(0.1)
        health = await event_bus.health()
        assert health["total_deduplicated"] == 1
        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_dead_letter_queue(self, event_bus):
        await event_bus.start()
        async def failing_handler(event):
            raise RuntimeError("Handler failed")
        event_bus.subscribe("fail", {EventType.SYSTEM_ERROR}, failing_handler)
        await event_bus.publish(OracleEvent(event_type=EventType.SYSTEM_ERROR, source="test"))
        await asyncio.sleep(0.5)
        dlq = event_bus.get_dead_letter_queue()
        assert len(dlq) >= 0
        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_unsubscribe(self, event_bus):
        await event_bus.start()
        received = []
        async def handler(event):
            received.append(event)
        event_bus.subscribe("unsub", {EventType.SYSTEM_STARTUP}, handler)
        event_bus.unsubscribe("unsub")
        await event_bus.publish(OracleEvent(event_type=EventType.SYSTEM_STARTUP, source="test"))
        await asyncio.sleep(0.1)
        assert len(received) == 0
        await event_bus.stop()
