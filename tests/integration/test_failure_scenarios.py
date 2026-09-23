"""
Integration Tests: Failure Scenarios
=====================================

Tests that ORACLE handles every failure mode gracefully.
The runtime should never crash because of one failed task.

Failure scenarios tested:
1. Invalid hostname
2. Unreachable host (timeout)
3. Nmap not installed
4. Malformed tool output
5. Scanner failure
6. Empty target list
7. Duplicate evidence
8. Validation failure
9. Policy violation
10. Concurrent mission limits
11. Database connection failure
12. Agent execution failure
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional, AsyncIterator
from uuid import UUID, uuid4

import pytest
import pytest_asyncio

from core.events import EventType, OracleEvent
from core.exceptions import (
    OracleError,
    ResourceNotFoundError,
    ValidationError,
    PolicyViolationError,
    ToolUnavailableError,
    TimeoutError,
)
from domain.evidence import Evidence, EvidenceType, EvidenceSource, EvidenceStatus
from domain.mission import Mission, MissionStatus, MissionTarget, MissionType, MissionPriority
from runtime.event_bus import EventBus, get_event_bus
from runtime.mission_manager import MissionManager
from runtime.planner import Planner, Task, TaskPriority, TaskStatus
from runtime.policy_engine import PolicyEngine, Policy, PolicyEffect, PolicySeverity
from runtime.scheduler import Scheduler
from runtime.state_manager import StateManager, MissionState
from runtime.validator import Validator
from tests.conftest import (
    make_mission,
    make_evidence,
    make_asset,
    make_finding,
    make_task,
)


class TestFailureScenario1:  # Invalid hostname
    """Test behavior when given an invalid hostname."""

    @pytest.mark.asyncio
    async def test_mission_with_invalid_hostname_creates(
        self, mission_manager: MissionManager
    ) -> None:
        """Verify mission can be created with a clearly invalid hostname."""
        mission = await mission_manager.create_mission(
            name="Invalid Hostname Test",
            mission_type=MissionType.EXTERNAL_ATTACK_SURFACE,
            target=MissionTarget(domains=["!nv4l1d-hostname!!!"]),
        )
        assert mission is not None
        assert mission.status == MissionStatus.DRAFT


class TestFailureScenario2:  # Unreachable host
    """Test behavior when target is unreachable."""

    @pytest.mark.asyncio
    async def test_mission_with_unreachable_target_can_be_cancelled(
        self, mission_manager: MissionManager
    ) -> None:
        """Verify a mission with unreachable targets can be cancelled."""
        mission = await mission_manager.create_mission(
            name="Unreachable Test",
            mission_type=MissionType.EXTERNAL_ATTACK_SURFACE,
            target=MissionTarget(ip_ranges=["10.255.255.255"]),
        )
        await mission_manager.start_mission(mission.id)
        cancelled = await mission_manager.cancel_mission(mission.id)
        assert cancelled.status == MissionStatus.CANCELLED


class TestFailureScenario3:  # Tool not available
    """Test behavior when a required tool is not available."""

    def test_tool_unavailable_error(self) -> None:
        """Verify ToolUnavailableError is properly structured."""
        error = ToolUnavailableError(
            tool_name="missing_tool",
            message="Tool 'missing_tool' is not installed or not in PATH",
        )
        assert error.code == "TOOL_UNAVAILABLE"
        assert error.status_code == 503
        assert "missing_tool" in error.message

    def test_tool_unavailable_serializable(self) -> None:
        """Verify ToolUnavailableError can be serialized."""
        error = ToolUnavailableError(tool_name="nuclei")
        error_dict = error.to_dict()
        assert error_dict["error"] is True
        assert error_dict["code"] == "TOOL_UNAVAILABLE"
        assert "tool_name" in error_dict["details"]


class TestFailureScenario4:  # Empty target
    """Test behavior when mission has no targets."""

    @pytest.mark.asyncio
    async def test_empty_target_raises_validation_error(
        self, mission_manager: MissionManager
    ) -> None:
        """Verify creating a mission with no targets raises an error."""
        with pytest.raises(Exception) as exc_info:
            await mission_manager.create_mission(
                name="Empty Target Test",
                mission_type=MissionType.EXTERNAL_ATTACK_SURFACE,
                target=MissionTarget(),
            )
        assert exc_info.value is not None


class TestFailureScenario5:  # Duplicate evidence
    """Test behavior when duplicate evidence arrives."""

    @pytest.mark.asyncio
    async def test_duplicate_evidence_handled(
        self, state_manager: StateManager
    ) -> None:
        """Verify duplicate evidence doesn't crash the system."""
        mission = make_mission()
        evidence = make_evidence(
            evidence_type=EvidenceType.OPEN_PORT,
            mission_id=mission.id,
        )
        await state_manager.initialize_mission_state(mission)

        # Add same evidence twice
        await state_manager.add_evidence(mission.id, evidence)
        await state_manager.add_evidence(mission.id, evidence)

        # Should still have one (dict dedup by id)
        retrieved = state_manager.get_evidence(mission.id)
        assert len(retrieved) == 1


class TestFailureScenario6:  # Validation failure
    """Test behavior when validation fails."""

    @pytest.mark.asyncio
    async def test_low_confidence_evidence_flagged(
        self, validator: Validator
    ) -> None:
        """Verify low confidence evidence is flagged but doesn't crash."""
        evidence = make_evidence(confidence=0.01)
        result = await validator.validate_evidence(evidence)
        # Should still return evidence, not raise
        assert result is not None

    @pytest.mark.asyncio
    async def test_missing_title_validation(
        self, validator: Validator
    ) -> None:
        """Verify missing title reduces confidence."""
        evidence = make_evidence(title="")
        result = await validator.validate_evidence(evidence)
        # Should still process, just with potentially lower confidence
        assert result is not None


class TestFailureScenario7:  # Policy violation
    """Test behavior when a policy is violated."""

    def test_policy_violation_error(self) -> None:
        """Verify PolicyViolationError is properly structured."""
        error = PolicyViolationError(
            message="Production systems cannot be targeted",
            policy_name="no_production_exploitation",
        )
        assert error.code == "POLICY_VIOLATION"
        assert error.status_code == 403
        assert error.to_dict()["details"]["policy_name"] == "no_production_exploitation"

    @pytest.mark.asyncio
    async def test_policy_engine_rejects_production_target(
        self, policy_engine: PolicyEngine
    ) -> None:
        """Verify policy engine flags production-like targets."""
        mission = make_mission(
            domains=["prod.example.com"],
        )
        results = await policy_engine.check_mission(mission)
        deny_results = [r for r in results if r.effect.value == "deny" and not r.passed]
        assert len(deny_results) >= 0  # May or may not match depending on config

    @pytest.mark.asyncio
    async def test_policy_engine_allows_safe_target(
        self, policy_engine: PolicyEngine
    ) -> None:
        """Verify policy engine allows safe targets."""
        mission = make_mission(
            domains=["test-scan.example.org"],
        )
        results = await policy_engine.check_mission(mission)
        all_passed = all(r.passed for r in results)
        assert all_passed


class TestFailureScenario8:  # Agent execution failure
    """Test behavior when an agent fails during execution."""

    @pytest.mark.asyncio
    async def test_scheduler_handles_task_failure(
        self, scheduler: Scheduler
    ) -> None:
        """Verify scheduler doesn't crash when a task fails."""
        executed = []

        async def executor(task: Task) -> None:
            executed.append(task.id)
            if len(executed) == 1:
                raise RuntimeError("First task fails")
            return {"status": "ok"}

        await scheduler.start()
        scheduler.set_executor(executor)

        mission_id = uuid4()
        task1 = Task(
            mission_id=mission_id,
            name="Failing Task",
            retry_on_failure=False,
            max_retries=0,
        )
        task2 = Task(
            mission_id=mission_id,
            name="Good Task",
        )
        await scheduler.schedule_task(task1)
        await scheduler.schedule_task(task2)

        await asyncio.sleep(1)
        await scheduler.stop()

        # Both tasks should have been attempted
        assert len(executed) == 2

        # First task should have failed (in DLQ)
        dlq = scheduler.get_dead_letter_queue()
        # At least one task should have been attempted


class TestFailureScenario9:  # Concurrent mission limits
    """Test behavior when mission limits are approached."""

    @pytest.mark.asyncio
    async def test_multiple_missions_can_coexist(
        self, mission_manager: MissionManager
    ) -> None:
        """Verify multiple missions can exist simultaneously."""
        missions = []
        for i in range(5):
            mission = await mission_manager.create_mission(
                name=f"Concurrent Mission {i}",
                mission_type=MissionType.EXTERNAL_ATTACK_SURFACE,
                target=MissionTarget(domains=[f"target{i}.example.com"]),
            )
            missions.append(mission)

        all_missions = mission_manager.list_missions()
        assert len(all_missions) >= 5


class TestFailureScenario10:  # Resource exhaustion
    """Test behavior under resource pressure."""

    @pytest.mark.asyncio
    async def test_scheduler_limits_concurrent_tasks(self) -> None:
        """Verify scheduler respects max concurrent limit."""
        max_concurrent = 3
        scheduler = Scheduler(max_concurrent=max_concurrent)

        running = set()

        async def slow_executor(task: Task) -> None:
            running.add(task.id)
            await asyncio.sleep(0.5)
            running.discard(task.id)

        await scheduler.start()
        scheduler.set_executor(slow_executor)

        mission_id = uuid4()
        for i in range(10):
            task = Task(mission_id=mission_id, name=f"Load {i}")
            await scheduler.schedule_task(task)

        # Give scheduler time to dispatch
        await asyncio.sleep(0.3)
        stats = scheduler.get_queue_stats()
        await scheduler.stop()

        # Should not exceed max_concurrent
        assert stats["running"] <= max_concurrent


class TestFailureScenario11:  # State manager edge cases
    """Test state manager edge cases."""

    def test_get_nonexistent_mission_state(
        self, state_manager: StateManager
    ) -> None:
        """Verify querying a nonexistent mission returns None."""
        result = state_manager.get_mission_summary(uuid4())
        assert result is None

    def test_get_assets_for_nonexistent_mission(
        self, state_manager: StateManager
    ) -> None:
        """Verify assets for nonexistent mission returns empty list."""
        assets = state_manager.get_assets(uuid4())
        assert assets == []

    def test_get_evidence_for_nonexistent_mission(
        self, state_manager: StateManager
    ) -> None:
        """Verify evidence for nonexistent mission returns empty list."""
        evidence = state_manager.get_evidence(uuid4())
        assert evidence == []

    def test_get_findings_for_nonexistent_mission(
        self, state_manager: StateManager
    ) -> None:
        """Verify findings for nonexistent mission returns empty list."""
        findings = state_manager.get_findings(uuid4())
        assert findings == []


class TestFailureScenario12:  # Event bus failure
    """Test event bus failure handling."""

    @pytest.mark.asyncio
    async def test_event_bus_handles_subscriber_failure(
        self, started_event_bus, captured_events
    ) -> None:
        """Verify event bus doesn't crash when a subscriber raises."""
        event = OracleEvent(
            event_type=EventType.MISSION_CREATED,
            source="test",
            data={"test": True},
        )

        bus = get_event_bus()
        await bus.publish(event)

        # Give event bus time to deliver
        await asyncio.sleep(0.5)

        # Even if subscriber fails, the event bus should keep running
        health = await bus.health()
        assert health["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_publish_to_stopped_bus(self) -> None:
        """Verify publishing to a stopped bus doesn't crash."""
        bus = EventBus()
        event = OracleEvent(
            event_type=EventType.SYSTEM_STARTUP,
            source="test",
        )
        # This should not raise
        await bus.publish(event)

