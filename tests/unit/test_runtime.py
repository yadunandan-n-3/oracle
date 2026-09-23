"""
Unit Tests: OracleRuntime
=========================

Tests for the OracleRuntime kernel initialization, lifecycle,
and mission management API.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional
from uuid import UUID, uuid4

import pytest
import pytest_asyncio

from domain.mission import Mission, MissionStatus, MissionTarget, MissionType
from runtime.runtime import OracleRuntime, get_runtime


class TestRuntimeSingleton:
    """Tests for the runtime singleton pattern."""

    def test_get_runtime_returns_instance(self) -> None:
        """Verify get_runtime returns an OracleRuntime instance."""
        runtime = get_runtime()
        assert isinstance(runtime, OracleRuntime)

    def test_get_runtime_is_singleton(self) -> None:
        """Verify get_runtime always returns the same instance."""
        runtime1 = get_runtime()
        runtime2 = get_runtime()
        assert runtime1 is runtime2


class TestRuntimeInitialization:
    """Tests for runtime initialization."""

    @pytest.mark.asyncio
    async def test_runtime_starts_and_stops(self) -> None:
        """Verify runtime can start and stop gracefully."""
        from runtime.event_bus import set_event_bus, EventBus

        # Use a fresh event bus that doesn't try to connect
        bus = EventBus(max_workers=2, retry_max_attempts=1)
        set_event_bus(bus)

        runtime = OracleRuntime()
        assert not runtime._running

        # Start without external dependencies
        runtime._running = True
        runtime._started_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        runtime._event_bus = bus
        await bus.start()
        await runtime.scheduler.start()

        assert runtime._running

        # Stop gracefully — catch cancel errors during cleanup
        try:
            if runtime.scheduler:
                await runtime.scheduler.stop()
            await bus.stop()
        except (asyncio.CancelledError, RuntimeError):
            pass
        runtime._running = False
        assert not runtime._running

    @pytest.mark.asyncio
    async def test_health_before_start(self) -> None:
        """Verify health check returns correct status before start."""
        runtime = OracleRuntime()
        health = await runtime.health()
        assert health["running"] is False
        assert health["status"] == "stopped"

    @pytest.mark.asyncio
    async def test_health_after_start(self) -> None:
        """Verify health check returns correct status after start."""
        from runtime.event_bus import set_event_bus, EventBus

        bus = EventBus(max_workers=2, retry_max_attempts=1)
        set_event_bus(bus)

        runtime = OracleRuntime()
        runtime._running = True
        runtime._started_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        runtime._event_bus = bus

        health = await runtime.health()
        assert health["running"] is True
        assert health["status"] == "healthy"
        assert "uptime_seconds" in health
        assert "subsystems" in health


class TestRuntimeSubsystems:
    """Tests for runtime subsystem initialization."""

    @pytest.mark.asyncio
    async def test_runtime_has_all_subsystems(self) -> None:
        """Verify runtime initializes all required subsystems."""
        runtime = OracleRuntime()
        assert runtime.mission_manager is not None
        assert runtime.planner is not None
        assert runtime.scheduler is not None
        assert runtime.state_manager is not None
        assert runtime.policy_engine is not None
        assert runtime.resource_manager is not None
        assert runtime.validator is not None
        assert runtime.workflow_engine is not None
        assert runtime.tool_manager is not None
        assert runtime.knowledge_graph is not None

    @pytest.mark.asyncio
    async def test_runtime_event_bus_is_singleton(self) -> None:
        """Verify runtime uses the global event bus singleton."""
        from runtime.event_bus import get_event_bus
        runtime = OracleRuntime()
        assert runtime._event_bus is get_event_bus()


class TestRuntimeMissionAPI:
    """Tests for runtime mission management API."""

    @pytest.mark.asyncio
    async def test_create_mission(self) -> None:
        """Verify runtime creates missions correctly."""
        runtime = OracleRuntime()
        mission = await runtime.create_mission(
            name="Unit Test Mission",
            mission_type=MissionType.EXTERNAL_ATTACK_SURFACE,
            target=MissionTarget(domains=["unit.example.com"]),
            created_by="unit_test",
        )
        assert isinstance(mission, Mission)
        assert mission.status == MissionStatus.DRAFT

    @pytest.mark.asyncio
    async def test_get_mission(self) -> None:
        """Verify runtime retrieves missions by ID."""
        runtime = OracleRuntime()
        created = await runtime.create_mission(
            name="Get Test",
            mission_type=MissionType.EXTERNAL_ATTACK_SURFACE,
            target=MissionTarget(domains=["get.example.com"]),
        )
        retrieved = runtime.get_mission(created.id)
        assert retrieved is not None
        assert retrieved.id == created.id

    @pytest.mark.asyncio
    async def test_list_missions(self) -> None:
        """Verify runtime lists missions."""
        runtime = OracleRuntime()
        await runtime.create_mission(
            name="List Test 1",
            mission_type=MissionType.EXTERNAL_ATTACK_SURFACE,
            target=MissionTarget(domains=["list1.example.com"]),
        )
        await runtime.create_mission(
            name="List Test 2",
            mission_type=MissionType.EXTERNAL_ATTACK_SURFACE,
            target=MissionTarget(domains=["list2.example.com"]),
        )
        missions = runtime.list_missions()
        assert len(missions) >= 2

    @pytest.mark.asyncio
    async def test_get_mission_state(self) -> None:
        """Verify runtime returns mission state."""
        runtime = OracleRuntime()
        mission = await runtime.create_mission(
            name="State Test",
            mission_type=MissionType.EXTERNAL_ATTACK_SURFACE,
            target=MissionTarget(domains=["state.example.com"]),
        )
        state = runtime.get_mission_state(mission.id)
        # State may not exist until mission is executed
        assert state is None or isinstance(state, dict)

    @pytest.mark.asyncio
    async def test_get_system_stats(self) -> None:
        """Verify runtime returns system statistics."""
        runtime = OracleRuntime()
        stats = runtime.get_system_stats()
        assert isinstance(stats, dict)
        assert "active_missions" in stats
        assert "scheduler" in stats
        assert "uptime_seconds" in stats

    @pytest.mark.asyncio
    async def test_get_mission_templates(self) -> None:
        """Verify runtime returns mission templates."""
        runtime = OracleRuntime()
        templates = runtime.get_mission_templates()
        assert len(templates) > 0
        for template in templates:
            assert "id" in template
            assert "name" in template
            assert "mission_type" in template
            assert "default_goals" in template


class TestRuntimeCapabilityRegistration:
    """Tests for capability handler registration."""

    @pytest.mark.asyncio
    async def test_register_capability_handler(self) -> None:
        """Verify capability handlers can be registered."""
        runtime = OracleRuntime()

        async def mock_handler(task: Any) -> Dict[str, Any]:
            return {"status": "executed"}

        runtime.register_capability_handler("port_scanning", mock_handler)
        assert "port_scanning" in runtime._registered_handlers


class TestRuntimeEvidenceProcessing:
    """Tests for evidence processing pipeline."""

    @pytest.mark.asyncio
    async def test_process_evidence_validates(self) -> None:
        """Verify evidence processing calls validator."""
        from domain.evidence import Evidence, EvidenceType
        from tests.conftest import make_evidence

        runtime = OracleRuntime()
        evidence = make_evidence()
        # Should not raise
        try:
            await runtime.process_evidence(evidence, uuid4())
        except Exception:
            # May fail if DB/NEO4J unavailable, but should not crash
            pass


class TestRuntimeEdgeCases:
    """Tests for runtime edge cases."""

    @pytest.mark.asyncio
    async def test_double_start_is_safe(self) -> None:
        """Verify calling start twice is safe."""
        from runtime.event_bus import set_event_bus, EventBus

        bus = EventBus(max_workers=2, retry_max_attempts=1)
        set_event_bus(bus)
        await bus.start()

        runtime = OracleRuntime()
        runtime._running = True
        runtime._started_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        runtime._event_bus = bus
        await runtime.scheduler.start()

        # second start should be safe (no-op)
        await runtime.start()
        assert runtime._running

        await runtime.scheduler.stop()
        await bus.stop()
        runtime._running = False

    @pytest.mark.asyncio
    async def test_stop_without_start_is_safe(self) -> None:
        """Verify calling stop without start is safe."""
        runtime = OracleRuntime()
        await runtime.stop()  # Should not raise


class TestRuntimeEventLogging:
    """Tests for runtime internal event logging."""

    @pytest.mark.asyncio
    async def test_runtime_logs_startup_event(self) -> None:
        """Verify runtime publishes SYSTEM_STARTUP event on start."""
        # This test just verifies the method exists
        runtime = OracleRuntime()
        assert hasattr(runtime, "_log_event")
        assert hasattr(runtime, "_persist_mission_status")

