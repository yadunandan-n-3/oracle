"""
Unit Tests: State Manager
=========================

Tests for the mission state management component.
"""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
import pytest_asyncio

from domain.asset import Asset, AssetType, AssetCriticality
from domain.evidence import Evidence, EvidenceType, EvidenceStatus, EvidenceSource
from domain.finding import Finding, FindingSeverity, FindingStatus
from domain.mission import Mission, MissionStatus, MissionTarget, MissionType
from runtime.state_manager import StateManager, MissionState
from runtime.planner import Task, TaskPriority, TaskStatus
from tests.conftest import make_mission, make_evidence, make_asset, make_finding, make_task


class TestStateManagerCreation:
    """Tests for state manager initialization."""

    @pytest.mark.asyncio
    async def test_initialize_mission_state(
        self, state_manager: StateManager
    ) -> None:
        """Verify mission state can be initialized."""
        mission = make_mission()
        state = await state_manager.initialize_mission_state(mission)
        assert state is not None
        assert state.mission.id == mission.id
        assert state.started_at is not None

    @pytest.mark.asyncio
    async def test_get_mission_state(
        self, state_manager: StateManager
    ) -> None:
        """Verify mission state can be retrieved."""
        mission = make_mission()
        await state_manager.initialize_mission_state(mission)
        state = await state_manager.get_mission_state(mission.id)
        assert state is not None
        assert state.mission.id == mission.id

    @pytest.mark.asyncio
    async def test_archive_mission_state(
        self, state_manager: StateManager
    ) -> None:
        """Verify mission state can be archived."""
        mission = make_mission()
        await state_manager.initialize_mission_state(mission)
        await state_manager.archive_mission_state(mission.id)
        state = await state_manager.get_mission_state(mission.id)
        assert state is None


class TestStateManagerTasks:
    """Tests for task state management."""

    @pytest.mark.asyncio
    async def test_register_active_task(
        self, state_manager: StateManager
    ) -> None:
        """Verify active task can be registered."""
        mission = make_mission()
        await state_manager.initialize_mission_state(mission)
        task = make_task(mission_id=mission.id)
        await state_manager.register_active_task(mission.id, task)
        state = await state_manager.get_mission_state(mission.id)
        assert state is not None
        assert task.id in state.active_tasks

    @pytest.mark.asyncio
    async def test_complete_task(
        self, state_manager: StateManager
    ) -> None:
        """Verify task can be marked as completed."""
        mission = make_mission()
        await state_manager.initialize_mission_state(mission)
        task = make_task(mission_id=mission.id)

        await state_manager.register_active_task(mission.id, task)
        await state_manager.complete_task(mission.id, task)

        state = await state_manager.get_mission_state(mission.id)
        assert state is not None
        assert task.id in state.completed_tasks
        assert task.id not in state.active_tasks

    @pytest.mark.asyncio
    async def test_fail_task(
        self, state_manager: StateManager
    ) -> None:
        """Verify task can be marked as failed."""
        mission = make_mission()
        await state_manager.initialize_mission_state(mission)
        task = make_task(mission_id=mission.id)

        await state_manager.register_active_task(mission.id, task)
        await state_manager.fail_task(mission.id, task)

        state = await state_manager.get_mission_state(mission.id)
        assert state is not None
        assert task.id in state.failed_tasks
        assert task.id not in state.active_tasks


class TestStateManagerAssets:
    """Tests for asset state management."""

    @pytest.mark.asyncio
    async def test_add_asset(
        self, state_manager: StateManager
    ) -> None:
        """Verify asset can be added to mission state."""
        mission = make_mission()
        await state_manager.initialize_mission_state(mission)
        asset = make_asset(value="10.0.0.1")
        await state_manager.add_asset(mission.id, asset)

        assets = state_manager.get_assets(mission.id)
        assert len(assets) == 1
        assert assets[0].value == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_add_duplicate_asset_updates(
        self, state_manager: StateManager
    ) -> None:
        """Verify adding same asset value updates existing."""
        mission = make_mission()
        await state_manager.initialize_mission_state(mission)

        asset1 = make_asset(value="10.0.0.1", open_ports=[80])
        await state_manager.add_asset(mission.id, asset1)

        asset2 = make_asset(value="10.0.0.1", open_ports=[443])
        await state_manager.add_asset(mission.id, asset2)

        assets = state_manager.get_assets(mission.id)
        assert len(assets) == 1
        # Both ports should be merged
        assert 80 in assets[0].open_ports
        assert 443 in assets[0].open_ports

    @pytest.mark.asyncio
    async def test_get_asset_by_value(
        self, state_manager: StateManager
    ) -> None:
        """Verify asset can be retrieved by value."""
        mission = make_mission()
        await state_manager.initialize_mission_state(mission)

        asset = make_asset(value="192.168.1.1")
        await state_manager.add_asset(mission.id, asset)

        retrieved = state_manager.get_asset_by_value(mission.id, "192.168.1.1")
        assert retrieved is not None
        assert retrieved.value == "192.168.1.1"

    @pytest.mark.asyncio
    async def test_get_asset_by_nonexistent_value(
        self, state_manager: StateManager
    ) -> None:
        """Verify querying nonexistent asset returns None."""
        mission = make_mission()
        await state_manager.initialize_mission_state(mission)

        retrieved = state_manager.get_asset_by_value(mission.id, "10.0.0.99")
        assert retrieved is None


class TestStateManagerFindings:
    """Tests for finding state management."""

    @pytest.mark.asyncio
    async def test_add_finding(
        self, state_manager: StateManager
    ) -> None:
        """Verify finding can be added to mission state."""
        mission = make_mission()
        await state_manager.initialize_mission_state(mission)
        finding = make_finding(
            title="Critical Vulnerability",
            severity=FindingSeverity.CRITICAL,
        )
        await state_manager.add_finding(mission.id, finding)

        findings = state_manager.get_findings(mission.id)
        assert len(findings) == 1
        assert findings[0].title == "Critical Vulnerability"

    @pytest.mark.asyncio
    async def test_add_finding_updates_mission_counters(
        self, state_manager: StateManager
    ) -> None:
        """Verify adding findings updates mission counters."""
        mission = make_mission()
        await state_manager.initialize_mission_state(mission)

        findings_data = [
            ("Critical One", FindingSeverity.CRITICAL),
            ("High One", FindingSeverity.HIGH),
            ("Medium One", FindingSeverity.MEDIUM),
            ("Low One", FindingSeverity.LOW),
        ]
        for title, severity in findings_data:
            finding = make_finding(title=title, severity=severity)
            await state_manager.add_finding(mission.id, finding)

        # Check mission counters via state
        state = await state_manager.get_mission_state(mission.id)
        assert state is not None
        assert state.mission.critical_findings == 1
        assert state.mission.high_findings == 1
        assert state.mission.medium_findings == 1
        assert state.mission.low_findings == 1
        assert state.mission.total_findings == 4

    @pytest.mark.asyncio
    async def test_get_findings_by_severity(
        self, state_manager: StateManager
    ) -> None:
        """Verify findings can be filtered by severity."""
        mission = make_mission()
        await state_manager.initialize_mission_state(mission)

        high = make_finding(title="High", severity=FindingSeverity.HIGH)
        low = make_finding(title="Low", severity=FindingSeverity.LOW)
        await state_manager.add_finding(mission.id, high)
        await state_manager.add_finding(mission.id, low)

        high_findings = state_manager.get_findings(mission.id, severity="high")
        assert len(high_findings) == 1
        assert high_findings[0].title == "High"


class TestStateManagerTimeline:
    """Tests for event timeline management."""

    @pytest.mark.asyncio
    async def test_log_event(
        self, state_manager: StateManager
    ) -> None:
        """Verify events can be logged to the timeline."""
        mission = make_mission()
        await state_manager.initialize_mission_state(mission)

        await state_manager.log_event(
            mission.id,
            "mission.started",
            {"mission_id": str(mission.id)},
        )
        timeline = state_manager.get_timeline(mission.id)
        assert len(timeline) == 1
        assert timeline[0]["event_type"] == "mission.started"

    @pytest.mark.asyncio
    async def test_timeline_limit(
        self, state_manager: StateManager
    ) -> None:
        """Verify timeline respects limit parameter."""
        mission = make_mission()
        await state_manager.initialize_mission_state(mission)

        for i in range(50):
            await state_manager.log_event(
                mission.id,
                f"event.{i}",
                {"index": i},
            )

        timeline_limited = state_manager.get_timeline(mission.id, limit=10)
        assert len(timeline_limited) == 10

        timeline_all = state_manager.get_timeline(mission.id, limit=100)
        assert len(timeline_all) == 50


class TestStateManagerContext:
    """Tests for agent context and memory management."""

    @pytest.mark.asyncio
    async def test_update_context(
        self, state_manager: StateManager
    ) -> None:
        """Verify mission context can be updated."""
        mission = make_mission()
        await state_manager.initialize_mission_state(mission)

        await state_manager.update_context(
            mission.id,
            {"phase": "discovery", "target": "example.com"},
        )
        state = await state_manager.get_mission_state(mission.id)
        assert state is not None
        assert state.context["phase"] == "discovery"
        assert state.context["target"] == "example.com"

    @pytest.mark.asyncio
    async def test_agent_memory(
        self, state_manager: StateManager
    ) -> None:
        """Verify agent memory can be set and retrieved."""
        mission = make_mission()
        await state_manager.initialize_mission_state(mission)

        await state_manager.update_agent_memory(
            mission.id,
            "discovery_agent",
            {"scanned_hosts": ["10.0.0.1", "10.0.0.2"]},
        )
        memory = state_manager.get_agent_memory(
            mission.id, "discovery_agent"
        )
        assert "scanned_hosts" in memory
        assert len(memory["scanned_hosts"]) == 2


class TestStateManagerSummary:
    """Tests for mission summary generation."""

    @pytest.mark.asyncio
    async def test_mission_summary(
        self, state_manager: StateManager
    ) -> None:
        """Verify mission summary contains all required fields."""
        mission = make_mission(name="Summary Test")
        await state_manager.initialize_mission_state(mission)

        summary = state_manager.get_mission_summary(mission.id)
        assert summary is not None
        assert summary["mission_name"] == "Summary Test"
        assert summary["mission_id"] == str(mission.id)
        assert "status" in summary
        assert "progress_percentage" in summary
        assert "total_tasks" in summary
        assert "active_tasks" in summary
        assert "completed_tasks" in summary
        assert "failed_tasks" in summary
        assert "total_assets" in summary
        assert "total_evidence" in summary
        assert "total_findings" in summary


class TestStateManagerEdgeCases:
    """Tests for edge cases in state management."""

    @pytest.mark.asyncio
    async def test_get_active_missions(
        self, state_manager: StateManager
    ) -> None:
        """Verify active missions query returns correct results."""
        # Create a mission in DRAFT (not active)
        draft_mission = make_mission(status=MissionStatus.DRAFT)
        await state_manager.initialize_mission_state(draft_mission)

        active = state_manager.get_active_missions()
        assert len(active) == 0

    @pytest.mark.asyncio
    async def test_operations_on_nonexistent_mission(
        self, state_manager: StateManager
    ) -> None:
        """Verify operations on nonexistent mission don't crash."""
        fake_id = uuid4()
        # These should not raise
        await state_manager.register_active_task(fake_id, make_task(mission_id=fake_id))
        await state_manager.complete_task(fake_id, make_task(mission_id=fake_id))
        await state_manager.fail_task(fake_id, make_task(mission_id=fake_id))
        await state_manager.add_asset(fake_id, make_asset())
        await state_manager.add_evidence(fake_id, make_evidence())
        await state_manager.add_finding(fake_id, make_finding())
        await state_manager.log_event(fake_id, "test", {})

