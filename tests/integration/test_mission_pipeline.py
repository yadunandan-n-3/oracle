"""
Integration Tests: Mission Pipeline
====================================

Tests the full mission lifecycle: create → plan → execute → complete.
Verifies events, state transitions, and evidence collection.
"""

from __future__ import annotations

import asyncio
from typing import List
from uuid import UUID

import pytest
import pytest_asyncio

from core.events import EventType, OracleEvent
from domain.mission import Mission, MissionStatus, MissionTarget, MissionType
from runtime.event_bus import get_event_bus
from runtime.mission_manager import MissionManager
from runtime.planner import Planner, TaskStatus
from runtime.state_manager import StateManager
from runtime.runtime import OracleRuntime
from tests.conftest import make_mission, make_evidence


class TestMissionCreation:
    """Tests for mission creation flow."""

    @pytest.mark.asyncio
    async def test_create_mission_basic(self, mission_manager: MissionManager) -> None:
        """Verify a mission can be created with required fields."""
        mission = await mission_manager.create_mission(
            name="Integration Test Mission",
            mission_type=MissionType.EXTERNAL_ATTACK_SURFACE,
            target=MissionTarget(domains=["test.example.com"]),
            description="Testing mission creation",
            created_by="test_user",
        )
        assert mission.id is not None
        assert mission.name == "Integration Test Mission"
        assert mission.mission_type == MissionType.EXTERNAL_ATTACK_SURFACE
        assert mission.status == MissionStatus.DRAFT
        assert mission.created_by == "test_user"

    @pytest.mark.asyncio
    async def test_create_mission_with_goals(
        self, mission_manager: MissionManager
    ) -> None:
        """Verify custom goals are attached correctly."""
        goals = ["Discover subdomains", "Scan for open ports", "Detect technologies"]
        mission = await mission_manager.create_mission(
            name="Goal Test",
            mission_type=MissionType.EXTERNAL_ATTACK_SURFACE,
            target=MissionTarget(domains=["example.com"]),
            goals=goals,
        )
        assert len(mission.goals) == 3
        assert mission.goals[0].description == "Discover subdomains"
        assert mission.goals[1].description == "Scan for open ports"

    @pytest.mark.asyncio
    async def test_create_mission_missing_target_raises(
        self, mission_manager: MissionManager
    ) -> None:
        """Verify mission creation fails without targets."""
        with pytest.raises(Exception):
            await mission_manager.create_mission(
                name="Empty Target",
                mission_type=MissionType.EXTERNAL_ATTACK_SURFACE,
                target=MissionTarget(),
            )

    @pytest.mark.asyncio
    async def test_create_mission_publishes_event(
        self, mission_manager: MissionManager, started_event_bus, captured_events
    ) -> None:
        """Verify MISSION_CREATED event is published."""
        mission = await mission_manager.create_mission(
            name="Event Test",
            mission_type=MissionType.EXTERNAL_ATTACK_SURFACE,
            target=MissionTarget(domains=["event-test.com"]),
        )
        await asyncio.sleep(0.01)
        # Check event was captured
        created_events = [
            e for e in captured_events
            if e.event_type == EventType.MISSION_CREATED
        ]
        assert len(created_events) >= 1
        assert created_events[0].data["mission_id"] == str(mission.id)


class TestMissionLifecycle:
    """Tests for mission state transitions."""

    @pytest.mark.asyncio
    async def test_mission_transitions_draft_to_planning(
        self, sample_mission: Mission, mission_manager: MissionManager
    ) -> None:
        """Verify mission moves from DRAFT to PLANNING on start."""
        mission_manager._missions[sample_mission.id] = sample_mission
        started = await mission_manager.start_mission(sample_mission.id)
        assert started.status == MissionStatus.PLANNING
        assert started.started_at is not None

    @pytest.mark.asyncio
    async def test_mission_transitions_to_completed(
        self, sample_mission: Mission, mission_manager: MissionManager
    ) -> None:
        """Verify mission can complete successfully."""
        mission_manager._missions[sample_mission.id] = sample_mission
        await mission_manager.start_mission(sample_mission.id)
        completed = await mission_manager.complete_mission(sample_mission.id)
        assert completed.status == MissionStatus.COMPLETED
        assert completed.completed_at is not None

    @pytest.mark.asyncio
    async def test_mission_transitions_to_failed(
        self, sample_mission: Mission, mission_manager: MissionManager
    ) -> None:
        """Verify mission can fail with error."""
        mission_manager._missions[sample_mission.id] = sample_mission
        await mission_manager.start_mission(sample_mission.id)
        failed = await mission_manager.fail_mission(
            sample_mission.id, "Test failure"
        )
        assert failed.status == MissionStatus.FAILED
        assert failed.metadata.get("failure_reason") == "Test failure"

    @pytest.mark.asyncio
    async def test_cannot_start_already_running_mission(
        self, sample_mission: Mission, mission_manager: MissionManager
    ) -> None:
        """Verify you cannot start a mission that's already in progress."""
        mission_manager._missions[sample_mission.id] = sample_mission
        await mission_manager.start_mission(sample_mission.id)
        with pytest.raises(Exception):
            await mission_manager.start_mission(sample_mission.id)

    @pytest.mark.asyncio
    async def test_cancel_running_mission(
        self, sample_mission: Mission, mission_manager: MissionManager
    ) -> None:
        """Verify a running mission can be cancelled."""
        mission_manager._missions[sample_mission.id] = sample_mission
        await mission_manager.start_mission(sample_mission.id)
        cancelled = await mission_manager.cancel_mission(sample_mission.id)
        assert cancelled.status == MissionStatus.CANCELLED


class TestMissionStateManagement:
    """Tests for mission state tracking."""

    @pytest.mark.asyncio
    async def test_mission_state_tracks_assets(
        self, mission_with_state, state_manager: StateManager, sample_asset
    ) -> None:
        """Verify assets are tracked in mission state."""
        await state_manager.add_asset(
            mission_with_state.mission.id, sample_asset
        )
        assets = state_manager.get_assets(mission_with_state.mission.id)
        assert len(assets) == 1
        assert assets[0].value == sample_asset.value

    @pytest.mark.asyncio
    async def test_mission_state_tracks_evidence(
        self, mission_with_state, state_manager: StateManager, sample_evidence
    ) -> None:
        """Verify evidence is tracked in mission state."""
        await state_manager.add_evidence(
            mission_with_state.mission.id, sample_evidence
        )
        evidence = state_manager.get_evidence(mission_with_state.mission.id)
        assert len(evidence) == 1
        assert evidence[0].id == sample_evidence.id

    @pytest.mark.asyncio
    async def test_mission_state_tracks_findings(
        self, mission_with_state, state_manager: StateManager, sample_finding
    ) -> None:
        """Verify findings are tracked in mission state."""
        await state_manager.add_finding(
            mission_with_state.mission.id, sample_finding
        )
        findings = state_manager.get_findings(mission_with_state.mission.id)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_mission_state_progress_percentage(
        self, mission_with_state, state_manager: StateManager
    ) -> None:
        """Verify progress percentage is calculated correctly."""
        state = mission_with_state
        assert state.progress_percentage == 0.0

        # Complete some tasks
        for task in state.plan.tasks[: len(state.plan.tasks) // 2]:
            task.status = TaskStatus.COMPLETED
            await state_manager.complete_task(
                state.mission.id, task
            )

        updated_state = await state_manager.get_mission_state(
            state.mission.id
        )
        assert updated_state is not None
        assert updated_state.progress_percentage > 0.0
        assert updated_state.progress_percentage <= 100.0

    @pytest.mark.asyncio
    async def test_mission_timeline_events(
        self, mission_with_state, state_manager: StateManager
    ) -> None:
        """Verify timeline events are logged correctly."""
        await state_manager.log_event(
            mission_with_state.mission.id,
            "mission.started",
            {"mission_id": str(mission_with_state.mission.id)},
        )
        await state_manager.log_event(
            mission_with_state.mission.id,
            "scan.completed",
            {"target": "test.example.com", "ports_found": 3},
        )

        timeline = state_manager.get_timeline(
            mission_with_state.mission.id
        )
        assert len(timeline) == 2
        assert timeline[0]["event_type"] == "mission.started"
        assert timeline[1]["event_type"] == "scan.completed"


class TestMissionQuerying:
    """Tests for mission listing and filtering."""

    @pytest.mark.asyncio
    async def test_list_missions(self, mission_manager: MissionManager) -> None:
        """Verify missions can be listed."""
        for i in range(3):
            await mission_manager.create_mission(
                name=f"Query Test {i}",
                mission_type=MissionType.EXTERNAL_ATTACK_SURFACE,
                target=MissionTarget(domains=[f"test{i}.example.com"]),
            )
        missions = mission_manager.list_missions()
        assert len(missions) == 3

    @pytest.mark.asyncio
    async def test_list_missions_filtered_by_type(
        self, mission_manager: MissionManager
    ) -> None:
        """Verify missions can be filtered by mission type."""
        await mission_manager.create_mission(
            name="External",
            mission_type=MissionType.EXTERNAL_ATTACK_SURFACE,
            target=MissionTarget(domains=["ext.example.com"]),
        )
        await mission_manager.create_mission(
            name="API",
            mission_type=MissionType.API_SECURITY_ASSESSMENT,
            target=MissionTarget(domains=["api.example.com"]),
        )
        external_missions = mission_manager.list_missions(
            mission_type=MissionType.EXTERNAL_ATTACK_SURFACE
        )
        assert len(external_missions) == 1
        assert external_missions[0].name == "External"

    @pytest.mark.asyncio
    async def test_mission_summary(
        self, mission_with_state, state_manager: StateManager
    ) -> None:
        """Verify mission summary is returned."""
        summary = state_manager.get_mission_summary(
            mission_with_state.mission.id
        )
        assert summary is not None
        assert summary["mission_name"] == mission_with_state.mission.name
        assert "mission_id" in summary
        assert "status" in summary
        assert "progress_percentage" in summary

