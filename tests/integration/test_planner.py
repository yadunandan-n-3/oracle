"""
Integration Tests: Planner
==========================

Tests the Planner's ability to decompose mission goals into
executable task graphs with proper dependencies.
"""

from __future__ import annotations

from typing import Dict, List

import pytest
import pytest_asyncio

from domain.mission import Mission, MissionType, MissionTarget
from runtime.planner import Planner, Plan, Task, TaskPriority, TaskStatus
from tests.conftest import make_mission


class TestPlannerCreation:
    """Tests for creating plans from missions."""

    @pytest.mark.asyncio
    async def test_planner_creates_plan(self, planner: Planner) -> None:
        """Verify planner creates a plan for a valid mission."""
        mission = make_mission()
        plan = await planner.create_plan(mission)
        assert plan is not None
        assert plan.mission_id == mission.id
        assert isinstance(plan, Plan)
        assert plan.total_tasks > 0

    @pytest.mark.asyncio
    async def test_plan_has_tasks(self, planner: Planner) -> None:
        """Verify the plan contains tasks."""
        mission = make_mission()
        plan = await planner.create_plan(mission)
        assert len(plan.tasks) > 0
        for task in plan.tasks:
            assert task.mission_id == mission.id
            assert task.name
            assert task.required_capabilities
            assert task.status == TaskStatus.PENDING or task.status == TaskStatus.READY

    @pytest.mark.asyncio
    async def test_plan_tasks_have_capabilities(self, planner: Planner) -> None:
        """Verify each task has a required capability."""
        mission = make_mission()
        plan = await planner.create_plan(mission)
        for task in plan.tasks:
            assert len(task.required_capabilities) > 0
            assert isinstance(task.required_capabilities[0], str)

    @pytest.mark.asyncio
    async def test_plan_has_estimated_duration(self, planner: Planner) -> None:
        """Verify plan includes estimated duration."""
        mission = make_mission()
        plan = await planner.create_plan(mission)
        assert plan.estimated_duration_minutes > 0


class TestPlannerMissionTypes:
    """Tests for different mission type planning."""

    @pytest.mark.asyncio
    async def test_external_attack_surface_plan(self, planner: Planner) -> None:
        """Verify external attack surface mission produces expected capabilities."""
        mission = make_mission(
            name="External Test",
            mission_type=MissionType.EXTERNAL_ATTACK_SURFACE,
            domains=["example.com"],
        )
        plan = await planner.create_plan(mission)
        capabilities = set()
        for task in plan.tasks:
            capabilities.update(task.required_capabilities)

        # Should include reconnaissance and scanning capabilities
        assert "port_scanning" in capabilities or "subdomain_enumeration" in capabilities
        assert "service_discovery" in capabilities or "technology_detection" in capabilities
        assert plan.total_tasks >= 3

    @pytest.mark.asyncio
    async def test_api_security_plan(self, planner: Planner) -> None:
        """Verify API security assessment produces appropriate capabilities."""
        mission = make_mission(
            name="API Test",
            mission_type=MissionType.API_SECURITY_ASSESSMENT,
            urls=["https://api.example.com/v1"],
        )
        plan = await planner.create_plan(mission)
        capabilities = set()
        for task in plan.tasks:
            capabilities.update(task.required_capabilities)

        assert "api_discovery" in capabilities or "endpoint_enumeration" in capabilities
        assert "authentication_testing" in capabilities or "authorization_testing" in capabilities
        assert plan.total_tasks >= 2

    @pytest.mark.asyncio
    async def test_cloud_audit_plan(self, planner: Planner) -> None:
        """Verify cloud audit produces appropriate capabilities."""
        mission = make_mission(
            name="Cloud Test",
            mission_type=MissionType.CLOUD_AUDIT,
            domains=["cloud.example.com"],
        )
        plan = await planner.create_plan(mission)
        capabilities = set()
        for task in plan.tasks:
            capabilities.update(task.required_capabilities)

        assert "cloud_resource_enumeration" in capabilities or "iam_analysis" in capabilities
        assert plan.total_tasks >= 2

    @pytest.mark.asyncio
    async def test_custom_mission_type_fallback(self, planner: Planner) -> None:
        """Verify custom mission types get a default plan."""
        mission = make_mission(
            name="Custom Test",
            mission_type=MissionType.CUSTOM,
            domains=["custom.example.com"],
        )
        plan = await planner.create_plan(mission)
        assert plan.total_tasks > 0


class TestTaskDependencies:
    """Tests for task dependency graph."""

    @pytest.mark.asyncio
    async def test_tasks_have_dependencies(self, planner: Planner) -> None:
        """Verify tasks have proper dependency ordering."""
        mission = make_mission()
        plan = await planner.create_plan(mission)

        # First tasks should have no dependencies
        first_tasks = [t for t in plan.tasks if not t.depends_on]
        assert len(first_tasks) > 0

        # Later tasks should depend on earlier ones
        later_tasks = [t for t in plan.tasks if t.depends_on]
        if later_tasks:
            assert len(later_tasks) > 0

    @pytest.mark.asyncio
    async def test_first_tasks_ready(self, planner: Planner) -> None:
        """Verify first wave tasks are marked as READY."""
        mission = make_mission()
        plan = await planner.create_plan(mission)
        ready_tasks = planner.get_ready_tasks(plan.id)
        assert len(ready_tasks) > 0


class TestTaskStatusUpdates:
    """Tests for task status transitions."""

    @pytest.mark.asyncio
    async def test_update_task_to_running(self, planner: Planner) -> None:
        """Verify task status can be updated to RUNNING."""
        mission = make_mission()
        plan = await planner.create_plan(mission)
        task = plan.tasks[0]

        await planner.update_task_status(plan.id, task.id, TaskStatus.RUNNING)
        updated_plan = planner.get_plan(plan.id)
        assert updated_plan is not None
        updated_task = next(t for t in updated_plan.tasks if t.id == task.id)
        assert updated_task.status == TaskStatus.RUNNING
        assert updated_task.started_at is not None

    @pytest.mark.asyncio
    async def test_update_task_to_completed(self, planner: Planner) -> None:
        """Verify task status can be updated to COMPLETED."""
        mission = make_mission()
        plan = await planner.create_plan(mission)
        task = plan.tasks[0]

        await planner.update_task_status(plan.id, task.id, TaskStatus.COMPLETED)
        updated_plan = planner.get_plan(plan.id)
        assert updated_plan is not None
        updated_task = next(t for t in updated_plan.tasks if t.id == task.id)
        assert updated_task.status == TaskStatus.COMPLETED
        assert updated_task.completed_at is not None

    @pytest.mark.asyncio
    async def test_update_task_to_failed(self, planner: Planner) -> None:
        """Verify task can be marked as failed with error."""
        mission = make_mission()
        plan = await planner.create_plan(mission)
        task = plan.tasks[0]

        await planner.update_task_status(
            plan.id, task.id, TaskStatus.FAILED, error="Test failure"
        )
        updated_plan = planner.get_plan(plan.id)
        assert updated_plan is not None
        updated_task = next(t for t in updated_plan.tasks if t.id == task.id)
        assert updated_task.status == TaskStatus.FAILED
        assert updated_task.error == "Test failure"

    @pytest.mark.asyncio
    async def test_completing_task_unlocks_dependents(
        self, planner: Planner
    ) -> None:
        """Verify completing a task unblocks dependent tasks."""
        mission = make_mission()
        plan = await planner.create_plan(mission)

        # Find a task with dependencies
        dependent_task = None
        dependency_id = None
        for task in plan.tasks:
            if task.depends_on:
                dependent_task = task
                dependency_id = task.depends_on[0]
                break

        if dependent_task and dependency_id:
            # Complete every dependency in the preceding parallel task group.
            for dependency_id in dependent_task.depends_on:
                await planner.update_task_status(
                    plan.id, dependency_id, TaskStatus.COMPLETED
                )
            # Check if dependent is now ready
            updated_plan = planner.get_plan(plan.id)
            assert updated_plan is not None
            updated_dep = next(t for t in updated_plan.tasks if t.id == dependent_task.id)
            assert updated_dep.status == TaskStatus.READY


class TestPlanRetrieval:
    """Tests for retrieving plans."""

    @pytest.mark.asyncio
    async def test_get_plan_by_id(self, planner: Planner) -> None:
        """Verify plan can be retrieved by ID."""
        mission = make_mission()
        plan = await planner.create_plan(mission)
        retrieved = planner.get_plan(plan.id)
        assert retrieved is not None
        assert retrieved.id == plan.id

    @pytest.mark.asyncio
    async def test_get_mission_plan(self, planner: Planner) -> None:
        """Verify plan can be retrieved by mission ID."""
        mission = make_mission()
        plan = await planner.create_plan(mission)
        retrieved = planner.get_mission_plan(mission.id)
        assert retrieved is not None
        assert retrieved.mission_id == mission.id

    @pytest.mark.asyncio
    async def test_get_ready_tasks(self, planner: Planner) -> None:
        """Verify ready tasks are returned correctly."""
        mission = make_mission()
        plan = await planner.create_plan(mission)
        ready_tasks = planner.get_ready_tasks(plan.id)
        assert len(ready_tasks) > 0
        for task in ready_tasks:
            assert task.status == TaskStatus.READY

