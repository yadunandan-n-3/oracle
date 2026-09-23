"""
Shared Test Fixtures
====================

Pytest fixtures shared across all ORACLE tests.
Provides mock database sessions, event bus, runtime, and domain objects.
"""

from __future__ import annotations

import asyncio
from typing import Any, AsyncGenerator, Dict, List, Optional
from uuid import UUID, uuid4

import pytest
import pytest_asyncio

from core.events import EventType, OracleEvent
from domain.asset import Asset, AssetType, AssetCriticality
from domain.evidence import Evidence, EvidenceType, EvidenceSource, EvidenceStatus
from domain.finding import Finding, FindingSeverity, FindingStatus
from domain.mission import (
    Mission,
    MissionGoal,
    MissionStatus,
    MissionTarget,
    MissionType,
    MissionPriority,
)
from runtime.event_bus import EventBus, get_event_bus, set_event_bus
from runtime.mission_manager import MissionManager
from runtime.state_manager import StateManager, MissionState
from runtime.planner import Planner, Plan, Task, TaskPriority, TaskStatus
from runtime.scheduler import Scheduler
from runtime.validator import Validator
from runtime.policy_engine import PolicyEngine
from runtime.resource_manager import ResourceManager, ResourceQuota


# ─── Helpers ───────────────────────────────────────────────────────────────


def make_mission(
    name: str = "Test Mission",
    mission_type: MissionType = MissionType.EXTERNAL_ATTACK_SURFACE,
    status: MissionStatus = MissionStatus.DRAFT,
    domains: Optional[List[str]] = None,
    ip_ranges: Optional[List[str]] = None,
    urls: Optional[List[str]] = None,
    goals: Optional[List[str]] = None,
) -> Mission:
    """Create a Mission with sensible defaults for testing."""
    target = MissionTarget(
        domains=domains or ["test.example.com"],
        ip_ranges=ip_ranges or [],
        urls=urls or [],
    )
    mission_goals = []
    if goals:
        for g in goals:
            mission_goals.append(MissionGoal(description=g))
    else:
        mission_goals.append(
            MissionGoal(description="Discover all subdomains and associated IP addresses")
        )

    return Mission(
        name=name,
        description=f"Test: {name}",
        mission_type=mission_type,
        priority=MissionPriority.MEDIUM,
        status=status,
        target=target,
        goals=mission_goals,
        created_by="test_user",
    )


def make_evidence(
    evidence_type: EvidenceType = EvidenceType.OPEN_PORT,
    asset_value: str = "192.168.1.1:80/tcp",
    title: str = "Open Port Detected",
    description: str = "",
    confidence: float = 0.95,
    raw_data: Optional[Dict[str, Any]] = None,
    cve_ids: Optional[List[str]] = None,
    mitre_techniques: Optional[List[str]] = None,
    asset_id: Optional[UUID] = None,
    mission_id: Optional[UUID] = None,
) -> Evidence:
    """Create an Evidence object with sensible defaults."""
    return Evidence(
        evidence_type=evidence_type,
        title=title,
        description=description or f"Evidence of type {evidence_type.value}",
        confidence=confidence,
        severity="medium",
        source=EvidenceSource(
            tool_name="nmap",
            tool_version="7.95",
            command="nmap -sS -p 80 target",
            agent_name="discovery_agent",
        ),
        asset_id=asset_id,
        asset_value=asset_value,
        mission_id=mission_id,
        raw_data=raw_data or {"port": 80, "protocol": "tcp", "service": "http"},
        status=EvidenceStatus.COLLECTED,
        cve_ids=cve_ids or [],
        mitre_techniques=mitre_techniques or ["T1046"],
        tags=["test", "open_port"],
    )


def make_asset(
    value: str = "192.168.1.1",
    asset_type: AssetType = AssetType.HOST,
    hostnames: Optional[List[str]] = None,
    open_ports: Optional[List[int]] = None,
    os: str = "",
) -> Asset:
    """Create an Asset with sensible defaults."""
    return Asset(
        asset_type=asset_type,
        value=value,
        label=hostnames[0] if hostnames else value,
        ip_addresses=[value],
        hostnames=hostnames or [],
        open_ports=open_ports or [80, 443],
        criticality=AssetCriticality.UNKNOWN,
        os=os,
    )


def make_finding(
    title: str = "Open Port 80",
    severity: FindingSeverity = FindingSeverity.MEDIUM,
    asset_value: str = "192.168.1.1",
    cve_id: Optional[str] = None,
    mitre_technique_id: Optional[str] = None,
) -> Finding:
    """Create a Finding with sensible defaults."""
    return Finding(
        title=title,
        description=f"Finding: {title}",
        severity=severity,
        status=FindingStatus.OPEN,
        asset_value=asset_value,
        cve_id=cve_id,
        mitre_technique_id=mitre_technique_id,
        discovered_by="discovery_agent",
    )


def make_task(
    mission_id: UUID,
    name: str = "port_scanning",
    capability: str = "port_scanning",
    priority: TaskPriority = TaskPriority.MEDIUM,
    depends_on: Optional[List[UUID]] = None,
    timeout: int = 300,
) -> Task:
    """Create a Task with sensible defaults."""
    return Task(
        mission_id=mission_id,
        name=name,
        description=f"Execute {capability}",
        priority=priority,
        status=TaskStatus.PENDING,
        required_capabilities=[capability],
        depends_on=depends_on or [],
        timeout_seconds=timeout,
        retry_on_failure=True,
        max_retries=3,
    )


# ─── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture
def event_bus() -> EventBus:
    """Create a fresh EventBus for each test."""
    bus = EventBus(max_workers=5, retry_max_attempts=1)
    set_event_bus(bus)
    return bus


@pytest_asyncio.fixture
async def started_event_bus(
    event_bus: EventBus,
    captured_events: List[OracleEvent],
) -> AsyncGenerator[EventBus, None]:
    """Start the event bus for tests that need it running."""
    async def capture(event: OracleEvent) -> None:
        captured_events.append(event)

    event_bus.subscribe("test_capturer", set(EventType), capture, "Capture test events")
    await event_bus.start()
    yield event_bus
    await event_bus.stop()
    event_bus.unsubscribe("test_capturer")


@pytest.fixture
def state_manager(event_bus: EventBus) -> StateManager:
    """Create a fresh StateManager."""
    return StateManager()


@pytest.fixture
def planner(event_bus: EventBus) -> Planner:
    """Create a fresh Planner."""
    return Planner()


@pytest.fixture
def validator(event_bus: EventBus) -> Validator:
    """Create a fresh Validator."""
    return Validator()


@pytest.fixture
def policy_engine() -> PolicyEngine:
    """Create a fresh PolicyEngine."""
    return PolicyEngine()


@pytest.fixture
def resource_manager() -> ResourceManager:
    """Create a fresh ResourceManager."""
    return ResourceManager()


@pytest.fixture
def scheduler() -> Scheduler:
    """Create a fresh Scheduler."""
    return Scheduler(max_concurrent=5)


@pytest.fixture
def sample_mission() -> Mission:
    """Create a sample mission for reuse."""
    return make_mission()


@pytest.fixture
def sample_evidence() -> Evidence:
    """Create a sample evidence object."""
    return make_evidence()


@pytest.fixture
def sample_asset() -> Asset:
    """Create a sample asset."""
    return make_asset()


@pytest.fixture
def sample_finding() -> Finding:
    """Create a sample finding."""
    return make_finding()


@pytest_asyncio.fixture
async def mission_with_state(
    sample_mission: Mission,
    state_manager: StateManager,
    planner: Planner,
) -> MissionState:
    """Create a mission with initialized state and plan."""
    plan = await planner.create_plan(sample_mission)
    state = await state_manager.initialize_mission_state(sample_mission, plan)
    return state


@pytest.fixture
def anyio_backend() -> str:
    """Use asyncio for async tests."""
    return "asyncio"


@pytest_asyncio.fixture
async def mission_manager(
    event_bus: EventBus,
) -> AsyncGenerator[MissionManager, None]:
    """Create a fresh MissionManager."""
    mm = MissionManager()
    yield mm


@pytest.fixture
def captured_events() -> List[OracleEvent]:
    """Capture published events during tests."""
    return []


@pytest_asyncio.fixture
async def event_capturer(
    captured_events: List[OracleEvent],
) -> AsyncGenerator[None, None]:
    """Start event bus and capture all events."""
    bus = get_event_bus()
    await bus.start()

    async def capture(event: OracleEvent) -> None:
        captured_events.append(event)

    bus.subscribe(
        "test_capturer",
        set(EventType),
        capture,
        "Capture all events for testing",
    )

    yield

    await bus.stop()
    bus.unsubscribe("test_capturer")

