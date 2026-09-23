"""
Integration Test Fixtures
=========================

Provides mock tool plugins, mock agents, and shared test utilities
for integration testing of the ORACLE runtime pipeline.
"""

from __future__ import annotations

import asyncio
from typing import Any, AsyncGenerator, AsyncIterator, Dict, List, Optional
from uuid import UUID

import pytest
import pytest_asyncio

from core.events import EventType, OracleEvent
from core.interfaces import OracleAgent, Evidence as CoreEvidence, Capability
from core.tool_manager import ToolManager, get_tool_manager
from domain.evidence import Evidence as DomainEvidence, EvidenceType, EvidenceSource, EvidenceStatus
from domain.mission import Mission, MissionTarget, MissionType, MissionStatus
from runtime.event_bus import get_event_bus, set_event_bus
from runtime.runtime import OracleRuntime, get_runtime
from tools.nmap import NmapPlugin


# ─── Mock Nmap Plugin ──────────────────────────────────────────────────────


class MockNmapPlugin(NmapPlugin):
    """
    Mock Nmap plugin for integration testing.

    Returns predictable results without requiring Nmap to be installed.
    """

    name = "nmap"
    version = "7.95-test"
    description = "Mock Nmap for testing"

    def __init__(self) -> None:
        super().__init__()
        self._available = True
        self._execution_count = 0
        self._fail_next = False

    def set_available(self, available: bool) -> None:
        """Control whether the mock reports as available."""
        self._available = available

    def set_fail_next(self, fail: bool = True) -> None:
        """Cause the next execution to fail."""
        self._fail_next = fail

    async def health_check(self) -> Dict[str, Any]:
        """Mock health check."""
        if self._available:
            return {"healthy": True, "available": True, "version": "7.95-test", "error": None}
        return {"healthy": False, "available": False, "version": None, "error": "Nmap not found"}

    async def execute(
        self,
        targets: List[str],
        ports: str = "1-1000",
        scan_type: str = "syn",
        timing: int = 3,
        service_detection: bool = True,
        os_detection: bool = False,
        nse_scripts: Optional[List[str]] = None,
        output_xml: bool = True,
        additional_args: Optional[List[str]] = None,
    ) -> AsyncIterator[bytes]:
        """Mock Nmap execution yielding simulated XML output."""
        self._execution_count += 1

        if self._fail_next:
            self._fail_next = False
            raise RuntimeError("Simulated Nmap execution failure")

        # Simulate XML output for a single host
        target = targets[0] if targets else "scanme.nmap.org"
        xml = f"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="{target}" addrtype="ipv4"/>
    <hostnames><hostname name="{target}" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu" method="table" conf="3"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.24.0" method="table" conf="3"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.24.0" method="table" conf="3"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.x" accuracy="95"/>
    </os>
  </host>
</nmaprun>"""
        yield xml.encode("utf-8")

# ─── Mock Tool Manager ─────────────────────────────────────────────────────


@pytest.fixture
def mock_nmap() -> MockNmapPlugin:
    """Create a fresh MockNmapPlugin."""
    return MockNmapPlugin()


@pytest.fixture
def tool_manager(mock_nmap: MockNmapPlugin) -> ToolManager:
    """Create a ToolManager with the mock Nmap registered."""
    tm = ToolManager()
    tm.register_tool("nmap", mock_nmap)
    return tm


# ─── Events Capture ────────────────────────────────────────────────────────


@pytest.fixture
def captured_events() -> List[OracleEvent]:
    """List to capture published events during integration tests."""
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

    # Subscribe to all event types
    bus.subscribe(
        "test_capturer",
        set(EventType),
        capture,
        "Capture all events for testing",
    )

    yield

    await bus.stop()
    bus.unsubscribe("test_capturer")

