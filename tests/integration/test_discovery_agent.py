"""
Integration Tests: Discovery Agent
===================================

Tests the DiscoveryAgent's ability to plan and execute
discovery tasks through the agent interface.
"""

from __future__ import annotations

from typing import Any, AsyncIterator, Dict, List
from uuid import UUID, uuid4

import pytest
import pytest_asyncio

from ai.agents.discovery_agent import DiscoveryAgent
from core.events import EventType, OracleEvent
from core.interfaces import Evidence as CoreEvidence, Capability, AgentStatus
from domain.evidence import Evidence as DomainEvidence, EvidenceType, EvidenceSource
from domain.mission import Mission, MissionTarget, MissionType
from runtime.event_bus import get_event_bus
from tests.conftest import make_mission


class TestDiscoveryAgentInitialization:
    """Tests for agent initialization."""

    @pytest.mark.asyncio
    async def test_agent_initializes(self) -> None:
        """Verify agent initializes without errors."""
        agent = DiscoveryAgent()
        await agent.initialize()
        status = await agent.get_status()
        assert status == AgentStatus.IDLE

    def test_agent_has_name(self) -> None:
        """Verify agent has required metadata."""
        agent = DiscoveryAgent()
        assert agent.name == "discovery_agent"
        assert agent.version == "0.1.0"
        assert len(agent.description) > 0

    def test_agent_has_capabilities(self) -> None:
        """Verify agent declares required capabilities."""
        agent = DiscoveryAgent()
        assert len(agent.capabilities) > 0
        for cap in agent.capabilities:
            assert isinstance(cap, Capability)
            assert cap.name
            assert cap.tools

    def test_agent_capabilities_include_port_scanning(self) -> None:
        """Verify port scanning capability is declared."""
        agent = DiscoveryAgent()
        cap_names = [c.name for c in agent.capabilities]
        assert "port_scanning" in cap_names
        assert "service_discovery" in cap_names


class TestDiscoveryAgentPlanning:
    """Tests for agent planning capability."""

    @pytest.mark.asyncio
    async def test_agent_creates_plan(self) -> None:
        """Verify agent creates a plan for a mission."""
        agent = DiscoveryAgent()
        await agent.initialize()
        mission = make_mission()
        plan = await agent.plan(mission)
        assert len(plan) > 0
        for task in plan:
            assert "id" in task
            assert "capability" in task
            assert "description" in task

    @pytest.mark.asyncio
    async def test_plan_includes_port_scanning(self) -> None:
        """Verify plan includes port scanning tasks."""
        agent = DiscoveryAgent()
        await agent.initialize()
        mission = make_mission(domains=["scanme.nmap.org"])
        plan = await agent.plan(mission)
        capabilities = [t["capability"] for t in plan]
        assert "port_scanning" in capabilities

    @pytest.mark.asyncio
    async def test_plan_respects_targets(self) -> None:
        """Verify plan includes all target hosts."""
        agent = DiscoveryAgent()
        await agent.initialize()
        mission = make_mission(
            domains=["host1.com", "host2.com", "host3.com"],
        )
        plan = await agent.plan(mission)
        # Should have a port scan task for each target
        port_scan_tasks = [t for t in plan if t["capability"] == "port_scanning"]
        assert len(port_scan_tasks) >= 1


class TestDiscoveryAgentExplain:
    """Tests for agent explanation capability."""

    @pytest.mark.asyncio
    async def test_explain_open_port_evidence(self) -> None:
        """Verify agent can explain open port evidence."""
        agent = DiscoveryAgent()
        await agent.initialize()
        evidence = CoreEvidence(
            source="discovery_agent",
            evidence_type="port",
            asset_value="192.168.1.1:80/tcp",
            data={"port": 80, "protocol": "tcp", "service": "http"},
            confidence=0.95,
        )
        explanation = await agent.explain(evidence)
        assert len(explanation) > 0
        assert "port" in explanation.lower() or "80" in explanation

    @pytest.mark.asyncio
    async def test_explain_host_evidence(self) -> None:
        """Verify agent can explain host evidence."""
        agent = DiscoveryAgent()
        await agent.initialize()
        evidence = CoreEvidence(
            source="discovery_agent",
            evidence_type="host",
            asset_value="192.168.1.1",
            data={"ip": "192.168.1.1", "status": "up"},
            confidence=0.95,
        )
        explanation = await agent.explain(evidence)
        assert len(explanation) > 0
        assert "host" in explanation.lower() or "online" in explanation.lower()


class TestDiscoveryAgentEdgeCases:
    """Tests for agent edge cases."""

    @pytest.mark.asyncio
    async def test_plan_for_minimal_mission(self) -> None:
        """Verify agent creates plan even for minimal mission."""
        agent = DiscoveryAgent()
        await agent.initialize()
        mission = make_mission(domains=["single.example.com"])
        plan = await agent.plan(mission)
        assert len(plan) > 0

    @pytest.mark.asyncio
    async def test_validate_low_confidence_evidence(self) -> None:
        """Verify low confidence evidence is flagged."""
        agent = DiscoveryAgent()
        await agent.initialize()
        evidence = CoreEvidence(
            source="discovery_agent",
            evidence_type="port",
            asset_value="192.168.1.1:80/tcp",
            data={},
            confidence=0.05,
        )
        is_valid, reason = await agent.validate(evidence)
        assert not is_valid
        assert "confidence" in reason.lower()

    @pytest.mark.asyncio
    async def test_validate_evidence_without_asset(self) -> None:
        """Verify evidence without asset value is rejected."""
        agent = DiscoveryAgent()
        await agent.initialize()
        evidence = CoreEvidence(
            source="discovery_agent",
            evidence_type="port",
            asset_value="",
            data={},
            confidence=0.9,
        )
        is_valid, reason = await agent.validate(evidence)
        assert not is_valid



class TestDiscoveryAgentVulnerabilityScanning:
    """Tests for the Nuclei-backed vulnerability_scanning capability."""

    def test_agent_capabilities_include_vulnerability_scanning(self) -> None:
        """Verify vulnerability_scanning capability is declared with nuclei as its tool."""
        agent = DiscoveryAgent()
        cap_names = [c.name for c in agent.capabilities]
        assert "vulnerability_scanning" in cap_names
        vuln_cap = next(c for c in agent.capabilities if c.name == "vulnerability_scanning")
        assert "nuclei" in vuln_cap.tools

    @pytest.mark.asyncio
    async def test_plan_includes_vulnerability_scan_after_service_discovery(self) -> None:
        """Verify the plan schedules Nuclei after service discovery, matching
        the Mission -> Discovery -> Nmap -> Nuclei -> Evidence pipeline."""
        agent = DiscoveryAgent()
        await agent.initialize()
        mission = make_mission(domains=["scanme.nmap.org"])
        plan = await agent.plan(mission)

        vuln_tasks = [t for t in plan if t["id"] == "vulnerability_scan"]
        assert len(vuln_tasks) == 1
        assert vuln_tasks[0]["capability"] == "vulnerability_scanning"
        assert "service_discovery" in vuln_tasks[0]["depends_on"]

        # asset_compilation should wait for the vuln scan too, so the
        # summary reflects a mission that's actually finished scanning.
        compilation_task = next(t for t in plan if t["id"] == "asset_compilation")
        assert "vulnerability_scan" in compilation_task["depends_on"]

    @pytest.mark.asyncio
    async def test_vulnerability_scan_degrades_gracefully_with_no_http_targets(self) -> None:
        """When no HTTP(S) services were discovered, the stage should yield
        low-confidence evidence rather than error out or hang."""
        agent = DiscoveryAgent()
        await agent.initialize()
        # No hosts have been discovered in this fresh agent, so there are
        # no HTTP(S) targets to build for Nuclei.
        evidence_items = []
        async for evidence in agent._execute_vulnerability_scan({}, {}):
            evidence_items.append(evidence)

        assert len(evidence_items) == 1
        assert evidence_items[0].data.get("targets_found") == 0

    @pytest.mark.asyncio
    async def test_explain_vulnerability_evidence(self) -> None:
        """Verify agent can explain nuclei-produced vulnerability evidence."""
        agent = DiscoveryAgent()
        await agent.initialize()
        evidence = CoreEvidence(
            source="nuclei",
            evidence_type="vulnerability",
            asset_value="https://example.com/",
            data={"cve_ids": ["CVE-2021-41773"]},
            confidence=0.9,
            severity="critical",
            title="Apache Path Traversal",
        )
        explanation = await agent.explain(evidence)
        assert "CRITICAL" in explanation
        assert "CVE-2021-41773" in explanation
        assert "Apache Path Traversal" in explanation
