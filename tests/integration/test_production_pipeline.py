"""Deterministic vertical tests for asset/evidence/finding production."""

from __future__ import annotations

import asyncio
from typing import Any
from uuid import UUID, uuid4

import pytest

from core.exceptions import IntegrationError
from core.interfaces import Evidence as AgentEvidence
from domain.evidence import Evidence, EvidenceSource, EvidenceType, from_agent_evidence
from domain.intelligence import ThreatIntelligence
from domain.intelligence.pipeline import FindingIntelligencePipeline
from domain.mission import MissionStatus, MissionTarget, MissionType
from runtime.execution_result import TaskExecutionResult
from runtime.ingestion import merge_assets
from runtime.planner import Task
from runtime.runtime import OracleRuntime
from tests.conftest import make_mission


class FakePersistence:
    """Transaction adapter with PostgreSQL-equivalent record semantics."""

    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.assets: dict[tuple[UUID, str], Any] = {}
        self.evidence: dict[UUID, Evidence] = {}
        self.findings: dict[UUID, Any] = {}
        self.counters: dict[UUID, dict[str, int]] = {}
        self.statuses: dict[UUID, MissionStatus] = {}
        self.events: list[tuple[UUID, str, dict[str, Any]]] = []

    def _check(self) -> None:
        if self.fail:
            raise RuntimeError("database write failed")

    async def create_mission(self, mission: Any) -> Any:
        self._check()
        return mission

    async def update_mission_status(self, mission_id: UUID, status: MissionStatus) -> None:
        self._check()
        self.statuses[mission_id] = status

    async def upsert_asset(self, mission_id: UUID, asset: Any) -> Any:
        self._check()
        key = (mission_id, asset.value)
        self.assets[key] = merge_assets(self.assets[key], asset) if key in self.assets else asset
        return self.assets[key]

    async def create_evidence(self, mission_id: UUID, evidence: Evidence) -> Evidence:
        self._check()
        self.evidence[evidence.id] = evidence
        return evidence

    async def upsert_finding(self, mission_id: UUID, finding: Any) -> Any:
        self._check()
        self.findings[finding.id] = finding
        return finding

    async def sync_mission_counters(self, mission_id: UUID, **values: int) -> None:
        self._check()
        self.counters[mission_id] = values

    async def log_event(
        self,
        mission_id: UUID,
        event_type: str,
        source: str = "",
        data: dict[str, Any] | None = None,
    ) -> None:
        self._check()
        self.events.append((mission_id, event_type, data or {}))


class FakeGraph:
    def __init__(self, available: bool = False, fail: bool = False) -> None:
        self.is_available = available
        self.fail = fail
        self.assets: list[UUID] = []
        self.evidence: list[UUID] = []
        self.findings: list[UUID] = []

    def _check(self) -> None:
        if self.fail:
            raise RuntimeError("neo4j write failed")

    async def create_asset_node(self, asset_id: UUID, *_: Any) -> None:
        self._check()
        self.assets.append(asset_id)

    async def create_evidence_node(self, evidence_id: UUID, *_: Any) -> None:
        self._check()
        self.evidence.append(evidence_id)

    async def create_finding_node(self, finding_id: UUID, *_: Any, **__: Any) -> None:
        self._check()
        self.findings.append(finding_id)

    async def update_mission_status(self, *_: Any) -> None:
        self._check()


class OfflineThreatIntelligence:
    async def enrich_finding(self, _: Any) -> ThreatIntelligence:
        return ThreatIntelligence()

    async def close(self) -> None:
        return None


def offline_intelligence_pipeline() -> FindingIntelligencePipeline:
    return FindingIntelligencePipeline(threat_intelligence=OfflineThreatIntelligence())


async def configured_runtime(
    *,
    persistence: FakePersistence | None = None,
    graph: FakeGraph | None = None,
) -> tuple[OracleRuntime, Any, FakePersistence]:
    runtime = OracleRuntime()
    runtime.intelligence_pipeline = offline_intelligence_pipeline()
    store = persistence or FakePersistence()
    runtime.mission_service = store
    runtime.knowledge_graph = graph or FakeGraph()
    mission = make_mission(domains=["pipeline.oracle.test"])
    await runtime.state_manager.initialize_mission_state(mission)
    return runtime, mission, store


def host_evidence(value: str = "10.20.30.40") -> Evidence:
    return from_agent_evidence(AgentEvidence(
        source="nmap",
        evidence_type="host",
        asset_value=value,
        data={"hostnames": ["server.oracle.test"], "status": "up"},
        confidence=0.95,
        title="Host discovered",
        description="Nmap reported the host as reachable",
        tags=["host", "discovered"],
    ))


def service_evidence(value: str = "10.20.30.40:80/tcp") -> Evidence:
    return Evidence(
        evidence_type=EvidenceType.SERVICE,
        title="Apache service detected",
        description="Nmap identified Apache HTTP Server 2.4.49",
        confidence=0.9,
        severity="informational",
        source=EvidenceSource(tool_name="nmap", agent_name="fake_discovery"),
        asset_value=value,
        raw_data={
            "port": 80,
            "protocol": "tcp",
            "service": "http",
            "product": "Apache httpd",
            "version": "2.4.49",
            "service_product": "Apache httpd",
            "service_version": "2.4.49",
        },
        tags=["http", "verified"],
    )


def vulnerability_evidence(value: str = "http://10.20.30.40:80") -> Evidence:
    return Evidence(
        evidence_type=EvidenceType.VULNERABILITY,
        title="Apache path traversal",
        description="The fake Nuclei matcher positively matched the fixture response",
        confidence=0.95,
        severity="high",
        source=EvidenceSource(tool_name="nuclei", agent_name="fake_discovery"),
        asset_value=value,
        raw_data={
            "template_id": "apache-path-traversal",
            "cve_ids": ["CVE-2021-41773"],
        },
        cve_ids=["CVE-2021-41773"],
        tags=["nuclei", "cve", "apache"],
    )


def task_result(mission_id: UUID, *evidence: Evidence) -> TaskExecutionResult:
    return TaskExecutionResult(
        mission_id=mission_id,
        task_id=uuid4(),
        capability="fake_discovery",
        evidence=list(evidence),
    )


@pytest.mark.asyncio
async def test_tool_failure_is_not_converted_to_evidence(event_bus: Any) -> None:
    from ai.agents.discovery_agent import DiscoveryAgent

    class FailingNuclei:
        def build_targets_from_hosts(self, _: list[Any]) -> list[str]:
            return ["https://10.20.30.40"]

        async def execute(self, **_: Any) -> Any:
            raise RuntimeError("nuclei failed")
            if False:
                yield b""

    agent = DiscoveryAgent()
    agent._nuclei = FailingNuclei()
    agent._discovered_hosts["10.20.30.40"] = object()
    emitted = []
    async for item in agent.execute({
        "mission_id": uuid4(),
        "task": {"id": str(uuid4())},
        "capability": "vulnerability_scanning",
        "params": {},
    }):
        emitted.append(item)

    assert len(emitted) == 1
    assert emitted[0].evidence_type == "error"
    assert all(item.evidence_type != "scan_result" for item in emitted)


@pytest.mark.asyncio
async def test_agent_result_produces_asset(event_bus: Any) -> None:
    runtime, mission, _ = await configured_runtime()
    outcome = await runtime.process_execution_result(task_result(mission.id, host_evidence()))
    assert len(outcome.assets) == 1
    assert outcome.assets[0].value == "10.20.30.40"


@pytest.mark.asyncio
async def test_asset_is_added_to_state(event_bus: Any) -> None:
    runtime, mission, _ = await configured_runtime()
    await runtime.process_execution_result(task_result(mission.id, host_evidence()))
    assets = runtime.state_manager.get_assets(mission.id)
    assert len(assets) == 1
    assert assets[0].hostnames == ["server.oracle.test"]


@pytest.mark.asyncio
async def test_asset_is_persisted(event_bus: Any) -> None:
    runtime, mission, store = await configured_runtime()
    outcome = await runtime.process_execution_result(task_result(mission.id, host_evidence()))
    assert outcome.persisted
    assert (mission.id, "10.20.30.40") in store.assets


@pytest.mark.asyncio
async def test_duplicate_asset_is_upserted(event_bus: Any) -> None:
    runtime, mission, store = await configured_runtime()
    first = service_evidence("10.20.30.40:80/tcp")
    second = service_evidence("10.20.30.40:443/tcp")
    second.raw_data["port"] = 443
    second.raw_data["service"] = "https"
    await runtime.process_execution_result(task_result(mission.id, first))
    await runtime.process_execution_result(task_result(mission.id, second))
    assert len(store.assets) == 1
    assert store.assets[(mission.id, "10.20.30.40")].open_ports == [80, 443]
    assert mission.total_assets_discovered == 1


@pytest.mark.asyncio
async def test_evidence_is_ingested(event_bus: Any) -> None:
    runtime, mission, _ = await configured_runtime()
    result = task_result(mission.id, host_evidence())
    await runtime.process_execution_result(result)
    ingested = runtime.state_manager.get_evidence(mission.id)
    assert len(ingested) == 1
    assert ingested[0].task_id == result.task_id
    assert ingested[0].source.execution_id == result.task_id


@pytest.mark.asyncio
async def test_evidence_is_persisted(event_bus: Any) -> None:
    runtime, mission, store = await configured_runtime()
    evidence = host_evidence()
    await runtime.process_execution_result(task_result(mission.id, evidence))
    assert evidence.id in store.evidence
    assert store.evidence[evidence.id].raw_data["status"] == "up"


@pytest.mark.asyncio
async def test_evidence_is_correlated_into_finding(event_bus: Any) -> None:
    runtime, mission, _ = await configured_runtime()
    outcome = await runtime.process_execution_result(
        task_result(mission.id, service_evidence(), vulnerability_evidence())
    )
    assert outcome.findings
    assert any(finding.discovered_by.startswith("correlation:") for finding in outcome.findings)


@pytest.mark.asyncio
async def test_finding_is_persisted(event_bus: Any) -> None:
    runtime, mission, store = await configured_runtime()
    outcome = await runtime.process_execution_result(
        task_result(mission.id, service_evidence(), vulnerability_evidence())
    )
    assert {finding.id for finding in outcome.findings}.issubset(store.findings)


@pytest.mark.asyncio
async def test_finding_has_evidence_reference(event_bus: Any) -> None:
    runtime, mission, _ = await configured_runtime()
    service = service_evidence()
    vulnerability = vulnerability_evidence()
    outcome = await runtime.process_execution_result(
        task_result(mission.id, service, vulnerability)
    )
    assert all(finding.evidence_ids for finding in outcome.findings)
    assert any(vulnerability.id in finding.evidence_ids for finding in outcome.findings)


@pytest.mark.asyncio
async def test_mission_counters_reflect_real_records(event_bus: Any) -> None:
    runtime, mission, store = await configured_runtime()
    await runtime.process_execution_result(
        task_result(mission.id, service_evidence(), vulnerability_evidence())
    )
    state = await runtime.state_manager.get_mission_state(mission.id)
    assert state is not None
    assert mission.total_assets_discovered == len(state.assets)
    assert mission.total_evidence == len(state.evidence)
    assert mission.total_findings == len(state.findings)
    assert mission.high_findings == sum(f.severity.value == "high" for f in state.findings.values())
    assert store.counters[mission.id]["total_findings"] == mission.total_findings


@pytest.mark.asyncio
async def test_concurrent_missions_do_not_share_assets(event_bus: Any) -> None:
    runtime = OracleRuntime()
    runtime.intelligence_pipeline = offline_intelligence_pipeline()
    runtime.mission_service = FakePersistence()
    runtime.knowledge_graph = FakeGraph()
    first = make_mission(domains=["first.oracle.test"])
    second = make_mission(domains=["second.oracle.test"])
    await runtime.state_manager.initialize_mission_state(first)
    await runtime.state_manager.initialize_mission_state(second)
    await asyncio.gather(
        runtime.process_execution_result(task_result(first.id, host_evidence("10.0.0.1"))),
        runtime.process_execution_result(task_result(second.id, host_evidence("10.0.0.2"))),
    )
    assert [asset.value for asset in runtime.state_manager.get_assets(first.id)] == ["10.0.0.1"]
    assert [asset.value for asset in runtime.state_manager.get_assets(second.id)] == ["10.0.0.2"]


@pytest.mark.asyncio
async def test_neo4j_failure_does_not_corrupt_postgres_state(event_bus: Any) -> None:
    graph = FakeGraph(available=True, fail=True)
    runtime, mission, store = await configured_runtime(graph=graph)
    evidence = host_evidence()
    outcome = await runtime.process_execution_result(task_result(mission.id, evidence))
    assert outcome.persisted
    assert not outcome.graph_projected
    assert "neo4j" in outcome.degraded_dependencies
    assert evidence.id in store.evidence
    assert runtime.state_manager.get_evidence(mission.id)


@pytest.mark.asyncio
async def test_database_failure_is_not_reported_as_success(event_bus: Any) -> None:
    store = FakePersistence(fail=True)
    runtime, mission, _ = await configured_runtime(persistence=store)
    result = task_result(mission.id, host_evidence())
    with pytest.raises(IntegrationError, match="PostgreSQL persistence failed"):
        await runtime.process_execution_result(result)
    assert result.success is False
    assert runtime.state_manager.get_assets(mission.id) == []
    assert mission.metadata["persistence"]["durable"] is False


@pytest.mark.asyncio
async def test_no_finding_created_without_correlating_evidence(event_bus: Any) -> None:
    runtime, mission, store = await configured_runtime()
    outcome = await runtime.process_execution_result(task_result(mission.id, host_evidence()))
    assert outcome.findings == []
    assert store.findings == {}
    assert mission.total_findings == 0


@pytest.mark.asyncio
async def test_full_fake_mission_produces_assets_evidence_and_findings(event_bus: Any) -> None:
    runtime = OracleRuntime()
    runtime.intelligence_pipeline = offline_intelligence_pipeline()
    runtime.scheduler._poll_interval = 0.001
    store = FakePersistence()
    runtime.mission_service = store
    runtime.knowledge_graph = FakeGraph()
    mission = await runtime.mission_manager.create_mission(
        name="Full fake production mission",
        mission_type=MissionType.CUSTOM,
        target=MissionTarget(domains=["vertical.oracle.test"]),
    )

    async def fake_handler(task: Task) -> TaskExecutionResult:
        evidence = []
        if task.capability == "reconnaissance":
            evidence = [service_evidence(), vulnerability_evidence()]
        result = TaskExecutionResult(
            mission_id=task.mission_id,
            task_id=task.id,
            capability=task.capability,
            evidence=evidence,
        )
        if evidence:
            await runtime.process_execution_result(result)
        return result

    for capability in ("reconnaissance", "analysis", "reporting"):
        runtime.register_capability_handler(capability, fake_handler)

    await runtime.scheduler.start()
    try:
        workflow = await runtime.execute_mission(mission.id)
        state = await runtime.state_manager.get_mission_state(mission.id)
        assert workflow is not None and workflow.succeeded
        assert mission.status == MissionStatus.COMPLETED
        assert state is not None
        assert state.assets and state.evidence and state.findings
        assert store.assets and store.evidence and store.findings
        assert mission.total_assets_discovered == len(store.assets)
        assert mission.total_evidence == len(store.evidence)
        assert mission.total_findings == len(store.findings)
        assert all(finding.evidence_ids for finding in store.findings.values())
    finally:
        await runtime.scheduler.stop()
