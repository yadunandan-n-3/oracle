"""P2 vertical tests for finding intelligence, risk, persistence, and graph."""

from __future__ import annotations

from contextlib import asynccontextmanager
import asyncio
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from domain.asset import Asset
from domain.evidence import Evidence, EvidenceSource, EvidenceType
from domain.finding import Finding, FindingSeverity
from domain.intelligence import CVEInfo, CWEInfo, EPSSInfo, KEVInfo, OWASPInfo
from domain.intelligence.pipeline import FindingIntelligencePipeline
from domain.mission import MissionTarget, MissionType
from knowledge import KnowledgeGraphService
from knowledge.intelligence.service import ThreatIntelligenceService
from runtime.execution_result import TaskExecutionResult
from runtime.runtime import OracleRuntime
from runtime.runtime import get_runtime
from tests.conftest import make_mission


class FakeProvider:
    def __init__(self, result: Any = None, error: str = "") -> None:
        self.result = result
        self.error = error

    async def lookup(self, _: str) -> Any:
        if self.error:
            raise RuntimeError(self.error)
        return self.result

    async def health_check(self) -> dict[str, Any]:
        return {"healthy": not self.error}

    async def close(self) -> None:
        return None


class FakeMitre:
    def __init__(self, error: str = "") -> None:
        self.error = error

    def map(self, **_: Any) -> list[Any]:
        if self.error:
            raise RuntimeError(self.error)
        return []


def fake_threat_service(*, failures: set[str] | None = None) -> ThreatIntelligenceService:
    failures = failures or set()

    def provider(name: str, result: Any) -> FakeProvider:
        return FakeProvider(result=result, error=f"{name} unavailable" if name in failures else "")

    return ThreatIntelligenceService(
        cve_service=provider("cve", CVEInfo(
            cve_id="CVE-2021-41773",
            description="Apache path traversal",
            cvss_score=9.8,
            cvss_severity="critical",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe_ids=["CWE-22"],
        )),
        cwe_service=provider("cwe", CWEInfo(
            cwe_id="CWE-22",
            name="Path Traversal",
        )),
        owasp_service=provider("owasp", OWASPInfo(
            owasp_id="A01:2021",
            category="Broken Access Control",
            cwe_mappings=["CWE-22"],
        )),
        epss_service=provider("epss", EPSSInfo(
            cve_id="CVE-2021-41773",
            epss_score=0.94,
            percentile=0.99,
        )),
        kev_service=provider("kev", KEVInfo(
            cve_id="CVE-2021-41773",
            vulnerability_name="Apache HTTP Server Path Traversal",
        )),
        mitre_mapper=FakeMitre("mitre unavailable" if "mitre" in failures else ""),
    )


def real_finding(mission_id: UUID | None = None) -> Finding:
    evidence_id = uuid4()
    return Finding(
        id=uuid4(),
        mission_id=mission_id or uuid4(),
        asset_id=uuid4(),
        title="Apache path traversal",
        description="Validated Nuclei match",
        severity=FindingSeverity.CRITICAL,
        confidence=0.95,
        asset_value="https://10.20.30.40",
        asset_type="web_application",
        evidence_ids=[evidence_id],
        cve_id="CVE-2021-41773",
        internet_exposed=True,
        metadata={"exploit_maturity": "weaponized"},
    )


def pipeline(*, failures: set[str] | None = None) -> FindingIntelligencePipeline:
    return FindingIntelligencePipeline(threat_intelligence=fake_threat_service(failures=failures))


@pytest.mark.asyncio
async def test_finding_to_cve_enrichment() -> None:
    intel = await fake_threat_service().enrich_finding(real_finding())
    assert intel.cve and intel.cve.cve_id == "CVE-2021-41773"


@pytest.mark.asyncio
async def test_finding_to_cwe_enrichment() -> None:
    intel = await fake_threat_service().enrich_finding(real_finding())
    assert intel.cwe and intel.cwe.cwe_id == "CWE-22"


@pytest.mark.asyncio
async def test_finding_to_owasp_enrichment() -> None:
    intel = await fake_threat_service().enrich_finding(real_finding())
    assert intel.owasp and intel.owasp.owasp_id == "A01:2021"


@pytest.mark.asyncio
async def test_epss_enrichment() -> None:
    intel = await fake_threat_service().enrich_finding(real_finding())
    assert intel.epss and intel.epss.epss_score == pytest.approx(0.94)


@pytest.mark.asyncio
async def test_kev_enrichment() -> None:
    intel = await fake_threat_service().enrich_finding(real_finding())
    assert intel.kev and intel.kev.cve_id == "CVE-2021-41773"


@pytest.mark.asyncio
async def test_partial_provider_failure() -> None:
    outcome = await pipeline(failures={"epss"}).process(real_finding())
    intel = outcome.enriched_finding.threat_intelligence
    assert intel and intel.degraded
    assert intel.provider_status["epss"] == "failed"
    assert intel.cve is not None
    assert outcome.finding.metadata["intelligence_status"] == "partial"


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["cve", "cwe", "epss", "kev"])
async def test_required_provider_failure_preserves_finding(provider: str) -> None:
    finding = real_finding()
    original_evidence_ids = list(finding.evidence_ids)
    outcome = await pipeline(failures={provider}).process(finding)
    intel = outcome.enriched_finding.threat_intelligence

    assert outcome.finding is finding
    assert outcome.finding.id == finding.id
    assert outcome.finding.evidence_ids == original_evidence_ids
    assert intel and intel.provider_status[provider] == "failed"
    assert getattr(intel, provider) is None
    assert outcome.finding.metadata["threat_intelligence"][provider] is None
    assert outcome.finding.metadata["intelligence_status"] == "partial"
    assert outcome.risk_score.score >= 0

    factors = {factor.name: factor for factor in outcome.risk_score.factors}
    if provider == "cve":
        assert factors["cvss_score"].source == "default"
    elif provider == "epss":
        assert factors["epss"].source == "default"
    elif provider == "kev":
        assert factors["kev"].source == "default"
        assert "No KEV data available" in factors["kev"].evidence


@pytest.mark.asyncio
async def test_complete_provider_failure() -> None:
    failures = {"cve", "cwe", "owasp", "epss", "kev", "mitre"}
    finding = real_finding()
    finding.cwe_id = "CWE-22"
    outcome = await pipeline(failures=failures).process(finding)
    assert outcome.finding.metadata["intelligence_status"] == "unavailable"
    assert outcome.risk_score.score >= 0
    assert outcome.finding.risk_factors


@pytest.mark.asyncio
async def test_enriched_finding_creation() -> None:
    finding = real_finding()
    outcome = await pipeline().process(finding)
    assert outcome.enriched_finding.finding_id == finding.id
    assert outcome.enriched_finding.evidence_ids == finding.evidence_ids
    assert outcome.enriched_finding.metadata["source_identity"]["finding_id"] == str(finding.id)


@pytest.mark.asyncio
async def test_risk_engine_receives_real_finding() -> None:
    finding = real_finding()
    outcome = await pipeline().process(finding)
    assert outcome.risk_score.finding_id == finding.id
    factors = {factor.name: factor for factor in outcome.risk_score.factors}
    assert factors["cvss_score"].value == pytest.approx(0.98)
    assert factors["epss"].value == pytest.approx(0.94)
    assert factors["kev"].value == 1.0
    assert outcome.risk_score.score == pytest.approx(82.35)
    assert outcome.risk_score.level.value == "high"


class FakePersistence:
    def __init__(self) -> None:
        self.findings: dict[UUID, Finding] = {}

    async def upsert_asset(self, *_: Any) -> None:
        return None

    async def create_evidence(self, *_: Any) -> None:
        return None

    async def upsert_finding(self, _: UUID, finding: Finding) -> Finding:
        self.findings[finding.id] = finding.model_copy(deep=True)
        return finding

    async def sync_mission_counters(self, *_: Any, **__: Any) -> None:
        return None


class FakeGraph:
    def __init__(self, available: bool = False) -> None:
        self.is_available = available
        self.assets: list[UUID] = []
        self.evidence: list[UUID] = []
        self.findings: list[tuple[UUID, dict[str, Any]]] = []

    async def create_asset_node(self, asset_id: UUID, *_: Any) -> None:
        self.assets.append(asset_id)

    async def create_mission_node(self, *_: Any) -> None:
        return None

    async def create_evidence_node(self, evidence_id: UUID, *_: Any) -> None:
        self.evidence.append(evidence_id)

    async def create_finding_node(
        self,
        finding_id: UUID,
        *_: Any,
        **details: Any,
    ) -> None:
        self.findings.append((finding_id, details))

    async def update_mission_status(self, *_: Any) -> None:
        return None

    async def health_check(self) -> dict[str, Any]:
        return {"healthy": self.is_available}


def vulnerability_evidence() -> Evidence:
    return Evidence(
        evidence_type=EvidenceType.VULNERABILITY,
        title="Apache path traversal",
        description="Validated fixture match",
        confidence=0.95,
        severity="critical",
        source=EvidenceSource(tool_name="nuclei"),
        asset_value="https://10.20.30.40",
        cve_ids=["CVE-2021-41773"],
        raw_data={"template_id": "apache-path-traversal"},
    )


async def run_runtime_pipeline(
    graph: FakeGraph | None = None,
) -> tuple[OracleRuntime, Any, FakePersistence, Any]:
    runtime = OracleRuntime()
    runtime.intelligence_pipeline = pipeline()
    runtime.knowledge_graph = graph or FakeGraph()
    store = FakePersistence()
    runtime.mission_service = store
    mission = make_mission(domains=["p2.oracle.test"])
    await runtime.state_manager.initialize_mission_state(mission)
    evidence = vulnerability_evidence()
    result = TaskExecutionResult(
        mission_id=mission.id,
        task_id=uuid4(),
        capability="vulnerability_scanning",
        evidence=[evidence],
    )
    outcome = await runtime.process_execution_result(result)
    return runtime, mission, store, outcome


@pytest.mark.asyncio
async def test_risk_score_persistence(event_bus: Any) -> None:
    _, _, store, outcome = await run_runtime_pipeline()
    persisted = store.findings[outcome.findings[0].id]
    assert persisted.risk_score == outcome.risk_scores[0].score
    assert persisted.metadata["risk_v2"]["score"] == persisted.risk_score


@pytest.mark.asyncio
async def test_risk_factors_persist(event_bus: Any) -> None:
    _, _, store, outcome = await run_runtime_pipeline()
    persisted = store.findings[outcome.findings[0].id]
    assert persisted.risk_factors
    assert persisted.risk_explanation
    assert persisted.risk_calculation_metadata["calculated_by"] == "risk_engine_v2"


class RecordingSession:
    def __init__(self) -> None:
        self.queries: list[str] = []

    async def run(self, query: str, **_: Any) -> None:
        self.queries.append(" ".join(query.split()))


class RecordingGraph(KnowledgeGraphService):
    def __init__(self) -> None:
        super().__init__()
        self.recording_session = RecordingSession()
        self._initialized = True
        self._driver = object()

    @asynccontextmanager
    async def session(self) -> Any:
        yield self.recording_session


async def graph_queries() -> str:
    graph = RecordingGraph()
    finding = real_finding()
    await graph.create_finding_node(
        finding.id,
        finding.asset_id,
        finding.title,
        finding.severity.value,
        finding.cve_id or "",
        mission_id=finding.mission_id,
        evidence_ids=finding.evidence_ids,
        cwe_id="CWE-22",
        risk_score=91.2,
        risk_level="critical",
        risk_id=f"risk:{finding.id}",
    )
    return "\n".join(graph.recording_session.queries)


@pytest.mark.asyncio
async def test_graph_finding_relationship() -> None:
    queries = await graph_queries()
    assert "MERGE (f)-[:AFFECTS]->(a)" in queries
    assert "MERGE (f)-[:SUPPORTED_BY]->(e)" in queries


@pytest.mark.asyncio
async def test_graph_cve_relationship() -> None:
    queries = await graph_queries()
    assert "MERGE (f)-[:REFERENCES]->(c)" in queries
    assert "MERGE (f)-[:CLASSIFIED_AS]->(c)" in queries


@pytest.mark.asyncio
async def test_graph_risk_relationship() -> None:
    queries = await graph_queries()
    assert "MERGE (r:Risk {finding_id: $fid})" in queries
    assert "MERGE (f)-[:HAS_RISK]->(r)" in queries


@pytest.mark.asyncio
async def test_full_finding_to_risk_pipeline(event_bus: Any) -> None:
    graph = FakeGraph(available=True)
    runtime, mission, store, first = await run_runtime_pipeline(graph)
    finding = first.findings[0]
    evidence = runtime.state_manager.get_evidence(mission.id)[0]
    second = await runtime.process_execution_result(TaskExecutionResult(
        mission_id=mission.id,
        task_id=uuid4(),
        capability="vulnerability_scanning",
        evidence=[evidence],
    ))

    assert first.enriched_findings and first.risk_scores
    assert finding.id in store.findings
    assert store.findings[finding.id].metadata["threat_intelligence"]["cve"]["cve_id"] == "CVE-2021-41773"
    assert store.findings[finding.id].risk_score is not None
    assert mission.overall_risk_score == finding.risk_score
    assert first.graph_projected
    assert graph.assets and graph.evidence and graph.findings
    assert graph.findings[0][0] == finding.id
    assert graph.findings[0][1]["risk_score"] == finding.risk_score
    assert graph.findings[0][1]["risk_id"]
    assert len(store.findings) == 1
    assert second.findings[0].id == finding.id


class DurablePersistence(FakePersistence):
    """PostgreSQL-contract adapter retained across runtime state resets."""

    def __init__(self) -> None:
        super().__init__()
        self.missions: dict[UUID, Any] = {}
        self.assets: dict[tuple[UUID, str], Asset] = {}
        self.evidence: dict[UUID, Evidence] = {}

    async def create_mission(self, mission: Any) -> Any:
        self.missions[mission.id] = mission.model_copy(deep=True)
        return mission

    async def get_mission(self, mission_id: UUID) -> Any:
        return self.missions.get(mission_id)

    async def list_missions(self, **_: Any) -> list[Any]:
        return [mission.model_copy(deep=True) for mission in self.missions.values()]

    async def update_mission_status(self, mission_id: UUID, status: Any) -> None:
        self.missions[mission_id].status = status
        if status.value == "completed":
            from datetime import datetime, timezone
            self.missions[mission_id].completed_at = datetime.now(timezone.utc)

    async def upsert_asset(self, mission_id: UUID, asset: Asset) -> Asset:
        self.assets[(mission_id, asset.value)] = asset.model_copy(deep=True)
        return asset

    async def list_assets(self, mission_id: UUID, **_: Any) -> list[Asset]:
        return [
            asset.model_copy(deep=True)
            for (stored_mission_id, _), asset in self.assets.items()
            if stored_mission_id == mission_id
        ]

    async def create_evidence(self, _: UUID, evidence: Evidence) -> Evidence:
        self.evidence[evidence.id] = evidence.model_copy(deep=True)
        return evidence

    async def get_finding(self, finding_id: UUID) -> Finding | None:
        finding = self.findings.get(finding_id)
        return finding.model_copy(deep=True) if finding else None

    async def list_findings(
        self,
        mission_id: UUID | None = None,
        severity: str | None = None,
        status: str | None = None,
        **_: Any,
    ) -> list[Finding]:
        findings = list(self.findings.values())
        if mission_id:
            findings = [finding for finding in findings if finding.mission_id == mission_id]
        if severity:
            findings = [finding for finding in findings if finding.severity.value == severity]
        if status:
            findings = [finding for finding in findings if finding.status.value == status]
        return [finding.model_copy(deep=True) for finding in findings]

    async def sync_mission_counters(self, mission_id: UUID, **values: Any) -> None:
        mission = self.missions[mission_id]
        mission.total_assets_discovered = values["total_assets"]
        mission.total_evidence = values["total_evidence"]
        mission.total_findings = values["total_findings"]
        mission.critical_findings = values["critical_findings"]
        mission.high_findings = values["high_findings"]
        mission.medium_findings = values["medium_findings"]
        mission.low_findings = values["low_findings"]
        mission.overall_risk_score = values["overall_risk_score"]

    async def log_event(self, *_: Any, **__: Any) -> None:
        return None


class DeterministicDiscoveryTool:
    def __init__(self) -> None:
        self.calls = 0

    async def execute(self) -> list[Evidence]:
        self.calls += 1
        return [vulnerability_evidence()]


def _run_durable_vertical_mission() -> tuple[OracleRuntime, DurablePersistence, Any, Any]:
    async def execute() -> tuple[OracleRuntime, DurablePersistence, Any, Any]:
        runtime = OracleRuntime()
        runtime.scheduler._poll_interval = 0.001
        runtime.intelligence_pipeline = pipeline()
        runtime.knowledge_graph = FakeGraph(available=True)
        store = DurablePersistence()
        runtime.mission_service = store
        tool = DeterministicDiscoveryTool()
        mission = await runtime.create_mission(
            name="P2 durable acceptance mission",
            mission_type=MissionType.CUSTOM,
            target=MissionTarget(domains=["durable.oracle.test"]),
        )

        async def handler(task: Any) -> TaskExecutionResult:
            evidence = await tool.execute() if task.capability == "reconnaissance" else []
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
            runtime.register_capability_handler(capability, handler)
        await runtime.scheduler.start()
        try:
            workflow = await runtime.execute_mission(mission.id)
        finally:
            await runtime.scheduler.stop()
        assert workflow and workflow.succeeded
        assert tool.calls == 1
        assert mission.status.value == "completed"
        finding = next(iter(store.findings.values()))
        return runtime, store, mission, finding

    return asyncio.run(execute())


def test_completed_mission_api_read_through_survives_state_clear() -> None:
    runtime, store, mission, persisted = _run_durable_vertical_mission()
    assert persisted.evidence_ids
    assert persisted.metadata["threat_intelligence"]["cve"]["cve_id"] == persisted.cve_id
    assert persisted.metadata["threat_intelligence"]["provider_status"]
    assert persisted.metadata["risk_v2"]["score"] == persisted.risk_score
    assert persisted.metadata["risk_v2"]["level"] == persisted.risk_level
    assert persisted.risk_factors
    assert persisted.risk_calculation_metadata["calculated_by"] == "risk_engine_v2"
    confidence_factor = next(
        factor for factor in persisted.risk_factors if factor["name"] == "confidence"
    )
    assert confidence_factor["value"] == pytest.approx(persisted.confidence)
    assert confidence_factor["value"] != pytest.approx(0.7)

    runtime.state_manager._states.clear()
    runtime.mission_manager._missions.clear()
    assert runtime.state_manager.get_mission_ids() == []
    assert runtime.get_mission(mission.id) is None

    app.dependency_overrides[get_runtime] = lambda: runtime
    try:
        with TestClient(app) as client:
            detail = client.get(f"/api/findings/{persisted.id}")
            listing = client.get(f"/api/findings?mission_id={mission.id}")
            dashboard = client.get("/api/dashboard")
            statistics = client.get("/api/statistics/risk-distribution")
            overview = client.get("/api/statistics/overview")
            report = client.get(f"/api/reports/{mission.id}")
            reports = client.get(f"/api/reports?mission_id={mission.id}")
    finally:
        app.dependency_overrides.pop(get_runtime, None)

    assert detail.status_code == 200
    payload = detail.json()
    assert payload["id"] == str(persisted.id)
    assert payload["evidence_ids"] == [str(value) for value in persisted.evidence_ids]
    assert payload["risk_score"] == persisted.risk_score
    assert payload["risk_level"] == persisted.risk_level
    assert payload["risk_factors"] == persisted.risk_factors
    assert payload["risk_calculation_metadata"] == persisted.risk_calculation_metadata
    assert payload["threat_intelligence"]["provider_status"]
    assert listing.status_code == 200 and listing.json()["total"] == 1
    assert dashboard.status_code == 200 and dashboard.json()["findings"]["total"] == 1
    assert statistics.status_code == 200
    assert statistics.json()["total_risk_scored_findings"] == 1
    assert overview.status_code == 200 and overview.json()["findings"]["total"] == 1
    assert report.status_code == 200 and report.json()["risk_score"] == persisted.risk_score
    assert reports.status_code == 200 and reports.json()["total"] == 1
    assert len(store.findings) == 1
