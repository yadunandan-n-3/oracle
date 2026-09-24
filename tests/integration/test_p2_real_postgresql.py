"""Opt-in P2 acceptance against a real PostgreSQL server and restart."""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import time
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from backend.database import close_database, init_database, session_scope
from backend.main import app
from backend.services import MissionService
from domain.mission import MissionTarget, MissionType
from runtime.execution_result import TaskExecutionResult
from runtime.runtime import OracleRuntime, get_runtime
from tests.integration.test_threat_intelligence_risk_pipeline import (
    DeterministicDiscoveryTool,
    FakeGraph,
    pipeline,
)


pytestmark = pytest.mark.skipif(
    os.getenv("ORACLE_RUN_POSTGRES_ACCEPTANCE") != "1",
    reason="set ORACLE_RUN_POSTGRES_ACCEPTANCE=1 for the real PostgreSQL acceptance test",
)


async def _execute_real_mission() -> dict[str, Any]:
    await init_database()
    runtime = OracleRuntime()
    runtime._database_available = True
    runtime.scheduler._poll_interval = 0.001
    runtime.intelligence_pipeline = pipeline()
    runtime.knowledge_graph = FakeGraph(available=False)
    tool = DeterministicDiscoveryTool()

    mission = await runtime.create_mission(
        name=f"P2 PostgreSQL acceptance {uuid4()}",
        mission_type=MissionType.CUSTOM,
        target=MissionTarget(domains=["postgres-acceptance.oracle.test"]),
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
        assert workflow and workflow.succeeded
        assert mission.status.value == "completed"
        assert tool.calls == 1

        state = await runtime.state_manager.get_mission_state(mission.id)
        assert state is not None and state.findings and state.evidence and state.assets
        finding = next(iter(state.findings.values()))
        evidence = [state.evidence[value] for value in finding.evidence_ids]

        # Repeat enrichment and the real PostgreSQL upsert. Stable primary and
        # risk identities must update the row rather than insert duplicates.
        await runtime.intelligence_pipeline.process(finding, evidence)
        async with session_scope() as session:
            service = MissionService(session)
            await service.upsert_finding(mission.id, finding)
            await service.upsert_finding(mission.id, finding)

        async with session_scope() as session:
            mission_row = (await session.execute(text(
                "SELECT status, total_assets_discovered, total_evidence, "
                "total_findings, overall_risk_score FROM missions WHERE id=:id"
            ), {"id": mission.id})).mappings().one()
            finding_row = (await session.execute(text(
                "SELECT id, mission_id, evidence_ids, risk_score, confidence, metadata "
                "FROM findings WHERE id=:id"
            ), {"id": finding.id})).mappings().one()
            counts = {
                "missions": (await session.execute(text(
                    "SELECT count(*) FROM missions WHERE id=:id"
                ), {"id": mission.id})).scalar_one(),
                "assets": (await session.execute(text(
                    "SELECT count(*) FROM assets WHERE mission_id=:id"
                ), {"id": mission.id})).scalar_one(),
                "evidence": (await session.execute(text(
                    "SELECT count(*) FROM evidence WHERE mission_id=:id"
                ), {"id": mission.id})).scalar_one(),
                "findings": (await session.execute(text(
                    "SELECT count(*) FROM findings WHERE mission_id=:id"
                ), {"id": mission.id})).scalar_one(),
            }

        metadata = finding_row["metadata"]
        assert mission_row["status"] == "completed"
        assert mission_row["total_assets_discovered"] >= 1
        assert mission_row["total_evidence"] >= 1
        assert mission_row["total_findings"] == 1
        assert mission_row["overall_risk_score"] == pytest.approx(finding.risk_score)
        assert counts == {"missions": 1, "assets": 1, "evidence": 1, "findings": 1}
        assert finding_row["evidence_ids"] == list(finding.evidence_ids)
        assert finding_row["risk_score"] == pytest.approx(finding.risk_score)
        assert metadata["threat_intelligence"]["provider_status"]
        assert metadata["threat_intelligence"]["cve"]["cve_id"] == finding.cve_id
        assert metadata["threat_intelligence"]["cwe"]
        assert metadata["threat_intelligence"]["owasp"]
        assert metadata["risk_v2"]["score"] == pytest.approx(finding.risk_score)
        assert metadata["risk_v2"]["level"] == finding.risk_level
        assert metadata["risk_v2"]["factors"]
        assert metadata["risk_v2"]["explanation"]
        confidence_factor = next(
            factor for factor in metadata["risk_v2"]["factors"]
            if factor["name"] == "confidence"
        )
        assert confidence_factor["value"] == pytest.approx(finding_row["confidence"])

        return {
            "mission_id": mission.id,
            "finding_id": finding.id,
            "risk_score": finding.risk_score,
            "risk_level": finding.risk_level,
            "evidence_ids": [str(value) for value in finding.evidence_ids],
        }
    finally:
        await runtime.scheduler.stop()
        await runtime.intelligence_pipeline.close()
        await close_database()


def _assert_api_reads_from_postgres(expected: dict[str, Any]) -> None:
    # A new runtime has no MissionManager or StateManager records. Its only
    # completed-mission source is PostgreSQL through MissionService.
    restarted = OracleRuntime()
    restarted._database_available = True
    restarted.knowledge_graph = FakeGraph(available=False)
    assert restarted.mission_manager._missions == {}
    assert restarted.state_manager.get_mission_ids() == []

    app.dependency_overrides[get_runtime] = lambda: restarted
    try:
        with TestClient(app) as client:
            finding = client.get(f"/api/findings/{expected['finding_id']}")
            findings = client.get(
                f"/api/findings?mission_id={expected['mission_id']}"
            )
            dashboard = client.get("/api/dashboard")
            overview = client.get("/api/statistics/overview")
            distribution = client.get("/api/statistics/risk-distribution")
            reports = client.get(
                f"/api/reports?mission_id={expected['mission_id']}"
            )
            report = client.get(f"/api/reports/{expected['mission_id']}")
    finally:
        app.dependency_overrides.pop(get_runtime, None)

    assert finding.status_code == 200
    payload = finding.json()
    assert payload["id"] == str(expected["finding_id"])
    assert payload["mission_id"] == str(expected["mission_id"])
    assert payload["evidence_ids"] == expected["evidence_ids"]
    assert payload["risk_score"] == pytest.approx(expected["risk_score"])
    assert payload["risk_level"] == expected["risk_level"]
    assert payload["risk_factors"]
    assert payload["risk_explanation"]
    assert payload["risk_calculation_metadata"]["calculated_by"] == "risk_engine_v2"
    intelligence = payload["threat_intelligence"]
    assert intelligence["provider_status"]
    assert intelligence["cve"] and intelligence["cwe"] and intelligence["owasp"]
    assert "epss" in intelligence and "kev" in intelligence
    assert findings.status_code == 200 and findings.json()["total"] == 1
    assert dashboard.status_code == 200 and dashboard.json()["findings"]["total"] >= 1
    assert overview.status_code == 200 and overview.json()["findings"]["total"] >= 1
    assert distribution.status_code == 200
    assert distribution.json()["total_risk_scored_findings"] >= 1
    assert reports.status_code == 200 and reports.json()["total"] == 1
    assert report.status_code == 200
    assert report.json()["risk_score"] == pytest.approx(expected["risk_score"])


async def _cleanup(mission_id: UUID) -> None:
    await init_database()
    try:
        async with session_scope() as session:
            for table in ("event_log", "findings", "evidence", "assets", "missions"):
                await session.execute(
                    text(f"DELETE FROM {table} WHERE mission_id=:id")
                    if table != "missions"
                    else text("DELETE FROM missions WHERE id=:id"),
                    {"id": mission_id},
                )
    finally:
        await close_database()


def _restart_real_postgres() -> None:
    container = os.getenv("ORACLE_POSTGRES_CONTAINER", "oracle-postgres")
    subprocess.run(
        ["docker", "restart", container],
        check=True,
        capture_output=True,
        text=True,
    )
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", 5432), timeout=1):
                return
        except OSError:
            time.sleep(0.5)
    raise AssertionError("PostgreSQL did not return on localhost:5432 after restart")


def test_real_postgresql_vertical_restart_and_api_read_through() -> None:
    expected = asyncio.run(_execute_real_mission())
    try:
        _assert_api_reads_from_postgres(expected)
        _restart_real_postgres()
        _assert_api_reads_from_postgres(expected)
    finally:
        asyncio.run(_cleanup(expected["mission_id"]))
