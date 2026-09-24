import asyncio
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from domain.finding import FindingSeverity
from domain.mission import MissionStatus, MissionTarget, MissionType
from runtime.runtime import get_runtime
from tests.conftest import make_finding, make_mission


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as test_client:
        runtime = get_runtime()
        # This module seeds runtime-only records and validates the documented
        # degraded-mode fallback. Make that mode explicit even when a local
        # PostgreSQL server happens to be running.
        runtime._database_available = False
        yield test_client


@pytest.fixture(autouse=True)
def reset_runtime_state() -> None:
    runtime = get_runtime()
    runtime.mission_manager._missions.clear()
    runtime.state_manager._states.clear()


def _seed_mission_and_findings(runtime) -> tuple:
    mission = make_mission(name="API Test Mission", status=MissionStatus.IN_PROGRESS)
    asyncio.run(
        runtime.mission_manager.create_mission(
            name=mission.name,
            mission_type=MissionType.EXTERNAL_ATTACK_SURFACE,
            target=MissionTarget(domains=["api.example.com"]),
            description="Integration test mission",
            priority="high",
        )
    )
    created = runtime.mission_manager.get_mission(list(runtime.mission_manager._missions.keys())[0])
    asyncio.run(runtime.state_manager.initialize_mission_state(created))

    finding_one = make_finding(title="Critical API Exposure", severity=FindingSeverity.CRITICAL, asset_value="api.example.com")
    finding_two = make_finding(title="Low Risk Header", severity=FindingSeverity.LOW, asset_value="api.example.com")
    finding_one.mission_id = created.id
    finding_two.mission_id = created.id
    finding_one.risk_score = 92.0
    finding_two.risk_score = 15.0
    asyncio.run(runtime.state_manager.add_finding(created.id, finding_one))
    asyncio.run(runtime.state_manager.add_finding(created.id, finding_two))
    return created, finding_one, finding_two


def test_missions_list_supports_pagination_and_sorting(client: TestClient) -> None:
    runtime = get_runtime()
    _seed_mission_and_findings(runtime)

    response = client.get("/api/missions?limit=1&offset=0&sort_by=name&sort_order=asc")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] >= 1
    assert body["limit"] == 1
    assert body["offset"] == 0
    assert body["missions"]
    assert body["missions"][0]["name"]


def test_findings_list_supports_pagination_and_sorting(client: TestClient) -> None:
    runtime = get_runtime()
    _seed_mission_and_findings(runtime)

    response = client.get("/api/findings?limit=1&offset=0&sort_by=risk_score&sort_order=desc")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert body["limit"] == 1
    assert body["offset"] == 0
    assert body["findings"][0]["title"] == "Critical API Exposure"


def test_findings_list_filters_by_asset(client: TestClient) -> None:
    runtime = get_runtime()
    _, finding_one, finding_two = _seed_mission_and_findings(runtime)
    finding_one.asset_id = uuid4()
    finding_two.asset_id = uuid4()

    response = client.get(f"/api/findings?asset_id={finding_one.asset_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["findings"][0]["id"] == str(finding_one.id)


def test_findings_summary_is_not_shadowed_by_detail_route(client: TestClient) -> None:
    runtime = get_runtime()
    _seed_mission_and_findings(runtime)

    response = client.get("/api/findings/stats/summary")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert body["by_severity"]["critical"] == 1


def test_dashboard_returns_graceful_payload(client: TestClient) -> None:
    runtime = get_runtime()
    _seed_mission_and_findings(runtime)

    response = client.get("/api/dashboard")

    assert response.status_code == 200
    body = response.json()
    assert body["missions"]["total"] >= 1
    assert body["findings"]["total"] == 2
    assert body["risk"]["overall_risk_level"] in {"none", "low", "medium", "high", "critical"}


def test_graph_health_and_summary_endpoints(client: TestClient) -> None:
    runtime = get_runtime()
    mission, _, _ = _seed_mission_and_findings(runtime)

    health = client.get("/api/graph/health")
    summary = client.get(f"/api/graph/mission/{mission.id}/summary")

    assert health.status_code == 200
    assert summary.status_code == 200
    assert summary.json()["available"] is False or summary.json()["node_count"] >= 0


def test_copilot_returns_structured_answer(client: TestClient) -> None:
    runtime = get_runtime()
    _seed_mission_and_findings(runtime)

    response = client.post(
        "/api/copilot/ask",
        json={"question": "What is the highest risk asset?"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["answer"]
    assert body["confidence"] >= 0
    assert isinstance(body["sources"], list)


def test_reports_endpoint_returns_report_payload(client: TestClient) -> None:
    runtime = get_runtime()
    mission, _, _ = _seed_mission_and_findings(runtime)

    response = client.get(f"/api/reports/{mission.id}?format=json")

    assert response.status_code == 200
    body = response.json()
    assert body["mission_id"] == str(mission.id)
    assert body["total_findings"] == 2
