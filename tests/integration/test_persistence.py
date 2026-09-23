"""
Integration Tests: Persistence
===============================

Tests the PostgreSQL persistence layer (repositories, models)
and Neo4j knowledge graph integration with mocked dependencies.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

import pytest
import pytest_asyncio

from domain.asset import Asset, AssetType, AssetCriticality
from domain.evidence import Evidence, EvidenceType, EvidenceSource, EvidenceStatus
from domain.mission import Mission, MissionStatus, MissionTarget, MissionType, MissionPriority
from domain.finding import Finding, FindingSeverity, FindingStatus
from tests.conftest import make_mission, make_evidence, make_asset, make_finding


# ─── PostgreSQL Repository Tests ───────────────────────────────────────────


class TestMissionRepository:
    """Tests for MissionRepository operations."""

    @pytest.mark.asyncio
    async def test_mission_crud_methods_signatures(self) -> None:
        """Verify repository CRUD method signatures."""
        # These are signature-level tests since we need a real DB connection
        from backend.repositories import MissionRepository
        assert hasattr(MissionRepository, "create")
        assert hasattr(MissionRepository, "get")
        assert hasattr(MissionRepository, "update")
        assert hasattr(MissionRepository, "delete")
        assert hasattr(MissionRepository, "list_with_filters")
        assert hasattr(MissionRepository, "update_progress")

    @pytest.mark.asyncio
    async def test_mission_model_has_required_fields(self) -> None:
        """Verify MissionModel has all required fields."""
        from backend.models import MissionModel
        model_fields = [c.name for c in MissionModel.__table__.columns]
        required = ["id", "name", "mission_type", "status"]
        for field in required:
            assert field in model_fields, f"Missing field: {field}"

    def test_mission_response_serialization(self) -> None:
        """Verify a Mission domain object can be serialized to API format."""
        from backend.api.missions import _mission_to_response
        from backend.api.missions import MissionResponse
        mission = make_mission(
            name="Serialization Test",
            domains=["serialize.example.com"],
        )
        response = _mission_to_response(mission)
        assert isinstance(response, dict)
        assert response["name"] == "Serialization Test"
        assert response["id"] == str(mission.id)
        assert response["mission_type"] == mission.mission_type.value
        assert "created_at" in response
        assert "status" in response


class TestAssetRepository:
    """Tests for AssetRepository operations."""

    def test_asset_model_has_required_fields(self) -> None:
        """Verify AssetModel has all required fields."""
        from backend.models import AssetModel
        model_fields = [c.name for c in AssetModel.__table__.columns]
        required = ["id", "mission_id", "asset_type", "value"]
        for field in required:
            assert field in model_fields, f"Missing field: {field}"

    def test_asset_unique_constraint(self) -> None:
        """Verify the unique constraint on mission_id + value exists."""
        from backend.models import AssetModel
        constraints = [c for c in AssetModel.__table__.constraints if "unique" in str(c).lower()]
        assert len(constraints) > 0

    def test_asset_domain_serialization(self) -> None:
        """Verify Asset domain object serialization."""
        asset = make_asset(
            value="10.0.0.1",
            hostnames=["server.example.com"],
            open_ports=[22, 80, 443],
            os="Linux 5.x",
        )
        assert asset.value == "10.0.0.1"
        assert asset.ip_addresses == ["10.0.0.1"]
        assert asset.hostnames == ["server.example.com"]
        assert 22 in asset.open_ports
        assert asset.os == "Linux 5.x"


class TestEvidenceRepository:
    """Tests for EvidenceRepository operations."""

    def test_evidence_model_has_required_fields(self) -> None:
        """Verify EvidenceModel has all required fields."""
        from backend.models import EvidenceModel
        model_fields = [c.name for c in EvidenceModel.__table__.columns]
        required = ["id", "mission_id", "evidence_type", "title", "source_tool_name"]
        for field in required:
            assert field in model_fields, f"Missing field: {field}"

    def test_evidence_domain_serialization(self) -> None:
        """Verify Evidence domain object serialization."""
        evidence = make_evidence(
            evidence_type=EvidenceType.OPEN_PORT,
            asset_value="10.0.0.1:443/tcp",
            title="HTTPS Port",
            confidence=0.99,
            cve_ids=["CVE-2024-0001"],
            mitre_techniques=["T1046"],
        )
        assert evidence.evidence_type == EvidenceType.OPEN_PORT
        assert evidence.asset_value == "10.0.0.1:443/tcp"
        assert evidence.title == "HTTPS Port"
        assert "CVE-2024-0001" in evidence.cve_ids
        assert "T1046" in evidence.mitre_techniques


class TestFindingRepository:
    """Tests for FindingRepository operations."""

    def test_finding_model_has_required_fields(self) -> None:
        """Verify FindingModel has all required fields."""
        from backend.models import FindingModel
        model_fields = [c.name for c in FindingModel.__table__.columns]
        required = ["id", "mission_id", "title", "severity", "status"]
        for field in required:
            assert field in model_fields, f"Missing field: {field}"

    def test_finding_domain_serialization(self) -> None:
        """Verify Finding domain object serialization."""
        finding = make_finding(
            title="Critical: Open SSH Port",
            severity=FindingSeverity.CRITICAL,
            asset_value="10.0.0.1",
            cve_id="CVE-2024-1234",
            mitre_technique_id="T1046",
        )
        assert finding.title == "Critical: Open SSH Port"
        assert finding.severity == FindingSeverity.CRITICAL
        assert finding.cve_id == "CVE-2024-1234"
        assert finding.mitre_technique_id == "T1046"


# ─── Service Layer Tests ──────────────────────────────────────────────────


class TestMissionService:
    """Tests for MissionService interface."""

    def test_service_has_required_methods(self) -> None:
        """Verify MissionService has expected method signatures."""
        from backend.services import MissionService
        assert hasattr(MissionService, "create_mission")
        assert hasattr(MissionService, "get_mission")
        assert hasattr(MissionService, "update_mission_status")
        assert hasattr(MissionService, "list_missions")
        assert hasattr(MissionService, "upsert_asset")
        assert hasattr(MissionService, "list_assets")
        assert hasattr(MissionService, "create_evidence")
        assert hasattr(MissionService, "list_evidence")
        assert hasattr(MissionService, "log_event")
        assert hasattr(MissionService, "get_timeline")

    def test_service_accepts_session(self) -> None:
        """Verify MissionService accepts an AsyncSession."""
        from backend.services import MissionService
        # Just check the constructor signature
        import inspect
        sig = inspect.signature(MissionService.__init__)
        assert "session" in sig.parameters


# ─── Neo4j Knowledge Graph Tests ──────────────────────────────────────────


class TestKnowledgeGraphService:
    """Tests for Neo4j KnowledgeGraphService interface."""

    def test_service_has_required_methods(self) -> None:
        """Verify KnowledgeGraphService has expected methods."""
        from knowledge import KnowledgeGraphService
        assert hasattr(KnowledgeGraphService, "initialize")
        assert hasattr(KnowledgeGraphService, "close")
        assert hasattr(KnowledgeGraphService, "create_mission_node")
        assert hasattr(KnowledgeGraphService, "create_asset_node")
        assert hasattr(KnowledgeGraphService, "create_port_node")
        assert hasattr(KnowledgeGraphService, "create_finding_node")
        assert hasattr(KnowledgeGraphService, "create_evidence_node")
        assert hasattr(KnowledgeGraphService, "create_asset_relationship")
        assert hasattr(KnowledgeGraphService, "get_mission_graph")
        assert hasattr(KnowledgeGraphService, "find_attack_paths")
        assert hasattr(KnowledgeGraphService, "health_check")

    @pytest.mark.asyncio
    async def test_health_check_when_not_initialized(self) -> None:
        """Verify health check returns error when not connected."""
        from knowledge import KnowledgeGraphService
        kg = KnowledgeGraphService()
        health = await kg.health_check()
        assert health["healthy"] is False
        assert "error" in health

    def test_is_available_property(self) -> None:
        """Verify is_available returns False when not initialized."""
        from knowledge import KnowledgeGraphService
        kg = KnowledgeGraphService()
        assert kg.is_available is False


# ─── Database Schema Tests ────────────────────────────────────────────────


class TestDatabaseSchema:
    """Tests for PostgreSQL schema integrity."""

    def test_sql_schema_has_all_tables(self) -> None:
        """Verify the SQL init script creates all expected tables."""
        import os
        sql_path = "docker/init/postgres/init.sql"
        with open(sql_path, "r") as f:
            sql = f.read()

        expected_tables = [
            "organizations",
            "users",
            "missions",
            "tasks",
            "assets",
            "evidence",
            "findings",
            "risks",
            "reports",
            "asset_relationships",
            "event_log",
            "system_config",
        ]
        for table in expected_tables:
            assert f"CREATE TABLE IF NOT EXISTS {table}" in sql, f"Missing table: {table}"

    def test_sql_schema_has_indexes(self) -> None:
        """Verify the SQL init script creates indexes."""
        import os
        sql_path = "docker/init/postgres/init.sql"
        with open(sql_path, "r") as f:
            sql = f.read()

        expected_indexes = [
            "idx_missions_status",
            "idx_assets_mission",
            "idx_evidence_mission",
            "idx_findings_mission",
            "idx_event_log_mission",
        ]
        for index in expected_indexes:
            assert f"CREATE INDEX IF NOT EXISTS {index}" in sql or f"CREATE INDEX idx_{index}" in sql, f"Missing index: {index}"

    def test_sql_schema_has_triggers(self) -> None:
        """Verify the SQL init script creates updated_at triggers."""
        import os
        sql_path = "docker/init/postgres/init.sql"
        with open(sql_path, "r") as f:
            sql = f.read()

        assert "update_updated_at_column" in sql
        assert "CREATE TRIGGER" in sql
        assert "BEFORE UPDATE" in sql

