"""
Integration Tests: Evidence Pipeline
=====================================

Tests the complete evidence lifecycle:
1. Collection
2. Validation (false positive check, consistency, completeness)
3. Cross-referencing
4. Persistence (state manager)
"""

from __future__ import annotations

import asyncio
from uuid import UUID, uuid4

import pytest
import pytest_asyncio

from domain.evidence import Evidence, EvidenceType, EvidenceStatus, EvidenceConfidence
from runtime.validator import Validator, ValidationResult
from runtime.state_manager import StateManager
from tests.conftest import make_evidence, make_mission


class TestEvidenceValidation:
    """Tests for the validator component."""

    @pytest.mark.asyncio
    async def test_validates_valid_evidence(self, validator: Validator) -> None:
        """Verify a well-formed evidence passes validation."""
        evidence = make_evidence()
        result = await validator.validate_evidence(evidence)
        assert result.status == EvidenceStatus.VALIDATED
        assert result.confidence > 0.5
        assert result.validated_at is not None

    @pytest.mark.asyncio
    async def test_detects_false_positive_port_zero(
        self, validator: Validator
    ) -> None:
        """Verify port 0 is flagged as a false positive."""
        evidence = make_evidence(
            evidence_type=EvidenceType.OPEN_PORT,
            raw_data={"port": 0, "protocol": "tcp"},
        )
        result = await validator.validate_evidence(evidence)
        assert result.status in (EvidenceStatus.DISPUTED, EvidenceStatus.COLLECTED)
        # Confidence should be low for port 0
        assert result.confidence < 0.5

    @pytest.mark.asyncio
    async def test_validates_high_confidence_evidence(
        self, validator: Validator
    ) -> None:
        """Verify high confidence evidence passes."""
        evidence = make_evidence(
            confidence=0.99,
            title="Confirmed Open Port",
            description="Port 443 is open and running nginx",
        )
        result = await validator.validate_evidence(evidence)
        assert result.status == EvidenceStatus.VALIDATED
        assert result.confidence > 0.5

    @pytest.mark.asyncio
    async def test_validation_adds_metadata(self, validator: Validator) -> None:
        """Verify validation adds metadata to evidence."""
        evidence = make_evidence()
        result = await validator.validate_evidence(evidence)
        assert "validation_results" in result.metadata
        assert len(result.metadata["validation_results"]) > 0


class TestCrossReferencing:
    """Tests for evidence cross-referencing."""

    @pytest.mark.asyncio
    async def test_cross_reference_with_cve(
        self, validator: Validator
    ) -> None:
        """Verify cross-referencing detects known CVEs."""
        evidence = make_evidence(
            cve_ids=["CVE-2024-1234", "CVE-2024-5678"],
        )
        knowledge_base = {
            "cves": {"CVE-2024-1234": {"severity": "high"}},
            "mitre": {},
            "cwes": {},
        }
        result = await validator.cross_reference(evidence, knowledge_base)
        assert result.passed
        assert len(result.matched_patterns) > 0
        assert any("cve_match" in p for p in result.matched_patterns)

    @pytest.mark.asyncio
    async def test_cross_reference_without_matches(
        self, validator: Validator
    ) -> None:
        """Verify cross-referencing returns no matches for unknown data."""
        evidence = make_evidence(cve_ids=["CVE-9999-9999"])
        knowledge_base = {"cves": {}, "mitre": {}, "cwes": {}}
        result = await validator.cross_reference(evidence, knowledge_base)
        assert not result.passed


class TestEvidenceStateManagement:
    """Tests for evidence tracking in state manager."""

    @pytest.mark.asyncio
    async def test_add_evidence_to_state(
        self, state_manager: StateManager
    ) -> None:
        """Verify evidence can be added to mission state."""
        mission = make_mission()
        evidence = make_evidence(mission_id=mission.id)
        await state_manager.initialize_mission_state(mission)
        await state_manager.add_evidence(mission.id, evidence)
        retrieved = state_manager.get_evidence(mission.id)
        assert len(retrieved) == 1
        assert retrieved[0].id == evidence.id

    @pytest.mark.asyncio
    async def test_get_evidence_by_type(
        self, state_manager: StateManager
    ) -> None:
        """Verify evidence can be filtered by type."""
        mission = make_mission()
        port_evidence = make_evidence(
            evidence_type=EvidenceType.OPEN_PORT,
            mission_id=mission.id,
        )
        web_evidence = make_evidence(
            evidence_type=EvidenceType.HTTP_ENDPOINT,
            mission_id=mission.id,
            title="Web Endpoint Found",
        )
        await state_manager.initialize_mission_state(mission)
        await state_manager.add_evidence(mission.id, port_evidence)
        await state_manager.add_evidence(mission.id, web_evidence)

        port_results = state_manager.get_evidence(
            mission.id, evidence_type="open_port"
        )
        assert len(port_results) == 1
        assert port_results[0].evidence_type == EvidenceType.OPEN_PORT

        web_results = state_manager.get_evidence(
            mission.id, evidence_type="http_endpoint"
        )
        assert len(web_results) == 1

    @pytest.mark.asyncio
    async def test_evidence_publishes_event(
        self, state_manager: StateManager, started_event_bus, captured_events
    ) -> None:
        """Verify adding evidence publishes EVIDENCE_COLLECTED event."""
        mission = make_mission()
        evidence = make_evidence(mission_id=mission.id)
        await state_manager.initialize_mission_state(mission)
        await state_manager.add_evidence(mission.id, evidence)
        await asyncio.sleep(0.01)

        # Check for the event
        ev_collected = [
            e for e in captured_events
            if e.event_type.value == "evidence.collected"
        ]
        assert len(ev_collected) >= 1


class TestEvidenceEdgeCases:
    """Tests for edge cases in evidence processing."""

    @pytest.mark.asyncio
    async def test_evidence_without_asset(
        self, validator: Validator
    ) -> None:
        """Verify evidence without asset reference is still processed."""
        evidence = make_evidence(
            asset_value="",
            asset_id=None,
        )
        result = await validator.validate_evidence(evidence)
        # Should still pass validation but with lower confidence
        assert result is not None

    @pytest.mark.asyncio
    async def test_empty_raw_data(self, validator: Validator) -> None:
        """Verify evidence with empty raw data is handled."""
        evidence = make_evidence(raw_data={})
        result = await validator.validate_evidence(evidence)
        # Should still validate, just with potentially lower scores
        assert result is not None

    @pytest.mark.asyncio
    async def test_evidence_with_multiple_cves(
        self, validator: Validator
    ) -> None:
        """Verify evidence with multiple CVEs is handled correctly."""
        evidence = make_evidence(
            cve_ids=["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"],
        )
        result = await validator.validate_evidence(evidence)
        assert len(result.cve_ids) == 3

    @pytest.mark.asyncio
    async def test_evidence_with_mitre_mappings(
        self, validator: Validator
    ) -> None:
        """Verify MITRE ATT&CK mappings are preserved."""
        techniques = ["T1046", "T1190", "T1135"]
        evidence = make_evidence(mitre_techniques=techniques)
        result = await validator.validate_evidence(evidence)
        assert len(result.mitre_techniques) == 3
        assert all(t in result.mitre_techniques for t in techniques)

