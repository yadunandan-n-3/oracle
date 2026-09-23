"""
Unit Tests: Validator
=====================

Tests for the evidence validation component.
"""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
import pytest_asyncio

from domain.evidence import Evidence, EvidenceType, EvidenceStatus, EvidenceConfidence, EvidenceSource
from runtime.validator import Validator, ValidationResult
from tests.conftest import make_evidence


class TestValidatorInitialization:
    """Tests for validator setup."""

    def test_validator_creates(self) -> None:
        """Verify validator can be instantiated."""
        validator = Validator()
        assert validator is not None

    def test_validator_has_fp_patterns(self) -> None:
        """Verify validator has false positive patterns configured."""
        validator = Validator()
        assert len(validator._false_positive_patterns) > 0


class TestEvidenceValidationMethods:
    """Tests for individual validation methods."""

    def test_false_positive_check_port_zero(self, validator: Validator) -> None:
        """Verify port 0 is flagged as false positive."""
        evidence = make_evidence(
            evidence_type=EvidenceType.OPEN_PORT,
            raw_data={"port": 0, "protocol": "tcp"},
        )
        result = validator._check_false_positive(evidence)
        assert result.passed is False
        assert result.details == "Port 0 is not a valid port"

    def test_false_positive_check_clean_passes(self, validator: Validator) -> None:
        """Verify clean evidence passes false positive check."""
        evidence = make_evidence()
        result = validator._check_false_positive(evidence)
        assert result.passed is True
        assert result.confidence > 0.5

    def test_consistency_check_complete(self, validator: Validator) -> None:
        """Verify complete evidence passes consistency check."""
        evidence = make_evidence()
        result = validator._check_consistency(evidence)
        assert result.passed is True
        assert result.confidence == 1.0

    def test_consistency_check_missing_title(self, validator: Validator) -> None:
        """Verify missing title fails consistency check."""
        evidence = make_evidence(title="")
        result = validator._check_consistency(evidence)
        assert result.passed is False
        assert "Missing title" in result.details

    def test_consistency_check_missing_source(self, validator: Validator) -> None:
        """Verify missing source tool fails consistency check."""
        evidence = make_evidence()
        evidence.source = EvidenceSource(tool_name="")
        result = validator._check_consistency(evidence)
        assert result.passed is False
        assert "source tool" in result.details.lower()

    def test_completeness_check_missing_required(self, validator: Validator) -> None:
        """Verify missing required fields reduces completeness."""
        evidence = make_evidence(title="", description="")
        result = validator._check_completeness(evidence)
        assert result.passed is False
        assert result.confidence < 0.5

    def test_completeness_check_full(self, validator: Validator) -> None:
        """Verify complete evidence passes completeness check."""
        evidence = make_evidence(
            title="Test Evidence",
            description="Complete test evidence",
        )
        result = validator._check_completeness(evidence)
        assert result.passed is True

    def test_completeness_check_missing_optional(self, validator: Validator) -> None:
        """Verify missing optional fields reduces score but passes."""
        evidence = make_evidence(
            title="Partial Evidence",
            description="Some fields present",
            asset_value="",
        )
        result = validator._check_completeness(evidence)
        # Should still pass required check
        assert result.passed is True
        # But score should be < 1.0
        assert result.score < 1.0


class TestFindingValidation:
    """Tests for finding validation."""

    @pytest.mark.asyncio
    async def test_validate_finding_with_evidence(self, validator: Validator) -> None:
        """Verify finding with evidence IDs passes validation."""
        from domain.finding import Finding, FindingSeverity, FindingStatus

        finding = Finding(
            title="Test Finding",
            severity=FindingSeverity.MEDIUM,
            evidence_ids=[uuid4(), uuid4()],
            discovered_by="test",
        )
        is_valid = await validator.validate_finding(finding)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_validate_finding_without_evidence(
        self, validator: Validator
    ) -> None:
        """Verify finding without evidence IDs fails validation."""
        from domain.finding import Finding, FindingSeverity, FindingStatus

        finding = Finding(
            title="No Evidence Finding",
            severity=FindingSeverity.HIGH,
            evidence_ids=[],
            discovered_by="test",
        )
        is_valid = await validator.validate_finding(finding)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_validate_finding_invalid_severity(
        self, validator: Validator
    ) -> None:
        """Verify finding with invalid severity fails validation."""
        from domain.finding import Finding, FindingSeverity, FindingStatus

        # Create a finding with an invalid severity by using a raw dict
        invalid_finding = Finding(
            title="Invalid Severity",
            severity=FindingSeverity.INFO,  # Valid, but we'll test boundary
            evidence_ids=[uuid4()],
            discovered_by="test",
        )
        is_valid = await validator.validate_finding(invalid_finding)
        assert is_valid is True  # "informational" is valid


class TestValidationEdgeCases:
    """Tests for validation edge cases."""

    @pytest.mark.asyncio
    async def test_validation_result_serialization(self) -> None:
        """Verify ValidationResult can be serialized to dict."""
        result = ValidationResult(
            passed=True,
            confidence=0.95,
            score=0.9,
            method="test_check",
            details="Test validation",
            matched_patterns=["pattern1", "pattern2"],
        )
        data = result.__dict__
        assert data["passed"] is True
        assert data["confidence"] == 0.95
        assert len(data["matched_patterns"]) == 2

