"""
Validator
=========

Validates evidence, findings, and tool outputs.

Every piece of evidence is validated before it enters the system.
False positive detection, confidence scoring, and cross-referencing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from core.events import EventType, OracleEvent
from core.logging import get_logger, get_mission_logger
from core.telemetry import telemetry
from domain.evidence import Evidence, EvidenceConfidence, EvidenceStatus
from runtime.event_bus import get_event_bus

logger = get_logger(__name__)
mission_logger = get_mission_logger()


@dataclass
class ValidationResult:
    """Result of a validation check."""

    passed: bool
    confidence: float
    score: float
    method: str
    details: str = ""
    matched_patterns: List[str] = field(default_factory=list)


class Validator:
    """
    Validates evidence, findings, and results in ORACLE.

    Validation methods:
    - Cross-referencing: Compare against known patterns
    - Confidence scoring: Statistical confidence in results
    - False positive detection: Known FP patterns
    - Consistency checking: Internal consistency of data
    """

    def __init__(self) -> None:
        self._event_bus = get_event_bus()

        # Known false positive patterns
        self._false_positive_patterns: List[Dict[str, Any]] = [
            {"type": "open_port", "pattern": {"port": 0}, "reason": "Port 0 is not a valid port"},
            {"type": "service", "pattern": {"name": "unknown"}, "reason": "Unknown service detected"},
            {"type": "vulnerability", "pattern": {"severity": "none"}, "reason": "No severity assigned"},
        ]

    async def validate_evidence(self, evidence: Evidence) -> Evidence:
        """
        Validate a piece of evidence.

        Runs all validation checks and updates the evidence
        with confidence scores and validation status.

        Args:
            evidence: The evidence to validate

        Returns:
            Validated evidence with updated status and confidence
        """
        mission_logger.start_timer(f"validate_{evidence.id}")
        mission_logger.log(
            "validation.started",
            mission_id=str(evidence.mission_id) if evidence.mission_id else None,
            tool="validator",
            status="started",
            details={
                "evidence_id": str(evidence.id),
                "evidence_type": evidence.evidence_type.value,
                "asset_value": evidence.asset_value,
            },
        )

        results = []

        # 1. False positive check
        fp_result = self._check_false_positive(evidence)
        results.append(fp_result)

        # 2. Consistency check
        consistency_result = self._check_consistency(evidence)
        results.append(consistency_result)

        # 3. Completeness check
        completeness_result = self._check_completeness(evidence)
        results.append(completeness_result)

        # All three checks must pass for evidence to be VALIDATED.
        # Previously only fp_result was consulted here, so evidence with a
        # missing title/tool/asset reference (failed consistency) or missing
        # required fields (failed completeness) could still be marked
        # VALIDATED as long as the false-positive check passed — the other
        # two checks were computed and stored in metadata but never actually
        # affected the outcome.
        all_passed = fp_result.passed and consistency_result.passed and completeness_result.passed
        combined_confidence = (
            fp_result.confidence * 0.5
            + consistency_result.confidence * 0.25
            + completeness_result.confidence * 0.25
        )

        if all_passed and combined_confidence > 0.8:
            evidence.status = EvidenceStatus.VALIDATED
            evidence.confidence = combined_confidence
        else:
            evidence.status = EvidenceStatus.DISPUTED
            evidence.confidence = combined_confidence / 2

        # Update evidence metadata
        evidence.validated_at = datetime.now(timezone.utc)
        evidence.validation_method = "validator.v1"
        evidence.metadata["validation_results"] = [r.__dict__ for r in results]

        duration_ms = mission_logger.stop_timer(f"validate_{evidence.id}") or 0.0

        # Record telemetry
        telemetry.record_histogram(
            "validator.evidence_duration_ms",
            value=duration_ms,
            attributes={
                "evidence_type": evidence.evidence_type.value,
                "status": evidence.status.value,
            },
        )

        mission_logger.log(
            "validation.completed",
            mission_id=str(evidence.mission_id) if evidence.mission_id else None,
            tool="validator",
            status="completed" if evidence.status == EvidenceStatus.VALIDATED else "disputed",
            duration_ms=duration_ms,
            details={
                "evidence_id": str(evidence.id),
                "evidence_type": evidence.evidence_type.value,
                "confidence": evidence.confidence,
                "status": evidence.status.value,
            },
        )

        # Publish validation event
        await self._event_bus.publish(OracleEvent(
            event_type=EventType.EVIDENCE_VALIDATED,
            source="validator",
            data={
                "evidence_id": str(evidence.id),
                "evidence_type": evidence.evidence_type.value,
                "confidence": evidence.confidence,
                "status": evidence.status.value,
            },
        ))

        return evidence

    async def validate_finding(self, finding: Any) -> bool:
        """
        Validate that a finding is legitimate.

        This checks for known false positive patterns and
        ensures the finding has sufficient evidence.

        Args:
            finding: The finding to validate

        Returns:
            True if the finding passes validation
        """
        # Check if finding has associated evidence
        if not finding.evidence_ids:
            logger.warning(
                "validation.no_evidence",
                finding_id=str(getattr(finding, 'id', 'unknown')),
            )
            return False

        # Check severity consistency
        valid_severities = {"critical", "high", "medium", "low", "informational"}
        if getattr(finding, 'severity', '').lower() not in valid_severities:
            return False

        return True

    async def cross_reference(
        self,
        evidence: Evidence,
        knowledge_base: Dict[str, Any],
    ) -> ValidationResult:
        """
        Cross-reference evidence against a knowledge base.

        Args:
            evidence: The evidence to cross-reference
            knowledge_base: Knowledge base to check against

        Returns:
            Validation result from cross-referencing
        """
        matched_patterns = []

        # Check CVE matches
        if evidence.cve_ids:
            for cve_id in evidence.cve_ids:
                if cve_id in knowledge_base.get("cves", {}):
                    matched_patterns.append(f"cve_match:{cve_id}")

        # Check MITRE technique matches
        if evidence.mitre_techniques:
            for technique in evidence.mitre_techniques:
                if technique in knowledge_base.get("mitre", {}):
                    matched_patterns.append(f"mitre_match:{technique}")

        # Check CWE matches
        if evidence.cwe_ids:
            for cwe_id in evidence.cwe_ids:
                if cwe_id in knowledge_base.get("cwes", {}):
                    matched_patterns.append(f"cwe_match:{cwe_id}")

        confidence = min(1.0, 0.5 + (len(matched_patterns) * 0.1))

        return ValidationResult(
            passed=len(matched_patterns) > 0,
            confidence=confidence,
            score=len(matched_patterns) * 0.1,
            method="cross_reference",
            details=f"Cross-referenced against knowledge base",
            matched_patterns=matched_patterns,
        )

    def _check_false_positive(self, evidence: Evidence) -> ValidationResult:
        """Check if evidence matches known false positive patterns."""
        for fp in self._false_positive_patterns:
            if fp["type"] == evidence.evidence_type.value:
                for key, value in fp["pattern"].items():
                    if evidence.raw_data.get(key) == value:
                        return ValidationResult(
                            passed=False,
                            confidence=0.0,
                            score=0.0,
                            method="false_positive_check",
                            details=fp["reason"],
                        )

        return ValidationResult(
            passed=True,
            confidence=0.9,
            score=1.0,
            method="false_positive_check",
            details="No false positive patterns matched",
        )

    def _check_consistency(self, evidence: Evidence) -> ValidationResult:
        """Check internal consistency of evidence data."""
        issues = []

        # Check required fields
        if not evidence.title:
            issues.append("Missing title")
        if not evidence.source.tool_name:
            issues.append("Missing source tool name")
        if not evidence.asset_value and not evidence.asset_id:
            issues.append("Missing asset reference")

        if issues:
            return ValidationResult(
                passed=False,
                confidence=0.5,
                score=0.5,
                method="consistency_check",
                details="; ".join(issues),
            )

        return ValidationResult(
            passed=True,
            confidence=1.0,
            score=1.0,
            method="consistency_check",
            details="Evidence data is consistent",
        )

    def _check_completeness(self, evidence: Evidence) -> ValidationResult:
        """Check if evidence has complete data."""
        required_fields = ["title", "description", "evidence_type"]
        optional_fields = ["asset_value", "severity"]

        missing_required = [
            f for f in required_fields if not getattr(evidence, f, None)
        ]
        missing_optional = [
            f for f in optional_fields if not getattr(evidence, f, None)
        ]

        if missing_required:
            return ValidationResult(
                passed=False,
                confidence=0.3,
                score=0.3,
                method="completeness_check",
                details=f"Missing required fields: {', '.join(missing_required)}",
            )

        completeness_score = 1.0 - (len(missing_optional) * 0.1)
        return ValidationResult(
            passed=True,
            confidence=completeness_score,
            score=completeness_score,
            method="completeness_check",
            details=f"All required fields present. Missing optional: {', '.join(missing_optional) if missing_optional else 'none'}",
        )


__all__ = ["Validator", "ValidationResult"]
