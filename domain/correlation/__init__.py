"""
Correlation Domain Models
=========================

Models for the Evidence Correlation Engine — the component that
correlates evidence from multiple tools (Nmap, Nuclei, etc.) into
unified findings.

Each correlation rule is a subclass of `CorrelationRule` that inspects
a set of evidence objects and, if its conditions are met, produces a
`CorrelationResult` with a confidence score and the evidence IDs that
contributed to the match.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class CorrelationType(str, Enum):
    """Types of correlation that can be performed."""

    IP_MATCH = "ip_match"
    HOSTNAME_MATCH = "hostname_match"
    PORT_MATCH = "port_match"
    TECHNOLOGY_MATCH = "technology_match"
    CVE_MATCH = "cve_match"
    SERVICE_MATCH = "service_match"
    VERSION_MATCH = "version_match"
    COMPOSITE = "composite"


class CorrelationResult(BaseModel):
    """
    The result of applying a correlation rule to a set of evidence.

    Contains the correlated finding metadata, the contributing evidence
    IDs, the confidence level, and the reasoning for the correlation.
    """

    id: UUID = Field(default_factory=uuid4)
    correlation_type: CorrelationType
    rule_name: str
    confidence: float  # 0.0 to 1.0
    evidence_ids: List[UUID] = Field(default_factory=list)
    asset_value: str = ""
    asset_id: Optional[UUID] = None
    technology: Optional[str] = None
    version: Optional[str] = None
    service: Optional[str] = None
    port: Optional[int] = None
    protocol: str = "tcp"
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    cve_ids: List[str] = Field(default_factory=list)
    cwe_ids: List[str] = Field(default_factory=list)
    description: str = ""
    reasoning: str = ""
    matched_on: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.now)

    model_config = {"extra": "allow"}


class CorrelationRule(ABC):
    """
    Abstract base class for all correlation rules.

    Each rule implements `evaluate()` which takes a list of evidence
    objects and returns a list of `CorrelationResult` objects.
    """

    name: str = "base_rule"
    description: str = "Base correlation rule"
    priority: int = 100  # Lower = higher priority

    @abstractmethod
    async def evaluate(
        self,
        evidence_list: List[Any],
        **kwargs: Any,
    ) -> List[CorrelationResult]:
        """
        Evaluate a set of evidence against this rule.

        Args:
            evidence_list: List of evidence objects (domain.evidence.Evidence)
            **kwargs: Additional context (mission, assets, etc.)

        Returns:
            List of CorrelationResult objects (empty if no matches)
        """
        ...


class EvidenceCorrelator(BaseModel):
    """
    Orchestrates all correlation rules against a set of evidence.

    Runs each registered rule, collects results, deduplicates by
    asset_value + technology, and merges overlapping correlations.
    """

    rules: List[CorrelationRule] = Field(default_factory=list)
    correlation_results: List[CorrelationResult] = Field(default_factory=list)

    def register_rule(self, rule: CorrelationRule) -> None:
        """Register a correlation rule."""
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority)

    async def correlate(
        self,
        evidence_list: List[Any],
        **kwargs: Any,
    ) -> List[CorrelationResult]:
        """
        Run all registered rules against the evidence.

        Args:
            evidence_list: List of evidence objects
            **kwargs: Additional context passed to each rule

        Returns:
            Deduplicated, merged list of CorrelationResult objects
        """
        all_results: List[CorrelationResult] = []
        for rule in self.rules:
            results = await rule.evaluate(evidence_list, **kwargs)
            all_results.extend(results)

        self.correlation_results = self._deduplicate(all_results)
        return self.correlation_results

    def _deduplicate(self, results: List[CorrelationResult]) -> List[CorrelationResult]:
        """
        Deduplicate correlation results by (asset_value, technology, cve).
        Keep the one with the highest confidence.
        """
        seen: Dict[str, CorrelationResult] = {}
        for result in results:
            key_parts = []
            if result.asset_value:
                key_parts.append(result.asset_value)
            if result.technology:
                key_parts.append(result.technology)
            if result.cve_ids:
                key_parts.append(",".join(sorted(result.cve_ids)))
            if result.port:
                key_parts.append(str(result.port))

            key = "|".join(key_parts) if key_parts else result.id.hex

            if key not in seen or result.confidence > seen[key].confidence:
                seen[key] = result

        return list(seen.values())

    model_config = {"arbitrary_types_allowed": True}


__all__ = [
    "CorrelationType",
    "CorrelationResult",
    "CorrelationRule",
    "EvidenceCorrelator",
]
