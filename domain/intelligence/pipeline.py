"""Finding-to-intelligence-to-risk integration using existing P2 services."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timezone
from typing import List, Optional
from uuid import NAMESPACE_URL, uuid5

from core.logging import get_logger
from domain.evidence import Evidence
from domain.finding import Finding
from domain.intelligence import EnrichedFinding, ThreatIntelligence
from domain.intelligence.service import SecurityIntelligenceService
from domain.risk.engine_v2 import RiskEngineV2
from domain.scoring import OracleRiskScoreV2
from knowledge.intelligence.service import ThreatIntelligenceService

logger = get_logger(__name__)


@dataclass
class FindingIntelligenceOutcome:
    """Canonical enriched finding and its explainable V2 risk result."""

    finding: Finding
    enriched_finding: EnrichedFinding
    risk_score: OracleRiskScoreV2


class FindingIntelligencePipeline:
    """Connect canonical findings to the existing intelligence and risk layers."""

    def __init__(
        self,
        threat_intelligence: Optional[ThreatIntelligenceService] = None,
        security_intelligence: Optional[SecurityIntelligenceService] = None,
        risk_engine: Optional[RiskEngineV2] = None,
    ) -> None:
        self.threat_intelligence = threat_intelligence or ThreatIntelligenceService()
        self.security_intelligence = security_intelligence or SecurityIntelligenceService()
        self.risk_engine = risk_engine or RiskEngineV2()

    async def process(
        self,
        finding: Finding,
        evidence: Optional[List[Evidence]] = None,
    ) -> FindingIntelligenceOutcome:
        """Enrich and score one real finding, then apply the result in place."""
        source_identity = {
            "finding_id": str(finding.id),
            "mission_id": str(finding.mission_id) if finding.mission_id else None,
            "asset_id": str(finding.asset_id) if finding.asset_id else None,
            "evidence_ids": [str(value) for value in finding.evidence_ids],
            "cve_id": finding.cve_id,
            "cwe_id": finding.cwe_id,
        }
        try:
            threat_intel = await self.threat_intelligence.enrich_finding(finding)
        except Exception as exc:  # the optional layer must not break ingestion
            logger.warning(
                "intelligence.enrichment_failed",
                finding_id=str(finding.id),
                error=str(exc),
            )
            threat_intel = ThreatIntelligence(
                provider_status={"orchestrator": "failed"},
                provider_errors={"orchestrator": str(exc)},
                degraded=True,
            )

        enriched = await self.security_intelligence.enrich_finding(
            finding=finding,
            evidence_list=evidence or [],
            threat_intel=threat_intel,
        )
        enriched.metadata["source_identity"] = source_identity

        risk = await self.risk_engine.score_enriched_finding(enriched)
        risk.id = uuid5(NAMESPACE_URL, f"oracle:risk:v2:{finding.id}")
        enriched.risk_score_v2 = risk.score
        enriched.risk_level = risk.level.value

        if threat_intel.cve:
            finding.cvss_score = threat_intel.cve.cvss_score
            finding.cvss_vector = threat_intel.cve.cvss_vector
        if not finding.cwe_id and threat_intel.cwe:
            finding.cwe_id = threat_intel.cwe.cwe_id
        if not finding.mitre_technique_id and threat_intel.mitre:
            finding.mitre_technique_id = threat_intel.mitre[0].technique_id
            finding.mitre_tactic = threat_intel.mitre[0].tactic

        finding.risk_score = risk.score
        finding.risk_level = risk.level.value
        finding.risk_factors = [factor.model_dump(mode="json") for factor in risk.factors]
        finding.risk_explanation = (
            risk.explanation.model_dump(mode="json") if risk.explanation else None
        )
        calculated_at = risk.calculated_at
        if calculated_at.tzinfo is None:
            calculated_at = calculated_at.replace(tzinfo=timezone.utc)
        finding.risk_calculation_metadata = {
            "risk_id": str(risk.id),
            "calculated_at": calculated_at.isoformat(),
            "calculated_by": risk.calculated_by,
            "engine": "OracleRiskScoreV2",
        }

        statuses = threat_intel.provider_status
        if not statuses:
            intelligence_status = "not_applicable"
        elif all(status == "failed" for status in statuses.values()):
            intelligence_status = "unavailable"
        elif threat_intel.degraded:
            intelligence_status = "partial"
        else:
            intelligence_status = "complete"

        finding.metadata.update({
            "source_identity": source_identity,
            "intelligence_status": intelligence_status,
            "threat_intelligence": threat_intel.model_dump(mode="json"),
            "enriched_finding": enriched.model_dump(mode="json"),
            "risk_v2": risk.model_dump(mode="json"),
        })
        return FindingIntelligenceOutcome(finding, enriched, risk)

    async def close(self) -> None:
        await self.threat_intelligence.close()


__all__ = ["FindingIntelligenceOutcome", "FindingIntelligencePipeline"]
