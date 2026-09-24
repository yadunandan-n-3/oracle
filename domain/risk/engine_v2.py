"""
Oracle Risk Engine V2
=====================

The 0-100 explainable risk scoring system for ORACLE.

V2 improves on V1 (0-10 scale) with:
- A 0-100 scale for finer granularity
- More factors: CVSS, confidence, EPSS, KEV, internet exposure,
  asset criticality, business importance, exploit maturity,
  evidence count, authentication required
- Full traceability: every factor carries an evidence string
- Integration with the Security Intelligence Service for enrichment

Score formula:
    Risk Score (0-100) = Σ(factor_value * factor_weight) * 100

Factors and their default weights:
    cvss_score          (25%) — CVSS v3 base score normalized to 0-1
    confidence          (15%) — How sure we are the finding is real
    epss                (15%) — EPSS probability of exploitation
    internet_exposure   (10%) — Whether the asset is internet-facing
    asset_criticality   (10%) — Criticality of the affected asset
    business_importance (10%) — Importance of the affected business function
    exploit_maturity    (10%) — How mature public exploitation tooling is
    kev                 (5%)  — Whether CISA has confirmed active exploitation
    evidence_count      (0%)  — Placeholder: evidence volume indicator

These weights are configurable per-organization.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from domain.intelligence import EnrichedFinding
from domain.scoring import (
    OracleRiskScoreV2,
    RiskExplanation,
    RiskFactorV2,
    RiskLevelV2,
)

# ─── Default weights — sum to 1.0 ──────────────────────────────────────────
DEFAULT_WEIGHTS_V2: Dict[str, float] = {
    "cvss_score": 0.25,
    "confidence": 0.15,
    "epss": 0.15,
    "internet_exposure": 0.10,
    "asset_criticality": 0.10,
    "business_importance": 0.10,
    "exploit_maturity": 0.10,
    "kev": 0.05,
    "evidence_count": 0.00,  # Reserved for future use
}

# ─── Asset criticality scores ──────────────────────────────────────────────
ASSET_CRITICALITY_SCORES: Dict[str, float] = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.50,
    "low": 0.25,
    "unknown": 0.30,
    "none": 0.0,
}

# ─── Business importance scores ────────────────────────────────────────────
BUSINESS_IMPORTANCE_SCORES: Dict[str, float] = {
    "critical": 1.0,
    "high": 0.80,
    "medium": 0.50,
    "low": 0.20,
    "none": 0.0,
}

# ─── Exploit maturity scores ───────────────────────────────────────────────
EXPLOIT_MATURITY_SCORES: Dict[str, float] = {
    "active": 1.0,             # Actively exploited in the wild
    "weaponized": 0.85,        # Public, ready-to-run exploit exists
    "proof_of_concept": 0.55,  # PoC exists but needs work
    "none": 0.2,               # No known public exploit
    "unknown": 0.35,           # Unassessed
}

# ─── CVSS score thresholds for severity ────────────────────────────────────
CVSS_SEVERITY_THRESHOLDS: Dict[str, float] = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 0.1,
}


def _level_from_score_v2(score: float) -> RiskLevelV2:
    """Bucket a 0-100 score into a RiskLevelV2."""
    if score >= 85:
        return RiskLevelV2.CRITICAL
    if score >= 70:
        return RiskLevelV2.HIGH
    if score >= 40:
        return RiskLevelV2.MEDIUM
    if score > 0:
        return RiskLevelV2.LOW
    return RiskLevelV2.NONE


class RiskEngineV2:
    """
    Oracle Risk Engine V2 — computes explainable 0-100 risk scores.

    Usage:
        engine = RiskEngineV2()
        risk = await engine.score_enriched_finding(enriched_finding)

    Or directly:
        risk = await engine.score(
            cvss_score=9.8,
            confidence=0.95,
            epss_score=0.94,
            internet_exposed=True,
            asset_criticality="critical",
            business_importance="high",
            exploit_maturity="weaponized",
            in_kev=True,
        )
    """

    def __init__(self, weights: Optional[Dict[str, float]] = None) -> None:
        self.weights = weights or dict(DEFAULT_WEIGHTS_V2)
        total = sum(self.weights.values())
        if abs(total - 1.0) > 1e-6:
            raise ValueError(
                f"RiskEngineV2 weights must sum to 1.0, got {total:.4f}: {self.weights}"
            )

    async def score_enriched_finding(
        self,
        enriched: EnrichedFinding,
    ) -> OracleRiskScoreV2:
        """
        Score an EnrichedFinding using all available data.

        Args:
            enriched: The EnrichedFinding from the Security Intelligence Service

        Returns:
            OracleRiskScoreV2 with full factor breakdown
        """
        ti = enriched.threat_intelligence

        cvss_score = None
        epss_score = None
        in_kev: Optional[bool] = None
        exploit_maturity = "unknown"

        if ti:
            if ti.cve and ti.cve.cvss_score is not None:
                cvss_score = ti.cve.cvss_score
            if ti.epss:
                epss_score = ti.epss.epss_score
            if ti.kev:
                in_kev = True
            elif ti.provider_status.get("kev") == "not_found":
                in_kev = False

        exploit_maturity = enriched.metadata.get("exploit_maturity", "unknown") or "unknown"

        return await self.score(
            cvss_score=cvss_score,
            confidence=enriched.confidence,
            epss_score=epss_score,
            internet_exposed=enriched.internet_exposed,
            asset_criticality=enriched.asset_criticality,
            business_importance=enriched.business_importance,
            exploit_maturity=exploit_maturity,
            in_kev=in_kev,
            evidence_count=len(enriched.evidence_ids),
            finding_id=enriched.finding_id,
            asset_id=enriched.asset_id,
            mission_id=enriched.mission_id,
        )

    async def score(
        self,
        cvss_score: Optional[float] = None,
        confidence: float = 0.5,
        epss_score: Optional[float] = None,
        internet_exposed: bool = False,
        asset_criticality: str = "unknown",
        business_importance: str = "medium",
        exploit_maturity: str = "unknown",
        in_kev: Optional[bool] = False,
        evidence_count: int = 0,
        finding_id: Optional[Any] = None,
        asset_id: Optional[Any] = None,
        mission_id: Optional[Any] = None,
    ) -> OracleRiskScoreV2:
        """
        Compute a risk score from individual factors.

        Args:
            cvss_score: CVSS v3 base score (0-10)
            confidence: Confidence the finding is real (0-1)
            epss_score: EPSS probability score (0-1)
            internet_exposed: Whether asset is internet-facing
            asset_criticality: Criticality of the asset
            business_importance: Business importance of the function
            exploit_maturity: Exploit maturity level
            in_kev: Whether CVE is in CISA KEV; ``None`` means unavailable
            evidence_count: Number of evidence items
            finding_id, asset_id, mission_id: Context IDs

        Returns:
            OracleRiskScoreV2 with full factor breakdown
        """
        factors: List[RiskFactorV2] = []

        # 1. CVSS Score
        cvss_factor = self._normalize_cvss(cvss_score)
        factors.append(RiskFactorV2(
            name="cvss_score",
            value=cvss_factor,
            weight=self.weights["cvss_score"],
            evidence=(
                f"CVSS v3 base score: {cvss_score:.1f}/10"
                if cvss_score is not None
                else "No CVSS data available — defaulting to moderate (0.5)"
            ),
            source="nvd" if cvss_score is not None else "default",
        ))

        # 2. Confidence
        factors.append(RiskFactorV2(
            name="confidence",
            value=max(0.0, min(1.0, confidence)),
            weight=self.weights["confidence"],
            evidence=f"Validation confidence: {confidence:.0%}",
            source="validator",
        ))

        # 3. EPSS
        epss_factor = min(1.0, epss_score or 0.0)
        factors.append(RiskFactorV2(
            name="epss",
            value=epss_factor,
            weight=self.weights["epss"],
            evidence=(
                f"EPSS probability of exploitation: {epss_score:.2%} (percentile: {getattr(getattr(self, '_last_epss', None), 'percentile', 'N/A')})"
                if epss_score is not None
                else "No EPSS data available — defaulting to 0.0"
            ),
            source="first" if epss_score is not None else "default",
        ))

        # 4. Internet exposure
        exposure_factor = 1.0 if internet_exposed else 0.2
        factors.append(RiskFactorV2(
            name="internet_exposure",
            value=exposure_factor,
            weight=self.weights["internet_exposure"],
            evidence=f"Asset is {'internet-facing' if internet_exposed else 'not internet-facing'}",
            source="finding.internet_exposed",
        ))

        # 5. Asset criticality
        criticality_factor = ASSET_CRITICALITY_SCORES.get(asset_criticality.lower(), 0.3)
        factors.append(RiskFactorV2(
            name="asset_criticality",
            value=criticality_factor,
            weight=self.weights["asset_criticality"],
            evidence=f"Asset criticality: {asset_criticality}",
            source="finding.asset_criticality",
        ))

        # 6. Business importance
        importance_factor = BUSINESS_IMPORTANCE_SCORES.get(business_importance.lower(), 0.5)
        factors.append(RiskFactorV2(
            name="business_importance",
            value=importance_factor,
            weight=self.weights["business_importance"],
            evidence=f"Business importance: {business_importance}",
            source="finding.business_importance",
        ))

        # 7. Exploit maturity
        maturity_factor = EXPLOIT_MATURITY_SCORES.get(exploit_maturity.lower(), 0.35)
        # Boost if internet-facing
        if internet_exposed:
            maturity_factor = min(1.0, maturity_factor + 0.1)
        factors.append(RiskFactorV2(
            name="exploit_maturity",
            value=maturity_factor,
            weight=self.weights["exploit_maturity"],
            evidence=f"Exploit maturity: {exploit_maturity}" +
                     ("; internet-facing (+0.10)" if internet_exposed else ""),
            source="finding.exploit_maturity",
        ))

        # 8. KEV (CISA Known Exploited Vulnerabilities)
        kev_factor = 1.0 if in_kev is True else 0.0
        factors.append(RiskFactorV2(
            name="kev",
            value=kev_factor,
            weight=self.weights["kev"],
            evidence=(
                "CVE is listed in CISA's Known Exploited Vulnerabilities catalog"
                if in_kev is True
                else (
                    "CVE is not in CISA KEV catalog"
                    if in_kev is False
                    else "No KEV data available — defaulting to 0.0"
                )
            ),
            source="cisa_kev" if in_kev is not None else "default",
        ))

        # 9. Evidence count (reserved, weight = 0)
        ev_count_factor = min(1.0, evidence_count / 10.0)
        factors.append(RiskFactorV2(
            name="evidence_count",
            value=ev_count_factor,
            weight=self.weights["evidence_count"],
            evidence=f"Evidence count: {evidence_count}",
            source="finding.evidence_ids",
        ))

        # Calculate weighted sum
        weighted_sum = sum(f.value * f.weight for f in factors)

        # Scale to 0-100
        overall_score = round(weighted_sum * 100.0, 2)
        level = _level_from_score_v2(overall_score)

        # Build explanation
        top_factors = sorted(factors, key=lambda f: f.value * f.weight, reverse=True)
        explanation = RiskExplanation(
            summary=f"Oracle Risk Score: {overall_score}/100 — {level.value.upper()}",
            score=overall_score,
            level=level,
            top_factors=[
                f"{f.name}: {round(f.value * f.weight * 100, 1)} points"
                for f in top_factors[:5]
                if f.value > 0 and f.weight > 0
            ],
            factor_details=factors,
            reasoning=self._build_reasoning(factors, overall_score, level),
        )

        return OracleRiskScoreV2(
            score=overall_score,
            level=level,
            factors=factors,
            finding_id=finding_id,
            asset_id=asset_id,
            mission_id=mission_id,
            cvss_score=cvss_score,
            confidence=confidence,
            exposure_score=exposure_factor,
            asset_criticality_score=criticality_factor,
            internet_facing_score=exposure_factor,
            exploit_availability_score=maturity_factor,
            business_importance_score=importance_factor,
            explanation=explanation,
        )

    # ─── Helper methods ──────────────────────────────────────────────

    @staticmethod
    def _normalize_cvss(cvss_score: Optional[float]) -> float:
        """Normalize CVSS v3 score (0-10) to 0.0-1.0."""
        if cvss_score is None:
            return 0.5  # Default: moderate
        return max(0.0, min(1.0, cvss_score / 10.0))

    @staticmethod
    def _build_reasoning(
        factors: List[RiskFactorV2],
        score: float,
        level: RiskLevelV2,
    ) -> str:
        """Build human-readable reasoning for the risk score."""
        positive_factors = [f for f in factors if f.value >= 0.5 and f.weight > 0]
        negative_factors = [f for f in factors if f.value < 0.5 and f.weight > 0]

        lines = [f"The overall Oracle Risk Score is {score:.1f}/100 ({level.value.upper()})."]

        if positive_factors:
            high_contributors = sorted(
                positive_factors,
                key=lambda f: f.value * f.weight,
                reverse=True,
            )[:3]
            lines.append("Key risk drivers:")
            for f in high_contributors:
                points = round(f.value * f.weight * 100, 1)
                lines.append(f"  - {f.name}: {points} points — {f.evidence}")

        if negative_factors:
            lines.append("Mitigating factors:")
            for f in negative_factors[:2]:
                lines.append(f"  - {f.name}: low ({f.evidence})")

        return "\n".join(lines)


__all__ = [
    "RiskEngineV2",
    "DEFAULT_WEIGHTS_V2",
    "ASSET_CRITICALITY_SCORES",
    "BUSINESS_IMPORTANCE_SCORES",
    "EXPLOIT_MATURITY_SCORES",
]
