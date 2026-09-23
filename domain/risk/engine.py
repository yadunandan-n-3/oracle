"""
Risk Engine
===========

Computes explainable risk scores for findings.

Design goal: every number the engine produces must be traceable back to a
named factor with its own weight and evidence string. No black-box ML
scoring here — a human should be able to read `RiskScore.factors` and see
exactly why the score came out the way it did.

Overall score = weighted sum of four factors, each normalized to 0.0-1.0,
then scaled to a 0.0-10.0 range:

    severity        (35%) — how bad the underlying issue is by class
    confidence       (15%) — how sure we are the finding is real
    exploitability  (30%) — how easy it is to actually exploit right now
    business_impact  (20%) — what happens to the business if it's exploited

These weights are intentionally simple and are themselves data — see
`DEFAULT_WEIGHTS` below — so they can be tuned per-organization without
touching the scoring logic.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from domain.finding import Finding, FindingSeverity
from domain.risk import RiskFactor, RiskLevel, RiskScore

# ─── Explainable scoring tables ─────────────────────────────────────────────
# Every table below is deliberately a flat, readable mapping rather than a
# formula, so the reasoning can be quoted directly in RiskFactor.evidence.

SEVERITY_SCORES: Dict[FindingSeverity, float] = {
    FindingSeverity.CRITICAL: 1.0,
    FindingSeverity.HIGH: 0.75,
    FindingSeverity.MEDIUM: 0.5,
    FindingSeverity.LOW: 0.25,
    FindingSeverity.INFO: 0.05,
}

# exploit_maturity, as stored on RiskScore / finding metadata: how mature is
# public exploitation tooling for this class of issue right now.
EXPLOIT_MATURITY_SCORES: Dict[str, float] = {
    "active": 1.0,             # Actively exploited in the wild
    "weaponized": 0.85,        # Public, ready-to-run exploit exists
    "proof_of_concept": 0.55,  # PoC exists but needs work to weaponize
    "none": 0.2,               # No known public exploit
    "unknown": 0.35,           # Unassessed — assume moderate-low risk
}

DATA_CLASSIFICATION_SCORES: Dict[str, float] = {
    "restricted": 1.0,
    "confidential": 0.8,
    "internal": 0.45,
    "public": 0.1,
}

DEFAULT_WEIGHTS: Dict[str, float] = {
    "severity": 0.35,
    "confidence": 0.15,
    "exploitability": 0.30,
    "business_impact": 0.20,
}


def _level_from_score(score: float) -> RiskLevel:
    """Bucket a 0.0-10.0 score into a RiskLevel. Boundaries are inclusive
    on the lower edge so a score of exactly 7.0 is HIGH, not MEDIUM."""
    if score >= 9.0:
        return RiskLevel.CRITICAL
    if score >= 7.0:
        return RiskLevel.HIGH
    if score >= 4.0:
        return RiskLevel.MEDIUM
    if score > 0.0:
        return RiskLevel.LOW
    return RiskLevel.NONE


class RiskEngine:
    """
    Computes RiskScore objects from Findings.

    Kept dependency-free (no I/O, no external services) so it can be unit
    tested in isolation and called synchronously from anywhere in the
    pipeline (validator, report generator, API layer).
    """

    def __init__(self, weights: Optional[Dict[str, float]] = None) -> None:
        self.weights = weights or dict(DEFAULT_WEIGHTS)
        total = sum(self.weights.values())
        if abs(total - 1.0) > 1e-6:
            raise ValueError(
                f"RiskEngine weights must sum to 1.0, got {total:.4f}: {self.weights}"
            )

    def score_finding(
        self,
        finding: Finding,
        *,
        confidence: Optional[float] = None,
        exploit_maturity: Optional[str] = None,
    ) -> RiskScore:
        """
        Compute an explainable RiskScore for a single finding.

        Args:
            finding: The finding to score.
            confidence: Override confidence (0.0-1.0). Falls back to the
                finding's own metadata["confidence"], then to 0.7 (evidence
                exists but wasn't independently re-validated by the caller).
            exploit_maturity: Override for exploit maturity. Falls back to
                finding.metadata.get("exploit_maturity"), then "unknown".

        Returns:
            A RiskScore with a full, human-readable factor breakdown.
        """
        resolved_confidence = self._resolve_confidence(finding, confidence)
        resolved_maturity = self._resolve_exploit_maturity(finding, exploit_maturity)

        severity_factor = self._severity_factor(finding)
        confidence_factor = self._confidence_factor(resolved_confidence)
        exploitability_factor = self._exploitability_factor(finding, resolved_maturity)
        impact_factor = self._business_impact_factor(finding)

        factors = [severity_factor, confidence_factor, exploitability_factor, impact_factor]

        weighted_sum = sum(f.value * f.weight for f in factors)
        overall_score = round(weighted_sum * 10.0, 2)
        level = _level_from_score(overall_score)

        return RiskScore(
            score=overall_score,
            level=level,
            factors=factors,
            finding_id=finding.id,
            asset_id=finding.asset_id,
            mission_id=finding.mission_id,
            likelihood=round((exploitability_factor.value + confidence_factor.value) / 2, 4),
            impact=round(impact_factor.value, 4),
            cvss_score=finding.cvss_score,
            exploit_maturity=resolved_maturity,
        )

    # ─── Factor computation ────────────────────────────────────────────

    def _severity_factor(self, finding: Finding) -> RiskFactor:
        value = SEVERITY_SCORES.get(finding.severity, 0.5)
        return RiskFactor(
            name="severity",
            value=value,
            weight=self.weights["severity"],
            evidence=f"Finding classified as {finding.severity.value}",
            source="finding.severity",
        )

    def _confidence_factor(self, confidence: float) -> RiskFactor:
        return RiskFactor(
            name="confidence",
            value=confidence,
            weight=self.weights["confidence"],
            evidence=f"Validation confidence of {confidence:.0%} that this finding is a true positive",
            source="validator",
        )

    def _exploitability_factor(self, finding: Finding, exploit_maturity: str) -> RiskFactor:
        maturity_score = EXPLOIT_MATURITY_SCORES.get(exploit_maturity, EXPLOIT_MATURITY_SCORES["unknown"])

        # Exposure and auth requirements shift the base maturity score:
        # an internet-facing, unauthenticated issue is meaningfully easier
        # to exploit than the same bug sitting behind auth on an internal host.
        exposure_bonus = 0.15 if finding.internet_exposed else 0.0
        auth_penalty = -0.1 if finding.authentication_required else 0.0

        value = max(0.0, min(1.0, maturity_score + exposure_bonus + auth_penalty))

        reasons = [f"exploit maturity: {exploit_maturity}"]
        if finding.internet_exposed:
            reasons.append("internet-exposed asset (+0.15)")
        if finding.authentication_required:
            reasons.append("requires authentication (-0.10)")

        return RiskFactor(
            name="exploitability",
            value=round(value, 4),
            weight=self.weights["exploitability"],
            evidence="; ".join(reasons),
            source="risk_engine",
        )

    def _business_impact_factor(self, finding: Finding) -> RiskFactor:
        classification = (finding.data_classification or "internal").lower()
        base = DATA_CLASSIFICATION_SCORES.get(classification, DATA_CLASSIFICATION_SCORES["internal"])
        exposure_bonus = 0.1 if finding.internet_exposed else 0.0
        value = max(0.0, min(1.0, base + exposure_bonus))

        evidence = f"data classification: {classification or 'internal (default)'}"
        if finding.internet_exposed:
            evidence += "; internet-exposed asset (+0.10)"

        return RiskFactor(
            name="business_impact",
            value=round(value, 4),
            weight=self.weights["business_impact"],
            evidence=evidence,
            source="finding.data_classification",
        )

    # ─── Resolution helpers ────────────────────────────────────────────

    @staticmethod
    def _resolve_confidence(finding: Finding, override: Optional[float]) -> float:
        if override is not None:
            return max(0.0, min(1.0, override))
        meta_confidence = finding.metadata.get("confidence") if finding.metadata else None
        if isinstance(meta_confidence, (int, float)):
            return max(0.0, min(1.0, float(meta_confidence)))
        return 0.7

    @staticmethod
    def _resolve_exploit_maturity(finding: Finding, override: Optional[str]) -> str:
        if override:
            return override
        meta_maturity = finding.metadata.get("exploit_maturity") if finding.metadata else None
        if isinstance(meta_maturity, str) and meta_maturity in EXPLOIT_MATURITY_SCORES:
            return meta_maturity
        return "unknown"


__all__ = ["RiskEngine", "DEFAULT_WEIGHTS", "SEVERITY_SCORES", "EXPLOIT_MATURITY_SCORES", "DATA_CLASSIFICATION_SCORES"]
