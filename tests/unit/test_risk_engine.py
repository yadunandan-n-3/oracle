"""
Unit Tests: Risk Engine
=======================

Verifies the explainable risk-scoring logic in domain/risk/engine.py.
"""

from __future__ import annotations

import pytest

from domain.finding import Finding, FindingSeverity
from domain.risk import RiskLevel
from domain.risk.engine import DEFAULT_WEIGHTS, RiskEngine


def _make_finding(**overrides) -> Finding:
    defaults = dict(
        title="Test finding",
        severity=FindingSeverity.MEDIUM,
        internet_exposed=False,
        authentication_required=False,
        data_classification="internal",
        metadata={},
    )
    defaults.update(overrides)
    return Finding(**defaults)


class TestRiskEngineWeights:
    def test_default_weights_sum_to_one(self) -> None:
        assert abs(sum(DEFAULT_WEIGHTS.values()) - 1.0) < 1e-9

    def test_rejects_weights_not_summing_to_one(self) -> None:
        with pytest.raises(ValueError):
            RiskEngine(weights={"severity": 0.5, "confidence": 0.5, "exploitability": 0.5, "business_impact": 0.5})

    def test_accepts_custom_weights_summing_to_one(self) -> None:
        engine = RiskEngine(weights={"severity": 0.4, "confidence": 0.2, "exploitability": 0.3, "business_impact": 0.1})
        finding = _make_finding()
        score = engine.score_finding(finding)
        assert 0.0 <= score.score <= 10.0


class TestRiskEngineScoring:
    def test_critical_exposed_weaponized_scores_critical(self) -> None:
        engine = RiskEngine()
        finding = _make_finding(
            severity=FindingSeverity.CRITICAL,
            internet_exposed=True,
            data_classification="restricted",
            metadata={"confidence": 0.95, "exploit_maturity": "weaponized"},
        )
        score = engine.score_finding(finding)
        assert score.level == RiskLevel.CRITICAL
        assert score.score >= 9.0

    def test_low_internal_scores_low_or_medium(self) -> None:
        engine = RiskEngine()
        finding = _make_finding(
            severity=FindingSeverity.LOW,
            internet_exposed=False,
            authentication_required=True,
            data_classification="public",
        )
        score = engine.score_finding(finding)
        assert score.level in (RiskLevel.LOW, RiskLevel.MEDIUM)

    def test_higher_severity_finding_scores_higher(self) -> None:
        engine = RiskEngine()
        low = engine.score_finding(_make_finding(severity=FindingSeverity.LOW))
        critical = engine.score_finding(_make_finding(severity=FindingSeverity.CRITICAL))
        assert critical.score > low.score

    def test_internet_exposed_increases_score(self) -> None:
        engine = RiskEngine()
        internal = engine.score_finding(_make_finding(internet_exposed=False))
        exposed = engine.score_finding(_make_finding(internet_exposed=True))
        assert exposed.score > internal.score

    def test_every_factor_has_evidence_string(self) -> None:
        engine = RiskEngine()
        score = engine.score_finding(_make_finding())
        assert len(score.factors) == 4
        for factor in score.factors:
            assert factor.evidence  # every factor must explain itself
            assert 0.0 <= factor.value <= 1.0

    def test_confidence_override_takes_precedence_over_metadata(self) -> None:
        engine = RiskEngine()
        finding = _make_finding(metadata={"confidence": 0.2})
        score = engine.score_finding(finding, confidence=0.9)
        confidence_factor = next(f for f in score.factors if f.name == "confidence")
        assert confidence_factor.value == 0.9

    def test_result_links_back_to_finding_ids(self) -> None:
        engine = RiskEngine()
        finding = _make_finding()
        score = engine.score_finding(finding)
        assert score.finding_id == finding.id
        assert score.asset_id == finding.asset_id
        assert score.mission_id == finding.mission_id
