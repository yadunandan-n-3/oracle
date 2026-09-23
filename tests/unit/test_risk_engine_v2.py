"""
Unit Tests: Risk Engine V2
===========================

Verifies the 0-100 explainable risk-scoring logic in domain/risk/engine_v2.py.
"""

from __future__ import annotations
from uuid import uuid4

import pytest

from domain.risk.engine_v2 import DEFAULT_WEIGHTS_V2, RiskEngineV2, _level_from_score_v2
from domain.scoring import RiskLevelV2


class TestRiskEngineV2Weights:
    def test_default_weights_sum_to_one(self) -> None:
        assert abs(sum(DEFAULT_WEIGHTS_V2.values()) - 1.0) < 1e-9

    def test_rejects_weights_not_summing_to_one(self) -> None:
        with pytest.raises(ValueError):
            RiskEngineV2(weights={
                "cvss_score": 0.5, "confidence": 0.5, "epss": 0.5,
                "internet_exposure": 0.5, "asset_criticality": 0.5,
                "business_importance": 0.5, "exploit_maturity": 0.5,
                "kev": 0.5, "evidence_count": 0.5,
            })

    @pytest.mark.asyncio
    async def test_accepts_custom_weights(self) -> None:
        engine = RiskEngineV2(weights={
            "cvss_score": 0.3, "confidence": 0.2, "epss": 0.1,
            "internet_exposure": 0.1, "asset_criticality": 0.1,
            "business_importance": 0.1, "exploit_maturity": 0.05,
            "kev": 0.05, "evidence_count": 0.0,
        })
        score = await engine.score(cvss_score=7.5, confidence=0.85)
        assert 0.0 <= score.score <= 100.0


class TestRiskEngineV2Scoring:
    @pytest.mark.asyncio
    async def test_critical_exposed_weaponized_scores_critical(self) -> None:
        engine = RiskEngineV2()
        score = await engine.score(
            cvss_score=9.8,
            confidence=0.95,
            epss_score=0.94,
            internet_exposed=True,
            asset_criticality="critical",
            business_importance="critical",
            exploit_maturity="weaponized",
            in_kev=True,
        )
        assert score.level == RiskLevelV2.CRITICAL
        assert score.score >= 85

    @pytest.mark.asyncio
    async def test_low_internal_scores_low(self) -> None:
        engine = RiskEngineV2()
        score = await engine.score(
            cvss_score=2.0,
            confidence=0.3,
            epss_score=0.01,
            internet_exposed=False,
            asset_criticality="low",
            business_importance="low",
            exploit_maturity="none",
            in_kev=False,
        )
        assert score.score < 40

    @pytest.mark.asyncio
    async def test_higher_cvss_scores_higher(self) -> None:
        engine = RiskEngineV2()
        low = await engine.score(cvss_score=2.0)
        critical = await engine.score(cvss_score=9.8)
        assert critical.score > low.score

    @pytest.mark.asyncio
    async def test_internet_exposed_increases_score(self) -> None:
        engine = RiskEngineV2()
        internal = await engine.score(internet_exposed=False)
        exposed = await engine.score(internet_exposed=True)
        assert exposed.score > internal.score

    @pytest.mark.asyncio
    async def test_kev_flag_increases_score(self) -> None:
        engine = RiskEngineV2()
        no_kev = await engine.score(in_kev=False)
        kev = await engine.score(in_kev=True)
        assert kev.score > no_kev.score

    @pytest.mark.asyncio
    async def test_every_factor_has_evidence_string(self) -> None:
        engine = RiskEngineV2()
        score = await engine.score(cvss_score=7.5, confidence=0.85)
        assert len(score.factors) == 9
        for factor in score.factors:
            assert factor.evidence
            assert 0.0 <= factor.value <= 1.0

    @pytest.mark.asyncio
    async def test_score_returns_in_range(self) -> None:
        engine = RiskEngineV2()
        score = await engine.score()
        assert 0.0 <= score.score <= 100.0

    @pytest.mark.asyncio
    async def test_score_has_explanation(self) -> None:
        engine = RiskEngineV2()
        score = await engine.score(cvss_score=9.8, internet_exposed=True)
        assert score.explanation is not None
        assert score.explanation.score == score.score
        assert score.explanation.level == score.level

    @pytest.mark.asyncio
    async def test_confidence_affects_score(self) -> None:
        engine = RiskEngineV2()
        low_conf = await engine.score(confidence=0.1)
        high_conf = await engine.score(confidence=0.95)
        assert high_conf.score > low_conf.score

    @pytest.mark.asyncio
    async def test_score_links_to_ids(self) -> None:
        engine = RiskEngineV2()
        finding_uuid = uuid4()
        asset_uuid = uuid4()
        score = await engine.score(finding_id=finding_uuid, asset_id=asset_uuid)
        assert score.finding_id == finding_uuid
        assert score.asset_id == asset_uuid

    @pytest.mark.asyncio
    async def test_epss_increases_score(self) -> None:
        engine = RiskEngineV2()
        no_epss = await engine.score(epss_score=0.0)
        high_epss = await engine.score(epss_score=0.95)
        assert high_epss.score > no_epss.score

    @pytest.mark.asyncio
    async def test_exploit_maturity_increases_score(self) -> None:
        engine = RiskEngineV2()
        mature = await engine.score(exploit_maturity="weaponized")
        basic = await engine.score(exploit_maturity="none")
        assert mature.score > basic.score


class TestRiskLevelV2:
    def test_critical_boundary(self) -> None:
        assert _level_from_score_v2(85) == RiskLevelV2.CRITICAL

    def test_high_boundary(self) -> None:
        assert _level_from_score_v2(70) == RiskLevelV2.HIGH
        assert _level_from_score_v2(84) == RiskLevelV2.HIGH

    def test_medium_boundary(self) -> None:
        assert _level_from_score_v2(40) == RiskLevelV2.MEDIUM
        assert _level_from_score_v2(69) == RiskLevelV2.MEDIUM

    def test_low_boundary(self) -> None:
        assert _level_from_score_v2(1) == RiskLevelV2.LOW
        assert _level_from_score_v2(39) == RiskLevelV2.LOW

    def test_none(self) -> None:
        assert _level_from_score_v2(0) == RiskLevelV2.NONE
