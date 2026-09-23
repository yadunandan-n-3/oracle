"""
Unit Tests: AI Explanation Engine
==================================

Verifies the AI Explanation Engine in ai/explanation/.
"""

from __future__ import annotations

import json
from uuid import uuid4

import pytest

from ai.explanation import AIExplanationService
from ai.providers import LLMProvider
from ai.providers.mock_provider import MockProvider
from ai.prompts.explanation_prompts import build_explanation_prompt, EXPLANATION_SCHEMA
from domain.intelligence import (
    CVEInfo, CWEInfo, EPSSInfo, KEVInfo, MitreIntelInfo,
    CVSSSeverity, EnrichedFinding, ThreatIntelligence,
)
from domain.scoring import (
    OracleRiskScoreV2, RiskFactorV2, RiskExplanation, RiskLevelV2,
)


class CapturingMockProvider(MockProvider):
    """Mock provider that captures the last prompt sent."""

    def __init__(self, response: str = "") -> None:
        super().__init__()
        self._last_prompt: str = ""
        self._response = response

    async def generate(self, prompt: str, **kwargs) -> str:
        self._last_prompt = prompt
        if self._response:
            return self._response
        return await super().generate(prompt, **kwargs)

    async def generate_structured(self, prompt: str, response_format: dict, **kwargs) -> dict:
        self._last_prompt = prompt
        if self._response:
            return json.loads(self._response)
        return await super().generate_structured(prompt, response_format, **kwargs)


def _make_enriched_finding(**overrides) -> EnrichedFinding:
    finding_id = uuid4()
    cve_info = CVEInfo(
        cve_id="CVE-2021-41773",
        cvss_score=7.5,
        cvss_severity=CVSSSeverity.HIGH,
        cwe_ids=["CWE-22"],
        affected_software=["Apache httpd 2.4.49"],
        description="Apache HTTP Server path traversal vulnerability",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
    )
    cwe_info = CWEInfo(
        cwe_id="CWE-22",
        name="Path Traversal",
        description="Improper limitation of pathname to restricted directory",
    )
    epss_info = EPSSInfo(
        cve_id="CVE-2021-41773",
        epss_score=0.94,
        percentile=0.98,
    )
    kev_info = KEVInfo(
        cve_id="CVE-2021-41773",
        vendor_project="Apache",
        product="HTTP Server",
        vulnerability_name="Apache HTTP Server Path Traversal",
        required_action="Apply updates per vendor instructions",
    )
    mitre_intel = MitreIntelInfo(
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic="Initial Access",
        tactic_id="TA0001",
        confidence=0.85,
        matched_on=["CVE: CVE-2021-41773", "CWE: CWE-22"],
    )
    ti = ThreatIntelligence(
        cve=cve_info,
        cwe=cwe_info,
        epss=epss_info,
        kev=kev_info,
        mitre=[mitre_intel],
    )

    defaults = dict(
        finding_id=finding_id,
        mission_id=uuid4(),
        asset_id=uuid4(),
        title="Apache Vulnerability - CVE-2021-41773",
        description="Apache 2.4.49 path traversal vulnerability detected",
        severity="critical",
        confidence=0.97,
        asset_value="10.0.0.5",
        asset_type="host",
        evidence_ids=[uuid4()],
        technology="Apache httpd",
        version="2.4.49",
        service="http",
        port=80,
        protocol="tcp",
        ip_address="10.0.0.5",
        hostname="web01.example.com",
        correlation_confidence=0.97,
        correlation_sources=["nmap", "nuclei"],
        threat_intelligence=ti,
        internet_exposed=True,
        remediation_steps=["Upgrade Apache to version 2.4.51 or later"],
        tags=["apache", "cve-2021-41773", "path-traversal"],
    )
    defaults.update(overrides)
    return EnrichedFinding(**defaults)


def _make_risk_score(finding_id, score: float = 96.0) -> OracleRiskScoreV2:
    return OracleRiskScoreV2(
        score=score,
        level=RiskLevelV2.CRITICAL,
        factors=[
            RiskFactorV2(name="cvss_score", value=0.98, weight=0.25, evidence="CVSS score: 9.8/10"),
            RiskFactorV2(name="confidence", value=0.95, weight=0.15, evidence="High confidence: 95%"),
            RiskFactorV2(name="internet_exposure", value=1.0, weight=0.10, evidence="Asset is internet-facing"),
        ],
        finding_id=finding_id,
        cvss_score=9.8,
        confidence=0.95,
        exposure_score=1.0,
        asset_criticality_score=0.75,
        internet_facing_score=1.0,
        exploit_availability_score=0.85,
        business_importance_score=0.80,
        explanation=RiskExplanation(
            summary="Oracle Risk Score: 96.0/100 — CRITICAL",
            score=96.0,
            level=RiskLevelV2.CRITICAL,
            top_factors=[
                "cvss_score: 24.5 points",
                "confidence: 14.3 points",
                "internet_exposure: 10.0 points",
            ],
            reasoning="The overall Oracle Risk Score is 96.0/100 (CRITICAL). Key risk drivers: cvss_score: 9.8/10 CVSS; confidence: 95% confidence; internet_exposure: internet-facing asset.",
        ),
    )


class TestExplanationPrompt:
    def test_prompt_contains_evidence(self) -> None:
        enriched = _make_enriched_finding()
        risk_score = _make_risk_score(enriched.finding_id)
        prompt = build_explanation_prompt(enriched, risk_score)
        assert "CVE-2021-41773" in prompt
        assert "Apache" in prompt
        assert "10.0.0.5" in prompt
        assert "T1190" in prompt

    def test_prompt_contains_risk_score(self) -> None:
        enriched = _make_enriched_finding()
        risk_score = _make_risk_score(enriched.finding_id)
        prompt = build_explanation_prompt(enriched, risk_score)
        assert "96" in prompt or "96.0" in prompt

    def test_prompt_contains_remediation(self) -> None:
        enriched = _make_enriched_finding()
        risk_score = _make_risk_score(enriched.finding_id)
        prompt = build_explanation_prompt(enriched, risk_score)
        assert "Upgrade Apache" in prompt

    def test_prompt_has_structured_sections(self) -> None:
        enriched = _make_enriched_finding()
        risk_score = _make_risk_score(enriched.finding_id)
        prompt = build_explanation_prompt(enriched, risk_score)
        assert "## Finding" in prompt
        assert "## Asset" in prompt
        assert "## Threat Intelligence" in prompt
        assert "## Risk Assessment" in prompt


class TestAIExplanationService:
    @pytest.mark.asyncio
    async def test_explain_finding_with_mock(self) -> None:
        service = AIExplanationService()
        enriched = _make_enriched_finding()
        risk_score = _make_risk_score(enriched.finding_id)
        result = await service.explain_finding(enriched, risk_score)
        assert result is not None
        assert "summary" in result
        assert "recommendation" in result
        assert "confidence" in result

    @pytest.mark.asyncio
    async def test_custom_provider(self) -> None:
        mock = CapturingMockProvider()
        service = AIExplanationService(provider=mock)
        enriched = _make_enriched_finding()
        risk_score = _make_risk_score(enriched.finding_id)
        result = await service.explain_finding(enriched, risk_score)
        assert result is not None
        assert "summary" in result

    @pytest.mark.asyncio
    async def test_provider_prompt_contains_context(self) -> None:
        mock = CapturingMockProvider()
        service = AIExplanationService(provider=mock)
        enriched = _make_enriched_finding()
        risk_score = _make_risk_score(enriched.finding_id)
        await service.explain_finding(enriched, risk_score)
        assert "Apache" in mock._last_prompt
        assert "CVE-2021-41773" in mock._last_prompt

    @pytest.mark.asyncio
    async def test_handles_failure_gracefully(self) -> None:
        class FailingProvider(LLMProvider):
            name = "failing"
            description = "Always fails"

            async def generate(self, prompt: str, **kwargs) -> str:
                raise RuntimeError("Provider unavailable")

            async def generate_structured(self, prompt: str, response_format: dict, **kwargs) -> dict:
                raise RuntimeError("Provider unavailable")

            async def health_check(self) -> dict:
                return {"healthy": False, "error": "Provider unavailable"}

        service = AIExplanationService(provider=FailingProvider())
        enriched = _make_enriched_finding()
        risk_score = _make_risk_score(enriched.finding_id)
        result = await service.explain_finding(enriched, risk_score)
        assert result is not None
        assert "summary" in result
        assert result["confidence"] == 0

    @pytest.mark.asyncio
    async def test_explanation_includes_recommendation(self) -> None:
        service = AIExplanationService()
        enriched = _make_enriched_finding()
        risk_score = _make_risk_score(enriched.finding_id)
        result = await service.explain_finding(enriched, risk_score)
        assert "recommendation" in result
        assert result["recommendation"]

    @pytest.mark.asyncio
    async def test_explain_findings_bulk(self) -> None:
        service = AIExplanationService()
        enriched1 = _make_enriched_finding(
            title="Apache Vulnerability",
            technology="Apache httpd",
            version="2.4.49",
        )
        enriched2 = _make_enriched_finding(
            finding_id=uuid4(),
            title="SSH Vulnerability",
            technology="OpenSSH",
            version="7.5",
        )
        risk_scores = {
            str(enriched1.finding_id): _make_risk_score(enriched1.finding_id, 96.0),
            str(enriched2.finding_id): _make_risk_score(enriched2.finding_id, 70.0),
        }
        results = await service.explain_findings_bulk([enriched1, enriched2], risk_scores)
        assert len(results) == 2
        for result in results:
            assert "summary" in result

    @pytest.mark.asyncio
    async def test_health_check(self) -> None:
        service = AIExplanationService()
        health = await service.health_check()
        assert "healthy" in health

    @pytest.mark.asyncio
    async def test_set_provider(self) -> None:
        service = AIExplanationService()
        mock = CapturingMockProvider()
        service.set_provider(mock)
        assert service.provider is mock


class TestExplanationSchema:
    def test_schema_has_required_fields(self) -> None:
        assert "properties" in EXPLANATION_SCHEMA
        assert "summary" in EXPLANATION_SCHEMA["properties"]
        assert "technical_reason" in EXPLANATION_SCHEMA["properties"]
        assert "recommendation" in EXPLANATION_SCHEMA["properties"]
        assert "confidence" in EXPLANATION_SCHEMA["properties"]

    def test_schema_required_list(self) -> None:
        required = EXPLANATION_SCHEMA.get("required", [])
        assert "summary" in required
        assert "technical_reason" in required
        assert "recommendation" in required
        assert "confidence" in required
