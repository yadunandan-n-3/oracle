"""
AI Explanation Engine
=====================

The intelligence layer that generates human-readable, structured
explanations for security findings.

This is the feature that recruiters will remember.

Instead of:
    "Apache vulnerability"

It produces:
    "Apache 2.4.49 was detected on 10.0.0.5. Nuclei confirmed
    CVE-2021-41773. This vulnerability allows path traversal and
    may lead to remote code execution. Confidence: 97%. MITRE:
    T1190. Recommendation: Upgrade Apache immediately."

Architecture:
    EnrichedFinding
    ↓
    Prompt Builder
    ↓
    LLM Provider
    ↓
    Structured JSON
    ↓
    Report

The LLM is NEVER given raw tool output. It only receives the
EnrichedFinding — which has already been correlated, enriched
with threat intelligence, and scored by the Risk Engine.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from core.logging import get_logger
from domain.intelligence import EnrichedFinding
from domain.scoring import OracleRiskScoreV2

from ai.providers import LLMProvider
from ai.providers.mock_provider import MockProvider
from ai.prompts.explanation_prompts import (
    EXPLANATION_SCHEMA,
    build_explanation_prompt,
    build_bulk_explanation_prompt,
)

logger = get_logger(__name__)


class AIExplanationService:
    """
    Generates AI-powered explanations for security findings.

    The service:
    1. Builds a structured prompt from the EnrichedFinding
    2. Sends it to the configured LLM provider
    3. Parses the structured JSON response
    4. Returns the explanation

    The LLM is only asked to explain — it never invents CVEs, CWEs,
    or risk scores. All of that is provided in the prompt by the
    Security Intelligence Service and Risk Engine.

    Usage:
        service = AIExplanationService(provider=OpenAIProvider())
        explanation = await service.explain_finding(enriched_finding, risk_score)
        # explanation = {
        #     "summary": "...",
        #     "technical_reason": "...",
        #     "business_impact": "...",
        #     "recommendation": "...",
        #     "verification": "...",
        #     "confidence": 95,
        # }
    """

    def __init__(self, provider: Optional[LLMProvider] = None) -> None:
        self._provider = provider or MockProvider()

    @property
    def provider(self) -> LLMProvider:
        """Get the current LLM provider."""
        return self._provider

    def set_provider(self, provider: LLMProvider) -> None:
        """Set a new LLM provider."""
        self._provider = provider
        logger.info("explanation.provider_changed", provider=provider.name)

    async def explain_finding(
        self,
        enriched: EnrichedFinding,
        risk_score: Optional[OracleRiskScoreV2] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Generate an AI explanation for a single finding.

        Args:
            enriched: The EnrichedFinding from the Security Intelligence Service
            risk_score: The OracleRiskScoreV2 from the Risk Engine
            **kwargs: Additional parameters passed to the LLM provider

        Returns:
            Dict with keys: summary, technical_reason, business_impact,
            recommendation, verification, confidence
        """
        if risk_score is None:
            risk_score = OracleRiskScoreV2(
                score=0.0,
                level=type("RiskLevelV2", (), {"value": "none"})(),
            )

        prompt = build_explanation_prompt(enriched, risk_score)

        try:
            explanation = await self._provider.generate_structured(
                prompt=prompt,
                response_format=EXPLANATION_SCHEMA,
                **kwargs,
            )

            # Validate the response has all required fields
            required_fields = ["summary", "technical_reason", "recommendation", "confidence"]
            for field in required_fields:
                if field not in explanation:
                    explanation[field] = "N/A"

            # Ensure confidence is an integer
            if "confidence" in explanation:
                try:
                    explanation["confidence"] = int(explanation["confidence"])
                except (TypeError, ValueError):
                    explanation["confidence"] = 0

            logger.info(
                "explanation.generated",
                finding_id=str(enriched.finding_id),
                confidence=explanation.get("confidence", 0),
                provider=self._provider.name,
            )

            return explanation

        except Exception as e:
            logger.error(
                "explanation.failed",
                finding_id=str(enriched.finding_id),
                error=str(e),
            )
            return {
                "summary": f"Failed to generate explanation: {e}",
                "technical_reason": "N/A",
                "business_impact": "N/A",
                "recommendation": "N/A",
                "verification": "N/A",
                "confidence": 0,
            }

    async def explain_findings_bulk(
        self,
        enriched_findings: List[EnrichedFinding],
        risk_scores: Optional[Dict[str, OracleRiskScoreV2]] = None,
        **kwargs: Any,
    ) -> List[Dict[str, Any]]:
        """
        Generate explanations for multiple findings.

        For now, this calls explain_finding for each finding individually.
        In the future, it could batch them into a single LLM call.

        Args:
            enriched_findings: List of EnrichedFinding objects
            risk_scores: Dict mapping finding_id -> OracleRiskScoreV2
            **kwargs: Additional parameters passed to the LLM provider

        Returns:
            List of explanation dicts, one per finding
        """
        risk_scores = risk_scores or {}
        explanations: List[Dict[str, Any]] = []

        for enriched in enriched_findings:
            risk = risk_scores.get(str(enriched.finding_id))
            explanation = await self.explain_finding(enriched, risk, **kwargs)
            explanations.append(explanation)

        return explanations

    async def generate_consolidated_summary(
        self,
        enriched_findings: List[EnrichedFinding],
        risk_scores: Optional[Dict[str, OracleRiskScoreV2]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Generate a consolidated summary of all findings.

        Useful for the executive summary section of the report.

        Args:
            enriched_findings: List of EnrichedFinding objects
            risk_scores: Dict mapping finding_id -> OracleRiskScoreV2
            **kwargs: Additional parameters passed to the LLM provider

        Returns:
            Dict with consolidated analysis
        """
        risk_scores = risk_scores or {}
        if not enriched_findings:
            return {
                "summary": "No findings to analyze.",
                "top_risks": [],
                "overall_assessment": "No security issues identified.",
                "recommendations": ["Continue periodic assessments."],
            }

        prompt = build_bulk_explanation_prompt(enriched_findings, risk_scores)

        try:
            consolidated = await self._provider.generate_structured(
                prompt=prompt,
                response_format={
                    "type": "object",
                    "properties": {
                        "summary": {"type": "string"},
                        "top_risks": {"type": "array", "items": {"type": "string"}},
                        "overall_assessment": {"type": "string"},
                        "recommendations": {"type": "array", "items": {"type": "string"}},
                    },
                },
                **kwargs,
            )

            logger.info(
                "explanation.consolidated_generated",
                finding_count=len(enriched_findings),
                provider=self._provider.name,
            )

            return consolidated

        except Exception as e:
            logger.error("explanation.consolidated_failed", error=str(e))
            return {
                "summary": f"Failed to generate consolidated summary: {e}",
                "top_risks": [],
                "overall_assessment": "Unable to generate assessment.",
                "recommendations": ["Review findings manually."],
            }

    async def health_check(self) -> Dict[str, Any]:
        """Check if the explanation service is available."""
        return await self._provider.health_check()


__all__ = ["AIExplanationService"]
