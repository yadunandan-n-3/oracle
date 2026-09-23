"""
Mock LLM Provider
=================

Deterministic mock provider for testing and offline use.

Returns pre-structured explanations without making any API calls.
Useful for:
- Unit testing the AI Explanation Engine
- Development/demo environments without an API key
- Air-gapped deployments
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from ai.providers import LLMProvider


class MockProvider(LLMProvider):
    """
    Mock LLM provider that returns deterministic responses.

    This provider never makes network calls and always returns
    the same structured response format. Useful for testing.
    """

    name = "mock"
    description = "Mock LLM provider for testing (no API key required)"

    async def generate(self, prompt: str, **kwargs: Any) -> str:
        """Return a deterministic text response."""
        return (
            "This is a mock AI explanation. The finding has been analyzed using "
            "available threat intelligence data. Please review the technical details "
            "and risk score for prioritization. Configure an LLM provider for "
            "production-quality explanations."
        )

    async def generate_structured(
        self,
        prompt: str,
        response_format: Dict[str, Any],
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Return a deterministic structured response."""
        return {
            "summary": "Mock explanation: Automated security analysis completed.",
            "technical_reason": "The identified vulnerability has been confirmed through "
                               "correlation of Nmap service detection and Nuclei template matching.",
            "business_impact": "If exploited, this vulnerability could lead to "
                              "unauthorized access, data exposure, or service disruption.",
            "recommendation": "Apply the vendor's latest security patch. Review "
                            "configuration and implement security best practices.",
            "verification": "Re-run the vulnerability scan after remediation to confirm the finding is resolved.",
            "confidence": 85,
            "source": "mock_provider",
        }

    async def health_check(self) -> Dict[str, Any]:
        """Mock provider is always healthy."""
        return {
            "healthy": True,
            "available": True,
            "error": None,
        }


__all__ = ["MockProvider"]
