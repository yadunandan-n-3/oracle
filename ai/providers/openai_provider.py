"""
OpenAI Provider
===============

LLM provider implementation using the OpenAI API.

Supports:
- GPT-4 and GPT-3.5-turbo models
- Structured JSON output via response_format
- Configurable temperature, max_tokens, top_p

Requires the OPENAI_API_KEY environment variable to be set.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from openai import AsyncOpenAI

from ai.providers import LLMProvider


class OpenAIProvider(LLMProvider):
    """
    OpenAI LLM provider.

    Uses the OpenAI API to generate explanations.
    Falls back to structured templates if the API is unavailable.
    """

    name = "openai"
    description = "OpenAI API provider (GPT-4, GPT-3.5-turbo)"

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> None:
        self._model = model
        self._api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self._base_url = base_url or os.getenv("OPENAI_BASE_URL", "")
        self._client: Optional[AsyncOpenAI] = None
        self._available: bool = bool(self._api_key)

    async def _ensure_client(self) -> AsyncOpenAI:
        if self._client is None:
            kwargs = {"api_key": self._api_key}
            if self._base_url:
                kwargs["base_url"] = self._base_url
            self._client = AsyncOpenAI(**kwargs)
        return self._client

    async def generate(self, prompt: str, **kwargs: Any) -> str:
        """
        Generate a response from the OpenAI API.

        Args:
            prompt: The prompt to send
            **kwargs: Overrides for temperature, max_tokens, model, etc.

        Returns:
            The generated text response

        Raises:
            RuntimeError: If the API key is not configured
        """
        if not self._available:
            return self._fallback_response(prompt)

        client = await self._ensure_client()
        model = kwargs.get("model", self._model)
        temperature = kwargs.get("temperature", 0.3)
        max_tokens = kwargs.get("max_tokens", 1024)

        response = await client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a senior cybersecurity analyst providing clear, accurate, and actionable explanations of security findings. Be precise and technical. Use structured reasoning.",
                },
                {"role": "user", "content": prompt},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
        )

        return response.choices[0].message.content or ""

    async def generate_structured(
        self,
        prompt: str,
        response_format: Dict[str, Any],
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Generate a structured JSON response from the OpenAI API.

        Args:
            prompt: The prompt to send
            response_format: JSON schema description of expected output
            **kwargs: Overrides for temperature, max_tokens, model, etc.

        Returns:
            Parsed JSON response as a dictionary
        """
        if not self._available:
            return self._fallback_structured(prompt)

        client = await self._ensure_client()
        model = kwargs.get("model", self._model)
        temperature = kwargs.get("temperature", 0.2)
        max_tokens = kwargs.get("max_tokens", 1024)

        response = await client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a senior cybersecurity analyst. "
                        "You MUST respond with valid JSON only, no markdown, no code fences. "
                        "The JSON must match the schema described in the user's request exactly."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
            response_format={"type": "json_object"},
        )

        content = response.choices[0].message.content or "{}"
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return self._fallback_structured(prompt)

    async def health_check(self) -> Dict[str, Any]:
        """Check if the OpenAI API is available."""
        if not self._available:
            return {
                "healthy": False,
                "available": False,
                "error": "OPENAI_API_KEY not configured",
            }

        try:
            client = await self._ensure_client()
            response = await client.models.list()
            return {
                "healthy": True,
                "available": True,
                "model": self._model,
                "error": None,
            }
        except Exception as e:
            return {
                "healthy": False,
                "available": True,
                "model": self._model,
                "error": str(e),
            }

    def _fallback_response(self, prompt: str) -> str:
        """Return a fallback response when the API is unavailable."""
        return (
            "AI Explanation Engine is not available (no API key configured). "
            "The finding has been scored and enriched with threat intelligence. "
            "Please configure an LLM provider to enable AI-generated explanations."
        )

    def _fallback_structured(self, prompt: str) -> Dict[str, Any]:
        """Return a fallback structured response when the API is unavailable."""
        return {
            "summary": "AI explanation unavailable — no LLM provider configured.",
            "technical_reason": "N/A",
            "business_impact": "N/A",
            "recommendation": "Configure an LLM provider (OPENAI_API_KEY) to enable AI explanations.",
            "verification": "N/A",
            "confidence": 0,
            "source": "fallback",
        }


__all__ = ["OpenAIProvider"]
