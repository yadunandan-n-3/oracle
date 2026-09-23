"""
LLM Provider Abstraction
========================

Abstract base class for LLM providers that the AI Explanation Engine
uses to generate structured explanations.

The AIExplanationService never knows which provider is being used —
it only calls `generate()` and receives a structured JSON response.

Providers:
- OpenAIProvider: Uses OpenAI API (requires API key)
- MockProvider: Returns deterministic explanations (for testing/offline)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class LLMProvider(ABC):
    """
    Abstract base class for LLM providers.

    Each provider implements:
    - generate(): Send a prompt and return the response
    - generate_structured(): Send a prompt and return structured JSON
    """

    name: str = "base_provider"
    description: str = "Base LLM provider"

    @abstractmethod
    async def generate(self, prompt: str, **kwargs: Any) -> str:
        """
        Generate a response from the LLM.

        Args:
            prompt: The prompt to send
            **kwargs: Provider-specific parameters (temperature, max_tokens, etc.)

        Returns:
            The generated text response
        """
        ...

    @abstractmethod
    async def generate_structured(
        self,
        prompt: str,
        response_format: Dict[str, Any],
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Generate a structured JSON response from the LLM.

        Args:
            prompt: The prompt to send
            response_format: JSON schema describing the expected output
            **kwargs: Provider-specific parameters

        Returns:
            Parsed JSON response as a dictionary
        """
        ...

    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """
        Check if the provider is available.

        Returns:
            Dict with healthy, available, and error keys
        """
        ...


__all__ = ["LLMProvider"]
