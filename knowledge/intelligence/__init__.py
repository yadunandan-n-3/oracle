"""
Threat Intelligence Engine
==========================

Provides the provider-based threat intelligence architecture.

Each intelligence source (CVE, CWE, OWASP, EPSS, KEV, MITRE) is a
provider implementing `ThreatIntelligenceProvider`. The
`ThreatIntelligenceService` orchestrates all providers, caching results
and returning a unified `ThreatIntelligence` object.

Architecture:
    ThreatIntelligenceService
        │
        ├── CVEService (NVD API + local cache)
        ├── CWEService (CWE database lookup)
        ├── OWASPService (CWE → OWASP mapping)
        ├── EPSSService (FIRST API)
        ├── KEVService (CISA KEV catalog)
        └── MitreMapper (already exists in knowledge/mitre/)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from domain.intelligence import (
    CVEInfo,
    CWEInfo,
    EPSSInfo,
    KEVInfo,
    MitreIntelInfo,
    OWASPInfo,
    ThreatIntelligence,
)


class ThreatIntelligenceProvider(ABC):
    """
    Abstract base class for all threat intelligence providers.

    Each provider is responsible for a single intelligence source.
    Providers are stateless — caching is handled by the service layer.
    """

    name: str = "base_provider"
    description: str = "Base threat intelligence provider"

    @abstractmethod
    async def lookup(self, identifier: str, **kwargs: Any) -> Optional[Any]:
        """
        Look up intelligence for a given identifier.

        Args:
            identifier: The identifier to look up (CVE ID, CWE ID, etc.)
            **kwargs: Additional context for the lookup

        Returns:
            The intelligence object, or None if not found
        """
        ...

    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """
        Check if the provider is available and functional.

        Returns:
            Dict with healthy, available, version, and error keys
        """
        ...


__all__ = ["ThreatIntelligenceProvider"]
