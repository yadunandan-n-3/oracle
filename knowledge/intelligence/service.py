"""
Threat Intelligence Service
===========================

Orchestrates all threat intelligence providers (CVE, CWE, OWASP, EPSS, KEV,
MITRE) into a unified `ThreatIntelligence` object.

The service:
1. Runs all registered providers in parallel for a given identifier
2. Caches results to avoid redundant lookups
3. Returns a single `ThreatIntelligence` object combining all provider data
4. Handles provider failures gracefully (partial results are better than none)
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional, Set
from uuid import UUID

from core.logging import get_logger
from domain.intelligence import (
    CVEInfo,
    CWEInfo,
    EPSSInfo,
    KEVInfo,
    MitreIntelInfo,
    OWASPInfo,
    ThreatIntelligence,
)
from knowledge.cve import CVEService
from knowledge.cwe import CWEService
from knowledge.epss import EPSSService
from knowledge.kev import KEVService
from knowledge.mitre import MitreMapper
from knowledge.owasp import OWASPService

logger = get_logger(__name__)


class ThreatIntelligenceService:
    """
    Orchestrates all threat intelligence providers.

    Usage:
        service = ThreatIntelligenceService()
        ti = await service.enrich("CVE-2021-41773")
        # ti.cve, ti.epss, ti.kev, ti.mitre, etc.
    """

    def __init__(self) -> None:
        self._cve_service = CVEService()
        self._cwe_service = CWEService()
        self._owasp_service = OWASPService()
        self._epss_service = EPSSService()
        self._kev_service = KEVService()
        self._mitre_mapper = MitreMapper()

        # Simple in-memory cache: identifier -> ThreatIntelligence
        self._cache: Dict[str, ThreatIntelligence] = {}

    async def enrich(
        self,
        cve_id: Optional[str] = None,
        cwe_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
        evidence_type: Optional[str] = None,
        force_refresh: bool = False,
    ) -> ThreatIntelligence:
        """
        Enrich a finding with all available threat intelligence.

        Runs all providers in parallel for maximum throughput.

        Args:
            cve_id: The CVE identifier to enrich
            cwe_id: The CWE identifier to enrich
            tags: Scanner/template tags for MITRE mapping
            evidence_type: Evidence type for MITRE mapping
            force_refresh: Bypass cache and re-fetch from providers

        Returns:
            ThreatIntelligence object with all available data
        """
        cache_key = self._build_cache_key(cve_id, cwe_id)

        if cache_key and cache_key in self._cache and not force_refresh:
            return self._cache[cache_key]

        # Run all lookups in parallel
        cve_future = self._lookup_cve(cve_id) if cve_id else None
        cwe_future = self._lookup_cwe(cwe_id) if cwe_id else None
        owasp_future = self._lookup_owasp(cwe_id) if cwe_id else None
        epss_future = self._lookup_epss(cve_id) if cve_id else None
        kev_future = self._lookup_kev(cve_id) if cve_id else None
        mitre_future = self._lookup_mitre(cve_id, cwe_id, tags, evidence_type) if (tags or evidence_type or cve_id or cwe_id) else None

        futures = [f for f in [cve_future, cwe_future, owasp_future, epss_future, kev_future, mitre_future] if f is not None]

        results = await asyncio.gather(*futures, return_exceptions=True)

        # Collect results, treating exceptions as None
        ti = ThreatIntelligence()
        idx = 0

        if cve_future:
            result = results[idx]
            if isinstance(result, CVEInfo):
                ti.cve = result
            elif isinstance(result, Exception):
                logger.warning("threat_intel.cve_lookup_failed", error=str(result))
            idx += 1

        if cwe_future:
            result = results[idx]
            if isinstance(result, CWEInfo):
                ti.cwe = result
            elif isinstance(result, Exception):
                logger.warning("threat_intel.cwe_lookup_failed", error=str(result))
            idx += 1

        if owasp_future:
            result = results[idx]
            if isinstance(result, OWASPInfo):
                ti.owasp = result
            elif isinstance(result, Exception):
                logger.warning("threat_intel.owasp_lookup_failed", error=str(result))
            idx += 1

        if epss_future:
            result = results[idx]
            if isinstance(result, EPSSInfo):
                ti.epss = result
            elif isinstance(result, Exception):
                logger.warning("threat_intel.epss_lookup_failed", error=str(result))
            idx += 1

        if kev_future:
            result = results[idx]
            if isinstance(result, KEVInfo):
                ti.kev = result
            elif isinstance(result, Exception):
                logger.warning("threat_intel.kev_lookup_failed", error=str(result))
            idx += 1

        if mitre_future:
            result = results[idx]
            if isinstance(result, list):
                ti.mitre = [
                    MitreIntelInfo(
                        technique_id=m.technique_id,
                        technique_name=m.technique_name,
                        tactic=m.tactic,
                        tactic_id=m.tactic_id,
                        confidence=m.confidence,
                        matched_on=m.matched_on,
                    )
                    for m in result
                ]
            elif isinstance(result, Exception):
                logger.warning("threat_intel.mitre_mapping_failed", error=str(result))

        # Cache the result
        if cache_key:
            self._cache[cache_key] = ti

        return ti

    async def enrich_finding(
        self,
        finding: Any,
        force_refresh: bool = False,
    ) -> ThreatIntelligence:
        """
        Convenience wrapper: enrich a Finding object with threat intel.

        Extracts CVE ID, CWE ID, tags, and evidence type from the finding.

        Args:
            finding: A Finding object (or duck-typed equivalent)
            force_refresh: Bypass cache

        Returns:
            ThreatIntelligence object
        """
        cve_id = getattr(finding, "cve_id", None) or getattr(finding, "cve", None)
        cwe_id = getattr(finding, "cwe_id", None) or getattr(finding, "cwe", None)
        tags = list(getattr(finding, "tags", None) or [])
        evidence_type = getattr(finding, "evidence_type", None)

        return await self.enrich(
            cve_id=cve_id,
            cwe_id=cwe_id,
            tags=tags,
            evidence_type=evidence_type,
            force_refresh=force_refresh,
        )

    async def enrich_bulk(
        self,
        identifiers: List[str],
        force_refresh: bool = False,
    ) -> Dict[str, ThreatIntelligence]:
        """
        Enrich multiple CVE IDs in bulk.

        Args:
            identifiers: List of CVE IDs
            force_refresh: Bypass cache

        Returns:
            Dict mapping CVE ID -> ThreatIntelligence
        """
        tasks = {
            cve_id: self.enrich(cve_id=cve_id, force_refresh=force_refresh)
            for cve_id in identifiers
        }
        results = await asyncio.gather(*list(tasks.values()), return_exceptions=True)

        return {
            cve_id: result if isinstance(result, ThreatIntelligence) else ThreatIntelligence()
            for cve_id, result in zip(tasks.keys(), results)
        }

    # ─── Provider Lookups ────────────────────────────────────────────

    async def _lookup_cve(self, cve_id: str) -> Optional[CVEInfo]:
        return await self._cve_service.lookup(cve_id)

    async def _lookup_cwe(self, cwe_id: str) -> Optional[CWEInfo]:
        return await self._cwe_service.lookup(cwe_id)

    async def _lookup_owasp(self, cwe_id: str) -> Optional[OWASPInfo]:
        return await self._owasp_service.lookup(cwe_id)

    async def _lookup_epss(self, cve_id: str) -> Optional[EPSSInfo]:
        return await self._epss_service.lookup(cve_id)

    async def _lookup_kev(self, cve_id: str) -> Optional[KEVInfo]:
        return await self._kev_service.lookup(cve_id)

    async def _lookup_mitre(
        self,
        cve_id: Optional[str],
        cwe_id: Optional[str],
        tags: Optional[List[str]],
        evidence_type: Optional[str],
    ) -> List[Any]:
        cve_ids = [cve_id] if cve_id else None
        cwe_ids = [cwe_id] if cwe_id else None
        return self._mitre_mapper.map(
            cve_ids=cve_ids,
            cwe_ids=cwe_ids,
            tags=tags,
            evidence_type=evidence_type,
        )

    # ─── Helper Methods ──────────────────────────────────────────────

    def _build_cache_key(self, cve_id: Optional[str], cwe_id: Optional[str]) -> str:
        """Build a cache key from identifiers."""
        parts = []
        if cve_id:
            parts.append(f"cve:{cve_id.upper().strip()}")
        if cwe_id:
            parts.append(f"cwe:{cwe_id.upper().strip()}")
        return "|".join(parts) if parts else ""

    async def health_check(self) -> Dict[str, Any]:
        """Check health of all providers."""
        cve_health = await self._cve_service.health_check()
        cwe_health = await self._cwe_service.health_check()
        owasp_health = await self._owasp_service.health_check()
        epss_health = await self._epss_service.health_check()
        kev_health = await self._kev_service.health_check()

        return {
            "healthy": all(
                h.get("healthy", False)
                for h in [cve_health, cwe_health, owasp_health, epss_health, kev_health]
            ),
            "providers": {
                "cve": cve_health,
                "cwe": cwe_health,
                "owasp": owasp_health,
                "epss": epss_health,
                "kev": kev_health,
            },
            "cache_size": len(self._cache),
        }

    async def close(self) -> None:
        """Close all provider connections."""
        await self._cve_service.close()
        await self._epss_service.close()
        await self._kev_service.close()


__all__ = ["ThreatIntelligenceService"]
