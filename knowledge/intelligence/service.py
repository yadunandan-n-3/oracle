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
from typing import Any, Dict, List, Optional

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

    def __init__(
        self,
        *,
        cve_service: Optional[Any] = None,
        cwe_service: Optional[Any] = None,
        owasp_service: Optional[Any] = None,
        epss_service: Optional[Any] = None,
        kev_service: Optional[Any] = None,
        mitre_mapper: Optional[Any] = None,
    ) -> None:
        self._cve_service = cve_service or CVEService()
        self._cwe_service = cwe_service or CWEService()
        self._owasp_service = owasp_service or OWASPService()
        self._epss_service = epss_service or EPSSService()
        self._kev_service = kev_service or KEVService()
        self._mitre_mapper = mitre_mapper or MitreMapper()

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

        lookups: List[tuple[str, Any]] = []
        if cve_id:
            lookups.extend([
                ("cve", self._lookup_cve(cve_id)),
                ("epss", self._lookup_epss(cve_id)),
                ("kev", self._lookup_kev(cve_id)),
            ])
        if cwe_id:
            lookups.extend([
                ("cwe", self._lookup_cwe(cwe_id)),
                ("owasp", self._lookup_owasp(cwe_id)),
            ])
        if tags or evidence_type or cve_id or cwe_id:
            lookups.append(("mitre", self._lookup_mitre(cve_id, cwe_id, tags, evidence_type)))

        ti = ThreatIntelligence()
        results = await asyncio.gather(
            *(lookup for _, lookup in lookups), return_exceptions=True
        )
        for (provider, _), result in zip(lookups, results):
            self._record_result(ti, provider, result)

        # A CVE response is authoritative for its CWE mapping. Resolve the
        # first mapped weakness only when the finding did not already carry a
        # CWE, then reuse the existing CWE and OWASP providers.
        derived_cwe = (
            ti.cve.cwe_ids[0]
            if not cwe_id and ti.cve and ti.cve.cwe_ids
            else None
        )
        if derived_cwe:
            derived = await asyncio.gather(
                self._lookup_cwe(derived_cwe),
                self._lookup_owasp(derived_cwe),
                return_exceptions=True,
            )
            self._record_result(ti, "cwe", derived[0])
            self._record_result(ti, "owasp", derived[1])

        ti.degraded = any(status == "failed" for status in ti.provider_status.values())

        # Cache the result
        if cache_key:
            self._cache[cache_key] = ti

        return ti

    @staticmethod
    def _record_result(
        ti: ThreatIntelligence,
        provider: str,
        result: Any,
    ) -> None:
        """Attach one provider result while preserving failure provenance."""
        if isinstance(result, Exception):
            ti.provider_status[provider] = "failed"
            ti.provider_errors[provider] = str(result)
            logger.warning(
                "threat_intel.provider_lookup_failed",
                provider=provider,
                error=str(result),
            )
            return

        ti.provider_status[provider] = "available" if result is not None else "not_found"
        if provider == "cve" and isinstance(result, CVEInfo):
            ti.cve = result
        elif provider == "cwe" and isinstance(result, CWEInfo):
            ti.cwe = result
        elif provider == "owasp" and isinstance(result, OWASPInfo):
            ti.owasp = result
        elif provider == "epss" and isinstance(result, EPSSInfo):
            ti.epss = result
        elif provider == "kev" and isinstance(result, KEVInfo):
            ti.kev = result
        elif provider == "mitre" and isinstance(result, list):
            ti.mitre = [
                MitreIntelInfo(
                    technique_id=item.technique_id,
                    technique_name=item.technique_name,
                    tactic=item.tactic,
                    tactic_id=item.tactic_id,
                    confidence=item.confidence,
                    matched_on=item.matched_on,
                )
                for item in result
            ]

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
        for service in (self._cve_service, self._epss_service, self._kev_service):
            close = getattr(service, "close", None)
            if close:
                await close()


__all__ = ["ThreatIntelligenceService"]
