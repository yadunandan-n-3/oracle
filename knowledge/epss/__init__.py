"""
EPSS Service
============

Threat intelligence provider for EPSS (Exploit Prediction Scoring System)
data. EPSS provides a probability score (0-1) that a CVE will be exploited
in the wild in the next 30 days.

Uses the FIRST EPSS API with local caching.
Source: https://www.first.org/epss/api
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from domain.intelligence import EPSSInfo
from knowledge.intelligence import ThreatIntelligenceProvider

# ─── Built-in EPSS Data ────────────────────────────────────────────────────
# Pre-fetched EPSS scores for common CVEs. These are updated periodically
# from the FIRST EPSS API.

_BUILTIN_EPSS: Dict[str, Dict[str, Any]] = {
    "CVE-2021-41773": {"epss_score": 0.94615, "percentile": 0.98070},
    "CVE-2021-42013": {"epss_score": 0.95310, "percentile": 0.98200},
    "CVE-2022-22965": {"epss_score": 0.97270, "percentile": 0.98740},
    "CVE-2023-44487": {"epss_score": 0.74410, "percentile": 0.95960},
    "CVE-2023-46604": {"epss_score": 0.92340, "percentile": 0.97750},
    "CVE-2024-27198": {"epss_score": 0.96810, "percentile": 0.98590},
    "CVE-2024-3094": {"epss_score": 0.96790, "percentile": 0.98580},
    "CVE-2024-4577": {"epss_score": 0.92460, "percentile": 0.97780},
}


class EPSSService(ThreatIntelligenceProvider):
    """
    EPSS threat intelligence provider.

    Looks up EPSS scores from:
    1. Local cache
    2. Built-in data
    3. FIRST EPSS API

    Results are cached in memory for the lifetime of the service.
    """

    name = "epss"
    description = "EPSS score lookup via FIRST API with local cache"

    EPSS_API_BASE = "https://api.first.org/data/v1/epss"

    def __init__(self) -> None:
        self._cache: Dict[str, EPSSInfo] = {}
        self._populate_builtins()
        self._http_client: Optional[httpx.AsyncClient] = None
        self._available: bool = True

    def _populate_builtins(self) -> None:
        """Populate cache from built-in EPSS data."""
        for cve_id, data in _BUILTIN_EPSS.items():
            self._cache[cve_id.upper()] = EPSSInfo(
                cve_id=cve_id.upper(),
                epss_score=data.get("epss_score", 0.0),
                percentile=data.get("percentile", 0.0),
                source="builtin",
            )

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=30.0)
        return self._http_client

    async def lookup(self, identifier: str, **kwargs: Any) -> Optional[EPSSInfo]:
        """
        Look up EPSS score for a CVE.

        Args:
            identifier: CVE ID (e.g., "CVE-2021-41773")
            **kwargs: Not used for EPSS lookup

        Returns:
            EPSSInfo if found, None otherwise
        """
        cve_id = identifier.upper().strip()

        # Check cache first
        cached = self._cache.get(cve_id)
        if cached:
            return cached

        # Try EPSS API
        try:
            result = await self._lookup_epss_api(cve_id)
            if result:
                self._cache[cve_id] = result
                return result
        except Exception:
            pass

        return None

    async def bulk_lookup(self, cve_ids: List[str]) -> Dict[str, Optional[EPSSInfo]]:
        """
        Look up EPSS scores for multiple CVEs in bulk.

        Args:
            cve_ids: List of CVE IDs

        Returns:
            Dict mapping CVE ID to EPSSInfo (or None if not found)
        """
        results: Dict[str, Optional[EPSSInfo]] = {}
        uncached: List[str] = []

        for cve_id in cve_ids:
            normalized = cve_id.upper().strip()
            cached = self._cache.get(normalized)
            if cached:
                results[normalized] = cached
            else:
                uncached.append(normalized)

        if uncached:
            try:
                api_results = await self._bulk_lookup_epss_api(uncached)
                for cve_id, info in api_results.items():
                    self._cache[cve_id] = info
                    results[cve_id] = info
            except Exception:
                pass

        return results

    async def _lookup_epss_api(self, cve_id: str) -> Optional[EPSSInfo]:
        """Look up EPSS score from the FIRST API."""
        try:
            client = await self._ensure_client()
            url = f"{self.EPSS_API_BASE}?cve={cve_id}"
            response = await client.get(url, timeout=15.0)

            if response.status_code != 200:
                return None

            data = response.json()
            epss_data = data.get("data", [])
            if not epss_data:
                return None

            record = epss_data[0]
            return EPSSInfo(
                cve_id=record.get("cve", cve_id),
                epss_score=float(record.get("epss", 0)),
                percentile=float(record.get("percentile", 0)),
                date=datetime.now(timezone.utc),
                source="first",
            )

        except Exception:
            return None

    async def _bulk_lookup_epss_api(self, cve_ids: List[str]) -> Dict[str, EPSSInfo]:
        """Bulk lookup EPSS scores from the FIRST API."""
        client = await self._ensure_client()
        cve_param = ",".join(cve_ids)
        url = f"{self.EPSS_API_BASE}?cve={cve_param}"
        response = await client.get(url, timeout=30.0)

        results: Dict[str, EPSSInfo] = {}
        if response.status_code != 200:
            return results

        data = response.json()
        for record in data.get("data", []):
            cve_id = record.get("cve", "")
            if cve_id:
                results[cve_id] = EPSSInfo(
                    cve_id=cve_id,
                    epss_score=float(record.get("epss", 0)),
                    percentile=float(record.get("percentile", 0)),
                    date=datetime.now(timezone.utc),
                    source="first",
                )

        return results

    async def health_check(self) -> Dict[str, Any]:
        """Check if the EPSS service is available."""
        try:
            client = await self._ensure_client()
            response = await client.get(f"{self.EPSS_API_BASE}?cve=CVE-2021-41773", timeout=10.0)
            return {
                "healthy": response.status_code == 200,
                "available": True,
                "cache_size": len(self._cache),
                "error": None if response.status_code == 200 else f"HTTP {response.status_code}",
            }
        except Exception as e:
            return {
                "healthy": True,
                "available": False,
                "cache_size": len(self._cache),
                "error": f"FIRST API unavailable, using built-in cache: {str(e)}",
            }

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None


__all__ = ["EPSSService", "_BUILTIN_EPSS"]
