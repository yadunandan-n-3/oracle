"""
KEV Service
===========

Threat intelligence provider for CISA KEV (Known Exploited Vulnerabilities)
catalog. Provides information about vulnerabilities that are known to be
exploited in the wild.

Uses the CISA KEV JSON catalog with local caching.
Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from domain.intelligence import KEVInfo
from knowledge.intelligence import ThreatIntelligenceProvider

# ─── Built-in KEV Data ─────────────────────────────────────────────────────
# Pre-fetched from CISA's KEV catalog. Update periodically.

_BUILTIN_KEV: Dict[str, Dict[str, Any]] = {
    "CVE-2021-41773": {
        "vendor_project": "Apache",
        "product": "HTTP Server",
        "vulnerability_name": "Apache HTTP Server Path Traversal",
        "short_description": "Apache HTTP Server 2.4.49 contains a path traversal vulnerability that can be exploited to perform remote code execution.",
        "required_action": "Apply updates per vendor instructions.",
        "known_ransomware_use": False,
    },
    "CVE-2021-42013": {
        "vendor_project": "Apache",
        "product": "HTTP Server",
        "vulnerability_name": "Apache HTTP Server Path Traversal",
        "short_description": "Apache HTTP Server 2.4.49 and 2.4.50 contain a path traversal vulnerability that can be exploited to perform remote code execution.",
        "required_action": "Apply updates per vendor instructions.",
        "known_ransomware_use": False,
    },
    "CVE-2022-22965": {
        "vendor_project": "VMware",
        "product": "Spring Framework",
        "vulnerability_name": "Spring Framework Remote Code Execution",
        "short_description": "Spring Framework contains a remote code execution vulnerability in Spring Cloud Function.",
        "required_action": "Apply updates per vendor instructions.",
        "known_ransomware_use": True,
    },
    "CVE-2023-44487": {
        "vendor_project": "Multiple",
        "product": "HTTP/2 Protocol",
        "vulnerability_name": "HTTP/2 Rapid Reset Attack",
        "short_description": "The HTTP/2 protocol contains a vulnerability that enables rapid reset attacks, leading to denial of service.",
        "required_action": "Apply updates per vendor instructions.",
        "known_ransomware_use": False,
    },
    "CVE-2023-46604": {
        "vendor_project": "Apache",
        "product": "ActiveMQ",
        "vulnerability_name": "Apache ActiveMQ Remote Code Execution",
        "short_description": "Apache ActiveMQ contains a deserialization vulnerability that allows remote code execution.",
        "required_action": "Apply updates per vendor instructions.",
        "known_ransomware_use": True,
    },
    "CVE-2024-27198": {
        "vendor_project": "JetBrains",
        "product": "TeamCity",
        "vulnerability_name": "JetBrains TeamCity Authentication Bypass",
        "short_description": "JetBrains TeamCity contains an authentication bypass vulnerability that allows remote code execution.",
        "required_action": "Apply updates per vendor instructions.",
        "known_ransomware_use": True,
    },
    "CVE-2024-3094": {
        "vendor_project": "Tukaani",
        "product": "XZ Utils",
        "vulnerability_name": "XZ Utils Backdoor",
        "short_description": "XZ Utils contains a malicious backdoor inserted via supply chain compromise, allowing remote code execution.",
        "required_action": "Downgrade to XZ Utils 5.4.x and apply security updates per vendor instructions.",
        "known_ransomware_use": False,
    },
    "CVE-2024-4577": {
        "vendor_project": "PHP",
        "product": "PHP",
        "vulnerability_name": "PHP CGI Argument Injection",
        "short_description": "PHP contains a CGI argument injection vulnerability that allows remote code execution on Windows systems.",
        "required_action": "Apply updates per vendor instructions.",
        "known_ransomware_use": True,
    },
}

KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KEVService(ThreatIntelligenceProvider):
    """
    KEV threat intelligence provider.

    Looks up KEV data from:
    1. Local cache
    2. Built-in KEV catalog
    3. CISA KEV catalog JSON feed

    Results are cached in memory for the lifetime of the service.
    """

    name = "kev"
    description = "CISA KEV catalog lookup with local cache"

    def __init__(self) -> None:
        self._cache: Dict[str, KEVInfo] = {}
        self._populate_builtins()
        self._http_client: Optional[httpx.AsyncClient] = None
        self._catalog_fetched = False

    def _populate_builtins(self) -> None:
        """Populate cache from built-in KEV data."""
        for cve_id, data in _BUILTIN_KEV.items():
            self._cache[cve_id.upper()] = KEVInfo(
                cve_id=cve_id.upper(),
                vendor_project=data.get("vendor_project", ""),
                product=data.get("product", ""),
                vulnerability_name=data.get("vulnerability_name", ""),
                short_description=data.get("short_description", ""),
                required_action=data.get("required_action", ""),
                known_ransomware_use=data.get("known_ransomware_use", False),
            )

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=30.0)
        return self._http_client

    async def lookup(self, identifier: str, **kwargs: Any) -> Optional[KEVInfo]:
        """
        Look up KEV data for a CVE.

        Args:
            identifier: CVE ID (e.g., "CVE-2021-41773")
            **kwargs: Not used for KEV lookup

        Returns:
            KEVInfo if found, None otherwise
        """
        cve_id = identifier.upper().strip()

        # Check cache first
        cached = self._cache.get(cve_id)
        if cached:
            return cached

        # Try to fetch the full catalog (once) and check again
        if not self._catalog_fetched:
            try:
                await self._fetch_catalog()
            except Exception:
                pass

        # Check cache again after catalog fetch
        return self._cache.get(cve_id)

    async def _fetch_catalog(self) -> None:
        """Fetch the full KEV catalog from CISA."""
        try:
            client = await self._ensure_client()
            response = await client.get(KEV_CATALOG_URL, timeout=30.0)

            if response.status_code != 200:
                return

            catalog = response.json()
            vulnerabilities = catalog.get("vulnerabilities", [])

            for vuln in vulnerabilities:
                cve_id = vuln.get("cveID", "").upper().strip()
                if not cve_id:
                    continue

                date_added = None
                if vuln.get("dateAdded"):
                    try:
                        date_added = datetime.fromisoformat(vuln["dateAdded"])
                    except Exception:
                        pass

                due_date = None
                if vuln.get("dueDate"):
                    try:
                        due_date = datetime.fromisoformat(vuln["dueDate"])
                    except Exception:
                        pass

                self._cache[cve_id] = KEVInfo(
                    cve_id=cve_id,
                    vendor_project=vuln.get("vendorProject", ""),
                    product=vuln.get("product", ""),
                    vulnerability_name=vuln.get("vulnerabilityName", ""),
                    date_added=date_added,
                    short_description=vuln.get("shortDescription", ""),
                    required_action=vuln.get("requiredAction", ""),
                    due_date=due_date,
                    known_ransomware_use=vuln.get("knownRansomwareCampaignUse", False),
                    notes=vuln.get("notes", ""),
                )

            self._catalog_fetched = True

        except Exception:
            pass

    async def health_check(self) -> Dict[str, Any]:
        """Check if the KEV service is available."""
        try:
            client = await self._ensure_client()
            response = await client.get(KEV_CATALOG_URL, timeout=15.0)
            return {
                "healthy": response.status_code == 200,
                "available": True,
                "cache_size": len(self._cache),
                "catalog_fetched": self._catalog_fetched,
                "error": None if response.status_code == 200 else f"HTTP {response.status_code}",
            }
        except Exception as e:
            return {
                "healthy": True,
                "available": False,
                "cache_size": len(self._cache),
                "catalog_fetched": self._catalog_fetched,
                "error": f"CISA KEV catalog unavailable, using built-in data: {str(e)}",
            }

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None


__all__ = ["KEVService", "_BUILTIN_KEV", "KEV_CATALOG_URL"]
