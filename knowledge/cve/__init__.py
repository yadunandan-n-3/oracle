"""
CVE Service
===========

Threat intelligence provider for CVE (Common Vulnerabilities and Exposures)
data. Uses a hybrid approach:

1. Check local cache (in-memory dict)
2. Fall back to NVD API (NIST NVD 2.0)
3. Return CVEInfo with parsed CVSS, CWE, and reference data

The local cache is populated from the NVD API on first lookup and
persists for the lifetime of the service. In production, this would be
backed by Redis or SQLite.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from domain.intelligence import CVEInfo, CVSSSeverity
from knowledge.intelligence import ThreatIntelligenceProvider

# ─── Local CVE Database (built-in fallback) ────────────────────────────────
# These are the most common CVEs that ORACLE will encounter during
# penetration testing and vulnerability scanning. Extended at runtime
# via the NVD API.

_BUILTIN_CVES: Dict[str, Dict[str, Any]] = {
    "CVE-2021-41773": {
        "description": "A flaw was found in Apache HTTP Server 2.4.49. A path traversal attack could result in remote code execution.",
        "cvss_score": 7.5,
        "cvss_severity": "high",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe_ids": ["CWE-22"],
        "affected_software": ["Apache HTTP Server 2.4.49"],
        "exploitability_score": 3.9,
        "impact_score": 3.6,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
            "https://httpd.apache.org/security/vulnerabilities_24.html",
        ],
    },
    "CVE-2021-42013": {
        "description": "A flaw was found in Apache HTTP Server 2.4.49 and 2.4.50. A path traversal attack could result in remote code execution.",
        "cvss_score": 9.8,
        "cvss_severity": "critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_ids": ["CWE-22"],
        "affected_software": ["Apache HTTP Server 2.4.49", "Apache HTTP Server 2.4.50"],
        "exploitability_score": 3.9,
        "impact_score": 5.9,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
            "https://httpd.apache.org/security/vulnerabilities_24.html",
        ],
    },
    "CVE-2022-22965": {
        "description": "A Spring Cloud Function vulnerability that allows remote code execution via crafted Spring Expression Language (SpEL) injection.",
        "cvss_score": 9.8,
        "cvss_severity": "critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_ids": ["CWE-94", "CWE-917"],
        "affected_software": ["Spring Cloud Function", "Spring Framework 5.3.x"],
        "exploitability_score": 3.9,
        "impact_score": 5.9,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
            "https://spring.io/security/cve-2022-22965",
        ],
    },
    "CVE-2023-44487": {
        "description": "HTTP/2 rapid reset attack vulnerability affecting multiple implementations.",
        "cvss_score": 7.5,
        "cvss_severity": "high",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe_ids": ["CWE-400"],
        "affected_software": ["HTTP/2 implementations"],
        "exploitability_score": 3.9,
        "impact_score": 3.6,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-44487",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        ],
    },
    "CVE-2023-46604": {
        "description": "Apache ActiveMQ deserialization vulnerability allowing remote code execution.",
        "cvss_score": 10.0,
        "cvss_severity": "critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe_ids": ["CWE-502"],
        "affected_software": ["Apache ActiveMQ"],
        "exploitability_score": 3.9,
        "impact_score": 6.0,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-46604",
        ],
    },
    "CVE-2024-27198": {
        "description": "JetBrains TeamCity authentication bypass vulnerability allowing remote code execution.",
        "cvss_score": 9.8,
        "cvss_severity": "critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_ids": ["CWE-287"],
        "affected_software": ["JetBrains TeamCity"],
        "exploitability_score": 3.9,
        "impact_score": 5.9,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-27198",
        ],
    },
    "CVE-2024-3094": {
        "description": "XZ Utils backdoor (liblzma) — a supply chain compromise that inserted a malicious backdoor into the XZ compression library.",
        "cvss_score": 10.0,
        "cvss_severity": "critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe_ids": ["CWE-912", "CWE-506"],
        "affected_software": ["XZ Utils 5.6.0", "XZ Utils 5.6.1"],
        "exploitability_score": 3.9,
        "impact_score": 6.0,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        ],
    },
    "CVE-2024-4577": {
        "description": "PHP CGI argument injection vulnerability allowing remote code execution on Windows systems.",
        "cvss_score": 9.8,
        "cvss_severity": "critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_ids": ["CWE-78"],
        "affected_software": ["PHP 8.1.x", "PHP 8.2.x", "PHP 8.3.x"],
        "exploitability_score": 3.9,
        "impact_score": 5.9,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-4577",
        ],
    },
}


class CVEService(ThreatIntelligenceProvider):
    """
    CVE threat intelligence provider.

    Looks up CVE data from:
    1. Local cache (in-memory)
    2. Built-in database (common CVEs)
    3. NVD API (NIST NVD 2.0)

    Results are cached in memory for the lifetime of the service.
    """

    name = "cve"
    description = "CVE lookup via NVD API with local fallback cache"

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self) -> None:
        self._cache: Dict[str, CVEInfo] = {}
        self._populate_builtins()
        self._http_client: Optional[httpx.AsyncClient] = None
        self._available: bool = True

    def _populate_builtins(self) -> None:
        """Populate cache from the built-in CVE database."""
        for cve_id, data in _BUILTIN_CVES.items():
            self._cache[cve_id.upper()] = CVEInfo(
                cve_id=cve_id.upper(),
                description=data.get("description", ""),
                cvss_score=data.get("cvss_score"),
                cvss_severity=CVSSSeverity(data.get("cvss_severity", "none")),
                cvss_vector=data.get("cvss_vector", ""),
                cwe_ids=data.get("cwe_ids", []),
                affected_software=data.get("affected_software", []),
                exploitability_score=data.get("exploitability_score"),
                impact_score=data.get("impact_score"),
                references=data.get("references", []),
                source="builtin",
            )

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=30.0)
        return self._http_client

    async def lookup(self, identifier: str, **kwargs: Any) -> Optional[CVEInfo]:
        """
        Look up a CVE by ID.

        Args:
            identifier: CVE ID (e.g., "CVE-2021-41773")
            **kwargs: Not used for CVE lookup

        Returns:
            CVEInfo if found, None otherwise
        """
        cve_id = identifier.upper().strip()

        # Check cache first
        cached = self._cache.get(cve_id)
        if cached:
            return cached

        # Try NVD API
        try:
            result = await self._lookup_nvd_api(cve_id)
            if result:
                self._cache[cve_id] = result
                return result
        except Exception:
            pass

        return None

    async def _lookup_nvd_api(self, cve_id: str) -> Optional[CVEInfo]:
        """Look up a CVE from the NVD API 2.0."""
        try:
            client = await self._ensure_client()
            url = f"{self.NVD_API_BASE}?cveId={cve_id}"
            response = await client.get(url)

            if response.status_code != 200:
                return None

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return None

            vuln = vulnerabilities[0].get("cve", {})
            return self._parse_nvd_response(vuln)

        except Exception:
            return None

    def _parse_nvd_response(self, vuln: Dict[str, Any]) -> CVEInfo:
        """Parse NVD API response into CVEInfo."""
        cve_id = vuln.get("id", "")

        # Description
        descriptions = vuln.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # CVSS v3.1 metrics
        metrics = vuln.get("metrics", {})
        cvss_data = None
        for metric_key in ["cvssMetricV31", "cvssMetricV30"]:
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                break

        cvss_score = None
        cvss_severity = CVSSSeverity.NONE
        cvss_vector = ""
        exploitability_score = None
        impact_score = None

        if cvss_data:
            cvss_score = cvss_data.get("baseScore")
            severity_str = (cvss_data.get("baseSeverity") or "").lower()
            cvss_severity = CVSSSeverity(severity_str) if severity_str in CVSSSeverity._value2member_map_ else CVSSSeverity.NONE
            cvss_vector = cvss_data.get("vectorString", "")
            exploitability_score = cvss_data.get("exploitabilityScore")
            impact_score = cvss_data.get("impactScore")

        # CWE
        weaknesses = vuln.get("weaknesses", [])
        cwe_ids: List[str] = []
        for weakness in weaknesses:
            for cwe_desc in weakness.get("description", []):
                cwe_value = cwe_desc.get("value", "")
                if cwe_value and cwe_value.startswith("CWE-"):
                    cwe_ids.append(cwe_value)

        # Affected software
        affected_software: List[str] = []
        configurations = vuln.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria", "")
                    # Parse CPE to get product:vendor:version
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3]
                        product = parts[4]
                        version = parts[5] if len(parts) > 5 else ""
                        sw = f"{vendor} {product} {version}".strip()
                        if sw and sw not in affected_software:
                            affected_software.append(sw)

        # References
        references: List[str] = []
        for ref in vuln.get("references", []):
            url = ref.get("url", "")
            if url:
                references.append(url)

        # Dates
        published = None
        modified = None
        if vuln.get("published"):
            try:
                published = datetime.fromisoformat(vuln["published"].replace("Z", "+00:00"))
            except Exception:
                pass
        if vuln.get("lastModified"):
            try:
                modified = datetime.fromisoformat(vuln["lastModified"].replace("Z", "+00:00"))
            except Exception:
                pass

        return CVEInfo(
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            cvss_severity=cvss_severity,
            cvss_vector=cvss_vector,
            cwe_ids=cwe_ids,
            affected_software=affected_software,
            exploitability_score=exploitability_score,
            impact_score=impact_score,
            published_date=published,
            last_modified_date=modified,
            references=references,
            source="nvd",
        )

    async def health_check(self) -> Dict[str, Any]:
        """Check if the CVE service is available."""
        try:
            client = await self._ensure_client()
            response = await client.get(f"{self.NVD_API_BASE}?cveId=CVE-2021-41773", timeout=10.0)
            return {
                "healthy": response.status_code == 200,
                "available": True,
                "cache_size": len(self._cache),
                "error": None if response.status_code == 200 else f"HTTP {response.status_code}",
            }
        except Exception as e:
            # Still functional with built-in cache
            return {
                "healthy": True,
                "available": False,
                "cache_size": len(self._cache),
                "error": f"NVD API unavailable, using built-in cache: {str(e)}",
            }

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None


__all__ = ["CVEService", "_BUILTIN_CVES"]
