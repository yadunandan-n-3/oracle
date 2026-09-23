"""
Apache Correlation Rule
=======================

Correlates Nmap-discovered Apache HTTP Server versions with Nuclei
vulnerability findings to produce unified findings.

Example:
    Nmap: Apache 2.4.49
    Nuclei: CVE-2021-41773
    → One finding: "Apache 2.4.49 - Path Traversal (CVE-2021-41773)"
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from domain.correlation import CorrelationResult, CorrelationRule, CorrelationType
from domain.evidence import Evidence

APACHE_PATTERN = re.compile(r"Apache[\s/]*(?:HTTP\s+Server)?[\s/]*(\d+\.\d+\.\d+)", re.IGNORECASE)
APACHE_CVE_MAP: Dict[str, List[str]] = {
    "2.4.49": ["CVE-2021-41773", "CVE-2021-42013"],
    "2.4.50": ["CVE-2021-42013"],
    "2.4.6": ["CVE-2024-????"],  # Placeholder for future CVEs
}


class ApacheCorrelationRule(CorrelationRule):
    """
    Correlates Apache HTTP Server evidence from Nmap with vulnerability
    findings from Nuclei.
    """

    name = "apache_correlation"
    description = "Correlates Apache version evidence with known CVEs"
    priority = 10  # High priority (specific technology)

    async def evaluate(
        self,
        evidence_list: List[Any],
        **kwargs: Any,
    ) -> List[CorrelationResult]:
        """
        Evaluate evidence for Apache-related correlations.

        Looks for:
        1. Nmap service evidence showing "Apache" + version
        2. Nuclei vulnerability evidence with CVE matching that version

        Args:
            evidence_list: List of domain.evidence.Evidence objects
            **kwargs: Additional context (mission, assets)

        Returns:
            List of CorrelationResult objects
        """
        results: List[CorrelationResult] = []
        evidence_by_asset: Dict[str, List[Evidence]] = {}

        # Group evidence by asset_value
        for evidence in evidence_list:
            if not isinstance(evidence, Evidence):
                continue
            asset = evidence.asset_value
            if asset not in evidence_by_asset:
                evidence_by_asset[asset] = []
            evidence_by_asset[asset].append(evidence)

        # For each asset, look for Apache version + CVE matches
        for asset_value, items in evidence_by_asset.items():
            apache_version = self._find_apache_version(items)
            if not apache_version:
                continue

            matched_cves = self._find_matching_cves(items, apache_version)
            if not matched_cves:
                continue

            # Build the correlation result
            matched_evidence_ids = [
                ev.id for ev in items
                if self._is_apache_evidence(ev) or self._is_cve_matching(ev, matched_cves)
            ]

            # Determine the host/IP from the asset value
            ip, port, protocol = self._parse_asset_value(asset_value)

            cve_descriptions = ", ".join(matched_cves[:3])
            results.append(CorrelationResult(
                correlation_type=CorrelationType.TECHNOLOGY_MATCH,
                rule_name=self.name,
                confidence=0.95,  # High confidence: specific version + CVE match
                evidence_ids=[ev.id for ev in items if ev.id],
                asset_value=ip or asset_value,
                technology="Apache",
                version=apache_version,
                service="http",
                port=port,
                protocol=protocol,
                ip_address=ip,
                cve_ids=matched_cves,
                description=f"Apache HTTP Server {apache_version} matched to {cve_descriptions}",
                reasoning=f"Nmap discovered Apache HTTP Server {apache_version} and Nuclei confirmed {cve_descriptions}",
                matched_on=[f"apache_version:{apache_version}", *[f"cve:{c}" for c in matched_cves]],
            ))

        return results

    def _find_apache_version(self, evidence_list: List[Evidence]) -> Optional[str]:
        """Find Apache HTTP Server version from evidence."""
        for ev in evidence_list:
            # Check service-related evidence
            if ev.evidence_type.value in ("service", "banner", "open_port"):
                raw_data = ev.raw_data or {}
                service = raw_data.get("service", "")
                product = raw_data.get("product", raw_data.get("service_product", ""))
                version = raw_data.get("version", raw_data.get("service_version", ""))
                if "apache" in (service + product).lower() and version:
                    return version

            # Check raw_data for version patterns
            raw_data = ev.raw_data or {}
            for key, value in raw_data.items():
                if isinstance(value, str) and "apache" in value.lower():
                    match = APACHE_PATTERN.search(value)
                    if match:
                        return match.group(1)

            # Check title and description
            if "apache" in ev.title.lower():
                match = APACHE_PATTERN.search(ev.title)
                if match:
                    return match.group(1)

            if "apache" in ev.description.lower():
                match = APACHE_PATTERN.search(ev.description)
                if match:
                    return match.group(1)

        return None

    def _find_matching_cves(self, evidence_list: List[Evidence], version: str) -> List[str]:
        """Find CVEs that match the Apache version."""
        known_cves = APACHE_CVE_MAP.get(version, [])

        # Also check Nuclei evidence for CVE matches
        discovered_cves: List[str] = []
        for ev in evidence_list:
            if ev.evidence_type.value == "vulnerability":
                raw_data = ev.raw_data or {}
                # Check for CVE in cve_ids or raw_data
                for cve in ev.cve_ids:
                    if cve not in discovered_cves:
                        discovered_cves.append(cve)

                data_cves = raw_data.get("cve_ids", [])
                for cve in data_cves:
                    if cve not in discovered_cves:
                        discovered_cves.append(cve)

        # Return intersection of known CVEs for this version + discovered CVEs
        # If no discovered CVEs, return the known ones anyway
        if discovered_cves:
            matching = [c for c in discovered_cves if c in known_cves]
            if matching:
                return matching

        return known_cves

    def _is_apache_evidence(self, evidence: Evidence) -> bool:
        """Check if evidence relates to Apache."""
        text = f"{evidence.title} {evidence.description}".lower()
        if "apache" in text:
            return True
        raw_data = evidence.raw_data or {}
        for value in raw_data.values():
            if isinstance(value, str) and "apache" in value.lower():
                return True
        return False

    def _is_cve_matching(self, evidence: Evidence, cves: List[str]) -> bool:
        """Check if evidence contains one of the target CVEs."""
        for cve in cves:
            if cve in evidence.cve_ids:
                return True
            raw_data = evidence.raw_data or {}
            for value in raw_data.values():
                if isinstance(value, str) and cve in value:
                    return True
        return False

    def _parse_asset_value(self, asset_value: str) -> tuple:
        """Parse IP, port, protocol from asset value strings."""
        ip = None
        port = None
        protocol = "tcp"

        # Pattern: 10.0.0.5:80/tcp or 10.0.0.5:443
        match = re.match(r"(\d+\.\d+\.\d+\.\d+):(\d+)(?:/(tcp|udp))?", asset_value)
        if match:
            ip = match.group(1)
            port = int(match.group(2))
            protocol = match.group(3) or "tcp"

        return ip, port, protocol

