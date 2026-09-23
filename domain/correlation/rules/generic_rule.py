"""
Generic Technology + CVE Correlation Rule
=========================================

A general-purpose rule that correlates any technology/product detected
by Nmap with any CVE discovered by Nuclei on the same asset (IP, hostname,
port).

This is the catch-all rule that handles cases not covered by the
Apache, SSH, or HTTP-specific rules.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from domain.correlation import CorrelationResult, CorrelationRule, CorrelationType
from domain.evidence import Evidence


class GenericTechCveCorrelationRule(CorrelationRule):
    """
    Generic correlation rule that matches technology evidence from Nmap
    with CVE evidence from Nuclei on the same asset.
    """

    name = "generic_tech_cve_correlation"
    description = "Correlates any technology + CVE on the same asset"
    priority = 50  # Lower priority than specific rules

    async def evaluate(
        self,
        evidence_list: List[Any],
        **kwargs: Any,
    ) -> List[CorrelationResult]:
        """
        Evaluate evidence for generic technology + CVE correlations.

        Matches evidence by:
        - IP address
        - Hostname
        - Port
        - Asset value

        Args:
            evidence_list: List of Evidence objects
            **kwargs: Additional context

        Returns:
            List of CorrelationResult objects
        """
        results: List[CorrelationResult] = []

        # Group evidence by resolved IP/asset
        tech_evidence: Dict[str, List[Evidence]] = {}
        vuln_evidence: Dict[str, List[Evidence]] = {}
        port_evidence: Dict[str, List[Evidence]] = {}

        for evidence in evidence_list:
            if not isinstance(evidence, Evidence):
                continue

            asset_key = self._resolve_asset_key(evidence)

            if evidence.evidence_type.value in ("service", "banner", "technology"):
                tech_evidence.setdefault(asset_key, []).append(evidence)

            if evidence.evidence_type.value == "vulnerability":
                vuln_evidence.setdefault(asset_key, []).append(evidence)

            if evidence.evidence_type.value == "port":
                port_evidence.setdefault(asset_key, []).append(evidence)

        # Correlate: for each asset with both technology and vulnerability evidence
        all_keys = set(tech_evidence.keys()) | set(vuln_evidence.keys())

        for asset_key in all_keys:
            techs = tech_evidence.get(asset_key, [])
            vulns = vuln_evidence.get(asset_key, [])
            ports = port_evidence.get(asset_key, [])

            if not techs and not vulns:
                continue

            # Extract technologies
            technologies = self._extract_technologies(techs)
            if not technologies and not vulns:
                continue

            # Extract CVEs from vulnerability evidence
            cves = self._extract_cves(vulns)

            if not cves and not technologies:
                continue

            # Build correlation
            ip = self._get_ip_from_evidence(*techs, *vulns, *ports)
            port = self._get_port_from_evidence(*techs, *vulns, *ports)

            confidence = self._compute_confidence(technologies, cves, techs, vulns)

            evidence_ids = [ev.id for ev in techs + vulns if ev.id]

            tech_str = ", ".join(technologies.keys()) if technologies else "unknown"
            cve_str = ", ".join(cves[:3]) if cves else "no CVEs"

            results.append(CorrelationResult(
                correlation_type=CorrelationType.COMPOSITE,
                rule_name=self.name,
                confidence=confidence,
                evidence_ids=evidence_ids,
                asset_value=ip or asset_key,
                technology=next(iter(technologies.keys())) if technologies else None,
                version=next(iter(technologies.values())) if technologies else None,
                ip_address=ip,
                port=port,
                cve_ids=cves,
                description=f"Technology {tech_str} with {' '.join(cves[:3])} on {ip or asset_key}",
                reasoning=(
                    f"Correlated {len(techs)} technology evidence item(s) with "
                    f"{len(vulns)} vulnerability evidence item(s) on {ip or asset_key}"
                ),
                matched_on=[
                    *(f"tech:{t}" for t in technologies),
                    *(f"cve:{c}" for c in cves),
                    f"asset:{asset_key}",
                ],
            ))

        return results

    def _resolve_asset_key(self, evidence: Evidence) -> str:
        """Resolve evidence to a canonical asset key (IP:port)."""
        asset = evidence.asset_value

        # Extract IP from asset_value
        ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", asset)
        if ip_match:
            return ip_match.group(1)

        return asset

    def _extract_technologies(self, evidence_list: List[Evidence]) -> Dict[str, str]:
        """Extract technology -> version mappings from evidence."""
        technologies: Dict[str, str] = {}
        for ev in evidence_list:
            raw_data = ev.raw_data or {}
            service = raw_data.get("service", "")
            product = raw_data.get("service_product", "")
            version = raw_data.get("service_version", "")

            tech_name = product or service
            if tech_name and tech_name not in technologies:
                technologies[tech_name] = version or ""

            # Check title/description for technology names
            text = f"{ev.title} {ev.description}"
            for tag in ev.tags:
                if tag not in ("open_port", "discovered", "verified", "host"):
                    if tag not in technologies:
                        technologies[tag] = ""

        return technologies

    def _extract_cves(self, evidence_list: List[Evidence]) -> List[str]:
        """Extract unique CVE IDs from evidence."""
        cves: List[str] = []
        for ev in evidence_list:
            for cve in ev.cve_ids:
                if cve not in cves:
                    cves.append(cve)
            raw_data = ev.raw_data or {}
            for cve in raw_data.get("cve_ids", []):
                if cve not in cves:
                    cves.append(cve)
        return cves

    def _compute_confidence(
        self,
        technologies: Dict[str, str],
        cves: List[str],
        tech_evidence: List[Evidence],
        vuln_evidence: List[Evidence],
    ) -> float:
        """Compute confidence based on evidence strength."""
        confidence = 0.0

        # Technology evidence boosts confidence
        if technologies:
            confidence += 0.3

        # Version-specific technology boosts confidence
        if any(v for v in technologies.values()):
            confidence += 0.1

        # CVEs boost confidence
        if cves:
            confidence += 0.35

        # Multiple evidence items of the same type boost confidence
        if len(tech_evidence) > 1:
            confidence += 0.05

        if len(vuln_evidence) > 1:
            confidence += 0.05

        # Tags with CVE or vulnerability indicators
        all_tags = set()
        for ev in tech_evidence + vuln_evidence:
            all_tags.update(t.lower() for t in ev.tags)
        if "cve" in all_tags:
            confidence += 0.05

        return min(confidence, 0.98)

    def _get_ip_from_evidence(self, *evidence_items: Evidence) -> Optional[str]:
        """Extract IP address from evidence items."""
        for ev in evidence_items:
            match = re.match(r"(\d+\.\d+\.\d+\.\d+)", ev.asset_value)
            if match:
                return match.group(1)
            raw_data = ev.raw_data or {}
            ip = raw_data.get("ip", "")
            if ip:
                return ip
        return None

    def _get_port_from_evidence(self, *evidence_items: Evidence) -> Optional[int]:
        """Extract port from evidence items."""
        for ev in evidence_items:
            match = re.search(r":(\d+)", ev.asset_value)
            if match:
                return int(match.group(1))
            raw_data = ev.raw_data or {}
            port = raw_data.get("port")
            if port is not None:
                return int(port)
        return None

