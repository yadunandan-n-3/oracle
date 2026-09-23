"""
HTTP Service Correlation Rule
=============================

Correlates HTTP service evidence from Nmap with web vulnerability
findings from Nuclei.

Example:
    Nmap: http on 80/tcp, http on 443/tcp
    Nuclei: xss, sqli, tech-detection on the same targets
    → One finding per technology + CVE combo
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from domain.correlation import CorrelationResult, CorrelationRule, CorrelationType
from domain.evidence import Evidence


class HttpServiceCorrelationRule(CorrelationRule):
    """
    Correlates HTTP service evidence from Nmap with web vulnerability
    findings from Nuclei.
    """

    name = "http_service_correlation"
    description = "Correlates HTTP services with web vulnerability findings"
    priority = 30

    HTTP_SERVICES = {"http", "https", "http-alt", "http-proxy", "https-alt"}

    async def evaluate(
        self,
        evidence_list: List[Any],
        **kwargs: Any,
    ) -> List[CorrelationResult]:
        """
        Evaluate evidence for HTTP service correlations.

        Args:
            evidence_list: List of Evidence objects
            **kwargs: Additional context

        Returns:
            List of CorrelationResult objects
        """
        results: List[CorrelationResult] = []
        nmap_http_assets: Dict[str, Dict] = {}
        nuclei_vuln_assets: Dict[str, List[Evidence]] = {}

        for evidence in evidence_list:
            if not isinstance(evidence, Evidence):
                continue

            if self._is_nmap_http_evidence(evidence):
                key = self._build_asset_key(evidence)
                if key not in nmap_http_assets:
                    nmap_http_assets[key] = {
                        "asset_value": evidence.asset_value,
                        "ip": "",
                        "port": None,
                        "protocol": "tcp",
                        "technologies": set(),
                        "tags": set(),
                    }
                self._update_http_asset_info(nmap_http_assets[key], evidence)

            elif evidence.evidence_type.value == "vulnerability" and evidence.source.tool_name == "nuclei":
                key = self._build_asset_key(evidence)
                if key not in nuclei_vuln_assets:
                    nuclei_vuln_assets[key] = []
                nuclei_vuln_assets[key].append(evidence)

        # Correlate: find matching Nmap HTTP services + Nuclei vulnerabilities
        for key, http_info in nmap_http_assets.items():
            matching_vulns = nuclei_vuln_assets.get(key, [])

            if not matching_vulns:
                # HTTP service with no vulnerabilities — still report as a finding
                ip, port, protocol = self._parse_asset_value(http_info["asset_value"])
                results.append(CorrelationResult(
                    correlation_type=CorrelationType.SERVICE_MATCH,
                    rule_name=self.name,
                    confidence=0.5,
                    evidence_ids=[],
                    asset_value=ip or http_info["asset_value"],
                    technology="http" if port != 443 else "https",
                    service="http",
                    port=port,
                    protocol=protocol,
                    ip_address=ip,
                    description=f"HTTP service detected on {ip or http_info['asset_value']}:{port}",
                    reasoning="Nmap identified an HTTP service",
                    matched_on=[f"http_service:{port}"],
                ))
                continue

            correlated_cves: List[str] = []
            for vuln in matching_vulns:
                for cve in vuln.cve_ids:
                    if cve not in correlated_cves:
                        correlated_cves.append(cve)

            evidence_ids = [ev.id for ev in matching_vulns if ev.id]
            ip, port, protocol = self._parse_asset_value(http_info["asset_value"])

            cve_descriptions = ", ".join(correlated_cves[:3]) if correlated_cves else "vulnerability"
            results.append(CorrelationResult(
                correlation_type=CorrelationType.COMPOSITE,
                rule_name=self.name,
                confidence=0.85 if correlated_cves else 0.6,
                evidence_ids=evidence_ids,
                asset_value=ip or http_info["asset_value"],
                technology="http" if port != 443 else "https",
                service="http",
                port=port,
                protocol=protocol,
                ip_address=ip,
                cve_ids=correlated_cves,
                description=f"HTTP service on {ip or http_info['asset_value']}:{port} with {len(matching_vulns)} vulnerability finding(s)",
                reasoning=(
                    f"Nmap identified an HTTP service on port {port} and Nuclei found "
                    f"{len(matching_vulns)} vulnerability finding(s) including {cve_descriptions}"
                ),
                matched_on=[
                    f"http_service:{port}",
                    *[f"cve:{c}" for c in correlated_cves],
                    f"vuln_count:{len(matching_vulns)}",
                ],
            ))

        return results

    def _is_nmap_http_evidence(self, evidence: Evidence) -> bool:
        """Check if evidence is Nmap HTTP service detection."""
        if evidence.source.tool_name != "nmap":
            return False

        raw_data = evidence.raw_data or {}
        service = (raw_data.get("service", "") or "").lower()

        if service in self.HTTP_SERVICES:
            return True

        # Check evidence type
        if evidence.evidence_type.value == "service":
            if any(s in service for s in self.HTTP_SERVICES):
                return True

        return False

    def _build_asset_key(self, evidence: Evidence) -> str:
        """Build a key for grouping evidence by asset + port."""
        raw_data = evidence.raw_data or {}
        port = raw_data.get("port", "")
        ip = evidence.asset_value.split(":")[0] if ":" in evidence.asset_value else evidence.asset_value
        return f"{ip}:{port}"

    def _update_http_asset_info(self, info: Dict, evidence: Evidence) -> None:
        """Update HTTP asset info from evidence."""
        raw_data = evidence.raw_data or {}
        ip, port, protocol = self._parse_asset_value(evidence.asset_value)
        if ip:
            info["ip"] = ip
        if port:
            info["port"] = port
        info["protocol"] = protocol

        service = raw_data.get("service", "")
        product = raw_data.get("service_product", "")
        version = raw_data.get("service_version", "")

        if product:
            tech = f"{product} {version}".strip() if version else product
            info["technologies"].add(tech)

        for tag in evidence.tags:
            info["tags"].add(tag)

    def _parse_asset_value(self, asset_value: str) -> tuple:
        ip = None
        port = None
        protocol = "tcp"
        match = re.match(r"(\d+\.\d+\.\d+\.\d+):(\d+)(?:/(tcp|udp))?", asset_value)
        if match:
            ip = match.group(1)
            port = int(match.group(2))
            protocol = match.group(3) or "tcp"
        return ip, port, protocol

