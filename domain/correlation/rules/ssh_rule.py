"""
SSH CVE Correlation Rule
========================

Correlates Nmap-discovered SSH services with known SSH-related CVEs.

Example:
    Nmap: OpenSSH 8.9
    Nuclei: CVE-2023-28531
    → One finding: "OpenSSH 8.9 - Vulnerability"
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from domain.correlation import CorrelationResult, CorrelationRule, CorrelationType
from domain.evidence import Evidence


class SSHCveCorrelationRule(CorrelationRule):
    """
    Correlates SSH service evidence from Nmap with SSH-related
    vulnerabilities from Nuclei.
    """

    name = "ssh_cve_correlation"
    description = "Correlates SSH version evidence with known CVEs"
    priority = 20

    SSH_PRODUCT_PATTERN = re.compile(
        r"(OpenSSH|Dropbear|libssh|PuTTY|SSH[-\s]*Server)", re.IGNORECASE
    )

    async def evaluate(
        self,
        evidence_list: List[Any],
        **kwargs: Any,
    ) -> List[CorrelationResult]:
        """
        Evaluate evidence for SSH-related correlations.

        Args:
            evidence_list: List of Evidence objects
            **kwargs: Additional context

        Returns:
            List of CorrelationResult objects
        """
        results: List[CorrelationResult] = []
        evidence_by_asset: Dict[str, List[Evidence]] = {}

        for evidence in evidence_list:
            if not isinstance(evidence, Evidence):
                continue
            asset = evidence.asset_value
            if asset not in evidence_by_asset:
                evidence_by_asset[asset] = []
            evidence_by_asset[asset].append(evidence)

        for asset_value, items in evidence_by_asset.items():
            ssh_info = self._find_ssh_info(items)
            if not ssh_info:
                continue

            product, version = ssh_info
            matched_cves = self._find_ssh_cves(items)

            if not matched_cves and not version:
                continue

            matched_evidence_ids = [
                ev.id for ev in items
                if self._is_ssh_evidence(ev)
            ]

            ip, port, protocol = self._parse_asset_value(asset_value)

            cve_descriptions = ", ".join(matched_cves[:3]) if matched_cves else "no specific CVEs"
            confidence = 0.9 if matched_cves else 0.6

            results.append(CorrelationResult(
                correlation_type=CorrelationType.SERVICE_MATCH,
                rule_name=self.name,
                confidence=confidence,
                evidence_ids=[ev.id for ev in items if ev.id],
                asset_value=ip or asset_value,
                technology=product,
                version=version or "",
                service="ssh",
                port=port,
                protocol=protocol,
                ip_address=ip,
                cve_ids=matched_cves,
                description=f"{product} {version or ''} on {ip or asset_value}".strip(),
                reasoning=(
                    f"Nmap discovered {product} {version or ''} and Nuclei confirmed {cve_descriptions}"
                    if matched_cves
                    else f"Nmap discovered {product} {version or ''}"
                ),
                matched_on=[f"ssh_product:{product}", *(f"cve:{c}" for c in matched_cves)],
            ))

        return results

    def _find_ssh_info(self, evidence_list: List[Evidence]) -> Optional[tuple]:
        """Find SSH product and version from evidence."""
        for ev in evidence_list:
            if ev.evidence_type.value in ("service", "banner", "port", "open_port"):
                raw_data = ev.raw_data or {}
                service = raw_data.get("service", "")
                product = raw_data.get("product", raw_data.get("service_product", ""))
                version = raw_data.get("version", raw_data.get("service_version", ""))

                if "ssh" in service.lower():
                    return (product or "OpenSSH", version)

                if self.SSH_PRODUCT_PATTERN.search(product):
                    return (product, version)

            # Check title/description
            text = f"{ev.title} {ev.description}"
            match = self.SSH_PRODUCT_PATTERN.search(text)
            if match:
                # Try to extract version
                ver_match = re.search(r"(\d+\.\d+(?:\.\d+)?)", text)
                return (match.group(1), ver_match.group(1) if ver_match else "")

        return None

    def _find_ssh_cves(self, evidence_list: List[Evidence]) -> List[str]:
        """Find CVE IDs related to SSH from vulnerability evidence."""
        cves: List[str] = []
        for ev in evidence_list:
            if ev.evidence_type.value == "vulnerability":
                tags = [t.lower() for t in ev.tags]
                if "ssh" in tags:
                    for cve in ev.cve_ids:
                        if cve not in cves:
                            cves.append(cve)
                    raw_data = ev.raw_data or {}
                    for cve in raw_data.get("cve_ids", []):
                        if cve not in cves:
                            cves.append(cve)
        return cves

    def _is_ssh_evidence(self, evidence: Evidence) -> bool:
        """Check if evidence relates to SSH."""
        text = f"{evidence.title} {evidence.description}".lower()
        if "ssh" in text:
            return True
        raw_data = evidence.raw_data or {}
        for value in raw_data.values():
            if isinstance(value, str) and "ssh" in value.lower():
                return True
        return "ssh" in [t.lower() for t in evidence.tags]

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

