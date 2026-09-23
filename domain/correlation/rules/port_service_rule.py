"""
Port + Service Correlation Rule
===============================

Correlates port evidence with service evidence on the same asset.

This rule combines raw port discoveries (port 80 open) with service
identification (port 80 runs Apache 2.4.49) into a single enriched
finding per (IP, port, protocol) tuple.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from domain.correlation import CorrelationResult, CorrelationRule, CorrelationType
from domain.evidence import Evidence


class PortServiceCorrelationRule(CorrelationRule):
    """
    Correlates port scanning evidence with service identification evidence.
    """

    name = "port_service_correlation"
    description = "Correlates open ports with identified services on the same (IP, port)"
    priority = 60

    async def evaluate(
        self,
        evidence_list: List[Any],
        **kwargs: Any,
    ) -> List[CorrelationResult]:
        """
        Evaluate evidence for port + service correlations.

        Args:
            evidence_list: List of Evidence objects
            **kwargs: Additional context

        Returns:
            List of CorrelationResult objects
        """
        results: List[CorrelationResult] = []

        # Group by (IP, port, protocol) key
        port_evidence: Dict[str, List[Evidence]] = {}
        service_evidence: Dict[str, List[Evidence]] = {}

        for evidence in evidence_list:
            if not isinstance(evidence, Evidence):
                continue

            key = self._build_key(evidence)
            if not key:
                continue

            if evidence.evidence_type.value in ("port", "open_port"):
                port_evidence.setdefault(key, []).append(evidence)
            elif evidence.evidence_type.value in ("service", "banner"):
                service_evidence.setdefault(key, []).append(evidence)

        # Correlate: for each key with both port and service evidence
        all_keys = set(port_evidence.keys()) | set(service_evidence.keys())

        for key in all_keys:
            ports = port_evidence.get(key, [])
            services = service_evidence.get(key, [])

            if not ports:
                continue

            # Extract the best port info
            port_info = self._extract_best_port_info(ports)
            if not port_info:
                continue

            # Extract the best service info
            service_info = self._extract_best_service_info(services) if services else None

            ip, port, protocol = port_info
            service_name = service_info.get("service", "") if service_info else ""
            product = service_info.get("product", "") if service_info else ""
            version = service_info.get("version", "") if service_info else ""

            evidence_ids = [ev.id for ev in ports + services if ev.id]

            technology = product or service_name
            confidence = 0.9 if service_info else 0.75

            results.append(CorrelationResult(
                correlation_type=CorrelationType.PORT_MATCH,
                rule_name=self.name,
                confidence=confidence,
                evidence_ids=evidence_ids,
                asset_value=ip,
                technology=technology or None,
                version=version or None,
                service=service_name or None,
                port=port,
                protocol=protocol,
                ip_address=ip,
                description=f"Port {port}/{protocol} open on {ip} running {product} {version}".strip(),
                reasoning=(
                    f"Nmap discovered port {port}/{protocol} open on {ip}"
                    + (f" running {product} {version}" if product else "")
                ),
                matched_on=[f"port:{port}/{protocol}", f"ip:{ip}"] + ([f"service:{service_name}"] if service_name else []),
            ))

        return results

    def _build_key(self, evidence: Evidence) -> Optional[str]:
        """Build a (IP, port, protocol) key from evidence."""
        raw_data = evidence.raw_data or {}
        asset = evidence.asset_value

        # Parse from asset_value like "10.0.0.1:80/tcp"
        match = re.match(r"(\d+\.\d+\.\d+\.\d+):(\d+)(?:/(tcp|udp))?", asset)
        if match:
            ip = match.group(1)
            port = match.group(2)
            protocol = match.group(3) or "tcp"
            return f"{ip}:{port}:{protocol}"

        # Parse from asset_value like "10.0.0.1:80"
        match = re.match(r"(\d+\.\d+\.\d+\.\d+):(\d+)", asset)
        if match:
            ip = match.group(1)
            port = match.group(2)
            protocol = raw_data.get("protocol", "tcp")
            return f"{ip}:{port}:{protocol}"

        return None

    def _extract_best_port_info(self, evidence_list: List[Evidence]) -> Optional[tuple]:
        """Extract the best (IP, port, protocol) tuple from evidence."""
        for ev in evidence_list:
            raw_data = ev.raw_data or {}
            asset = ev.asset_value

            match = re.match(r"(\d+\.\d+\.\d+\.\d+):(\d+)(?:/(tcp|udp))?", asset)
            if match:
                return (match.group(1), int(match.group(2)), match.group(3) or "tcp")

            # Try from raw_data
            ip = raw_data.get("ip", "")
            port = raw_data.get("port")
            protocol = raw_data.get("protocol", "tcp")
            if ip and port is not None:
                return (ip, int(port), protocol)

        return None

    def _extract_best_service_info(self, evidence_list: List[Evidence]) -> Dict[str, str]:
        """Extract the best service info from evidence."""
        for ev in evidence_list:
            raw_data = ev.raw_data or {}
            service = raw_data.get("service", "")
            product = raw_data.get("service_product", "")
            version = raw_data.get("service_version", "")

            if product or service:
                return {
                    "service": service,
                    "product": product,
                    "version": version,
                }

            # Try from tags
            if ev.tags:
                for tag in ev.tags:
                    if tag not in ("open_port", "discovered", "verified"):
                        return {"service": tag, "product": "", "version": ""}

        return {}

