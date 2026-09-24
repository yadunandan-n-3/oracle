"""
Security Intelligence Service
=============================

Central enrichment layer that combines evidence, correlation results,
and threat intelligence into a unified `EnrichedFinding`.

This service prevents each downstream component (Risk Engine, AI
Explanation Engine, Report Generator) from performing its own
independent enrichment logic.

Pipeline:
    Evidence + CorrelationResults + ThreatIntelligence
    ↓
    SecurityIntelligenceService.enrich()
    ↓
    EnrichedFinding  ← single truth for all downstream components

Design decisions:
- Evidence is immutable — never modified after collection
- The EnrichedFinding references evidence IDs but does not modify them
- Multiple correlation results for the same finding are merged
- Provider failures produce partial results (graceful degradation)
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from core.logging import get_logger
from domain.evidence import Evidence
from domain.finding import Finding
from domain.intelligence import EnrichedFinding, ThreatIntelligence
from domain.scoring import AssetIntelligence

logger = get_logger(__name__)


class SecurityIntelligenceService:
    """
    Enriches findings with correlation, threat intelligence, and
    business context.

    Usage:
        service = SecurityIntelligenceService()
        enriched = await service.enrich_finding(
            finding=finding,
            evidence_list=evidence_list,
            threat_intel=threat_intel,
        )
    """

    def __init__(self) -> None:
        self._asset_intelligence: Dict[str, AssetIntelligence] = {}

    async def enrich_finding(
        self,
        finding: Finding,
        evidence_list: Optional[List[Evidence]] = None,
        correlation_results: Optional[List[Any]] = None,
        threat_intel: Optional[ThreatIntelligence] = None,
        asset_intel: Optional[AssetIntelligence] = None,
    ) -> EnrichedFinding:
        """
        Enrich a Finding into an EnrichedFinding with all available context.

        Args:
            finding: The original Finding object
            evidence_list: List of evidence associated with this finding
            correlation_results: Results from the Evidence Correlator
            threat_intel: Aggregated threat intelligence data
            asset_intel: Pre-built asset intelligence (or None to build)

        Returns:
            EnrichedFinding with all enrichment data
        """
        evidence_list = evidence_list or []
        correlation_results = correlation_results or []

        # Build enriched finding from the finding
        enriched = EnrichedFinding(
            finding_id=finding.id,
            mission_id=finding.mission_id,
            asset_id=finding.asset_id,
            title=finding.title,
            description=finding.description,
            severity=finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
            confidence=finding.confidence,
            asset_value=finding.asset_value,
            asset_type=finding.asset_type,
            evidence_ids=finding.evidence_ids,
            internet_exposed=finding.internet_exposed,
            authentication_required=finding.authentication_required,
            data_classification=finding.data_classification or "internal",
            tags=finding.tags,
            metadata=dict(finding.metadata) if finding.metadata else {},
            remediation_steps=finding.remediation_steps,
            remediation_effort=finding.remediation_effort,
        )

        # Apply correlation results
        if correlation_results:
            self._apply_correlation_results(enriched, correlation_results)

        # Apply threat intelligence
        if threat_intel:
            self._apply_threat_intelligence(enriched, threat_intel)

        # Apply or build asset intelligence
        if asset_intel is None:
            asset_intel = await self._build_asset_intelligence(finding, evidence_list)
        enriched.asset_criticality = asset_intel.risk_level
        enriched.business_importance = str(
            finding.metadata.get("business_importance", "medium")
        )

        # Calculate CVSS from threat intel if available
        if threat_intel and threat_intel.cve and threat_intel.cve.cvss_score is not None:
            enriched.metadata["cvss_score"] = threat_intel.cve.cvss_score
            enriched.metadata["cvss_severity"] = threat_intel.cve.cvss_severity.value if hasattr(threat_intel.cve.cvss_severity, "value") else str(threat_intel.cve.cvss_severity)

        return enriched

    async def enrich_findings_bulk(
        self,
        findings: List[Finding],
        evidence_map: Optional[Dict[UUID, List[Evidence]]] = None,
        correlation_map: Optional[Dict[UUID, List[Any]]] = None,
        threat_intel_map: Optional[Dict[str, ThreatIntelligence]] = None,
    ) -> List[EnrichedFinding]:
        """
        Enrich multiple findings in bulk.

        Args:
            findings: List of Finding objects
            evidence_map: Dict mapping finding_id -> evidence list
            correlation_map: Dict mapping finding_id -> correlation results
            threat_intel_map: Dict mapping CVE ID -> ThreatIntelligence

        Returns:
            List of EnrichedFinding objects
        """
        evidence_map = evidence_map or {}
        correlation_map = correlation_map or {}
        threat_intel_map = threat_intel_map or {}

        enriched_findings: List[EnrichedFinding] = []
        for finding in findings:
            evidence = evidence_map.get(finding.id, [])
            correlations = correlation_map.get(finding.id, [])

            # Find matching threat intel by CVE
            threat_intel = None
            if finding.cve_id and finding.cve_id in threat_intel_map:
                threat_intel = threat_intel_map[finding.cve_id]

            enriched = await self.enrich_finding(
                finding=finding,
                evidence_list=evidence,
                correlation_results=correlations,
                threat_intel=threat_intel,
            )
            enriched_findings.append(enriched)

        return enriched_findings

    # ─── Internal enrichment methods ─────────────────────────────────

    def _apply_correlation_results(
        self,
        enriched: EnrichedFinding,
        correlation_results: List[Any],
    ) -> None:
        """Apply correlation results to an enriched finding."""
        best_confidence = enriched.correlation_confidence
        all_sources = list(enriched.correlation_sources)
        all_matched_on: List[str] = []
        all_cves: List[str] = []

        for result in correlation_results:
            # Track best confidence
            if result.confidence > best_confidence:
                best_confidence = result.confidence

            # Collect sources
            rule_name = getattr(result, "rule_name", "") or getattr(result, "rule", "")
            if rule_name and rule_name not in all_sources:
                all_sources.append(rule_name)

            # Collect matched_on
            matched_on = getattr(result, "matched_on", [])
            all_matched_on.extend(matched_on)

            # Collect CVEs
            cves = getattr(result, "cve_ids", [])
            all_cves.extend(cves)

            # Fill technology/version/service/port if not already set
            if not enriched.technology:
                enriched.technology = getattr(result, "technology", None) or getattr(result, "technologies", [None])[0] if hasattr(result, "technologies") and result.technologies else None
            if not enriched.version:
                enriched.version = getattr(result, "version", None)
            if not enriched.service:
                enriched.service = getattr(result, "service", None)
            if not enriched.port:
                enriched.port = getattr(result, "port", None)
            if not enriched.ip_address:
                enriched.ip_address = getattr(result, "ip_address", None)

        enriched.correlation_confidence = best_confidence
        enriched.correlation_sources = all_sources

        # Deduplicate and merge CVEs
        existing_cves = set(enriched.metadata.get("correlated_cves", []))
        all_cves_set = existing_cves | set(all_cves)
        if all_cves_set:
            enriched.metadata["correlated_cves"] = sorted(all_cves_set)

        if all_matched_on:
            enriched.metadata["correlation_matched_on"] = all_matched_on

    def _apply_threat_intelligence(
        self,
        enriched: EnrichedFinding,
        threat_intel: ThreatIntelligence,
    ) -> None:
        """Apply threat intelligence to an enriched finding."""
        enriched.threat_intelligence = threat_intel

        # Update CVSS score from CVE data
        if threat_intel.cve and threat_intel.cve.cvss_score is not None:
            enriched.metadata["cvss_score"] = threat_intel.cve.cvss_score
            enriched.metadata["cvss_severity"] = threat_intel.cve.cvss_severity.value if hasattr(threat_intel.cve.cvss_severity, "value") else str(threat_intel.cve.cvss_severity)

    async def _build_asset_intelligence(
        self,
        finding: Finding,
        evidence_list: List[Evidence],
    ) -> AssetIntelligence:
        """Build asset intelligence from a finding and its evidence."""
        asset_key = finding.asset_value or str(finding.asset_id)

        # Check if we already have intelligence for this asset
        if asset_key in self._asset_intelligence:
            asset_intel = self._asset_intelligence[asset_key]
            # Update with new info
            if finding.cve_id and finding.cve_id not in asset_intel.cve_ids:
                asset_intel.cve_ids.append(finding.cve_id)
            if finding.id not in asset_intel.finding_ids:
                asset_intel.finding_ids.append(finding.id)
            asset_intel.finding_count = len(asset_intel.finding_ids)
            severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
            if severity in ("critical", "high"):
                if severity == "critical":
                    asset_intel.critical_finding_count += 1
                else:
                    asset_intel.high_finding_count += 1
            asset_intel.last_seen = datetime.now()
            return asset_intel

        # Build new asset intelligence
        technologies: Dict[str, str] = {}
        ip_addresses: List[str] = []
        hostnames: List[str] = []
        open_ports: List[int] = []
        services: List[str] = []
        os_name = None

        for evidence in evidence_list:
            raw_data = evidence.raw_data or {}

            # Extract IP
            if hasattr(evidence, "asset_value"):
                import re
                ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", evidence.asset_value)
                if ip_match and ip_match.group(1) not in ip_addresses:
                    ip_addresses.append(ip_match.group(1))

            # Extract technology
            product = raw_data.get("service_product", "")
            service = raw_data.get("service", "")
            version = raw_data.get("service_version", "")
            if product:
                technologies[product] = version or ""
            if service and service not in services:
                services.append(service)

            # Extract port
            port = raw_data.get("port")
            if port is not None and port not in open_ports:
                open_ports.append(int(port))

            # Extract OS
            os_val = raw_data.get("os", "")
            if os_val:
                os_name = os_val

        asset_intel = AssetIntelligence(
            asset_id=finding.asset_id or UUID(int=0),
            asset_value=asset_key,
            asset_type=finding.asset_type or "unknown",
            mission_id=finding.mission_id,
            technologies=technologies,
            operating_system=os_name,
            open_ports=open_ports,
            services=services,
            hostnames=hostnames,
            ip_addresses=ip_addresses,
            internet_exposed=finding.internet_exposed,
            finding_ids=[finding.id],
            finding_count=1,
            critical_finding_count=1 if finding.severity.value == "critical" else 0,
            high_finding_count=1 if finding.severity.value == "high" else 0,
            cve_ids=[finding.cve_id] if finding.cve_id else [],
            tags=finding.tags,
        )

        self._asset_intelligence[asset_key] = asset_intel
        return asset_intel

    def get_asset_intelligence(self, asset_key: str) -> Optional[AssetIntelligence]:
        """Get cached asset intelligence for an asset."""
        return self._asset_intelligence.get(asset_key)

    def get_all_asset_intelligence(self) -> Dict[str, AssetIntelligence]:
        """Get all cached asset intelligence."""
        return dict(self._asset_intelligence)


__all__ = ["SecurityIntelligenceService"]
