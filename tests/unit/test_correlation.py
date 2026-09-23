"""
Unit Tests: Evidence Correlation Engine
========================================

Verifies the evidence correlation logic in domain/correlation/.
"""

from __future__ import annotations

import pytest

from domain.correlation import CorrelationRule, CorrelationResult, EvidenceCorrelator
from domain.correlation.rules import (
    ApacheCorrelationRule,
    SSHCveCorrelationRule,
    HttpServiceCorrelationRule,
    GenericTechCveCorrelationRule,
    PortServiceCorrelationRule,
)
from domain.evidence import Evidence, EvidenceType, EvidenceSource


def _make_evidence(**overrides) -> Evidence:
    defaults = dict(
        evidence_type=EvidenceType.OPEN_PORT,
        title="Test Evidence",
        asset_value="10.0.0.1:80/tcp",
        source=EvidenceSource(tool_name="nmap"),
        raw_data={"port": 80, "service": "http", "product": "Apache httpd", "version": "2.4.49"},
        tags=["host", "discovered"],
    )
    defaults.update(overrides)
    return Evidence(**defaults)


class TestCorrelationResult:
    def test_creates_with_defaults(self) -> None:
        result = CorrelationResult(
            correlation_type="ip_match",
            rule_name="test_rule",
            confidence=0.85,
        )
        assert result.id is not None
        assert result.confidence == 0.85
        assert result.protocol == "tcp"
        assert len(result.evidence_ids) == 0

    def test_with_cve_ids(self) -> None:
        result = CorrelationResult(
            correlation_type="cve_match",
            rule_name="test_rule",
            confidence=0.9,
            cve_ids=["CVE-2021-41773"],
            asset_value="10.0.0.1",
        )
        assert "CVE-2021-41773" in str(result.cve_ids)
        assert result.asset_value == "10.0.0.1"


class TestCorrelationRuleABC:
    def test_rule_requires_evaluate_implementation(self) -> None:
        class IncompleteRule(CorrelationRule):
            name = "incomplete"
            description = "Incomplete rule"
            priority = 100

        with pytest.raises(TypeError):
            IncompleteRule()


class TestEvidenceCorrelator:
    @pytest.mark.asyncio
    async def test_empty_evidence_returns_empty(self) -> None:
        correlator = EvidenceCorrelator()
        results = await correlator.correlate([])
        assert results == []

    @pytest.mark.asyncio
    async def test_single_evidence_returns_no_correlation(self) -> None:
        correlator = EvidenceCorrelator()
        evidence = _make_evidence()
        results = await correlator.correlate([evidence])
        assert results == []

    @pytest.mark.asyncio
    async def test_correlates_with_rule(self) -> None:
        class SimpleRule(CorrelationRule):
            name = "simple"
            description = "Simple test rule"
            priority = 50

            async def evaluate(self, evidence_list, **kwargs):
                if len(evidence_list) >= 2:
                    return [CorrelationResult(
                        correlation_type="composite",
                        rule_name=self.name,
                        confidence=0.8,
                        evidence_ids=[e.id for e in evidence_list[:2]],
                        asset_value=evidence_list[0].asset_value,
                    )]
                return []

        correlator = EvidenceCorrelator()
        correlator.register_rule(SimpleRule())
        ev1 = _make_evidence(asset_value="10.0.0.1:80/tcp")
        ev2 = _make_evidence(
            evidence_type=EvidenceType.VULNERABILITY,
            asset_value="https://10.0.0.1:80",
            source=EvidenceSource(tool_name="nuclei"),
            cve_ids=["CVE-2021-41773"],
        )
        results = await correlator.correlate([ev1, ev2])
        assert len(results) >= 1
        for result in results:
            assert len(result.evidence_ids) >= 1

    @pytest.mark.asyncio
    async def test_multiple_rules_aggregate(self) -> None:
        class RuleA(CorrelationRule):
            name = "rule_a"
            description = "Rule A"
            priority = 10
            async def evaluate(self, evidence_list, **kwargs):
                return [CorrelationResult(
                    correlation_type="ip_match", rule_name=self.name,
                    confidence=0.7, asset_value="10.0.0.1",
                )]

        class RuleB(CorrelationRule):
            name = "rule_b"
            description = "Rule B"
            priority = 20
            async def evaluate(self, evidence_list, **kwargs):
                return [CorrelationResult(
                    correlation_type="cve_match", rule_name=self.name,
                    confidence=0.9, asset_value="10.0.0.1",
                    cve_ids=["CVE-2021-41773"],
                )]

        correlator = EvidenceCorrelator()
        correlator.register_rule(RuleA())
        correlator.register_rule(RuleB())
        ev = _make_evidence()
        results = await correlator.correlate([ev])
        assert len(results) >= 1


class TestPortServiceCorrelationRule:
    @pytest.mark.asyncio
    async def test_matches_port(self) -> None:
        rule = PortServiceCorrelationRule()
        port_evidence = _make_evidence(
            evidence_type=EvidenceType.OPEN_PORT,
            asset_value="10.0.0.1:3306/tcp",
            raw_data={"port": 3306, "service": "mysql"},
        )
        results = await rule.evaluate([port_evidence])
        assert len(results) >= 1
        assert results[0].port == 3306

    @pytest.mark.asyncio
    async def test_matches_port_with_service(self) -> None:
        rule = PortServiceCorrelationRule()
        port_evidence = _make_evidence(
            evidence_type=EvidenceType.OPEN_PORT,
            asset_value="10.0.0.1:443/tcp",
            raw_data={"port": 443, "service": "https"},
        )
        service_evidence = _make_evidence(
            evidence_type=EvidenceType.SERVICE,
            asset_value="10.0.0.1:443/tcp",
            raw_data={"service": "https", "service_product": "Apache", "service_version": "2.4.49"},
        )
        results = await rule.evaluate([port_evidence, service_evidence])
        assert len(results) >= 1


class TestGenericTechCveCorrelationRule:
    @pytest.mark.asyncio
    async def test_matches_tech_with_cve(self) -> None:
        rule = GenericTechCveCorrelationRule()
        tech_evidence = _make_evidence(
            evidence_type=EvidenceType.SERVICE,
            asset_value="10.0.0.1",
            raw_data={"service_product": "Apache", "service_version": "2.4.49"},
        )
        vuln_evidence = _make_evidence(
            evidence_type=EvidenceType.VULNERABILITY,
            asset_value="10.0.0.1",
            source=EvidenceSource(tool_name="nuclei"),
            cve_ids=["CVE-2021-41773"],
        )
        results = await rule.evaluate([tech_evidence, vuln_evidence])
        assert len(results) >= 1


class TestApacheCorrelationRule:
    @pytest.mark.asyncio
    async def test_matches_apache_with_cve(self) -> None:
        rule = ApacheCorrelationRule()
        port_evidence = _make_evidence(
            evidence_type=EvidenceType.OPEN_PORT,
            raw_data={"port": 80, "service": "http", "product": "Apache httpd", "version": "2.4.49"},
        )
        cve_evidence = _make_evidence(
            evidence_type=EvidenceType.VULNERABILITY,
            asset_value="https://10.0.0.1:80",
            source=EvidenceSource(tool_name="nuclei"),
            raw_data={"template_id": "apache-traversal", "name": "Apache Path Traversal"},
            cve_ids=["CVE-2021-41773"],
        )
        results = await rule.evaluate([port_evidence, cve_evidence])
        assert len(results) >= 1
        result = results[0]
        assert result.confidence > 0.8


class TestHttpServiceCorrelationRule:
    @pytest.mark.asyncio
    async def test_matches_http(self) -> None:
        rule = HttpServiceCorrelationRule()
        http_evidence = _make_evidence(
            evidence_type=EvidenceType.SERVICE,
            asset_value="10.0.0.1:80",
            raw_data={"port": 80, "service": "http", "product": "Apache httpd", "version": "2.4.49"},
        )
        results = await rule.evaluate([http_evidence])
        assert len(results) >= 1


class TestSSHCveCorrelationRule:
    @pytest.mark.asyncio
    async def test_matches_ssh(self) -> None:
        rule = SSHCveCorrelationRule()
        ssh_evidence = _make_evidence(
            evidence_type=EvidenceType.OPEN_PORT,
            asset_value="10.0.0.1:22/tcp",
            raw_data={"port": 22, "service": "ssh", "product": "OpenSSH", "version": "7.5"},
        )
        results = await rule.evaluate([ssh_evidence])
        assert len(results) >= 1
