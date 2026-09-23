"""
Integration Tests: Nuclei Plugin
=================================

Tests NucleiPlugin parsing and normalization against realistic JSONL
fixtures, without requiring the real `nuclei` binary to be installed.
`execute()` (subprocess invocation) is intentionally not covered here —
`parse()`/`normalize()`/`build_targets_from_hosts()` are pure functions
and are what actually needs correctness coverage.
"""

from __future__ import annotations

import json

import pytest

from tools.common import HostInfo, PortInfo, VulnerabilityInfo
from tools.nuclei import NucleiPlugin


def _jsonl_line(**overrides) -> str:
    record = {
        "template-id": "generic-template",
        "info": {
            "name": "Generic Finding",
            "severity": "medium",
            "description": "A generic finding",
            "tags": ["misc"],
        },
        "host": "https://example.com",
        "matched-at": "https://example.com/",
    }
    record.update(overrides)
    return json.dumps(record)


class TestNucleiHealthCheck:
    @pytest.mark.asyncio
    async def test_health_check_missing_binary_reports_unhealthy(self) -> None:
        plugin = NucleiPlugin()
        plugin._binary = "definitely-not-a-real-binary-xyz"
        health = await plugin.health_check()
        assert health["healthy"] is False
        assert health["available"] is False
        assert "not found" in health["error"]


class TestNucleiParsing:
    @pytest.mark.asyncio
    async def test_parses_critical_cve_finding(self) -> None:
        plugin = NucleiPlugin()
        raw = _jsonl_line(
            **{
                "template-id": "CVE-2021-41773",
                "info": {
                    "name": "Apache Path Traversal",
                    "severity": "critical",
                    "tags": ["cve", "apache", "rce"],
                    "classification": {
                        "cve-id": ["CVE-2021-41773"],
                        "cwe-id": ["CWE-22"],
                        "cvss-score": 9.8,
                    },
                },
            }
        )
        findings = await plugin.parse(raw.encode())
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "critical"
        assert f.cve_ids == ["CVE-2021-41773"]
        assert f.cvss_score == 9.8
        assert f.confidence == 0.9

    @pytest.mark.asyncio
    async def test_parses_multiple_lines(self) -> None:
        plugin = NucleiPlugin()
        raw = "\n".join([_jsonl_line(), _jsonl_line(**{"template-id": "second-template"})])
        findings = await plugin.parse(raw.encode())
        assert len(findings) == 2

    @pytest.mark.asyncio
    async def test_skips_malformed_lines_without_failing(self) -> None:
        plugin = NucleiPlugin()
        raw = "\n".join([_jsonl_line(), "{not valid json", ""])
        findings = await plugin.parse(raw.encode())
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_empty_output_returns_empty_list(self) -> None:
        plugin = NucleiPlugin()
        findings = await plugin.parse(b"")
        assert findings == []

    @pytest.mark.asyncio
    async def test_unknown_severity_defaults_to_informational(self) -> None:
        plugin = NucleiPlugin()
        raw = _jsonl_line(**{"info": {"name": "Weird", "severity": "banana"}})
        findings = await plugin.parse(raw.encode())
        assert findings[0].severity == "informational"

    @pytest.mark.asyncio
    async def test_record_without_template_id_is_skipped(self) -> None:
        plugin = NucleiPlugin()
        raw = json.dumps({"info": {"name": "no template id"}, "host": "https://x"})
        findings = await plugin.parse(raw.encode())
        assert findings == []


class TestNucleiNormalization:
    @pytest.mark.asyncio
    async def test_normalize_produces_evidence_with_correct_fields(self) -> None:
        plugin = NucleiPlugin()
        raw = _jsonl_line(
            **{
                "template-id": "CVE-2021-41773",
                "info": {
                    "name": "Apache Path Traversal",
                    "severity": "critical",
                    "tags": ["cve", "rce"],
                    "classification": {"cve-id": ["CVE-2021-41773"]},
                },
            }
        )
        findings = await plugin.parse(raw.encode())
        evidence = await plugin.normalize(findings)

        assert len(evidence) == 1
        e = evidence[0]
        assert e.source == "nuclei"
        assert e.evidence_type == "vulnerability"
        assert e.severity == "critical"
        assert e.cve_ids == ["CVE-2021-41773"]
        assert "T1190" in e.mitre_techniques
        assert "CVE-2021-41773" in e.tags

    @pytest.mark.asyncio
    async def test_normalize_accepts_dict_input(self) -> None:
        plugin = NucleiPlugin()
        vuln_dict = VulnerabilityInfo(template_id="t1", name="Test", severity="low").to_dict()
        evidence = await plugin.normalize([vuln_dict])
        assert len(evidence) == 1
        assert evidence[0].title == "Test"

    @pytest.mark.asyncio
    async def test_normalize_ignores_unrecognized_input_types(self) -> None:
        plugin = NucleiPlugin()
        evidence = await plugin.normalize(["not a valid entry", 42])
        assert evidence == []


class TestNucleiTargetBuilding:
    def test_builds_http_and_https_targets_from_hosts(self) -> None:
        plugin = NucleiPlugin()
        host = HostInfo(
            ip="10.0.0.5",
            ports=[
                PortInfo(port=80, service="http", state="open"),
                PortInfo(port=443, service="https", state="open"),
                PortInfo(port=8443, service="https-alt", state="open"),
                PortInfo(port=22, service="ssh", state="open"),
            ],
        )
        targets = plugin.build_targets_from_hosts([host])
        assert "http://10.0.0.5" in targets
        assert "https://10.0.0.5" in targets
        assert "https://10.0.0.5:8443" in targets
        assert not any("22" in t for t in targets)

    def test_no_http_ports_yields_no_targets(self) -> None:
        plugin = NucleiPlugin()
        host = HostInfo(ip="10.0.0.9", ports=[PortInfo(port=22, service="ssh", state="open")])
        assert plugin.build_targets_from_hosts([host]) == []
