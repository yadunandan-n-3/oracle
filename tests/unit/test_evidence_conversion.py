"""
Unit Tests: Agent Evidence -> Domain Evidence Conversion
=========================================================

Covers domain.evidence.from_agent_evidence(), which bridges the
lightweight core.interfaces.Evidence (yielded by agents/tool plugins)
into the full domain.evidence.Evidence expected by the Validator and
the rest of the runtime pipeline.

This gap previously went untested: existing integration tests build
domain.evidence.Evidence objects by hand and call validate_evidence()
directly, never exercising the real agent -> runtime.process_evidence()
path where the mismatch actually occurs.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from core.interfaces import Evidence as AgentEvidence
from domain.evidence import Evidence as DomainEvidence
from domain.evidence import EvidenceType, from_agent_evidence


class TestFromAgentEvidence:
    def test_converts_known_evidence_type(self) -> None:
        agent_ev = AgentEvidence(
            source="nmap",
            evidence_type="open_port",
            asset_value="10.0.0.1:80/tcp",
            data={"port": 80, "service": "http"},
            confidence=0.95,
            severity="informational",
            tags=["open_port"],
        )
        domain_ev = from_agent_evidence(agent_ev)

        assert isinstance(domain_ev, DomainEvidence)
        assert domain_ev.evidence_type == EvidenceType.OPEN_PORT
        assert domain_ev.asset_value == "10.0.0.1:80/tcp"
        assert domain_ev.confidence == 0.95
        assert domain_ev.source.tool_name == "nmap"
        assert domain_ev.raw_data == {"port": 80, "service": "http"}

    def test_unmapped_evidence_type_falls_back_to_raw_output(self) -> None:
        # NmapPlugin/DiscoveryAgent use ad-hoc strings like "port", "host",
        # "os" that aren't in EvidenceType — these must not raise.
        agent_ev = AgentEvidence(
            source="nmap",
            evidence_type="port",
            asset_value="10.0.0.1:80/tcp",
        )
        domain_ev = from_agent_evidence(agent_ev)
        assert domain_ev.evidence_type == EvidenceType.RAW_OUTPUT
        assert domain_ev.metadata["source_evidence_type"] == "port"

    def test_attaches_mission_id(self) -> None:
        mission_id = uuid4()
        agent_ev = AgentEvidence(source="nuclei", evidence_type="vulnerability", asset_value="https://x")
        domain_ev = from_agent_evidence(agent_ev, mission_id=mission_id)
        assert domain_ev.mission_id == mission_id

    def test_passes_through_cve_and_mitre(self) -> None:
        agent_ev = AgentEvidence(
            source="nuclei",
            evidence_type="vulnerability",
            asset_value="https://example.com",
            cve_ids=["CVE-2021-41773"],
            mitre_techniques=["T1190"],
        )
        domain_ev = from_agent_evidence(agent_ev)
        assert domain_ev.cve_ids == ["CVE-2021-41773"]
        assert domain_ev.mitre_techniques == ["T1190"]

    def test_domain_evidence_passes_through_unchanged(self) -> None:
        # If something already produces a domain.evidence.Evidence,
        # from_agent_evidence should be a no-op, not double-wrap it.
        already_domain = DomainEvidence(
            evidence_type=EvidenceType.VULNERABILITY,
            title="Already domain",
            asset_value="https://example.com",
        )
        result = from_agent_evidence(already_domain)
        assert result is already_domain

    def test_rejects_unrelated_types(self) -> None:
        with pytest.raises(TypeError):
            from_agent_evidence({"not": "an evidence object"})
