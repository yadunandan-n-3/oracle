"""
Unit Tests: MITRE ATT&CK Mapping Engine
=========================================

Verifies knowledge/mitre/__init__.py's signal-based, traceable mapping
from CVE/CWE/tags/evidence_type to ATT&CK techniques.
"""

from __future__ import annotations

from knowledge.mitre import ATTACK_TECHNIQUES, MitreMapper


class FakeFinding:
    def __init__(self, cve_id=None, cwe_id=None, tags=None):
        self.cve_id = cve_id
        self.cwe_id = cwe_id
        self.tags = tags or []
        self.metadata = {}
        self.mitre_technique_id = None
        self.mitre_tactic = None


class TestMitreMapperSignals:
    def test_cve_maps_to_exploit_public_facing_application(self) -> None:
        mapper = MitreMapper()
        mappings = mapper.map(cve_ids=["CVE-2021-41773"])
        assert mappings
        assert mappings[0].technique_id == "T1190"
        assert "CVE: CVE-2021-41773" in mappings[0].matched_on

    def test_cwe_maps_to_expected_technique(self) -> None:
        mapper = MitreMapper()
        mappings = mapper.map(cwe_ids=["CWE-798"])
        assert mappings
        assert mappings[0].technique_id == "T1552"

    def test_unknown_cwe_produces_no_mapping(self) -> None:
        mapper = MitreMapper()
        mappings = mapper.map(cwe_ids=["CWE-99999-not-real"])
        assert mappings == []

    def test_evidence_type_maps_to_discovery_technique(self) -> None:
        mapper = MitreMapper()
        mappings = mapper.map(evidence_type="open_port")
        assert mappings
        assert mappings[0].technique_id == "T1046"
        assert mappings[0].tactic == "Discovery"

    def test_no_signals_produces_no_mappings(self) -> None:
        mapper = MitreMapper()
        assert mapper.map() == []

    def test_multiple_independent_signals_boost_confidence(self) -> None:
        mapper = MitreMapper()
        cve_only = mapper.map(cve_ids=["CVE-2021-41773"])
        combined = mapper.map(cve_ids=["CVE-2021-41773"], cwe_ids=["CWE-22"], tags=["rce"])
        assert combined[0].technique_id == cve_only[0].technique_id == "T1190"
        assert combined[0].confidence > cve_only[0].confidence
        assert len(combined[0].matched_on) > len(cve_only[0].matched_on)

    def test_confidence_never_exceeds_cap(self) -> None:
        mapper = MitreMapper()
        mappings = mapper.map(
            cve_ids=["CVE-1", "CVE-2"],
            cwe_ids=["CWE-22"],
            tags=["rce", "cve", "sqli"],
            evidence_type="vulnerability",
        )
        assert all(m.confidence <= MitreMapper.MAX_CONFIDENCE for m in mappings)

    def test_mappings_sorted_by_descending_confidence(self) -> None:
        mapper = MitreMapper()
        mappings = mapper.map(cve_ids=["CVE-2021-41773"], cwe_ids=["CWE-22"])
        confidences = [m.confidence for m in mappings]
        assert confidences == sorted(confidences, reverse=True)

    def test_every_mapping_has_at_least_one_matched_on_reason(self) -> None:
        mapper = MitreMapper()
        mappings = mapper.map(cve_ids=["CVE-1"], cwe_ids=["CWE-22"], tags=["rce"])
        for m in mappings:
            assert len(m.matched_on) >= 1


class TestMitreMapperFindingIntegration:
    def test_map_finding_uses_finding_attributes(self) -> None:
        mapper = MitreMapper()
        finding = FakeFinding(cve_id="CVE-2021-41773", cwe_id="CWE-22", tags=["rce"])
        mappings = mapper.map_finding(finding)
        assert mappings
        assert mappings[0].technique_id == "T1190"

    def test_apply_to_finding_sets_top_mapping(self) -> None:
        mapper = MitreMapper()
        finding = FakeFinding(cve_id="CVE-2021-41773")
        result = mapper.apply_to_finding(finding)
        assert result.mitre_technique_id == "T1190"
        assert result.mitre_tactic == "Initial Access"
        assert "mitre_mappings" in result.metadata
        assert len(result.metadata["mitre_mappings"]) >= 1

    def test_apply_to_finding_with_no_signals_leaves_finding_unchanged(self) -> None:
        mapper = MitreMapper()
        finding = FakeFinding()
        result = mapper.apply_to_finding(finding)
        assert result.mitre_technique_id is None
        assert "mitre_mappings" not in result.metadata


class TestAttackTechniqueDatabase:
    def test_all_techniques_have_required_fields(self) -> None:
        for technique in ATTACK_TECHNIQUES.values():
            assert technique.technique_id.startswith("T")
            assert technique.name
            assert technique.tactic
            assert technique.tactic_id.startswith("TA")
            assert technique.url.startswith("https://attack.mitre.org/")

    def test_technique_ids_are_unique_keys(self) -> None:
        for key, technique in ATTACK_TECHNIQUES.items():
            assert key == technique.technique_id
