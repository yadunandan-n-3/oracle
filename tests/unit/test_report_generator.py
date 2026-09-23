"""
Unit Tests: Report Generator
==============================

Covers domain/report/generator.py — Report assembly (generate()) and
HTML rendering (render_html()).
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

import pytest

from domain.finding import FindingSeverity
from domain.report import ReportFormat
from domain.report.generator import ReportGenerator, _DEFAULT_REMEDIATION
from domain.risk import RiskLevel, RiskScore
from tests.conftest import make_asset, make_finding, make_mission


class TestReportGeneration:
    def test_generate_produces_html_format_report(self) -> None:
        mission = make_mission()
        generator = ReportGenerator()
        report = generator.generate(mission, [])
        assert report.format == ReportFormat.HTML
        assert report.mission_id == mission.id
        assert report.mission_name == mission.name

    def test_generate_counts_findings_by_severity(self) -> None:
        mission = make_mission()
        findings = [
            make_finding(severity=FindingSeverity.CRITICAL),
            make_finding(severity=FindingSeverity.CRITICAL),
            make_finding(severity=FindingSeverity.LOW),
        ]
        report = ReportGenerator().generate(mission, findings)
        assert report.total_findings == 3
        assert report.total_critical == 2
        assert report.total_low == 1
        assert report.total_high == 0

    def test_generate_with_no_findings_reports_zero_risk(self) -> None:
        mission = make_mission()
        report = ReportGenerator().generate(mission, [])
        assert report.total_findings == 0
        assert report.risk_score is None
        assert report.risk_level == RiskLevel.NONE.value
        assert "no findings" in report.executive_summary.lower()

    def test_overall_risk_uses_highest_score_not_average(self) -> None:
        """A single critical finding shouldn't be diluted by averaging
        against low-severity noise."""
        mission = make_mission()
        critical = make_finding(severity=FindingSeverity.CRITICAL)
        info = make_finding(severity=FindingSeverity.INFO)
        risk_scores = [
            RiskScore(score=9.5, level=RiskLevel.CRITICAL, finding_id=critical.id),
            RiskScore(score=0.5, level=RiskLevel.LOW, finding_id=info.id),
        ]
        report = ReportGenerator().generate(mission, [critical, info], risk_scores=risk_scores)
        assert report.risk_score == 9.5
        assert report.risk_level == RiskLevel.CRITICAL.value

    def test_executive_summary_flags_critical_urgency(self) -> None:
        mission = make_mission()
        findings = [make_finding(severity=FindingSeverity.CRITICAL)]
        risk_scores = [RiskScore(score=9.0, level=RiskLevel.CRITICAL, finding_id=findings[0].id)]
        report = ReportGenerator().generate(mission, findings, risk_scores=risk_scores)
        assert "CRITICAL" in report.executive_summary
        assert "immediate remediation" in report.executive_summary

    def test_recommendations_use_finding_remediation_steps_when_present(self) -> None:
        mission = make_mission()
        finding = make_finding(severity=FindingSeverity.HIGH)
        finding.remediation_steps = ["Patch to the latest version", "Restrict network access"]
        report = ReportGenerator().generate(mission, [finding])
        assert len(report.high_recommendations) == 2
        assert any("Patch to the latest version" in r for r in report.high_recommendations)

    def test_recommendations_fall_back_to_cwe_guidance(self) -> None:
        mission = make_mission()
        finding = make_finding(severity=FindingSeverity.CRITICAL)
        finding.cwe_id = "CWE-89"
        report = ReportGenerator().generate(mission, [finding])
        assert len(report.critical_recommendations) == 1
        assert "parameterized" in report.critical_recommendations[0].lower()

    def test_recommendations_consolidate_shared_guidance_across_findings(self) -> None:
        """Two findings that share the same underlying fix (same CWE) should
        be consolidated into one recommendation line naming both findings —
        not have the second one silently dropped as a 'duplicate'."""
        mission = make_mission()
        f1 = make_finding(title="SQLi on /login", severity=FindingSeverity.HIGH)
        f1.cwe_id = "CWE-89"
        f2 = make_finding(title="SQLi on /search", severity=FindingSeverity.HIGH)
        f2.cwe_id = "CWE-89"
        report = ReportGenerator().generate(mission, [f1, f2])
        assert len(report.high_recommendations) == 1
        assert "SQLi on /login" in report.high_recommendations[0]
        assert "SQLi on /search" in report.high_recommendations[0]


class TestReportHtmlRendering:
    def test_render_html_produces_valid_document(self) -> None:
        mission = make_mission()
        findings = [make_finding(severity=FindingSeverity.CRITICAL, cve_id="CVE-2021-41773")]
        generator = ReportGenerator()
        report = generator.generate(mission, findings)
        html = generator.render_html(report, findings)
        assert html.strip().startswith("<!DOCTYPE html>")
        assert "</html>" in html
        assert report.title in html

    def test_render_html_escapes_finding_content(self) -> None:
        """Finding text should be HTML-escaped, not injected raw."""
        mission = make_mission()
        finding = make_finding(title="<script>alert(1)</script>")
        generator = ReportGenerator()
        report = generator.generate(mission, [finding])
        html = generator.render_html(report, [finding])
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_render_html_includes_mitre_mapping_for_cve_finding(self) -> None:
        mission = make_mission()
        finding = make_finding(severity=FindingSeverity.CRITICAL, cve_id="CVE-2021-41773")
        generator = ReportGenerator()
        report = generator.generate(mission, [finding])
        html = generator.render_html(report, [finding])
        assert "T1190" in html

    def test_render_html_handles_empty_mission(self) -> None:
        mission = make_mission()
        generator = ReportGenerator()
        report = generator.generate(mission, [])
        html = generator.render_html(report, [])
        assert "No findings were identified" in html

    def test_render_html_includes_assets_section(self) -> None:
        mission = make_mission()
        asset = make_asset(value="10.0.0.5", open_ports=[22, 80])
        generator = ReportGenerator()
        report = generator.generate(mission, [], assets=[asset])
        html = generator.render_html(report, [], assets=[asset])
        assert "10.0.0.5" in html
        assert "22, 80" in html
