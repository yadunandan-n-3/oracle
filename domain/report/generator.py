"""
Report Generator
=================

Assembles ORACLE's domain models (Mission, Finding, RiskScore, MITRE
mappings) into a populated `Report` and renders it as a professional,
self-contained HTML document.

Pipeline (v0.2 Sprint 4):
    Findings + Risk Scores + MITRE Mappings
    ↓
    ReportGenerator.generate()  -> Report (structured data)
    ↓
    ReportGenerator.render_html()  -> str (HTML, no external dependencies)

Design choices:
- The HTML template is self-contained (inline CSS, no CDN fetches), since
  ORACLE is designed to be able to run in air-gapped environments.
- Executive summary / recommendation text is template-generated from the
  actual finding data (counts, top risks, affected assets) — not an LLM
  call — so the report is deterministic and requires no external API.
  The AI Explanation Engine (a separate, future piece) can enrich this
  later without changing the report's structure.
"""

from __future__ import annotations

from collections import Counter, OrderedDict, defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence

from jinja2 import Environment, select_autoescape

from domain.asset import Asset
from domain.finding import Finding, FindingSeverity
from domain.mission import Mission
from domain.report import Report, ReportFormat, ReportSection, ReportType
from domain.risk import RiskLevel, RiskScore
from knowledge.mitre import MitreMapper

# Generic remediation guidance used when a finding doesn't carry its own
# remediation_steps. Keyed on the same CWE/tag vocabulary the MITRE mapper
# and Nuclei plugin already use, so it stays consistent across the pipeline.
_DEFAULT_REMEDIATION: Dict[str, str] = {
    "CWE-22": "Validate and canonicalize all file paths server-side; deny traversal sequences.",
    "CWE-78": "Avoid invoking shell commands with user input; use parameterized APIs instead.",
    "CWE-89": "Use parameterized queries/prepared statements; never concatenate user input into SQL.",
    "CWE-79": "Encode output contextually and apply a strict Content-Security-Policy.",
    "CWE-287": "Enforce strong authentication (MFA where possible) on all access paths.",
    "CWE-798": "Remove hardcoded credentials; rotate any that were exposed; use a secrets manager.",
    "CWE-521": "Enforce a strong password policy and rate-limit authentication attempts.",
    "CWE-311": "Encrypt sensitive data in transit and at rest using current TLS/cipher standards.",
    "CWE-918": "Restrict outbound requests from the server to an explicit allow-list of destinations.",
}
_FALLBACK_REMEDIATION = "Review the affected component, apply the vendor's latest security patch, and re-test."

_SEVERITY_ORDER = [
    FindingSeverity.CRITICAL,
    FindingSeverity.HIGH,
    FindingSeverity.MEDIUM,
    FindingSeverity.LOW,
    FindingSeverity.INFO,
]


class ReportGenerator:
    """
    Builds a Report from mission results and renders it to HTML.

    Usage:
        generator = ReportGenerator()
        report = generator.generate(mission, findings, assets, risk_scores)
        html = generator.render_html(report, findings, risk_scores)
    """

    def __init__(self, mitre_mapper: Optional[MitreMapper] = None) -> None:
        self.mitre_mapper = mitre_mapper or MitreMapper()
        self._env = Environment(autoescape=select_autoescape(["html"]))

    # ─── Report Assembly ────────────────────────────────────────────────

    def generate(
        self,
        mission: Mission,
        findings: Sequence[Finding],
        assets: Optional[Sequence[Asset]] = None,
        risk_scores: Optional[Sequence[RiskScore]] = None,
        report_type: ReportType = ReportType.TECHNICAL_DETAIL,
    ) -> Report:
        """
        Assemble a populated Report from mission results.

        Args:
            mission: The mission these findings belong to
            findings: Validated findings to report on
            assets: Discovered assets (for the asset inventory section)
            risk_scores: Risk scores, one per finding where available.
                Findings without a matching score are still reported, just
                without a numeric risk value.
            report_type: The report type/audience this is generated for

        Returns:
            A fully populated Report ready for render_html() or JSON export.
        """
        assets = list(assets or [])
        risk_scores = list(risk_scores or [])
        risk_by_finding = {rs.finding_id: rs for rs in risk_scores if rs.finding_id}

        severity_counts = Counter(f.severity for f in findings)
        cvss_values = [f.cvss_score for f in findings if f.cvss_score is not None]

        overall_score, overall_level = self._overall_risk(findings, risk_by_finding)

        recommendations = self._build_recommendations(findings)

        report = Report(
            title=f"ORACLE Security Assessment Report — {mission.name}",
            report_type=report_type,
            format=ReportFormat.HTML,
            mission_id=mission.id,
            mission_name=mission.name,
            project_id=mission.project_id,
            executive_summary=self._build_executive_summary(mission, findings, severity_counts, overall_level),
            findings_summary={sev.value: severity_counts.get(sev, 0) for sev in _SEVERITY_ORDER},
            risk_score=overall_score,
            risk_level=overall_level.value,
            critical_recommendations=recommendations[FindingSeverity.CRITICAL],
            high_recommendations=recommendations[FindingSeverity.HIGH],
            medium_recommendations=recommendations[FindingSeverity.MEDIUM],
            low_recommendations=recommendations[FindingSeverity.LOW],
            total_assets=len(assets),
            total_findings=len(findings),
            total_critical=severity_counts.get(FindingSeverity.CRITICAL, 0),
            total_high=severity_counts.get(FindingSeverity.HIGH, 0),
            total_medium=severity_counts.get(FindingSeverity.MEDIUM, 0),
            total_low=severity_counts.get(FindingSeverity.LOW, 0),
            total_info=severity_counts.get(FindingSeverity.INFO, 0),
            average_cvss=round(sum(cvss_values) / len(cvss_values), 2) if cvss_values else None,
            generated_by="oracle_report_generator",
            generated_at=datetime.now(),
            mission_duration_seconds=self._mission_duration_seconds(mission),
        )

        return report

    def _overall_risk(
        self,
        findings: Sequence[Finding],
        risk_by_finding: Dict[Any, RiskScore],
    ) -> tuple[Optional[float], RiskLevel]:
        """Overall score is the highest individual finding risk score present
        (a single unpatched critical shouldn't be diluted by averaging it
        against a pile of informational findings)."""
        scores = [risk_by_finding[f.id].score for f in findings if f.id in risk_by_finding]
        if not scores:
            return None, RiskLevel.NONE

        top_score = max(scores)
        if top_score >= 9.0:
            level = RiskLevel.CRITICAL
        elif top_score >= 7.0:
            level = RiskLevel.HIGH
        elif top_score >= 4.0:
            level = RiskLevel.MEDIUM
        elif top_score > 0.0:
            level = RiskLevel.LOW
        else:
            level = RiskLevel.NONE

        return round(top_score, 2), level

    def _build_executive_summary(
        self,
        mission: Mission,
        findings: Sequence[Finding],
        severity_counts: Counter,
        overall_level: RiskLevel,
    ) -> str:
        total = len(findings)
        critical = severity_counts.get(FindingSeverity.CRITICAL, 0)
        high = severity_counts.get(FindingSeverity.HIGH, 0)

        if total == 0:
            return (
                f"ORACLE assessed {mission.name} and identified no findings requiring "
                f"attention at this time. Continued periodic assessment is recommended."
            )

        headline = (
            f"ORACLE assessed {mission.name} and identified {total} finding"
            f"{'s' if total != 1 else ''}, with an overall risk level of "
            f"{overall_level.value.upper()}."
        )

        urgency = ""
        if critical:
            urgency = (
                f" {critical} finding{'s' if critical != 1 else ''} rated CRITICAL "
                f"require immediate remediation, as they represent an active, high-confidence "
                f"path to compromise."
            )
        elif high:
            urgency = (
                f" {high} finding{'s' if high != 1 else ''} rated HIGH should be prioritized "
                f"in the next remediation cycle."
            )

        return headline + urgency

    def _build_recommendations(
        self,
        findings: Sequence[Finding],
    ) -> Dict[FindingSeverity, List[str]]:
        # (severity, guidance_text) -> list of finding titles that guidance applies to.
        # Consolidating this way means two findings that happen to share the
        # same underlying fix (e.g. two SQLi endpoints, same CWE) both show
        # up under one recommendation line instead of the second being
        # silently dropped as a "duplicate".
        grouped: Dict[FindingSeverity, "OrderedDict[str, List[str]]"] = defaultdict(OrderedDict)

        for finding in findings:
            if finding.remediation_steps:
                for step in finding.remediation_steps:
                    grouped[finding.severity].setdefault(step, []).append(finding.title)
                continue

            guidance = _DEFAULT_REMEDIATION.get(finding.cwe_id or "", _FALLBACK_REMEDIATION)
            grouped[finding.severity].setdefault(guidance, []).append(finding.title)

        result: Dict[FindingSeverity, List[str]] = {}
        for severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH, FindingSeverity.MEDIUM, FindingSeverity.LOW):
            lines = []
            for guidance, titles in grouped.get(severity, {}).items():
                affected = ", ".join(titles)
                lines.append(f"{affected}: {guidance}")
            result[severity] = lines

        return result

    @staticmethod
    def _mission_duration_seconds(mission: Mission) -> Optional[int]:
        if mission.started_at and mission.completed_at:
            return int((mission.completed_at - mission.started_at).total_seconds())
        return None

    # ─── HTML Rendering ─────────────────────────────────────────────────

    def render_html(
        self,
        report: Report,
        findings: Sequence[Finding],
        assets: Optional[Sequence[Asset]] = None,
        risk_scores: Optional[Sequence[RiskScore]] = None,
    ) -> str:
        """
        Render a Report (plus its underlying findings/assets/risk scores)
        as a self-contained HTML document.
        """
        assets = list(assets or [])
        risk_scores = list(risk_scores or [])
        risk_by_finding = {rs.finding_id: rs for rs in risk_scores if rs.finding_id}

        # Ensure every finding has a MITRE mapping to show, computing one
        # on the fly if it wasn't already applied upstream.
        mitre_by_finding: Dict[Any, list] = {}
        for finding in findings:
            if finding.mitre_technique_id:
                mappings = finding.metadata.get("mitre_mappings") or [{
                    "technique_id": finding.mitre_technique_id,
                    "technique_name": "",
                    "tactic": finding.mitre_tactic or "",
                    "confidence": None,
                    "matched_on": [],
                }]
            else:
                mappings = [m.to_dict() for m in self.mitre_mapper.map_finding(finding)]
            mitre_by_finding[finding.id] = mappings

        sorted_findings = sorted(
            findings,
            key=lambda f: (
                _SEVERITY_ORDER.index(f.severity) if f.severity in _SEVERITY_ORDER else len(_SEVERITY_ORDER),
                -(risk_by_finding[f.id].score if f.id in risk_by_finding else 0.0),
            ),
        )

        # All technique mappings across the mission, for the ATT&CK coverage table.
        technique_counts: Counter = Counter()
        for mappings in mitre_by_finding.values():
            for m in mappings:
                if m.get("technique_id"):
                    technique_counts[(m["technique_id"], m.get("technique_name", ""), m.get("tactic", ""))] += 1

        template = self._env.from_string(_HTML_TEMPLATE)
        return template.render(
            report=report,
            findings=sorted_findings,
            assets=assets,
            risk_by_finding=risk_by_finding,
            mitre_by_finding=mitre_by_finding,
            technique_counts=sorted(technique_counts.items(), key=lambda kv: -kv[1]),
            severity_order=_SEVERITY_ORDER,
            generated_at=report.generated_at.strftime("%Y-%m-%d %H:%M UTC"),
        )


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{ report.title }}</title>
<style>
  :root {
    --critical: #b91c1c; --high: #c2410c; --medium: #a16207;
    --low: #1d4ed8; --info: #6b7280; --bg: #0f172a; --panel: #ffffff;
  }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
         margin: 0; background: #f1f5f9; color: #1e293b; line-height: 1.5; }
  header.hero { background: var(--bg); color: #f8fafc; padding: 40px 48px; }
  header.hero h1 { margin: 0 0 8px 0; font-size: 26px; }
  header.hero p { margin: 0; color: #94a3b8; font-size: 14px; }
  main { max-width: 1000px; margin: 0 auto; padding: 32px 24px 64px; }
  section.panel { background: var(--panel); border-radius: 10px; padding: 28px 32px;
                  margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
  h2 { font-size: 19px; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; margin-top: 0; }
  .metrics { display: flex; gap: 16px; flex-wrap: wrap; margin: 16px 0; }
  .metric { flex: 1; min-width: 110px; background: #f8fafc; border-radius: 8px;
            padding: 14px 16px; text-align: center; border: 1px solid #e2e8f0; }
  .metric .n { font-size: 26px; font-weight: 700; display: block; }
  .metric .l { font-size: 11px; text-transform: uppercase; color: #64748b; letter-spacing: .04em; }
  .sev-critical .n { color: var(--critical); } .sev-high .n { color: var(--high); }
  .sev-medium .n { color: var(--medium); } .sev-low .n { color: var(--low); }
  .sev-info .n { color: var(--info); }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
  th { color: #64748b; font-size: 11px; text-transform: uppercase; letter-spacing: .03em; }
  .badge { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 11px;
           font-weight: 600; color: white; text-transform: uppercase; }
  .badge.critical { background: var(--critical); } .badge.high { background: var(--high); }
  .badge.medium { background: var(--medium); } .badge.low { background: var(--low); }
  .badge.informational { background: var(--info); }
  .finding { border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px 18px; margin-bottom: 14px; }
  .finding h3 { margin: 0 0 6px 0; font-size: 15px; }
  .finding .meta { font-size: 12px; color: #64748b; margin-bottom: 10px; }
  .finding .meta span { margin-right: 14px; }
  .mitre-tag { display: inline-block; background: #eef2ff; color: #4338ca; border-radius: 6px;
               padding: 2px 8px; font-size: 11px; margin: 2px 4px 0 0; }
  .rec-list { padding-left: 20px; margin: 6px 0; }
  .rec-list li { margin-bottom: 6px; font-size: 14px; }
  .empty { color: #94a3b8; font-style: italic; }
  footer { text-align: center; color: #94a3b8; font-size: 12px; padding: 20px; }
</style>
</head>
<body>
<header class="hero">
  <h1>{{ report.title }}</h1>
  <p>Generated {{ generated_at }} &middot; Report type: {{ report.report_type.value if report.report_type.value else report.report_type }}</p>
</header>
<main>

  <section class="panel">
    <h2>Executive Summary</h2>
    <p>{{ report.executive_summary }}</p>
    <div class="metrics">
      <div class="metric"><span class="n">{{ report.total_assets }}</span><span class="l">Assets</span></div>
      <div class="metric"><span class="n">{{ report.total_findings }}</span><span class="l">Findings</span></div>
      <div class="metric sev-critical"><span class="n">{{ report.total_critical }}</span><span class="l">Critical</span></div>
      <div class="metric sev-high"><span class="n">{{ report.total_high }}</span><span class="l">High</span></div>
      <div class="metric sev-medium"><span class="n">{{ report.total_medium }}</span><span class="l">Medium</span></div>
      <div class="metric sev-low"><span class="n">{{ report.total_low }}</span><span class="l">Low</span></div>
    </div>
    {% if report.risk_score is not none %}
    <p><strong>Overall Risk Score:</strong> {{ report.risk_score }} / 10.0
       (<span class="badge {{ report.risk_level }}">{{ report.risk_level }}</span>)</p>
    {% endif %}
  </section>

  <section class="panel">
    <h2>Mission Summary</h2>
    <table>
      <tr><th>Mission</th><td>{{ report.mission_name }}</td></tr>
      <tr><th>Mission ID</th><td>{{ report.mission_id }}</td></tr>
      {% if report.mission_duration_seconds %}
      <tr><th>Duration</th><td>{{ (report.mission_duration_seconds / 60) | round(1) }} minutes</td></tr>
      {% endif %}
      {% if report.average_cvss %}
      <tr><th>Average CVSS</th><td>{{ report.average_cvss }}</td></tr>
      {% endif %}
    </table>
  </section>

  <section class="panel">
    <h2>Assets ({{ assets|length }})</h2>
    {% if assets %}
    <table>
      <tr><th>Value</th><th>Type</th><th>Open Ports</th><th>Criticality</th></tr>
      {% for asset in assets %}
      <tr>
        <td>{{ asset.value }}</td>
        <td>{{ asset.asset_type.value if asset.asset_type.value else asset.asset_type }}</td>
        <td>{{ asset.open_ports|join(', ') if asset.open_ports else '—' }}</td>
        <td>{{ asset.criticality.value if asset.criticality.value else asset.criticality }}</td>
      </tr>
      {% endfor %}
    </table>
    {% else %}
    <p class="empty">No assets recorded for this mission.</p>
    {% endif %}
  </section>

  <section class="panel">
    <h2>Findings ({{ findings|length }})</h2>
    {% if findings %}
      {% for finding in findings %}
      <div class="finding">
        <h3><span class="badge {{ finding.severity.value if finding.severity.value else finding.severity }}">{{ finding.severity.value if finding.severity.value else finding.severity }}</span>
            &nbsp; {{ finding.title }}</h3>
        <div class="meta">
          <span>Asset: {{ finding.asset_value or '—' }}</span>
          {% if finding.cve_id %}<span>CVE: {{ finding.cve_id }}</span>{% endif %}
          {% if finding.cwe_id %}<span>CWE: {{ finding.cwe_id }}</span>{% endif %}
          {% if finding.id in risk_by_finding %}<span>Risk: {{ risk_by_finding[finding.id].score }}/10</span>{% endif %}
        </div>
        <p>{{ finding.description or 'No further description provided.' }}</p>
        {% set mappings = mitre_by_finding.get(finding.id, []) %}
        {% if mappings %}
        <div>
          {% for m in mappings %}
            <span class="mitre-tag">{{ m.technique_id }} — {{ m.technique_name }}{% if m.confidence %} ({{ (m.confidence * 100) | round | int }}%){% endif %}</span>
          {% endfor %}
        </div>
        {% endif %}
      </div>
      {% endfor %}
    {% else %}
    <p class="empty">No findings were identified during this assessment.</p>
    {% endif %}
  </section>

  <section class="panel">
    <h2>MITRE ATT&amp;CK Coverage</h2>
    {% if technique_counts %}
    <table>
      <tr><th>Technique</th><th>Name</th><th>Tactic</th><th>Findings</th></tr>
      {% for (technique_id, name, tactic), count in technique_counts %}
      <tr><td>{{ technique_id }}</td><td>{{ name }}</td><td>{{ tactic }}</td><td>{{ count }}</td></tr>
      {% endfor %}
    </table>
    {% else %}
    <p class="empty">No ATT&amp;CK techniques were mapped for this mission.</p>
    {% endif %}
  </section>

  <section class="panel">
    <h2>Risk Assessment</h2>
    {% if report.risk_score is not none %}
    <p>The highest individual finding risk score for this mission was
       <strong>{{ report.risk_score }}/10</strong>, an overall level of
       <span class="badge {{ report.risk_level }}">{{ report.risk_level }}</span>.</p>
    {% else %}
    <p class="empty">No risk scores were computed for this mission's findings.</p>
    {% endif %}
  </section>

  <section class="panel">
    <h2>Recommendations</h2>
    {% for label, items in [('Critical', report.critical_recommendations), ('High', report.high_recommendations), ('Medium', report.medium_recommendations), ('Low', report.low_recommendations)] %}
      {% if items %}
      <h3>{{ label }}</h3>
      <ul class="rec-list">
        {% for item in items %}<li>{{ item }}</li>{% endfor %}
      </ul>
      {% endif %}
    {% endfor %}
    {% if not (report.critical_recommendations or report.high_recommendations or report.medium_recommendations or report.low_recommendations) %}
    <p class="empty">No remediation recommendations were generated.</p>
    {% endif %}
  </section>

</main>
<footer>Generated by ORACLE {{ report.generated_by }}</footer>
</body>
</html>
"""

__all__ = ["ReportGenerator"]
