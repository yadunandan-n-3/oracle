"""
Explanation Prompts
===================

Prompt templates for the AI Explanation Engine.

These prompts are carefully designed to:
1. Give the LLM structured evidence, not raw tool output
2. Constrain the LLM to explain, not invent
3. Return a consistent JSON structure
4. Include all context: evidence, MITRE, CVE, risk, asset

The prompts NEVER include raw Nmap XML, Nuclei JSONL, or any other
unstructured tool output. The evidence is pre-processed by the
Security Intelligence Service into an EnrichedFinding.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from domain.intelligence import EnrichedFinding, ThreatIntelligence
from domain.scoring import OracleRiskScoreV2

# ─── JSON Schema for the structured explanation ────────────────────────────

EXPLANATION_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {
            "type": "string",
            "description": "One-sentence executive summary of the finding",
        },
        "technical_reason": {
            "type": "string",
            "description": "Technical explanation of the vulnerability, how it was detected, and why it matters",
        },
        "business_impact": {
            "type": "string",
            "description": "What the business impact would be if this vulnerability were exploited",
        },
        "recommendation": {
            "type": "string",
            "description": "Clear, actionable remediation recommendation",
        },
        "verification": {
            "type": "string",
            "description": "How to verify the finding and confirm remediation",
        },
        "confidence": {
            "type": "integer",
            "description": "Confidence score 0-100 in the explanation's accuracy",
            "minimum": 0,
            "maximum": 100,
        },
    },
    "required": [
        "summary",
        "technical_reason",
        "business_impact",
        "recommendation",
        "verification",
        "confidence",
    ],
}


def build_explanation_prompt(
    enriched: EnrichedFinding,
    risk_score: OracleRiskScoreV2,
) -> str:
    """
    Build a prompt for the LLM to explain a finding.

    The prompt includes:
    - Finding title, severity, description
    - Asset information (value, type, technology, version)
    - Correlation evidence (sources, confidence)
    - Threat intelligence (CVE, CVSS, EPSS, KEV, MITRE)
    - Risk score (V2 score, level, top factors)

    Args:
        enriched: The EnrichedFinding from the Security Intelligence Service
        risk_score: The OracleRiskScoreV2 from the Risk Engine

    Returns:
        A formatted prompt string ready to send to the LLM
    """
    ti = enriched.threat_intelligence

    # Build threat intelligence section
    threat_intel_lines = []
    if ti:
        if ti.cve:
            cve = ti.cve
            threat_intel_lines.append(f"  - CVE: {cve.cve_id}")
            if cve.cvss_score is not None:
                threat_intel_lines.append(f"  - CVSS Score: {cve.cvss_score}/10 ({cve.cvss_severity.value})")
            if cve.cwe_ids:
                threat_intel_lines.append(f"  - CWE: {', '.join(cve.cwe_ids)}")
            if cve.affected_software:
                threat_intel_lines.append(f"  - Affected Software: {', '.join(cve.affected_software[:3])}")
            if cve.description:
                threat_intel_lines.append(f"  - Description: {cve.description[:300]}")
        if ti.epss:
            threat_intel_lines.append(f"  - EPSS: {ti.epss.epss_score:.2%} probability of exploitation")
        if ti.kev:
            threat_intel_lines.append(f"  - CISA KEV: Listed in Known Exploited Vulnerabilities catalog")
        if ti.mitre:
            for m in ti.mitre[:3]:
                threat_intel_lines.append(f"  - MITRE: {m.technique_id} - {m.technique_name} ({m.tactic})")

    # Build risk score section
    risk_lines = []
    if risk_score.explanation:
        risk_lines.append(f"  - Oracle Risk Score: {risk_score.score}/100 ({risk_score.level.value.upper()})")
        if risk_score.explanation.top_factors:
            for factor in risk_score.explanation.top_factors[:3]:
                risk_lines.append(f"  - {factor}")

    prompt = f"""You are a senior cybersecurity analyst. Explain the following security finding in a clear, structured format.

## Finding
- Title: {enriched.title}
- Severity: {enriched.severity}
- Description: {enriched.description or 'N/A'}

## Asset
- Value: {enriched.asset_value or 'N/A'}
- Type: {enriched.asset_type or 'N/A'}
- Technology: {enriched.technology or 'N/A'}
- Version: {enriched.version or 'N/A'}
- Service: {enriched.service or 'N/A'}
- Port: {enriched.port or 'N/A'}
- Internet Facing: {'Yes' if enriched.internet_exposed else 'No'}

## Correlation
- Confidence: {enriched.correlation_confidence:.0%}
- Sources: {', '.join(enriched.correlation_sources) or 'N/A'}
- Evidence Count: {len(enriched.evidence_ids)}

## Threat Intelligence
{chr(10).join(threat_intel_lines) if threat_intel_lines else '  - No threat intelligence data available.'}

## Risk Assessment
{chr(10).join(risk_lines) if risk_lines else '  - No risk score computed.'}

## Remediation
- Suggested Steps: {', '.join(enriched.remediation_steps) if enriched.remediation_steps else 'N/A'}

## Instructions
Based ONLY on the information above, provide:
1. **summary**: A one-sentence executive summary of this finding.
2. **technical_reason**: A technical explanation of the vulnerability, how it was detected, and why it matters. Reference specific evidence (e.g., "Nmap detected Apache 2.4.49, which Nuclei confirmed is vulnerable to CVE-2021-41773").
3. **business_impact**: What the business impact would be if this were exploited.
4. **recommendation**: A clear, actionable remediation recommendation.
5. **verification**: How to verify the finding and confirm remediation.
6. **confidence**: An integer 0-100 indicating your confidence in this explanation.

IMPORTANT:
- Do NOT invent information that is not in the data above.
- Do NOT reference specific CVEs or CWEs that are not listed.
- Base your explanation strictly on the evidence provided.
- Output valid JSON ONLY."""
    return prompt


def build_bulk_explanation_prompt(
    enriched_findings: List[EnrichedFinding],
    risk_scores: Dict[str, OracleRiskScoreV2],
) -> str:
    """
    Build a prompt for explaining multiple findings in a single call.

    Useful for generating a consolidated report summary.

    Args:
        enriched_findings: List of EnrichedFinding objects
        risk_scores: Dict mapping finding_id -> OracleRiskScoreV2

    Returns:
        A formatted prompt string
    """
    finding_blocks: List[str] = []

    for i, enriched in enumerate(enriched_findings[:10]):  # Limit to 10
        risk = risk_scores.get(str(enriched.finding_id))
        risk_line = f"Risk: {risk.score}/100 ({risk.level.value})" if risk else "Risk: N/A"
        ti_line = ""
        if enriched.threat_intelligence and enriched.threat_intelligence.cve:
            ti_line = f"CVE: {enriched.threat_intelligence.cve.cve_id} (CVSS: {enriched.threat_intelligence.cve.cvss_score})"

        finding_blocks.append(
            f"Finding {i+1}: {enriched.title} [{enriched.severity}]\n"
            f"  Asset: {enriched.asset_value} | {enriched.technology} {enriched.version}\n"
            f"  {ti_line}\n"
            f"  {risk_line}\n"
            f"  Evidence: {len(enriched.evidence_ids)} items from {', '.join(enriched.correlation_sources)}"
        )

    findings_text = "\n\n".join(finding_blocks)

    prompt = f"""You are a senior cybersecurity analyst. Review the following {len(enriched_findings[:10])} security findings and provide a consolidated analysis.

{findings_text}

## Instructions
Based ONLY on the information above, provide a JSON object with:
1. "summary": Consolidated executive summary of all findings
2. "top_risks": List of the top 3 most critical findings with brief reasoning
3. "overall_assessment": Overall security posture assessment
4. "recommendations": Prioritized list of remediation recommendations

Output valid JSON ONLY."""
    return prompt


__all__ = [
    "EXPLANATION_SCHEMA",
    "build_explanation_prompt",
    "build_bulk_explanation_prompt",
]
