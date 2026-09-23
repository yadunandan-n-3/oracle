"""
AI Security Analyst (Copilot) API
=================================

Chat with an AI that has access to your security data.
The copilot answers questions using EnrichedFindings and Knowledge Graph context.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from core.logging import get_logger
from domain.finding import FindingSeverity
from runtime.runtime import get_runtime, OracleRuntime

logger = get_logger(__name__)

router = APIRouter()


class CopilotRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=2000, description="The user's question for the AI analyst")
    mission_id: Optional[str] = Field(None, description="Optional mission ID to scope the question to")
    conversation_id: Optional[str] = Field(None, description="Conversation ID for multi-turn context")


class CopilotResponse(BaseModel):
    answer: str = Field(..., description="The AI's answer")
    confidence: float = Field(0.0, description="Confidence in the answer (0-1)")
    sources: List[str] = Field(default_factory=list, description="Sources used to generate the answer")
    suggested_questions: List[str] = Field(default_factory=list, description="Follow-up questions the user might ask")
    conversation_id: str = Field("", description="Conversation ID for continuing the conversation")


@router.post("/ask", response_model=CopilotResponse)
async def ask_copilot(
    request: CopilotRequest,
    runtime: OracleRuntime = Depends(get_runtime),
) -> Dict[str, Any]:
    """Ask the AI Security Analyst a question."""
    question = request.question.lower().strip()
    mission_id = UUID(request.mission_id) if request.mission_id else None
    conversation_id = request.conversation_id or f"conv_{UUID(int=0)}"

    state_manager = runtime.state_manager

    # ─── Analyze the question to determine intent ────────────────────
    answer = ""
    sources: List[str] = []
    suggested_questions: List[str] = []

    if _is_asking_for_highest_risk_asset(question):
        answer, sources, suggested_questions = _answer_highest_risk_asset(state_manager, mission_id)

    elif _is_asking_for_risk_breakdown(question):
        answer, sources, suggested_questions = _answer_risk_breakdown(state_manager, mission_id)

    elif _is_asking_for_critical_findings(question):
        answer, sources, suggested_questions = _answer_critical_findings(state_manager, mission_id)

    elif _is_asking_for_attack_path(question):
        answer, sources, suggested_questions = await _answer_attack_path(runtime, state_manager, mission_id)

    elif _is_asking_for_what_to_patch(question):
        answer, sources, suggested_questions = _answer_what_to_patch(state_manager, mission_id)

    elif _is_asking_for_mission_summary(question):
        answer, sources, suggested_questions = await _answer_mission_summary(state_manager, mission_id)

    elif _is_asking_for_explanation(question):
        answer, sources, suggested_questions = await _answer_explanation(state_manager, question, mission_id)

    elif _is_asking_for_executive_summary(question):
        answer, sources, suggested_questions = await _answer_executive_summary(state_manager, mission_id)

    else:
        answer, sources, suggested_questions = await _answer_general(state_manager, question, mission_id)

    return {
        "answer": answer,
        "confidence": 0.85 if answer else 0.0,
        "sources": sources[:5],
        "suggested_questions": suggested_questions[:5],
        "conversation_id": conversation_id,
    }


# ─── Intent Detection ───────────────────────────────────────────────────


def _is_asking_for_highest_risk_asset(q: str) -> bool:
    keywords = ["highest risk", "most critical", "riskiest", "most vulnerable", "top risk"]
    return any(kw in q for kw in keywords) and ("asset" in q or "host" in q or "server" in q or "system" in q)


def _is_asking_for_risk_breakdown(q: str) -> bool:
    keywords = ["risk breakdown", "risk distribution", "how many critical", "risk summary", "risk overview"]
    return any(kw in q for kw in keywords)


def _is_asking_for_critical_findings(q: str) -> bool:
    keywords = ["critical finding", "show finding", "list finding", "what finding", "vulnerabilities"]
    return any(kw in q for kw in keywords) or ("critical" in q and "finding" in q)


def _is_asking_for_attack_path(q: str) -> bool:
    keywords = ["attack path", "attack chain", "compromise path", "how to exploit", "kill chain", "what becomes reachable"]
    return any(kw in q for kw in keywords)


def _is_asking_for_what_to_patch(q: str) -> bool:
    keywords = ["patch first", "what to patch", "priority", "remediate", "fix first", "most urgent"]
    return any(kw in q for kw in keywords)


def _is_asking_for_mission_summary(q: str) -> bool:
    keywords = ["mission summary", "mission status", "mission progress", "how is mission", "mission overview"]
    return any(kw in q for kw in keywords) or (("summary" in q or "status" in q) and "mission" in q)


def _is_asking_for_explanation(q: str) -> bool:
    keywords = ["explain", "why is", "tell me about", "what is", "describe", "how does"]
    return any(kw in q for kw in keywords) and any(k in q for k in ["cve", "finding", "vulnerability", "risk"])


def _is_asking_for_executive_summary(q: str) -> bool:
    keywords = ["executive summary", "overall assessment", "security posture", "how are we doing", "health check"]
    return any(kw in q for kw in keywords)


# ─── Answer Builders ────────────────────────────────────────────────────


def _answer_highest_risk_asset(
    state_manager: Any, mission_id: Optional[UUID] = None,
) -> tuple:
    """Find the highest-risk asset across all missions."""
    highest_risk = 0
    highest_asset = None
    highest_finding = None
    sources = []

    missions = _get_missions(state_manager, mission_id)
    for mid in missions:
        findings = state_manager.get_findings(mid)
        for finding in findings:
            if finding.asset_value and (finding.risk_score or 0) > highest_risk:
                highest_risk = finding.risk_score or 0
                highest_asset = finding.asset_value
                highest_finding = finding

    if not highest_asset:
        return "No assets with risk scores found.", [], [
            "What is my overall risk level?",
            "Show me all findings",
            "List my missions",
        ]

    answer = (
        f"**Highest-Risk Asset: {highest_asset}**\n\n"
        f"Risk Score: **{highest_risk:.1f}/100**\n\n"
    )
    if highest_finding:
        answer += (
            f"Top Finding: **{highest_finding.title}**\n"
            f"Severity: {highest_finding.severity.value if hasattr(highest_finding.severity, 'value') else str(highest_finding.severity)}\n"
        )
        if highest_finding.cve_id:
            answer += f"CVE: {highest_finding.cve_id}\n"
            sources.append(f"CVE: {highest_finding.cve_id}")
        if highest_finding.remediation_steps:
            answer += f"\n**Recommendation:** {highest_finding.remediation_steps[0]}"

    sources.append(f"Asset: {highest_asset}")
    if highest_finding:
        sources.append(f"Finding: {highest_finding.title}")

    return answer, sources, [
        f"Explain why {highest_asset} is high risk",
        "Show me the attack path to this asset",
        "What should I patch first?",
        "Give me an executive summary",
    ]


def _answer_risk_breakdown(
    state_manager: Any, mission_id: Optional[UUID] = None,
) -> tuple:
    """Summarize the risk distribution."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
    total = 0

    missions = _get_missions(state_manager, mission_id)
    for mid in missions:
        findings = state_manager.get_findings(mid)
        for finding in findings:
            total += 1
            score = finding.risk_score or 0
            if score >= 85:
                counts["critical"] += 1
            elif score >= 70:
                counts["high"] += 1
            elif score >= 40:
                counts["medium"] += 1
            elif score > 0:
                counts["low"] += 1
            else:
                counts["none"] += 1

    if total == 0:
        return "No risk-scored findings available.", [], [
            "What missions are running?",
            "Show me all findings",
            "How is the system health?",
        ]

    answer = (
        f"**Risk Distribution** ({total} total findings)\n\n"
        f"🔴 Critical: {counts['critical']}\n"
        f"🟠 High: {counts['high']}\n"
        f"🟡 Medium: {counts['medium']}\n"
        f"🟢 Low: {counts['low']}\n"
        f"⚪ None: {counts['none']}\n\n"
    )

    if counts['critical'] > 0:
        answer += f"⚠️ **{counts['critical']} critical finding{'s' if counts['critical'] > 1 else ''} require immediate attention!**"
    elif counts['high'] > 0:
        answer += f"⚠️ **{counts['high']} high finding{'s' if counts['high'] > 1 else ''} should be prioritized in the next remediation cycle.**"
    else:
        answer += "✅ No critical or high-risk findings detected."

    return answer, ["Risk Engine V2"], [
        "What is my highest-risk asset?",
        "Show me critical findings",
        "What should I patch first?",
    ]


def _answer_critical_findings(
    state_manager: Any, mission_id: Optional[UUID] = None,
) -> tuple:
    """List all critical findings."""
    critical = []
    sources = []

    missions = _get_missions(state_manager, mission_id)
    for mid in missions:
        findings = state_manager.get_findings(mid)
        for finding in findings:
            sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            if sev == "critical" or (finding.risk_score or 0) >= 85:
                critical.append(finding)
                if finding.cve_id:
                    sources.append(finding.cve_id)

    if not critical:
        return "No critical findings detected. ✅", [], [
            "Show me high-risk findings",
            "What is my risk breakdown?",
            "How is the system health?",
        ]

    answer = f"**Critical Findings** ({len(critical)} total)\n\n"
    for f in critical[:10]:
        answer += f"🔴 **{f.title}**\n"
        answer += f"   Asset: {f.asset_value}\n"
        if f.cve_id:
            answer += f"   CVE: {f.cve_id}\n"
        if f.risk_score:
            answer += f"   Risk: {f.risk_score:.1f}/100\n"
        if f.remediation_steps:
            answer += f"   Fix: {f.remediation_steps[0][:100]}...\n"
        answer += "\n"

    if len(critical) > 10:
        answer += f"... and {len(critical) - 10} more critical findings."

    return answer, sources, [
        "What is my highest-risk asset?",
        "What should I patch first?",
        "Show me the attack path",
    ]


async def _answer_attack_path(
    runtime: Any, state_manager: Any, mission_id: Optional[UUID] = None,
) -> tuple:
    """Analyze attack paths from the knowledge graph."""
    if not runtime.knowledge_graph.is_available:
        return "Knowledge graph is not available. Attack path analysis requires Neo4j.", [], [
            "What is my highest-risk asset?",
            "Show me critical findings",
            "Give me an executive summary",
        ]

    missions = _get_missions(state_manager, mission_id)
    paths = []
    for mid in missions[:3]:  # Limit to 3 missions
        found = await runtime.knowledge_graph.find_attack_paths(mid)
        paths.extend(found)

    if not paths:
        return "No attack paths found. The knowledge graph may not have enough connected data yet.", [], [
            "What is my highest-risk asset?",
            "What should I patch first?",
            "Show me critical findings",
        ]

    answer = f"**Attack Path Analysis** ({len(paths)} paths found)\n\n"
    for i, path in enumerate(paths[:5], 1):
        answer += f"📍 Path {i}: {path.get('path', 'Unknown path')[:200]}\n"
        if path.get('longer'):
            answer += f"   Extended: {path['longer'][:200]}\n"
        answer += "\n"

    return answer, ["Knowledge Graph (Neo4j)"], [
        "What is the highest-risk asset in this path?",
        "Show me critical findings for this path",
        "What should I patch first?",
    ]


def _answer_what_to_patch(
    state_manager: Any, mission_id: Optional[UUID] = None,
) -> tuple:
    """Prioritize what to patch first based on risk."""
    findings_by_priority = []
    sources = []

    missions = _get_missions(state_manager, mission_id)
    for mid in missions:
        findings = state_manager.get_findings(mid)
        for finding in findings:
            if finding.risk_score and finding.risk_score >= 70:
                findings_by_priority.append(finding)
                if finding.cve_id:
                    sources.append(finding.cve_id)

    findings_by_priority.sort(key=lambda f: -(f.risk_score or 0))

    if not findings_by_priority:
        return "No high-priority findings requiring immediate patching. ✅", [], [
            "Show me all findings",
            "What is my risk breakdown?",
            "Give me an executive summary",
        ]

    answer = f"**Patch Priority** ({len(findings_by_priority)} items)\n\n"
    for i, f in enumerate(findings_by_priority[:10], 1):
        sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
        answer += f"{i}. **{f.title}** [Risk: {f.risk_score:.1f}/100 | {sev.upper()}]\n"
        answer += f"   Asset: {f.asset_value}\n"
        if f.cve_id:
            answer += f"   CVE: {f.cve_id}\n"
        if f.remediation_steps:
            answer += f"   Fix: {f.remediation_steps[0]}\n"
        answer += "\n"

    return answer, sources, [
        "Explain the top finding in detail",
        "What is the impact if I don't patch?",
        "Show me the attack path for this vulnerability",
    ]


async def _answer_mission_summary(
    state_manager: Any, mission_id: Optional[UUID] = None,
) -> tuple:
    """Summarize mission status and progress."""
    missions = _get_missions(state_manager, mission_id)
    if not missions:
        return "No missions found.", [], [
            "Create a new mission",
            "What are the mission templates?",
            "How is the system health?",
        ]

    answer = "**Mission Summary**\n\n"
    sources = []
    for mid in missions:
        state = await state_manager.get_mission_state(mid)
        if not state:
            continue
        mission = state.mission
        status = mission.status.value if hasattr(mission.status, 'value') else str(mission.status)
        answer += (
            f"📋 **{mission.name}**\n"
            f"   Status: {status.upper()}\n"
            f"   Type: {mission.mission_type.value if hasattr(mission.mission_type, 'value') else str(mission.mission_type)}\n"
            f"   Progress: {state.progress_percentage:.0f}%\n"
            f"   Assets: {state.total_assets} | Findings: {mission.total_findings} | "
            f"Critical: {mission.critical_findings} | High: {mission.high_findings}\n"
            f"   Duration: {(datetime.now(timezone.utc) - state.started_at).total_seconds() / 60:.0f} min\n\n"
        )
        sources.append(mission.name)

    return answer, sources, [
        "What is my highest-risk asset?",
        "Show me critical findings",
        "Give me an executive summary",
    ]


async def _answer_explanation(
    state_manager: Any, question: str, mission_id: Optional[UUID] = None,
) -> tuple:
    """Explain a specific finding or vulnerability."""
    # Extract CVE or finding reference from the question
    import re
    cve_match = re.search(r'CVE-\d{4}-\d+', question, re.IGNORECASE)
    cve_id = cve_match.group(0).upper() if cve_match else None

    findings_list = []
    sources = []

    missions = _get_missions(state_manager, mission_id)
    for mid in missions:
        findings = state_manager.get_findings(mid)
        for finding in findings:
            if cve_id and finding.cve_id == cve_id:
                findings_list.append(finding)
                sources.append(finding.cve_id)
            elif not cve_id and finding.title and any(w in finding.title.lower() for w in question.lower().split()):
                findings_list.append(finding)

    if not findings_list:
        if cve_id:
            return f"I couldn't find detailed information about {cve_id} in the current mission data.", [], [
                f"What is the risk score for {cve_id}?",
                "Show me all critical findings",
                "What should I patch first?",
            ]
        return "I couldn't find a matching finding. Try being more specific or ask about a CVE ID.", [], [
            "Show me critical findings",
            "What is my highest-risk asset?",
            "What should I patch first?",
        ]

    finding = findings_list[0]
    sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
    answer = (
        f"**{finding.title}**\n\n"
        f"**Severity:** {sev.upper()}\n"
        f"**Asset:** {finding.asset_value}\n"
    )
    if finding.cve_id:
        answer += f"**CVE:** {finding.cve_id}\n"
    if finding.cvss_score:
        answer += f"**CVSS:** {finding.cvss_score}/10\n"
    if finding.risk_score:
        answer += f"**Oracle Risk Score:** {finding.risk_score:.1f}/100\n"
    if finding.description:
        answer += f"\n{finding.description}\n"
    if finding.remediation_steps:
        answer += f"\n**Recommendation:**\n"
        for step in finding.remediation_steps[:3]:
            answer += f"• {step}\n"

    return answer, sources, [
        f"What is the risk breakdown for this finding?",
        f"What attack path uses this vulnerability?",
        "What should I patch first?",
    ]


async def _answer_executive_summary(
    state_manager: Any, mission_id: Optional[UUID] = None,
) -> tuple:
    """Generate an executive summary of overall security posture."""
    total_findings = 0
    critical_count = 0
    high_count = 0
    medium_count = 0
    total_missions = 0
    total_assets = 0
    max_risk = 0

    missions = _get_missions(state_manager, mission_id)
    for mid in missions:
        state = await state_manager.get_mission_state(mid)
        if not state:
            continue
        total_missions += 1
        total_assets += state.total_assets
        findings = state_manager.get_findings(mid)
        for finding in findings:
            total_findings += 1
            sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            if sev == "critical":
                critical_count += 1
            elif sev == "high":
                high_count += 1
            elif sev == "medium":
                medium_count += 1
            if finding.risk_score and finding.risk_score > max_risk:
                max_risk = finding.risk_score

    if total_missions == 0:
        return "No missions have been executed yet. Start a mission to generate a security assessment.", [], [
            "Create a new mission",
            "What are the mission templates?",
            "How is the system health?",
        ]

    if max_risk >= 85:
        posture = "**CRITICAL** — Immediate action required"
    elif max_risk >= 70:
        posture = "**HIGH** — Priority action required"
    elif max_risk >= 40:
        posture = "**MODERATE** — Continued monitoring recommended"
    else:
        posture = "**GOOD** — No significant risks detected"

    answer = (
        f"## Executive Security Summary\n\n"
        f"**Overall Posture:** {posture}\n\n"
        f"**Coverage:** {total_missions} mission{'s' if total_missions > 1 else ''} | "
        f"{total_assets} asset{'s' if total_assets > 1 else ''} | "
        f"{total_findings} finding{'s' if total_findings > 1 else ''}\n\n"
        f"**Finding Breakdown:**\n"
        f"🔴 Critical: {critical_count}\n"
        f"🟠 High: {high_count}\n"
        f"🟡 Medium: {medium_count}\n"
    )

    if critical_count > 0:
        answer += (
            f"\n⚠️ **{critical_count} critical finding{'s' if critical_count > 1 else ''}** "
            f"require immediate remediation. These represent active, high-confidence "
            f"paths to compromise.\n"
        )
        answer += f"\n**Recommended Actions:**\n"
        answer += f"1. Patch critical findings immediately\n"
        answer += f"2. Review and remediate high-priority findings\n"
        answer += f"3. Continue scheduled assessments\n"
    elif high_count > 0:
        answer += (
            f"\n⚠️ **{high_count} high finding{'s' if high_count > 1 else ''}** "
            f"should be prioritized in the next remediation cycle.\n"
        )
    else:
        answer += "\n✅ No critical or high-risk findings detected.\n"

    return answer, ["Risk Engine V2", "Security Intelligence Service"], [
        "What is my highest-risk asset?",
        "What should I patch first?",
        "Show me the attack path",
    ]


async def _answer_general(
    state_manager: Any, question: str, mission_id: Optional[UUID] = None,
) -> tuple:
    """Handle general questions with relevant data context."""
    missions = _get_missions(state_manager, mission_id)
    total_missions = len(missions)
    total_findings = 0
    total_assets = 0
    for mid in missions:
        state = await state_manager.get_mission_state(mid)
        if state:
            total_assets += state.total_assets
            total_findings += state.mission.total_findings

    answer = (
        f"I've analyzed your ORACLE security data.\n\n"
        f"📊 **Current Status:**\n"
        f"• {total_missions} mission{'s' if total_missions != 1 else ''}\n"
        f"• {total_assets} asset{'s' if total_assets != 1 else ''} discovered\n"
        f"• {total_findings} finding{'s' if total_findings != 1 else ''} identified\n\n"
        f"I can help you with:\n"
        f"• 🔍 **Risk Analysis** — \"What is my highest-risk asset?\"\n"
        f"• 📋 **Findings** — \"Show me critical findings\"\n"
        f"• 🛡️ **Attack Paths** — \"Show me the attack path\"\n"
        f"• 🔧 **Remediation** — \"What should I patch first?\"\n"
        f"• 📈 **Summary** — \"Give me an executive summary\"\n"
        f"• 💡 **Explanations** — \"Explain CVE-2021-41773\"\n"
    )

    return answer, ["ORACLE Security Intelligence"], [
        "What is my highest-risk asset?",
        "Show me critical findings",
        "Give me an executive summary",
        "What should I patch first?",
    ]


# ─── Helpers ────────────────────────────────────────────────────────────


def _get_missions(state_manager: Any, mission_id: Optional[UUID] = None) -> List[UUID]:
    """Get list of mission IDs to query."""
    if mission_id:
        return [mission_id]
    return list(state_manager._states.keys())

