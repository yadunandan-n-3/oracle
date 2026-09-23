"""
Statistics API Routes
=====================

Aggregate statistics across all missions.
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from uuid import UUID

from fastapi import APIRouter, Depends

from core.logging import get_logger
from runtime.runtime import get_runtime, OracleRuntime

logger = get_logger(__name__)

router = APIRouter()


@router.get("/overview")
async def get_overview_stats(
    runtime: OracleRuntime = Depends(get_runtime),
) -> Dict[str, Any]:
    """Get overview statistics across all missions."""
    state_manager = runtime.state_manager

    total_missions = 0
    active_missions = 0
    completed_missions = 0
    failed_missions = 0
    cancelled_missions = 0
    total_assets = 0
    total_findings = 0
    total_evidence = 0
    critical_findings = 0
    high_findings = 0
    medium_findings = 0
    low_findings = 0

    severity_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    status_distribution = {"draft": 0, "planning": 0, "in_progress": 0, "completed": 0, "failed": 0, "cancelled": 0}

    for mission_state in state_manager._states.values():
        mission = mission_state.mission
        total_missions += 1

        status = mission.status.value if hasattr(mission.status, 'value') else str(mission.status)
        if status in status_distribution:
            status_distribution[status] += 1

        if status == "in_progress":
            active_missions += 1
        elif status == "completed":
            completed_missions += 1
        elif status == "failed":
            failed_missions += 1
        elif status == "cancelled":
            cancelled_missions += 1

        total_assets += len(mission_state.assets)
        total_evidence += len(mission_state.evidence)

        findings = state_manager.get_findings(mission.id)
        total_findings += len(findings)
        for finding in findings:
            sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            if sev in severity_distribution:
                severity_distribution[sev] += 1
            if sev == "critical":
                critical_findings += 1
            elif sev == "high":
                high_findings += 1
            elif sev == "medium":
                medium_findings += 1
            elif sev == "low":
                low_findings += 1

    return {
        "missions": {
            "total": total_missions,
            "active": active_missions,
            "completed": completed_missions,
            "failed": failed_missions,
            "cancelled": cancelled_missions,
            "by_status": status_distribution,
        },
        "assets": {
            "total": total_assets,
        },
        "findings": {
            "total": total_findings,
            "critical": critical_findings,
            "high": high_findings,
            "medium": medium_findings,
            "low": low_findings,
            "by_severity": severity_distribution,
        },
        "evidence": {
            "total": total_evidence,
        },
        "system": await runtime.health(),
    }


@router.get("/risk-distribution")
async def get_risk_distribution(
    runtime: OracleRuntime = Depends(get_runtime),
) -> Dict[str, Any]:
    """Get risk score distribution across all findings."""
    state_manager = runtime.state_manager

    risk_buckets = {
        "critical": {"count": 0, "min": 85, "max": 100},
        "high": {"count": 0, "min": 70, "max": 84},
        "medium": {"count": 0, "min": 40, "max": 69},
        "low": {"count": 0, "min": 1, "max": 39},
        "none": {"count": 0, "min": 0, "max": 0},
    }

    risk_scores = []
    for mission_state in state_manager._states.values():
        findings = state_manager.get_findings(mission_state.mission.id)
        for finding in findings:
            if finding.risk_score is not None:
                risk_scores.append(finding.risk_score)
                score = finding.risk_score
                if score >= 85:
                    risk_buckets["critical"]["count"] += 1
                elif score >= 70:
                    risk_buckets["high"]["count"] += 1
                elif score >= 40:
                    risk_buckets["medium"]["count"] += 1
                elif score > 0:
                    risk_buckets["low"]["count"] += 1
                else:
                    risk_buckets["none"]["count"] += 1

    avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
    max_risk = max(risk_scores) if risk_scores else 0
    min_risk = min(risk_scores) if risk_scores else 0

    return {
        "distribution": risk_buckets,
        "average_risk_score": round(avg_risk, 2),
        "max_risk_score": round(max_risk, 2),
        "min_risk_score": round(min_risk, 2),
        "total_risk_scored_findings": len(risk_scores),
    }

