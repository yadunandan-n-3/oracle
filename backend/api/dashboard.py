"""
Dashboard API Routes
====================

Aggregated dashboard data that powers the main dashboard UI.
Consolidates mission stats, asset counts, finding distributions,
risk trends, and AI recommendations into a single endpoint.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import UUID

from fastapi import APIRouter, Depends

from core.logging import get_logger
from domain.finding import FindingSeverity
from runtime.runtime import get_runtime, OracleRuntime

logger = get_logger(__name__)

router = APIRouter()


@router.get("")
async def get_dashboard(
    runtime: OracleRuntime = Depends(get_runtime),
) -> Dict[str, Any]:
    """Get all dashboard data in a single response."""
    try:
        return await _build_dashboard_data(runtime)
    except Exception as e:
        logger.error("dashboard.build_failed", error=str(e))
        # Return partial/graceful degradation response
        return {
            "missions": {"total": 0, "active": 0, "completed": 0, "failed": 0, "by_status": {}, "by_type": {}, "recent": []},
            "assets": {"total": 0, "by_type": {}},
            "findings": {"total": 0, "critical": 0, "high": 0, "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}, "recent": [], "top_cves": [], "top_mitre_techniques": []},
            "risk": {"average_risk_score": 0, "max_risk_score": 0, "overall_risk_level": "none", "total_risk_scored_findings": 0},
            "evidence": {"total": 0},
            "system": {"running": False, "uptime_seconds": 0, "active_workflows": 0, "knowledge_graph_healthy": False},
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "error": str(e),
        }


async def _build_dashboard_data(runtime: OracleRuntime) -> Dict[str, Any]:
    """Build dashboard data with error isolation per section."""
    state_manager = runtime.state_manager

    # ─── Mission Summary ────────────────────────────────────────────────
    mission_status_counts = Counter()
    mission_type_counts = Counter()
    total_missions = 0
    active_missions = 0
    completed_missions = 0
    failed_missions = 0
    recent_missions: List[Dict[str, Any]] = []

    # ─── Asset Summary ──────────────────────────────────────────────────
    total_assets = 0
    asset_type_counts = Counter()

    # ─── Finding Summary ────────────────────────────────────────────────
    severity_counts: Dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0
    }
    total_findings = 0
    critical_findings = 0
    high_findings = 0
    recent_findings: List[Dict[str, Any]] = []
    top_cves: Counter = Counter()
    top_mitre: Counter = Counter()

    # ─── Risk Summary ───────────────────────────────────────────────────
    risk_scores: List[float] = []

    # ─── Evidence Summary ───────────────────────────────────────────────
    total_evidence = 0

    # PostgreSQL is authoritative when available. Runtime state is an
    # explicit degraded-mode fallback for installations without persistence.
    all_states = state_manager.get_all_states()
    persisted_missions = await runtime.get_authoritative_missions()
    persisted_findings = await runtime.get_authoritative_findings()
    persisted_by_mission: Dict[UUID, List[Any]] = {}
    if persisted_findings is not None:
        for finding in persisted_findings:
            persisted_by_mission.setdefault(finding.mission_id, []).append(finding)

    if persisted_missions is not None:
        mission_sources = [(mission, None) for mission in persisted_missions]
    else:
        mission_sources = [(state.mission, state) for state in all_states.values()]

    for mission, mission_state in mission_sources:
        try:
            total_missions += 1
            status = mission.status.value if hasattr(mission.status, 'value') else str(mission.status)
            mission_status_counts[status] += 1
            mtype = mission.mission_type.value if hasattr(mission.mission_type, 'value') else str(mission.mission_type)
            mission_type_counts[mtype] += 1

            if status == "in_progress":
                active_missions += 1
            elif status == "completed":
                completed_missions += 1
            elif status == "failed":
                failed_missions += 1

            # Recent missions
            recent_missions.append({
                "id": str(mission.id),
                "name": mission.name,
                "status": status,
                "mission_type": mtype,
                "priority": mission.priority.value if hasattr(mission.priority, 'value') else str(mission.priority),
                "total_assets": mission.total_assets_discovered,
                "total_findings": mission.total_findings,
                "critical_findings": mission.critical_findings,
                "high_findings": mission.high_findings,
                "created_at": mission.created_at.isoformat(),
                "completed_at": mission.completed_at.isoformat() if mission.completed_at else None,
            })

            # Assets
            if persisted_missions is not None:
                assets = await runtime.get_authoritative_assets(mission.id) or []
            else:
                assets = list(mission_state.assets.values()) if mission_state else []
            total_assets += len(assets)
            for asset in assets:
                atype = asset.asset_type.value if hasattr(asset.asset_type, 'value') else str(asset.asset_type)
                asset_type_counts[atype] += 1

            # Evidence
            total_evidence += mission.total_evidence

            # Findings
            findings = (
                persisted_by_mission.get(mission.id, [])
                if persisted_findings is not None
                else state_manager.get_findings(mission.id)
            )
            total_findings += len(findings)

            all_findings_sorted = sorted(
                findings,
                key=lambda f: (
                    0 if (
                        f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                    ) in {FindingSeverity.CRITICAL.value, FindingSeverity.HIGH.value} else 1,
                    -(f.risk_score or 0),
                ),
            )

            for finding in findings:
                sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
                if sev in severity_counts:
                    severity_counts[sev] += 1
                if sev == "critical":
                    critical_findings += 1
                elif sev == "high":
                    high_findings += 1

                # Risk scores
                if finding.risk_score is not None:
                    risk_scores.append(finding.risk_score)

                # Top CVEs
                if finding.cve_id:
                    top_cves[finding.cve_id] += 1

                # Top MITRE
                if finding.mitre_technique_id:
                    top_mitre[f"{finding.mitre_technique_id} ({finding.mitre_tactic})"] += 1

            # Recent findings (limit to 10 per mission for performance)
            for finding in all_findings_sorted[:10]:
                recent_findings.append({
                    "id": str(finding.id),
                    "title": finding.title,
                    "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                    "status": finding.status.value if hasattr(finding.status, 'value') else str(finding.status),
                    "asset_value": finding.asset_value,
                    "cve_id": finding.cve_id,
                    "risk_score": finding.risk_score,
                    "mission_id": str(mission.id),
                    "discovered_at": finding.discovered_at.isoformat() if hasattr(finding, 'discovered_at') else None,
                })
        except Exception as e:
            logger.warning("dashboard.mission_processing_failed", mission_id=str(mission.id), error=str(e))
            continue

    # Sort recent missions by created_at (most recent first)
    recent_missions.sort(key=lambda m: m.get("created_at", ""), reverse=True)

    # Sort recent findings by risk score (highest first)
    recent_findings.sort(key=lambda f: -(f.get("risk_score") or 0))

    # Risk statistics
    avg_risk = round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else 0
    max_risk = round(max(risk_scores), 2) if risk_scores else 0

    # Overall risk level
    if max_risk >= 85:
        overall_risk_level = "critical"
    elif max_risk >= 70:
        overall_risk_level = "high"
    elif max_risk >= 40:
        overall_risk_level = "medium"
    elif max_risk > 0:
        overall_risk_level = "low"
    else:
        overall_risk_level = "none"

    # System health
    system_health = await runtime.health()

    return {
        "missions": {
            "total": total_missions,
            "active": active_missions,
            "completed": completed_missions,
            "failed": failed_missions,
            "by_status": dict(mission_status_counts),
            "by_type": dict(mission_type_counts),
            "recent": recent_missions[:10],
        },
        "assets": {
            "total": total_assets,
            "by_type": dict(asset_type_counts),
        },
        "findings": {
            "total": total_findings,
            "critical": critical_findings,
            "high": high_findings,
            "by_severity": severity_counts,
            "recent": recent_findings[:20],
            "top_cves": [{"cve_id": cve, "count": count} for cve, count in top_cves.most_common(10)],
            "top_mitre_techniques": [{"technique": tech, "count": count} for tech, count in top_mitre.most_common(10)],
        },
        "risk": {
            "average_risk_score": avg_risk,
            "max_risk_score": max_risk,
            "overall_risk_level": overall_risk_level,
            "total_risk_scored_findings": len(risk_scores),
        },
        "evidence": {
            "total": total_evidence,
        },
        "system": {
            "running": system_health.get("running", False),
            "uptime_seconds": system_health.get("uptime_seconds", 0),
            "active_workflows": system_health.get("subsystems", {}).get("active_workflows", 0),
            "knowledge_graph_healthy": system_health.get("subsystems", {}).get("knowledge_graph", {}).get("healthy", False),
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

