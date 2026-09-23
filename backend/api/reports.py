"""
Reports API Routes
==================

Generate, list, and retrieve security reports.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from core.logging import get_logger
from domain.report import ReportFormat, ReportType, Report
from domain.report.generator import ReportGenerator
from runtime.runtime import get_runtime, OracleRuntime

logger = get_logger(__name__)

router = APIRouter()


@router.get("")
async def list_reports(
    mission_id: Optional[str] = Query(None, description="Filter by mission ID"),
    report_type: Optional[str] = Query(None, description="Filter by report type"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    runtime: OracleRuntime = Depends(get_runtime),
) -> Dict[str, Any]:
    """List all generated reports."""
    state_manager = runtime.state_manager
    reports = []

    missions_to_check = []
    if mission_id:
        missions_to_check.append(UUID(mission_id))
    else:
        for mission_state in state_manager._states.values():
            missions_to_check.append(mission_state.mission.id)

    for mid in missions_to_check:
        state = await state_manager.get_mission_state(mid)
        if state:
            mission = state.mission
            report_type_filter = report_type or "technical_detail"
            try:
                report_type_enum = ReportType(report_type_filter)
            except ValueError:
                report_type_enum = ReportType.TECHNICAL_DETAIL

            reports.append({
                "id": str(mission.id),
                "title": f"ORACLE Security Assessment Report — {mission.name}",
                "report_type": report_type_enum.value,
                "mission_id": str(mission.id),
                "mission_name": mission.name,
                "status": mission.status.value if hasattr(mission.status, 'value') else str(mission.status),
                "total_findings": mission.total_findings,
                "critical_findings": mission.critical_findings,
                "high_findings": mission.high_findings,
                "medium_findings": mission.medium_findings,
                "low_findings": mission.low_findings,
                "risk_score": mission.overall_risk_score,
                "generated_at": mission.completed_at.isoformat() if mission.completed_at else None,
                "created_at": mission.created_at.isoformat(),
            })

    total = len(reports)
    paged = reports[offset:offset + limit]

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "reports": paged,
    }


@router.get("/{mission_id}")
async def get_report(
    mission_id: UUID,
    report_type: str = Query("technical_detail", description="Report type"),
    format: str = Query("json", description="Output format: json or html"),
    runtime: OracleRuntime = Depends(get_runtime),
) -> Any:
    """Get a report for a mission."""
    state_manager = runtime.state_manager
    state = await state_manager.get_mission_state(mission_id)

    if not state:
        # Try to find the mission from the mission manager
        mission = runtime.get_mission(mission_id)
        if not mission:
            raise HTTPException(status_code=404, detail=f"Mission {mission_id} not found")
    else:
        mission = state.mission

    # Get findings and assets from state manager
    findings = state_manager.get_findings(mission_id) if state else []
    assets = state_manager.get_assets(mission_id) if state else []

    try:
        report_type_enum = ReportType(report_type)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid report type: {report_type}",
        )

    try:
        output_format = ReportFormat(format)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid format: {format}. Valid: json, html",
        )

    # Generate the report
    generator = ReportGenerator()
    report = generator.generate(
        mission=mission,
        findings=findings,
        assets=assets,
        report_type=report_type_enum,
    )

    if output_format == ReportFormat.HTML:
        html = generator.render_html(report, findings, assets)
        return {"format": "html", "content": html, "title": report.title}

    return {
        "id": str(report.id),
        "title": report.title,
        "report_type": report.report_type.value,
        "format": report.format.value,
        "mission_id": str(report.mission_id) if report.mission_id else None,
        "mission_name": report.mission_name,
        "executive_summary": report.executive_summary,
        "findings_summary": report.findings_summary,
        "risk_score": report.risk_score,
        "risk_level": report.risk_level,
        "critical_recommendations": report.critical_recommendations,
        "high_recommendations": report.high_recommendations,
        "medium_recommendations": report.medium_recommendations,
        "low_recommendations": report.low_recommendations,
        "total_assets": report.total_assets,
        "total_findings": report.total_findings,
        "total_critical": report.total_critical,
        "total_high": report.total_high,
        "total_medium": report.total_medium,
        "total_low": report.total_low,
        "total_info": report.total_info,
        "average_cvss": report.average_cvss,
        "generated_at": report.generated_at.isoformat(),
        "mission_duration_seconds": report.mission_duration_seconds,
        "findings": [_finding_to_response(f) for f in findings],
        "assets": [_asset_to_response(a) for a in assets],
    }


def _finding_to_response(finding: Any) -> Dict[str, Any]:
    return {
        "id": str(finding.id),
        "title": finding.title,
        "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
        "asset_value": finding.asset_value,
        "cve_id": finding.cve_id,
        "cvss_score": finding.cvss_score,
        "risk_score": finding.risk_score,
        "remediation_steps": finding.remediation_steps,
    }


def _asset_to_response(asset: Any) -> Dict[str, Any]:
    return {
        "id": str(asset.id),
        "value": asset.value,
        "asset_type": asset.asset_type.value if hasattr(asset.asset_type, 'value') else str(asset.asset_type),
        "open_ports": asset.open_ports,
        "services": asset.services,
        "criticality": asset.criticality.value if hasattr(asset.criticality, 'value') else str(asset.criticality),
        "ip_addresses": asset.ip_addresses,
        "hostnames": asset.hostnames,
    }

