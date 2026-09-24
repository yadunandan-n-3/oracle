"""
Reports API Routes
==================

Generate, list, and retrieve security reports.
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from core.logging import get_logger
from domain.finding import Finding
from domain.mission import Mission, MissionTarget
from domain.report import ReportFormat, ReportType
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
    persisted_missions = await runtime.get_authoritative_missions()
    if persisted_missions is not None:
        missions = persisted_missions
    else:
        missions = [state.mission for state in state_manager.get_all_states().values()]
    if mission_id:
        missions = [mission for mission in missions if mission.id == UUID(mission_id)]

    for mission in missions:
        if mission:
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
    persisted_mission = await runtime.get_authoritative_mission(mission_id)
    if persisted_mission is not None:
        mission = _as_domain_mission(persisted_mission)
    elif state:
        mission = state.mission
    else:
        mission = runtime.get_mission(mission_id)
        if not mission:
            raise HTTPException(status_code=404, detail=f"Mission {mission_id} not found")

    # Get findings and assets from state manager
    persisted_findings = await runtime.get_authoritative_findings(mission_id=mission_id)
    raw_findings = (
        persisted_findings
        if persisted_findings is not None
        else (state_manager.get_findings(mission_id) if state else [])
    )
    findings = [_as_domain_finding(finding) for finding in raw_findings]
    persisted_assets = await runtime.get_authoritative_assets(mission_id)
    assets = (
        persisted_assets
        if persisted_assets is not None
        else (state_manager.get_assets(mission_id) if state else [])
    )

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
        return {
            "format": "html",
            "content": html,
            "title": report.title,
            "risk_score": mission.overall_risk_score,
            "risk_score_scale": 100,
        }

    overall_risk = mission.overall_risk_score
    if overall_risk is None:
        overall_risk = max(
            (finding.risk_score for finding in findings if finding.risk_score is not None),
            default=None,
        )
    if overall_risk is None:
        overall_level = "none"
    elif overall_risk >= 85:
        overall_level = "critical"
    elif overall_risk >= 70:
        overall_level = "high"
    elif overall_risk >= 40:
        overall_level = "medium"
    elif overall_risk > 0:
        overall_level = "low"
    else:
        overall_level = "none"

    return {
        "id": str(report.id),
        "title": report.title,
        "report_type": report.report_type.value,
        "format": report.format.value,
        "mission_id": str(report.mission_id) if report.mission_id else None,
        "mission_name": report.mission_name,
        "executive_summary": report.executive_summary,
        "findings_summary": report.findings_summary,
        "risk_score": overall_risk,
        "risk_score_scale": 100,
        "risk_level": overall_level,
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
    metadata = getattr(finding, "metadata", {}) or {}
    return {
        "id": str(finding.id),
        "title": finding.title,
        "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
        "asset_value": finding.asset_value,
        "cve_id": finding.cve_id,
        "cvss_score": finding.cvss_score,
        "risk_score": finding.risk_score,
        "risk_level": finding.risk_level,
        "risk_factors": finding.risk_factors,
        "risk_explanation": finding.risk_explanation,
        "intelligence_status": metadata.get("intelligence_status", "not_processed"),
        "remediation_steps": finding.remediation_steps,
    }


def _as_domain_finding(finding: Any) -> Finding:
    """Hydrate a persisted ORM finding for the domain report generator."""
    if isinstance(finding, Finding):
        return finding
    data: Dict[str, Any] = {}
    for field_name in Finding.model_fields:
        source_name = "metadata_" if field_name == "metadata" else field_name
        if hasattr(finding, source_name):
            data[field_name] = getattr(finding, source_name)
    risk_v2 = data.get("metadata", {}).get("risk_v2", {})
    data["risk_level"] = risk_v2.get("level", "none")
    data["risk_factors"] = risk_v2.get("factors", [])
    data["risk_explanation"] = risk_v2.get("explanation")
    data["risk_calculation_metadata"] = {
        "risk_id": risk_v2.get("id"),
        "calculated_at": risk_v2.get("calculated_at"),
        "calculated_by": risk_v2.get("calculated_by"),
        "engine": "OracleRiskScoreV2" if risk_v2 else None,
    }
    return Finding.model_validate(data)


def _as_domain_mission(mission: Any) -> Mission:
    """Hydrate a persisted ORM mission for restart-safe report generation."""
    if isinstance(mission, Mission):
        return mission
    data: Dict[str, Any] = {}
    for field_name in Mission.model_fields:
        source_name = "metadata_" if field_name == "metadata" else field_name
        if hasattr(mission, source_name):
            data[field_name] = getattr(mission, source_name)
    data["target"] = MissionTarget(
        domains=list(mission.target_domains or []),
        ip_ranges=list(mission.target_ip_ranges or []),
        urls=list(mission.target_urls or []),
        api_endpoints=list(mission.target_api_endpoints or []),
        excluded_targets=list(mission.target_excluded or []),
    )
    return Mission.model_validate(data)


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

