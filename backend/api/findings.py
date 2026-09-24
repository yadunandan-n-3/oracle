"""
Findings API Routes
===================

CRUD operations for security findings.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Literal, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from core.logging import get_logger
from domain.finding import FindingStatus
from runtime.runtime import get_runtime, OracleRuntime

logger = get_logger(__name__)

router = APIRouter()


@router.get("")
async def list_findings(
    mission_id: Optional[UUID] = Query(None, description="Filter by mission ID"),
    severity: Optional[str] = Query(None, description="Filter by severity (critical, high, medium, low, informational)"),
    status: Optional[str] = Query(None, description="Filter by status (open, in_progress, resolved, accepted, false_positive)"),
    asset_id: Optional[UUID] = Query(None, description="Filter by asset ID"),
    sort_by: Literal["severity", "risk_score", "discovered_at", "title", "status"] = Query(
        "risk_score",
        description="Sort field: severity, risk_score, discovered_at, title, status",
    ),
    sort_order: Literal["asc", "desc"] = Query("desc", description="Sort order: asc or desc"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    runtime: OracleRuntime = Depends(get_runtime),
) -> Dict[str, Any]:
    """List findings with optional filtering, sorting, and pagination."""
    state_manager = runtime.state_manager

    persisted = await runtime.get_authoritative_findings(
        mission_id=mission_id,
        severity=severity,
        status=status,
    )
    if persisted is not None:
        all_findings = persisted
    else:
        all_findings = []
        target_ids = [mission_id] if mission_id else state_manager.get_mission_ids()
        for mid in target_ids:
            all_findings.extend(state_manager.get_findings(
                mid,
                severity=severity,
                status=status,
            ))

    if asset_id is not None:
        all_findings = [finding for finding in all_findings if finding.asset_id == asset_id]

    # Apply sorting
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    reverse = sort_order.lower() == "desc"

    if sort_by == "severity":
        all_findings.sort(
            key=lambda f: severity_order.get(
                f.severity.value if hasattr(f.severity, 'value') else str(f.severity), 5
            ),
            reverse=not reverse,  # Severity: critical = 0, so for desc we want reverse=False
        )
    elif sort_by == "risk_score":
        all_findings.sort(
            key=lambda f: (f.risk_score or 0) if f.risk_score is not None else (-1 if reverse else float('inf')),
            reverse=reverse,
        )
    elif sort_by == "title":
        all_findings.sort(
            key=lambda f: f.title.lower(),
            reverse=reverse,
        )
    elif sort_by == "status":
        all_findings.sort(
            key=lambda f: f.status.value if hasattr(f.status, 'value') else str(f.status),
            reverse=reverse,
        )
    else:  # discovered_at
        all_findings.sort(
            key=lambda f: f.discovered_at.isoformat() if hasattr(f, 'discovered_at') and f.discovered_at else "",
            reverse=reverse,
        )

    total = len(all_findings)
    paged = all_findings[offset:offset + limit]
    page = (offset // limit) + 1 if limit > 0 else 1
    total_pages = max(1, (total + limit - 1) // limit) if limit > 0 else 1

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "page": page,
        "total_pages": total_pages,
        "has_next": offset + limit < total,
        "has_prev": offset > 0,
        "findings": [_finding_to_response(f) for f in paged],
    }


@router.get("/{finding_id:uuid}")
async def get_finding(
    finding_id: UUID,
    runtime: OracleRuntime = Depends(get_runtime),
) -> Dict[str, Any]:
    """Get a specific finding by ID."""
    persisted = await runtime.get_authoritative_finding(finding_id)
    if persisted is not None:
        return _finding_to_response(persisted)

    state_manager = runtime.state_manager

    # Search across all active missions
    for mission_state in state_manager._states.values():
        findings = state_manager.get_findings(mission_state.mission.id)
        for finding in findings:
            if finding.id == finding_id:
                return _finding_to_response(finding)

    raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")


@router.patch("/{finding_id:uuid}/status")
async def update_finding_status(
    finding_id: UUID,
    status: str = Query(..., description="New status (open, in_progress, resolved, accepted, false_positive)"),
    runtime: OracleRuntime = Depends(get_runtime),
) -> Dict[str, Any]:
    """Update the status of a finding."""
    # Validate status
    valid_statuses = {"open", "in_progress", "resolved", "accepted", "false_positive"}
    if status not in valid_statuses:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid status '{status}'. Valid: {', '.join(sorted(valid_statuses))}",
        )

    state_manager = runtime.state_manager
    for mission_state in state_manager._states.values():
        findings = state_manager.get_findings(mission_state.mission.id)
        for finding in findings:
            if finding.id == finding_id:
                finding.status = FindingStatus(status)
                finding.updated_at = datetime.now(timezone.utc)  # Touch timestamp
                return _finding_to_response(finding)

    raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")


@router.get("/stats/summary")
async def get_findings_summary(
    mission_id: Optional[UUID] = Query(None, description="Filter by mission ID"),
    runtime: OracleRuntime = Depends(get_runtime),
) -> Dict[str, Any]:
    """Get aggregate statistics for findings."""
    state_manager = runtime.state_manager
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    status_counts = {"open": 0, "in_progress": 0, "resolved": 0, "accepted": 0, "false_positive": 0}
    total = 0

    missions_to_check = []
    if mission_id:
        missions_to_check.append(mission_id)
    else:
        missions_to_check = list(state_manager._states.keys())

    for mid in missions_to_check:
        findings = state_manager.get_findings(mid)
        for finding in findings:
            sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            st = finding.status.value if hasattr(finding.status, 'value') else str(finding.status)
            if sev in severity_counts:
                severity_counts[sev] += 1
            if st in status_counts:
                status_counts[st] += 1
            total += 1

    return {
        "total": total,
        "by_severity": severity_counts,
        "by_status": status_counts,
    }


def _finding_to_response(finding: Any) -> Dict[str, Any]:
    """Convert a Finding domain model to API response."""
    metadata = getattr(finding, "metadata_", None)
    if metadata is None:
        metadata = getattr(finding, "metadata", {}) or {}
    risk_v2 = metadata.get("risk_v2", {})
    threat_intelligence = metadata.get("threat_intelligence", {})
    risk_level = getattr(finding, "risk_level", None) or risk_v2.get("level", "none")
    risk_factors = getattr(finding, "risk_factors", None) or risk_v2.get("factors", [])
    risk_explanation = (
        getattr(finding, "risk_explanation", None)
        or risk_v2.get("explanation")
    )
    calculation = (
        getattr(finding, "risk_calculation_metadata", None)
        or {
            "risk_id": risk_v2.get("id"),
            "calculated_at": risk_v2.get("calculated_at"),
            "calculated_by": risk_v2.get("calculated_by"),
            "engine": "OracleRiskScoreV2" if risk_v2 else None,
        }
    )
    return {
        "id": str(finding.id),
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
        "status": finding.status.value if hasattr(finding.status, 'value') else str(finding.status),
        "asset_id": str(finding.asset_id) if finding.asset_id else None,
        "asset_value": finding.asset_value,
        "asset_type": finding.asset_type,
        "cve_id": finding.cve_id,
        "cwe_id": finding.cwe_id,
        "cvss_score": finding.cvss_score,
        "cvss_vector": finding.cvss_vector,
        "mitre_technique_id": finding.mitre_technique_id,
        "mitre_tactic": finding.mitre_tactic,
        "remediation_steps": finding.remediation_steps,
        "remediation_effort": finding.remediation_effort,
        "affected_component": finding.affected_component,
        "affected_url": finding.affected_url,
        "affected_port": finding.affected_port,
        "business_impact": finding.business_impact,
        "internet_exposed": finding.internet_exposed,
        "authentication_required": finding.authentication_required,
        "risk_score": finding.risk_score,
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "risk_explanation": risk_explanation,
        "risk_calculation_metadata": calculation,
        "intelligence_status": metadata.get("intelligence_status", "not_processed"),
        "threat_intelligence": threat_intelligence,
        "confidence": getattr(finding, "confidence", None),
        "evidence_ids": [str(eid) for eid in (finding.evidence_ids or [])],
        "mission_id": str(finding.mission_id) if finding.mission_id else None,
        "tags": finding.tags,
        "discovered_at": finding.discovered_at.isoformat() if hasattr(finding, 'discovered_at') else None,
        "updated_at": finding.updated_at.isoformat() if hasattr(finding, 'updated_at') else None,
    }

