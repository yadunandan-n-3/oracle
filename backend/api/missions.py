"""
Mission API Routes
==================

CRUD operations for ORACLE missions.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from core.exceptions import ResourceNotFoundError, ValidationError
from core.logging import get_logger
from domain.mission import Mission, MissionStatus, MissionTarget, MissionType
from runtime.runtime import get_runtime, OracleRuntime

logger = get_logger(__name__)

router = APIRouter()


def _get_runtime() -> OracleRuntime:
    """Dependency injection for the Runtime."""
    return get_runtime()


# ─── Request/Response Schemas ─────────────────────────────────────────────

from pydantic import BaseModel, Field


class CreateMissionRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = ""
    mission_type: str = "external_attack_surface"
    priority: str = "medium"
    target_domains: List[str] = Field(default_factory=list)
    target_ip_ranges: List[str] = Field(default_factory=list)
    target_urls: List[str] = Field(default_factory=list)
    goals: List[str] = Field(default_factory=list)
    organization_id: Optional[str] = None
    project_id: Optional[str] = None


class MissionResponse(BaseModel):
    id: str
    name: str
    description: str
    mission_type: str
    priority: str
    status: str
    total_assets_discovered: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    tags: List[str] = []


# ─── Routes ───────────────────────────────────────────────────────────────

@router.post("", response_model=MissionResponse, status_code=201)
async def create_mission(
    request: CreateMissionRequest,
    runtime: OracleRuntime = Depends(_get_runtime),
) -> Dict[str, Any]:
    """Create a new security mission."""
    try:
        mission_type = MissionType(request.mission_type)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid mission type: {request.mission_type}. Valid types: {[t.value for t in MissionType]}",
        )

    target = MissionTarget(
        domains=request.target_domains,
        ip_ranges=request.target_ip_ranges,
        urls=request.target_urls,
    )

    mission = await runtime.create_mission(
        name=request.name,
        mission_type=mission_type,
        target=target,
        description=request.description,
        goals=request.goals or None,
        priority=request.priority,
        organization_id=UUID(request.organization_id) if request.organization_id else None,
        project_id=UUID(request.project_id) if request.project_id else None,
    )

    return _mission_to_response(mission)


@router.get("")
async def list_missions(
    status: Optional[str] = Query(None),
    mission_type: Optional[str] = Query(None),
    organization_id: Optional[str] = Query(None),
    sort_by: str = Query("created_at", description="Sort field: created_at, name, status, priority, mission_type"),
    sort_order: str = Query("desc", description="Sort order: asc or desc"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    runtime: OracleRuntime = Depends(_get_runtime),
) -> Dict[str, Any]:
    """List all missions with optional filtering, sorting, and pagination."""
    missions = runtime.list_missions(
        organization_id=UUID(organization_id) if organization_id else None,
        status=MissionStatus(status) if status else None,
        mission_type=MissionType(mission_type) if mission_type else None,
        limit=10000,  # Get all for sorting — consider adding sort to runtime in future
        offset=0,
    )

    # Apply sorting
    valid_sort_fields = {"created_at", "name", "status", "priority", "mission_type"}
    if sort_by not in valid_sort_fields:
        sort_by = "created_at"

    reverse = sort_order.lower() == "desc"
    missions.sort(
        key=lambda m: (
            getattr(m, sort_by, "") if hasattr(m, sort_by) else str(getattr(m, sort_by, ""))
        ),
        reverse=reverse,
    )

    total = len(missions)
    paged = missions[offset : offset + limit]
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
        "missions": [_mission_to_response(m) for m in paged],
    }


@router.get("/{mission_id}", response_model=MissionResponse)
async def get_mission(
    mission_id: UUID,
    runtime: OracleRuntime = Depends(_get_runtime),
) -> Dict[str, Any]:
    """Get a specific mission by ID."""
    mission = runtime.get_mission(mission_id)
    if not mission:
        raise HTTPException(status_code=404, detail=f"Mission {mission_id} not found")
    return _mission_to_response(mission)


@router.post("/{mission_id}/execute")
async def execute_mission(
    mission_id: UUID,
    runtime: OracleRuntime = Depends(_get_runtime),
) -> Dict[str, Any]:
    """Start executing a mission."""
    mission = runtime.get_mission(mission_id)
    if not mission:
        raise HTTPException(status_code=404, detail=f"Mission {mission_id} not found")

    await runtime.execute_mission(mission_id)
    return {"status": "started", "mission_id": str(mission_id)}


@router.post("/{mission_id}/cancel")
async def cancel_mission(
    mission_id: UUID,
    runtime: OracleRuntime = Depends(_get_runtime),
) -> Dict[str, Any]:
    """Cancel a running mission."""
    await runtime.cancel_mission(mission_id)
    return {"status": "cancelled", "mission_id": str(mission_id)}


@router.get("/{mission_id}/state")
async def get_mission_state(
    mission_id: UUID,
    runtime: OracleRuntime = Depends(_get_runtime),
) -> Dict[str, Any]:
    """Get the live state of a mission."""
    state = runtime.get_mission_state(mission_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Mission state for {mission_id} not found")
    return state


@router.get("/{mission_id}/timeline")
async def get_mission_timeline(
    mission_id: UUID,
    limit: int = Query(100, ge=1, le=1000),
    runtime: OracleRuntime = Depends(_get_runtime),
) -> List[Dict[str, Any]]:
    """Get the event timeline for a mission."""
    state = await runtime.state_manager.get_mission_state(mission_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Mission {mission_id} not found")

    return state.events[-limit:]


# ─── Helpers ──────────────────────────────────────────────────────────────

def _mission_to_response(mission: Mission) -> Dict[str, Any]:
    """Convert a Mission domain model to API response."""
    return {
        "id": str(mission.id),
        "name": mission.name,
        "description": mission.description,
        "mission_type": mission.mission_type.value,
        "priority": mission.priority.value,
        "status": mission.status.value,
        "total_assets_discovered": mission.total_assets_discovered,
        "total_findings": mission.total_findings,
        "critical_findings": mission.critical_findings,
        "high_findings": mission.high_findings,
        "medium_findings": mission.medium_findings,
        "low_findings": mission.low_findings,
        "created_at": mission.created_at.isoformat(),
        "started_at": mission.started_at.isoformat() if mission.started_at else None,
        "completed_at": mission.completed_at.isoformat() if mission.completed_at else None,
        "tags": mission.tags,
    }
