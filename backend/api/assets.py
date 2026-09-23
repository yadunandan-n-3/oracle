"""
Asset API Routes
================

CRUD operations for discovered assets.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from core.logging import get_logger
from runtime.runtime import get_runtime, OracleRuntime

logger = get_logger(__name__)

router = APIRouter()


# Schemas

class AssetResponse(BaseModel):
    id: str
    asset_type: str
    value: str
    label: str = ""
    description: str = ""
    status: str = "active"
    criticality: str = "unknown"
    ip_addresses: List[str] = []
    hostnames: List[str] = []
    open_ports: List[int] = []
    services: List[str] = []
    technologies: List[str] = []
    tags: List[str] = []


# Routes


@router.get("/missions/{mission_id}")
async def list_mission_assets(
    mission_id: UUID,
    asset_type: Optional[str] = Query(None),
    runtime: OracleRuntime = Depends(get_runtime),
) -> List[Dict[str, Any]]:
    """Get all assets discovered in a mission."""
    state_manager = runtime.state_manager
    assets = state_manager.get_assets(mission_id, asset_type)
    return [_asset_to_response(a) for a in assets]


@router.get("/lookup")
async def get_asset(
    mission_id: UUID = Query(...),
    asset_value: str = Query(...),
    runtime: OracleRuntime = Depends(get_runtime),
) -> Dict[str, Any]:
    """Get a specific asset by its value (IP, domain, URL)."""
    state_manager = runtime.state_manager
    asset = await state_manager.get_asset_by_value(mission_id, asset_value)
    if not asset:
        raise HTTPException(
            status_code=404,
            detail=f"Asset '{asset_value}' not found in mission {mission_id}",
        )
    return _asset_to_response(asset)


def _asset_to_response(asset: Any) -> Dict[str, Any]:
    """Convert an Asset domain model to API response."""
    return {
        "id": str(asset.id),
        "asset_type": asset.asset_type.value,
        "value": asset.value,
        "label": asset.label,
        "description": asset.description,
        "status": asset.status.value,
        "criticality": asset.criticality.value if hasattr(asset.criticality, 'value') else asset.criticality,
        "ip_addresses": asset.ip_addresses,
        "hostnames": asset.hostnames,
        "open_ports": asset.open_ports,
        "services": asset.services,
        "technologies": asset.technologies,
        "tags": asset.tags,
    }
