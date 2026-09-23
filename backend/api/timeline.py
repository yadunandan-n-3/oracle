"""
Timeline API Routes
===================

Mission event timeline with structured steps.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from core.logging import get_logger
from runtime.runtime import get_runtime, OracleRuntime

logger = get_logger(__name__)

router = APIRouter()


# Define the standard mission pipeline steps
MISSION_PIPELINE_STEPS = [
    {"id": "created", "label": "Mission Created", "icon": "create", "description": "Mission is defined and scoped"},
    {"id": "planning", "label": "Planning", "icon": "plan", "description": "Breaking goals into executable tasks"},
    {"id": "discovery", "label": "Discovery", "icon": "search", "description": "Asset discovery and enumeration"},
    {"id": "nmap_scan", "label": "Nmap Scan", "icon": "scan", "description": "Port scanning and service detection"},
    {"id": "nuclei_scan", "label": "Nuclei Scan", "icon": "vulnerability", "description": "Vulnerability scanning"},
    {"id": "correlation", "label": "Correlation", "icon": "correlate", "description": "Correlating evidence across tools"},
    {"id": "threat_intel", "label": "Threat Intelligence", "icon": "intel", "description": "Enriching with CVE, EPSS, KEV data"},
    {"id": "risk_assessment", "label": "Risk Assessment", "icon": "risk", "description": "Scoring and prioritizing findings"},
    {"id": "ai_explanation", "label": "AI Explanation", "icon": "ai", "description": "Generating AI-powered explanations"},
    {"id": "report", "label": "Report", "icon": "report", "description": "Generating final report"},
]


@router.get("/mission/{mission_id}")
async def get_mission_timeline(
    mission_id: UUID,
    limit: int = Query(200, ge=1, le=1000),
    runtime: OracleRuntime = Depends(get_runtime),
) -> Dict[str, Any]:
    """Get the event timeline for a mission with structured pipeline steps."""
    state_manager = runtime.state_manager
    state = await state_manager.get_mission_state(mission_id)

    if not state:
        raise HTTPException(status_code=404, detail=f"Mission {mission_id} not found")

    # Get raw events from state
    raw_events = state.events[-limit:] if state.events else []

    # Build enriched timeline with pipeline step mapping
    events = []
    for event in raw_events:
        enriched_event = {
            "timestamp": event.get("timestamp", ""),
            "event_type": event.get("event_type", ""),
            "data": event.get("data", {}),
            "pipeline_step": _map_event_to_pipeline_step(event.get("event_type", "")),
        }
        events.append(enriched_event)

    # Determine which pipeline steps have been completed
    pipeline_status = []
    for step in MISSION_PIPELINE_STEPS:
        step_events = [e for e in events if e["pipeline_step"] == step["id"]]
        step_status = "pending"
        if step_events:
            # Check the last event type for completion status
            last_event = step_events[-1]
            event_type = last_event["event_type"]
            if "failed" in event_type:
                step_status = "failed"
            elif "completed" in event_type or "report" in event_type:
                step_status = "completed"
            else:
                step_status = "in_progress"

        pipeline_status.append({
            **step,
            "status": step_status,
            "event_count": len(step_events),
            "events": step_events[-5:] if step_events else [],  # Last 5 events per step
        })

    return {
        "mission_id": str(mission_id),
        "mission_name": state.mission.name,
        "mission_status": state.mission.status.value if hasattr(state.mission.status, 'value') else str(state.mission.status),
        "total_events": len(raw_events),
        "pipeline_steps": pipeline_status,
        "events": events,
    }


@router.get("/pipeline-steps")
async def get_pipeline_steps() -> Dict[str, Any]:
    """Get the standard mission pipeline steps definition."""
    return {
        "pipeline_steps": MISSION_PIPELINE_STEPS,
        "description": "Standard ORACLE mission execution pipeline",
    }


def _map_event_to_pipeline_step(event_type: str) -> str:
    """Map event types to pipeline steps."""
    mapping = {
        "mission.created": "created",
        "mission.planned": "planning",
        "discovery": "discovery",
        "asset.discovered": "discovery",
        "scan.started": "nmap_scan",
        "scan.completed": "nmap_scan",
        "scan.failed": "nmap_scan",
        "nuclei": "nuclei_scan",
        "vulnerability": "nuclei_scan",
        "evidence.correlated": "correlation",
        "finding.correlated": "correlation",
        "finding.enriched": "threat_intel",
        "threat_intel": "threat_intel",
        "risk.assessed": "risk_assessment",
        "risk": "risk_assessment",
        "ai_explanation": "ai_explanation",
        "explanation": "ai_explanation",
        "report.generated": "report",
        "mission.completed": "report",
    }

    for key, step in mapping.items():
        if key in event_type:
            return step
    return "unknown"

