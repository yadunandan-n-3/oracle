"""
Universal Search API
====================

Search across all ORACLE entities: missions, assets, findings, reports, CVEs, and MITRE techniques.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from core.logging import get_logger
from runtime.runtime import get_runtime, OracleRuntime

logger = get_logger(__name__)

router = APIRouter()


@router.get("")
async def universal_search(
    q: str = Query(..., min_length=1, max_length=200, description="Search query"),
    entity_types: Optional[str] = Query(None, description="Comma-separated entity types to search (missions,assets,findings,cves,mitre)"),
    limit: int = Query(20, ge=1, le=100),
    runtime: OracleRuntime = Depends(get_runtime),
) -> Dict[str, Any]:
    """Search across all ORACLE entities."""
    query = q.lower().strip()
    types = entity_types.split(",") if entity_types else ["missions", "assets", "findings", "cves", "mitre"]

    results = {
        "query": q,
        "missions": [],
        "assets": [],
        "findings": [],
        "cves": [],
        "mitre": [],
    }

    state_manager = runtime.state_manager

    # Search missions
    if "missions" in types:
        for mission_state in state_manager._states.values():
            mission = mission_state.mission
            if (query in mission.name.lower() or
                query in mission.description.lower() or
                query in mission.mission_type.value.lower()):
                results["missions"].append({
                    "id": str(mission.id),
                    "name": mission.name,
                    "description": mission.description[:200] if mission.description else "",
                    "mission_type": mission.mission_type.value if hasattr(mission.mission_type, 'value') else str(mission.mission_type),
                    "status": mission.status.value if hasattr(mission.status, 'value') else str(mission.status),
                    "match": "name" if query in mission.name.lower() else "description",
                })

    # Search assets
    if "assets" in types:
        for mission_state in state_manager._states.values():
            mid = mission_state.mission.id
            assets = state_manager.get_assets(mid)
            for asset in assets:
                if (query in asset.value.lower() or
                    query in asset.label.lower() or
                    query in str(asset.open_ports) or
                    any(query in s.lower() for s in asset.services) or
                    any(query in t.lower() for t in asset.tags)):
                    results["assets"].append({
                        "id": str(asset.id),
                        "value": asset.value,
                        "label": asset.label,
                        "asset_type": asset.asset_type.value if hasattr(asset.asset_type, 'value') else str(asset.asset_type),
                        "mission_id": str(mid),
                        "ip_addresses": asset.ip_addresses[:3],
                        "open_ports": asset.open_ports[:5],
                        "services": asset.services[:3],
                    })

    # Search findings
    if "findings" in types:
        for mission_state in state_manager._states.values():
            mid = mission_state.mission.id
            findings = state_manager.get_findings(mid)
            for finding in findings:
                if (query in finding.title.lower() or
                    query in (finding.description or "").lower() or
                    (finding.cve_id and query in finding.cve_id.lower()) or
                    (finding.cwe_id and query in finding.cwe_id.lower()) or
                    query in finding.asset_value.lower() or
                    any(query in t.lower() for t in finding.tags)):
                    results["findings"].append({
                        "id": str(finding.id),
                        "title": finding.title,
                        "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                        "status": finding.status.value if hasattr(finding.status, 'value') else str(finding.status),
                        "asset_value": finding.asset_value,
                        "cve_id": finding.cve_id,
                        "mission_id": str(mid),
                        "risk_score": finding.risk_score,
                    })

    # Search CVEs in knowledge graph
    if "cves" in types and runtime.knowledge_graph.is_available:
        try:
            for mission_state in state_manager._states.values():
                mid = mission_state.mission.id
                graph = await runtime.knowledge_graph.get_mission_graph(mid)
                for node in graph.get("nodes", []):
                    if node.get("type") == "cve" and query in str(node.get("id", "")).lower():
                        results["cves"].append({
                            "id": node.get("id"),
                            "label": node.get("label", node.get("id")),
                            "properties": node.get("properties", {}),
                            "mission_id": str(mid),
                        })
        except Exception as e:
            logger.warning("search.cve_search_failed", error=str(e))

    # Search MITRE techniques in knowledge graph
    if "mitre" in types and runtime.knowledge_graph.is_available:
        try:
            for mission_state in state_manager._states.values():
                mid = mission_state.mission.id
                graph = await runtime.knowledge_graph.get_mission_graph(mid)
                for node in graph.get("nodes", []):
                    if node.get("type") == "mitre_technique" and query in str(node.get("id", "")).lower():
                        results["mitre"].append({
                            "id": node.get("id"),
                            "label": node.get("label", node.get("id")),
                            "properties": node.get("properties", {}),
                            "mission_id": str(mid),
                        })
        except Exception as e:
            logger.warning("search.mitre_search_failed", error=str(e))

    # Sort results by relevance (exact matches first)
    for category in results:
        results[category] = sorted(
            results[category],
            key=lambda x: 0 if query == str(x.get("name", x.get("value", x.get("title", x.get("id", ""))))).lower() else 1,
        )[:limit]

    total = sum(len(results[k]) for k in results)
    return {
        "query": q,
        "total_results": total,
        "results": results,
    }

