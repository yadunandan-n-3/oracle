"""
Knowledge Graph API Routes
==========================

Expose Neo4j knowledge graph data to the frontend.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from core.logging import get_logger
from runtime.runtime import get_runtime, OracleRuntime

logger = get_logger(__name__)

router = APIRouter()


@router.get("/mission/{mission_id}")
async def get_mission_graph(
    mission_id: UUID,
    runtime: OracleRuntime = Depends(get_runtime),
) -> Dict[str, Any]:
    """Get the full knowledge graph for a mission."""
    kg = runtime.knowledge_graph
    if not kg.is_available:
        # Return empty graph instead of error
        return {"nodes": [], "relationships": [], "available": False}

    try:
        graph = await kg.get_mission_graph(mission_id)
        graph["available"] = True
        return graph
    except Exception as e:
        logger.error("graph.api_failed", mission_id=str(mission_id), error=str(e))
        return {"nodes": [], "relationships": [], "available": False, "error": str(e)}


@router.get("/mission/{mission_id}/attack-paths")
async def get_attack_paths(
    mission_id: UUID,
    max_depth: int = Query(5, ge=1, le=10, description="Maximum path depth"),
    runtime: OracleRuntime = Depends(get_runtime),
) -> Dict[str, Any]:
    """Find potential attack paths in the mission graph."""
    kg = runtime.knowledge_graph
    if not kg.is_available:
        return {"paths": [], "available": False}

    try:
        paths = await kg.find_attack_paths(mission_id, max_depth=max_depth)
        return {"paths": paths, "available": True, "max_depth": max_depth}
    except Exception as e:
        logger.error("graph.attack_paths_failed", mission_id=str(mission_id), error=str(e))
        return {"paths": [], "available": False, "error": str(e)}


@router.get("/mission/{mission_id}/assets/{asset_id}/connections")
async def get_asset_connections(
    mission_id: UUID,
    asset_id: UUID,
    runtime: OracleRuntime = Depends(get_runtime),
) -> Dict[str, Any]:
    """Get connections for a specific asset in the knowledge graph."""
    kg = runtime.knowledge_graph
    if not kg.is_available:
        return {"nodes": [], "relationships": [], "available": False}

    try:
        graph = await kg.get_mission_graph(mission_id)
        # Filter to only show the requested asset and its connections
        asset_node = None
        connected_nodes = []
        connections = []

        for node in graph.get("nodes", []):
            if node.get("id") == str(asset_id):
                asset_node = node
                break

        if asset_node:
            connected_ids = {str(asset_id)}
            for rel in graph.get("relationships", []):
                if rel.get("source") == str(asset_id):
                    connected_ids.add(rel.get("target"))
                elif rel.get("target") == str(asset_id):
                    connected_ids.add(rel.get("source"))

            for node in graph.get("nodes", []):
                if node.get("id") in connected_ids:
                    connected_nodes.append(node)

            for rel in graph.get("relationships", []):
                if rel.get("source") == str(asset_id) or rel.get("target") == str(asset_id):
                    connections.append(rel)

        return {
            "nodes": connected_nodes,
            "relationships": connections,
            "available": True,
            "center_asset": asset_node,
        }
    except Exception as e:
        logger.error("graph.connections_failed", asset_id=str(asset_id), error=str(e))
        return {"nodes": [], "relationships": [], "available": False, "error": str(e)}


@router.get("/health")
async def graph_health(
    runtime: OracleRuntime = Depends(get_runtime),
) -> Dict[str, Any]:
    """Check knowledge graph connectivity."""
    kg = runtime.knowledge_graph
    try:
        health = await kg.health_check()
        return health
    except Exception as e:
        return {"healthy": False, "error": str(e)}


@router.get("/mission/{mission_id}/summary")
async def get_graph_summary(
    mission_id: UUID,
    runtime: OracleRuntime = Depends(get_runtime),
) -> Dict[str, Any]:
    """Get a summary of the knowledge graph for a mission."""
    kg = runtime.knowledge_graph
    if not kg.is_available:
        return {"available": False, "node_count": 0, "relationship_count": 0}

    try:
        graph = await kg.get_mission_graph(mission_id)
        nodes = graph.get("nodes", [])
        rels = graph.get("relationships", [])

        # Count by type
        node_types = {}
        for node in nodes:
            ntype = node.get("type", "unknown")
            node_types[ntype] = node_types.get(ntype, 0) + 1

        rel_types = {}
        for rel in rels:
            rtype = rel.get("type", "unknown")
            rel_types[rtype] = rel_types.get(rtype, 0) + 1

        return {
            "available": True,
            "node_count": len(nodes),
            "relationship_count": len(rels),
            "node_types": node_types,
            "relationship_types": rel_types,
        }
    except Exception as e:
        logger.error("graph.summary_failed", mission_id=str(mission_id), error=str(e))
        return {"available": False, "error": str(e), "node_count": 0, "relationship_count": 0}

