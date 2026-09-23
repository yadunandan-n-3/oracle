"""
Knowledge Graph Service
=======================

Neo4j integration for ORACLE's security knowledge graph.

Stores relationships between assets, evidence, findings, and missions.
Neo4j should answer attack-path questions, not duplicate PostgreSQL.

Relationship types:
    MISSION_DISCOVERED -> Asset
    ASSET_RUNS -> Service
    SERVICE_HAS_VERSION -> Version
    ASSET_HAS_PORT -> Port
    ASSET_HAS_FINDING -> Finding
    ASSET_CONNECTED_TO -> Asset
    FINDING_RELATES_TO -> CVE
    FINDING_MAPS_TO -> MITRE_TECHNIQUE
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
from uuid import UUID

from neo4j import AsyncGraphDatabase, AsyncSession as Neo4jSession
from neo4j.exceptions import ServiceUnavailable

from core.config import settings
from core.logging import get_logger, get_mission_logger
from core.telemetry import telemetry

logger = get_logger(__name__)


class KnowledgeGraphService:
    """
    Neo4j-based knowledge graph for ORACLE.

    Stores and queries relationships between security entities.
    """

    def __init__(self) -> None:
        self._driver = None
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the Neo4j connection."""
        if self._initialized:
            return

        async def _connect() -> None:
            uri = settings.neo4j_uri
            user = settings.neo4j_user
            password = settings.neo4j_password.get_secret_value()

            self._driver = AsyncGraphDatabase.driver(
                uri,
                auth=(user, password),
                max_connection_pool_size=10,
                connection_timeout=5,
            )

            async with self._driver.session() as session:
                result = await session.run("RETURN 1 AS test")
                await result.single()

        try:
            await asyncio.wait_for(_connect(), timeout=2.0)
            self._initialized = True
            logger.info("knowledge.neo4j_connected", uri=settings.neo4j_uri)

        except asyncio.TimeoutError:
            logger.warning("knowledge.neo4j_init_timeout", uri=settings.neo4j_uri)
            if self._driver:
                await self._driver.close()
                self._driver = None
            self._initialized = False
        except ServiceUnavailable as e:
            logger.error("knowledge.neo4j_unavailable", error=str(e))
            self._initialized = False
        except Exception as e:
            logger.error("knowledge.neo4j_init_failed", error=str(e))
            self._initialized = False

    async def close(self) -> None:
        """Close the Neo4j connection."""
        if self._driver:
            await self._driver.close()
            self._driver = None
            self._initialized = False
            logger.info("knowledge.neo4j_disconnected")

    @property
    def is_available(self) -> bool:
        return self._initialized and self._driver is not None

    def session(self) -> Neo4jSession:
        """Get a Neo4j session."""
        if not self._driver:
            raise RuntimeError("Neo4j driver not initialized")
        return self._driver.session()

    async def create_mission_node(self, mission_id: UUID, name: str, mission_type: str) -> None:
        """Create a mission node in the graph."""
        if not self.is_available:
            return
        mid = str(mission_id)
        mission_logger.start_timer(f"graph_create_mission_{mid}")
        try:
            async with self.session() as session:
                await session.run(
                    """
                    MERGE (m:Mission {id: $id})
                    SET m.name = $name, m.type = $type, m.created_at = datetime()
                    """,
                    id=mid, name=name, type=mission_type,
                )
            duration = mission_logger.stop_timer(f"graph_create_mission_{mid}") or 0.0
            telemetry.record_histogram("knowledge.graph.write_latency", duration, {"operation": "create_mission"})
            mission_logger.log_persistence(mid, "neo4j", "completed", duration)
            logger.info("knowledge.mission_node_created", mission_id=mid)
        except Exception as e:
            duration = mission_logger.stop_timer(f"graph_create_mission_{mid}") or 0.0
            mission_logger.log_persistence(mid, "neo4j", "failed", duration, error=str(e))
            raise

    async def update_mission_status(self, mission_id: UUID, status: str) -> None:
        """Update mission node status."""
        if not self.is_available:
            return
        mid = str(mission_id)
        mission_logger.start_timer(f"graph_update_status_{mid}")
        try:
            async with self.session() as session:
                await session.run(
                    """
                    MATCH (m:Mission {id: $id})
                    SET m.status = $status, m.updated_at = datetime()
                    """,
                    id=mid, status=status,
                )
            duration = mission_logger.stop_timer(f"graph_update_status_{mid}") or 0.0
            telemetry.record_histogram("knowledge.graph.write_latency", duration, {"operation": "update_mission_status"})
        except Exception as e:
            mission_logger.stop_timer(f"graph_update_status_{mid}")
            raise

    async def create_asset_node(
        self, asset_id: UUID, mission_id: UUID, asset_type: str, value: str,
        label: str = "", ip_addresses: List[str] = None, hostnames: List[str] = None,
        open_ports: List[int] = None, os: str = "",
    ) -> None:
        """Create an asset node connected to its mission."""
        if not self.is_available:
            return
        async with self.session() as session:
            await session.run(
                """
                MERGE (a:Asset {id: $id})
                SET a.type = $type, a.value = $value, a.label = $label,
                    a.ip_addresses = $ips, a.hostnames = $hostnames,
                    a.open_ports = $ports, a.os = $os, a.created_at = datetime()
                """,
                id=str(asset_id), type=asset_type, value=value, label=label,
                ips=ip_addresses or [], hostnames=hostnames or [],
                ports=open_ports or [], os=os or "",
            )
            await session.run(
                """
                MATCH (m:Mission {id: $mid}) MATCH (a:Asset {id: $aid})
                MERGE (m)-[r:DISCOVERED]->(a) SET r.discovered_at = datetime(), r.confidence = 1.0
                """,
                mid=str(mission_id), aid=str(asset_id),
            )

    async def create_port_node(
        self, asset_id: UUID, port: int, protocol: str,
        service: str = "", service_version: str = "", state: str = "open",
    ) -> None:
        """Create a port node connected to an asset."""
        if not self.is_available:
            return
        port_id = f"{asset_id}:{port}/{protocol}"
        async with self.session() as session:
            await session.run(
                """
                MERGE (p:Port {id: $pid}) SET p.port = $port, p.protocol = $proto,
                    p.service = $svc, p.version = $ver, p.state = $state
                """,
                pid=port_id, port=port, proto=protocol, svc=service, ver=service_version, state=state,
            )
            await session.run(
                "MATCH (a:Asset {id: $aid}) MATCH (p:Port {id: $pid}) MERGE (a)-[r:HAS_PORT]->(p) SET r.discovered_at = datetime()",
                aid=str(asset_id), pid=port_id,
            )
            if service:
                await session.run(
                    """
                    MERGE (s:Service {name: $svc}) SET s.version = $ver
                    WITH s MATCH (p:Port {id: $pid}) MERGE (p)-[r:RUNS]->(s) SET r.detected_at = datetime()
                    """,
                    svc=service, ver=service_version or "", pid=port_id,
                )

    async def create_finding_node(
        self, finding_id: UUID, asset_id: UUID, title: str, severity: str,
        cve_id: str = "", mitre_technique: str = "",
    ) -> None:
        """Create a finding node connected to an asset."""
        if not self.is_available:
            return
        async with self.session() as session:
            await session.run(
                "MERGE (f:Finding {id: $id}) SET f.title = $title, f.severity = $severity, f.created_at = datetime()",
                id=str(finding_id), title=title, severity=severity,
            )
            await session.run(
                "MATCH (a:Asset {id: $aid}) MATCH (f:Finding {id: $fid}) MERGE (a)-[r:HAS_FINDING]->(f) SET r.discovered_at = datetime()",
                aid=str(asset_id), fid=str(finding_id),
            )
            if cve_id:
                await session.run(
                    "MATCH (f:Finding {id: $fid}) MERGE (c:CVE {id: $cve}) MERGE (f)-[r:RELATES_TO]->(c) SET r.mapped_at = datetime()",
                    fid=str(finding_id), cve=cve_id,
                )
            if mitre_technique:
                await session.run(
                    "MATCH (f:Finding {id: $fid}) MERGE (t:MITRE_Technique {id: $tech}) MERGE (f)-[r:MAPS_TO]->(t) SET r.mapped_at = datetime()",
                    fid=str(finding_id), tech=mitre_technique,
                )

    async def create_evidence_node(
        self, evidence_id: UUID, mission_id: UUID, asset_id: Optional[UUID],
        evidence_type: str, title: str, confidence: float,
    ) -> None:
        """Create an evidence node connected to mission and asset."""
        if not self.is_available:
            return
        async with self.session() as session:
            await session.run(
                "MERGE (e:Evidence {id: $id}) SET e.type = $type, e.title = $title, e.confidence = $conf, e.created_at = datetime()",
                id=str(evidence_id), type=evidence_type, title=title, conf=confidence,
            )
            await session.run(
                "MATCH (m:Mission {id: $mid}) MATCH (e:Evidence {id: $eid}) MERGE (m)-[r:HAS_EVIDENCE]->(e)",
                mid=str(mission_id), eid=str(evidence_id),
            )
            if asset_id:
                await session.run(
                    "MATCH (a:Asset {id: $aid}) MATCH (e:Evidence {id: $eid}) MERGE (a)-[r:HAS_EVIDENCE]->(e)",
                    aid=str(asset_id), eid=str(evidence_id),
                )

    async def create_asset_relationship(
        self, source_asset_id: UUID, target_asset_id: UUID,
        relationship_type: str, properties: Dict[str, Any] = None,
    ) -> None:
        """Create a relationship between two assets."""
        if not self.is_available:
            return
        async with self.session() as session:
            await session.run(
                f"MATCH (a:Asset {{id: $sid}}) MATCH (b:Asset {{id: $tid}}) "
                f"MERGE (a)-[r:{relationship_type}]->(b) SET r += $props, r.created_at = datetime()",
                sid=str(source_asset_id), tid=str(target_asset_id), props=properties or {},
            )

    async def get_mission_graph(self, mission_id: UUID) -> Dict[str, Any]:
        """Get the full knowledge graph for a mission."""
        if not self.is_available:
            return {"nodes": [], "relationships": []}
        async with self.session() as session:
            result = await session.run(
                """
                MATCH (m:Mission {id: $mid})
                OPTIONAL MATCH (m)-[:DISCOVERED]->(a:Asset)
                OPTIONAL MATCH (a)-[:HAS_PORT]->(p:Port)
                OPTIONAL MATCH (p)-[:RUNS]->(s:Service)
                OPTIONAL MATCH (a)-[:HAS_FINDING]->(f:Finding)
                OPTIONAL MATCH (f)-[:RELATES_TO]->(c:CVE)
                OPTIONAL MATCH (f)-[:MAPS_TO]->(t:MITRE_Technique)
                RETURN m, collect(DISTINCT a) as assets, collect(DISTINCT p) as ports,
                       collect(DISTINCT s) as services, collect(DISTINCT f) as findings,
                       collect(DISTINCT c) as cves, collect(DISTINCT t) as techniques
                """,
                mid=str(mission_id),
            )
            record = await result.single()
            if not record:
                return {"nodes": [], "relationships": []}

            nodes = []
            relationships = []
            mission = record.get("m")
            if mission:
                nodes.append({"id": mission.get("id"), "label": "Mission", "type": "mission", "properties": dict(mission.items())})
                for asset in record.get("assets", []):
                    nodes.append({"id": asset.get("id"), "label": asset.get("label", asset.get("value")), "type": "asset", "properties": dict(asset.items())})
                    relationships.append({"source": mission.get("id"), "target": asset.get("id"), "type": "DISCOVERED"})
                for port in record.get("ports", []):
                    nodes.append({"id": port.get("id"), "label": f"Port {port.get('port')}/{port.get('protocol', 'tcp')}", "type": "port", "properties": dict(port.items())})
                for svc in record.get("services", []):
                    nodes.append({"id": svc.get("name"), "label": svc.get("name"), "type": "service", "properties": dict(svc.items())})
                for finding in record.get("findings", []):
                    nodes.append({"id": finding.get("id"), "label": finding.get("title"), "type": "finding", "properties": dict(finding.items())})
                for cve in record.get("cves", []):
                    nodes.append({"id": cve.get("id"), "label": cve.get("id"), "type": "cve", "properties": dict(cve.items())})
                for tech in record.get("techniques", []):
                    nodes.append({"id": tech.get("id"), "label": tech.get("id"), "type": "mitre_technique", "properties": dict(tech.items())})
            return {"nodes": nodes, "relationships": relationships}

    async def find_attack_paths(self, mission_id: UUID, max_depth: int = 5) -> List[Dict[str, Any]]:
        """Find potential attack paths in the mission graph."""
        if not self.is_available:
            return []
        async with self.session() as session:
            result = await session.run(
                "MATCH path = (m:Mission {id: $mid})-[:DISCOVERED]->(a:Asset) "
                "OPTIONAL MATCH longer = (a)-[:HAS_PORT|RUNS|HAS_FINDING|CONNECTED_TO*1..$depth]->(n) "
                "RETURN path, longer LIMIT 50",
                mid=str(mission_id), depth=max_depth,
            )
            paths = []
            async for record in result:
                paths.append({"path": str(record.get("path", "")), "longer": str(record.get("longer", ""))})
            return paths

    async def health_check(self) -> Dict[str, Any]:
        """Check Neo4j connectivity."""
        try:
            if not self.is_available:
                return {"healthy": False, "error": "Neo4j not initialized"}
            async with self.session() as session:
                result = await session.run("MATCH (n) RETURN count(n) AS count")
                record = await result.single()
                node_count = record.get("count", 0) if record else 0
            return {"healthy": True, "node_count": node_count, "uri": settings.neo4j_uri}
        except Exception as e:
            return {"healthy": False, "error": str(e)}


# Global singleton
_knowledge_graph: Optional[KnowledgeGraphService] = None


def get_knowledge_graph() -> KnowledgeGraphService:
    """Get or create the global KnowledgeGraphService singleton."""
    global _knowledge_graph
    if _knowledge_graph is None:
        _knowledge_graph = KnowledgeGraphService()
    return _knowledge_graph


__all__ = ["KnowledgeGraphService", "get_knowledge_graph"]
