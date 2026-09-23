"""
Service Layer
=============

Connects the ORACLE Runtime to PostgreSQL via the Repository pattern.

Services coordinate operations between the runtime and persistence,
providing a clean API for the runtime to store and retrieve data.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from backend.models import (
    AssetModel,
    EvidenceModel,
    FindingModel,
    MissionModel,
    EventLogModel,
)
from backend.repositories import (
    AssetRepository,
    EvidenceRepository,
    EventLogRepository,
    FindingRepository,
    MissionRepository,
    OrganizationRepository,
    UserRepository,
)
from core.events import EventType
from core.logging import get_logger
from domain.asset import Asset
from domain.evidence import Evidence
from domain.mission import Mission, MissionStatus, MissionTarget

logger = get_logger(__name__)


class MissionService:
    """Service for mission persistence operations."""

    def __init__(self, session: AsyncSession) -> None:
        self._mission_repo = MissionRepository(session)
        self._asset_repo = AssetRepository(session)
        self._evidence_repo = EvidenceRepository(session)
        self._finding_repo = FindingRepository(session)
        self._event_log_repo = EventLogRepository(session)
        self._session = session

    # ─── Mission Operations ──────────────────────────────────────────────

    async def create_mission(self, mission: Mission) -> MissionModel:
        """Persist a new mission to PostgreSQL."""
        data = {
            "id": mission.id,
            "name": mission.name,
            "description": mission.description,
            "mission_type": mission.mission_type.value,
            "priority": mission.priority.value,
            "status": mission.status.value,
            "target_domains": mission.target.domains,
            "target_ip_ranges": mission.target.ip_ranges,
            "target_urls": mission.target.urls,
            "organization_id": mission.organization_id,
            "created_by": mission.created_by,
            "allowed_techniques": mission.allowed_techniques,
            "restricted_techniques": mission.restricted_techniques,
            "max_duration_minutes": mission.max_duration_minutes,
            "schedule": mission.schedule,
            "auto_remediate": mission.auto_remediate,
            "tags": mission.tags,
            "goals": [g.model_dump() for g in mission.goals],
            "metadata_": mission.metadata,
        }
        return await self._mission_repo.create(data)

    async def get_mission(self, mission_id: UUID) -> Optional[MissionModel]:
        """Get a mission by ID."""
        return await self._mission_repo.get(mission_id)

    async def update_mission_status(
        self, mission_id: UUID, status: MissionStatus
    ) -> MissionModel:
        """Update mission status."""
        data = {"status": status.value}
        if status == MissionStatus.IN_PROGRESS:
            from datetime import datetime, timezone
            data["started_at"] = datetime.now(timezone.utc)
        elif status in (MissionStatus.COMPLETED, MissionStatus.FAILED, MissionStatus.CANCELLED):
            from datetime import datetime, timezone
            data["completed_at"] = datetime.now(timezone.utc)
        return await self._mission_repo.update(mission_id, data)

    async def list_missions(
        self,
        organization_id: Optional[UUID] = None,
        status: Optional[str] = None,
        mission_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[MissionModel]:
        """List missions with filters."""
        return await self._mission_repo.list_with_filters(
            organization_id=organization_id,
            status=status,
            mission_type=mission_type,
            limit=limit,
            offset=offset,
        )

    # ─── Asset Operations ────────────────────────────────────────────────

    async def upsert_asset(self, mission_id: UUID, asset: Asset) -> AssetModel:
        """Persist an asset (create or update)."""
        data = {
            "id": asset.id,
            "asset_type": asset.asset_type.value,
            "value": asset.value,
            "label": asset.label,
            "description": asset.description,
            "status": asset.status.value if hasattr(asset.status, 'value') else asset.status,
            "criticality": asset.criticality.value if hasattr(asset.criticality, 'value') else asset.criticality,
            "ip_addresses": asset.ip_addresses,
            "hostnames": asset.hostnames,
            "domains": asset.domains,
            "open_ports": asset.open_ports,
            "services": asset.services,
            "technologies": list(asset.technologies) if hasattr(asset, 'technologies') else [],
            "os": asset.os if hasattr(asset, 'os') else None,
            "tags": asset.tags,
        }
        return await self._asset_repo.upsert(mission_id, data)

    async def list_assets(
        self,
        mission_id: UUID,
        asset_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AssetModel]:
        """List assets for a mission."""
        return await self._asset_repo.list_by_mission(
            mission_id, asset_type, limit, offset
        )

    # ─── Evidence Operations ─────────────────────────────────────────────

    async def create_evidence(self, mission_id: UUID, evidence: Evidence) -> EvidenceModel:
        """Persist a piece of evidence."""
        data = {
            "id": evidence.id,
            "mission_id": mission_id,
            "evidence_type": evidence.evidence_type.value if hasattr(evidence.evidence_type, 'value') else evidence.evidence_type,
            "status": evidence.status.value if hasattr(evidence.status, 'value') else "collected",
            "title": evidence.title,
            "description": evidence.description,
            "confidence": evidence.confidence,
            "severity": evidence.severity,
            "source_tool_name": evidence.source.tool_name if hasattr(evidence, 'source') else "unknown",
            "source_tool_version": evidence.source.tool_version if hasattr(evidence, 'source') and hasattr(evidence.source, 'tool_version') else "",
            "source_command": evidence.source.command if hasattr(evidence, 'source') and hasattr(evidence.source, 'command') else "",
            "source_agent_name": evidence.source.agent_name if hasattr(evidence, 'source') and hasattr(evidence.source, 'agent_name') else "",
            "asset_id": evidence.asset_id,
            "asset_value": evidence.asset_value,
            "raw_data": evidence.raw_data,
            "normalized_data": evidence.normalized_data,
            "cve_ids": evidence.cve_ids,
            "cwe_ids": evidence.cwe_ids,
            "mitre_techniques": evidence.mitre_techniques,
            "hash": evidence.hash if hasattr(evidence, 'hash') and evidence.hash else "",
            "tags": evidence.tags,
        }
        return await self._evidence_repo.create(data)

    async def list_evidence(
        self,
        mission_id: UUID,
        evidence_type: Optional[str] = None,
        asset_id: Optional[UUID] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[EvidenceModel]:
        """List evidence for a mission."""
        return await self._evidence_repo.list_by_mission(
            mission_id, evidence_type, asset_id, limit, offset
        )

    # ─── Event Log Operations ───────────────────────────────────────────

    async def log_event(
        self,
        mission_id: UUID,
        event_type: str,
        source: str = "",
        data: Dict[str, Any] = None,
    ) -> EventLogModel:
        """Log an event to the mission timeline."""
        return await self._event_log_repo.log_event(
            mission_id=mission_id,
            event_type=event_type,
            source=source,
            data=data or {},
        )

    async def get_timeline(
        self,
        mission_id: UUID,
        limit: int = 100,
        offset: int = 0,
    ) -> List[EventLogModel]:
        """Get the event timeline for a mission."""
        return await self._event_log_repo.list_by_mission(
            mission_id, limit, offset
        )


__all__ = ["MissionService"]
