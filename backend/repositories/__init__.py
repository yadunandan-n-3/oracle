"""
Repository Layer
================

Implements the Repository pattern for ORACLE domain objects.

Every domain object gets a repository that abstracts the database.
The runtime never calls SQLAlchemy directly.

Architecture:
    Runtime / Services
        ↓
    Repository (abstract)
        ↓
    SQLAlchemy ORM
        ↓
    PostgreSQL
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, TypeVar
from uuid import UUID

from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

from backend.models import (
    AssetModel,
    EvidenceModel,
    FindingModel,
    MissionModel,
    OrganizationModel,
    UserModel,
    EventLogModel,
)
from core.exceptions import ResourceNotFoundError
from core.interfaces import Repository
from core.logging import get_logger

logger = get_logger(__name__)

T = TypeVar("T")


class BaseRepository(Repository[T]):
    """Base repository with common CRUD operations."""

    def __init__(self, session: AsyncSession, model_class: type) -> None:
        self._session = session
        self._model = model_class

    async def create(self, data: Dict[str, Any]) -> T:
        """Create a new record."""
        instance = self._model(**data)
        self._session.add(instance)
        await self._session.flush()
        return instance

    async def get(self, id: UUID) -> Optional[T]:
        """Get a record by ID."""
        result = await self._session.execute(
            select(self._model).where(self._model.id == id)
        )
        return result.scalar_one_or_none()

    async def get_or_raise(self, id: UUID) -> T:
        """Get a record by ID or raise."""
        instance = await self.get(id)
        if instance is None:
            model_name = self._model.__name__.replace("Model", "")
            raise ResourceNotFoundError(model_name, str(id))
        return instance

    async def update(self, id: UUID, data: Dict[str, Any]) -> Optional[T]:
        """Update a record."""
        instance = await self.get(id)
        if instance is None:
            return None
        for key, value in data.items():
            if hasattr(instance, key):
                setattr(instance, key, value)
        await self._session.flush()
        return instance

    async def delete(self, id: UUID) -> bool:
        """Delete a record."""
        instance = await self.get(id)
        if instance is None:
            return False
        await self._session.delete(instance)
        await self._session.flush()
        return True

    async def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """Count records with optional filters."""
        query = select(func.count()).select_from(self._model)
        query = self._apply_filters(query, filters)
        result = await self._session.execute(query)
        return result.scalar() or 0

    async def list(
        self,
        filters: Optional[Dict[str, Any]] = None,
        order_by: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[T]:
        """List records with optional filtering."""
        query = select(self._model)
        query = self._apply_filters(query, filters)
        if order_by:
            column = getattr(self._model, order_by.lstrip("-"), None)
            if column:
                if order_by.startswith("-"):
                    query = query.order_by(column.desc())
                else:
                    query = query.order_by(column.asc())
        query = query.offset(offset).limit(limit)
        result = await self._session.execute(query)
        return list(result.scalars().all())

    def _apply_filters(
        self, query: Select, filters: Optional[Dict[str, Any]] = None
    ) -> Select:
        """Apply filters to a query."""
        if not filters:
            return query
        for key, value in filters.items():
            column = getattr(self._model, key, None)
            if column is not None:
                if isinstance(value, (list, tuple)):
                    query = query.where(column.in_(value))
                elif isinstance(value, dict):
                    if "gt" in value:
                        query = query.where(column > value["gt"])
                    if "gte" in value:
                        query = query.where(column >= value["gte"])
                    if "lt" in value:
                        query = query.where(column < value["lt"])
                    if "lte" in value:
                        query = query.where(column <= value["lte"])
                    if "ne" in value:
                        query = query.where(column != value["ne"])
                    if "like" in value:
                        query = query.where(column.like(f"%{value['like']}%"))
                else:
                    query = query.where(column == value)
        return query


class OrganizationRepository(BaseRepository):
    """Repository for Organization operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, OrganizationModel)


class UserRepository(BaseRepository):
    """Repository for User operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, UserModel)

    async def get_by_email(self, email: str) -> Optional[UserModel]:
        """Get a user by email."""
        result = await self._session.execute(
            select(UserModel).where(UserModel.email == email)
        )
        return result.scalar_one_or_none()


class MissionRepository(BaseRepository):
    """Repository for Mission operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, MissionModel)

    async def list_with_filters(
        self,
        organization_id: Optional[UUID] = None,
        status: Optional[str] = None,
        mission_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[MissionModel]:
        """List missions with domain-specific filters."""
        filters = {}
        if organization_id:
            filters["organization_id"] = organization_id
        if status:
            filters["status"] = status
        if mission_type:
            filters["mission_type"] = mission_type
        return await self.list(
            filters=filters or None,
            order_by="-created_at",
            limit=limit,
            offset=offset,
        )

    async def update_progress(
        self,
        mission_id: UUID,
        assets_discovered: int = 0,
        findings: int = 0,
        critical: int = 0,
        high: int = 0,
        medium: int = 0,
        low: int = 0,
    ) -> MissionModel:
        """Update mission progress counters."""
        mission = await self.get_or_raise(mission_id)
        mission.total_assets_discovered += assets_discovered
        mission.total_findings += findings
        mission.critical_findings += critical
        mission.high_findings += high
        mission.medium_findings += medium
        mission.low_findings += low
        await self._session.flush()
        return mission


class AssetRepository(BaseRepository):
    """Repository for Asset operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, AssetModel)

    async def get_by_value(self, mission_id: UUID, value: str) -> Optional[AssetModel]:
        """Get an asset by its value within a mission."""
        result = await self._session.execute(
            select(AssetModel).where(
                and_(
                    AssetModel.mission_id == mission_id,
                    AssetModel.value == value,
                )
            )
        )
        return result.scalar_one_or_none()

    async def list_by_mission(
        self,
        mission_id: UUID,
        asset_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AssetModel]:
        """List assets for a mission with optional type filter."""
        filters = {"mission_id": mission_id}
        if asset_type:
            filters["asset_type"] = asset_type
        return await self.list(
            filters=filters,
            order_by="-first_seen_at",
            limit=limit,
            offset=offset,
        )

    async def upsert(self, mission_id: UUID, data: Dict[str, Any]) -> AssetModel:
        """Create or update an asset by mission_id + value."""
        value = data.get("value")
        existing = await self.get_by_value(mission_id, value) if value else None
        if existing:
            for key, val in data.items():
                if hasattr(existing, key) and key not in ("id", "mission_id", "created_at"):
                    setattr(existing, key, val)
            await self._session.flush()
            return existing
        else:
            data["mission_id"] = mission_id
            instance = AssetModel(**data)
            self._session.add(instance)
            await self._session.flush()
            return instance


class EvidenceRepository(BaseRepository):
    """Repository for Evidence operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, EvidenceModel)

    async def list_by_mission(
        self,
        mission_id: UUID,
        evidence_type: Optional[str] = None,
        asset_id: Optional[UUID] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[EvidenceModel]:
        """List evidence for a mission with optional filters."""
        filters = {"mission_id": mission_id}
        if evidence_type:
            filters["evidence_type"] = evidence_type
        if asset_id:
            filters["asset_id"] = asset_id
        return await self.list(
            filters=filters,
            order_by="-collected_at",
            limit=limit,
            offset=offset,
        )

    async def get_by_hash(self, hash_value: str) -> Optional[EvidenceModel]:
        """Get evidence by its dedup hash."""
        result = await self._session.execute(
            select(EvidenceModel).where(EvidenceModel.hash == hash_value)
        )
        return result.scalar_one_or_none()


class FindingRepository(BaseRepository):
    """Repository for Finding operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, FindingModel)

    async def list_by_mission(
        self,
        mission_id: UUID,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[FindingModel]:
        """List findings with optional filters."""
        filters = {"mission_id": mission_id}
        if severity:
            filters["severity"] = severity
        if status:
            filters["status"] = status
        return await self.list(
            filters=filters,
            order_by="-discovered_at",
            limit=limit,
            offset=offset,
        )


class EventLogRepository(BaseRepository):
    """Repository for Event Log operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, EventLogModel)

    async def list_by_mission(
        self,
        mission_id: UUID,
        limit: int = 100,
        offset: int = 0,
    ) -> List[EventLogModel]:
        """List event log entries for a mission."""
        return await self.list(
            filters={"mission_id": mission_id},
            order_by="-timestamp",
            limit=limit,
            offset=offset,
        )

    async def log_event(
        self,
        mission_id: UUID,
        event_type: str,
        source: str = "",
        data: Dict[str, Any] = None,
        correlation_id: str = "",
    ) -> EventLogModel:
        """Log an event to the mission timeline."""
        return await self.create({
            "mission_id": mission_id,
            "event_type": event_type,
            "source": source,
            "data": data or {},
            "correlation_id": correlation_id,
        })


__all__ = [
    "BaseRepository",
    "OrganizationRepository",
    "UserRepository",
    "MissionRepository",
    "AssetRepository",
    "EvidenceRepository",
    "FindingRepository",
    "EventLogRepository",
]
