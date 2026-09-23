"""
SQLAlchemy ORM Models
=====================

Database models for ORACLE.
Maps domain objects to PostgreSQL tables.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    ARRAY,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.asyncio import AsyncAttrs, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(AsyncAttrs, DeclarativeBase):
    """Base class for all ORM models."""
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def generate_uuid() -> uuid.UUID:
    return uuid.uuid4()


# ─── Organization ─────────────────────────────────────────────────────────


class OrganizationModel(Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    slug: Mapped[Optional[str]] = mapped_column(String(255), unique=True)
    domain: Mapped[Optional[str]] = mapped_column(String(255))
    plan: Mapped[str] = mapped_column(String(50), default="free")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    settings: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


# ─── User ────────────────────────────────────────────────────────────────


class UserModel(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), default="")
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="viewer")
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("organizations.id"))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


# ─── Mission ──────────────────────────────────────────────────────────────


class MissionModel(Base):
    __tablename__ = "missions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    mission_type: Mapped[str] = mapped_column(String(50), nullable=False)
    priority: Mapped[str] = mapped_column(String(20), default="medium")
    status: Mapped[str] = mapped_column(String(20), default="draft")

    # Target scope
    target_domains: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)
    target_ip_ranges: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)
    target_urls: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)
    target_api_endpoints: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)
    target_excluded: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)
    allowed_techniques: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)
    restricted_techniques: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)

    # Organization
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("organizations.id"))
    project_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True))
    created_by: Mapped[Optional[str]] = mapped_column(String(255))
    assigned_to: Mapped[Optional[str]] = mapped_column(String(255))

    # Execution
    max_duration_minutes: Mapped[Optional[int]] = mapped_column(Integer)
    schedule: Mapped[Optional[str]] = mapped_column(String(100))
    auto_remediate: Mapped[bool] = mapped_column(Boolean, default=False)

    # Results
    total_assets_discovered: Mapped[int] = mapped_column(Integer, default=0)
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    critical_findings: Mapped[int] = mapped_column(Integer, default=0)
    high_findings: Mapped[int] = mapped_column(Integer, default=0)
    medium_findings: Mapped[int] = mapped_column(Integer, default=0)
    low_findings: Mapped[int] = mapped_column(Integer, default=0)
    overall_risk_score: Mapped[Optional[float]] = mapped_column(Float)

    # Goals
    goals: Mapped[Dict[str, Any]] = mapped_column(JSON, default=list)

    # Timeline
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Tags & metadata
    tags: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)
    metadata_: Mapped[Dict[str, Any]] = mapped_column("metadata", JSON, default=dict)

    # Relationships
    assets = relationship("AssetModel", back_populates="mission", lazy="selectin")
    evidence_list = relationship("EvidenceModel", back_populates="mission", lazy="selectin")


# ─── Asset ────────────────────────────────────────────────────────────────


class AssetModel(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("mission_id", "value"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    mission_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("missions.id"), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(50), nullable=False)
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    label: Mapped[str] = mapped_column(String(255), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="active")
    criticality: Mapped[str] = mapped_column(String(20), default="unknown")
    ip_addresses: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)
    hostnames: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)
    domains: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)
    open_ports: Mapped[List[int]] = mapped_column(ARRAY(Integer), default=list)
    services: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)
    technologies: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)
    mac_address: Mapped[Optional[str]] = mapped_column(String(17))
    os: Mapped[Optional[str]] = mapped_column(String(255))
    os_version: Mapped[Optional[str]] = mapped_column(String(100))
    tags: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)
    metadata_: Mapped[Dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Relationships
    mission = relationship("MissionModel", back_populates="assets")
    evidence_list = relationship("EvidenceModel", back_populates="asset", lazy="selectin")


# ─── Evidence ─────────────────────────────────────────────────────────────


class EvidenceModel(Base):
    __tablename__ = "evidence"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    mission_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("missions.id"), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="collected")
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(20), default="informational")

    # Source
    source_tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    source_tool_version: Mapped[str] = mapped_column(String(50), default="")
    source_command: Mapped[str] = mapped_column(Text, default="")
    source_agent_name: Mapped[str] = mapped_column(String(100), default="")
    source_execution_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True))

    # Asset
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id"))
    asset_value: Mapped[str] = mapped_column(String(255), default="")

    # Data
    raw_data: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    normalized_data: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)

    # Correlations
    correlated_evidence_ids: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)

    # Security references
    cve_ids: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)
    cwe_ids: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)
    mitre_techniques: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)

    # Validation
    validated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    validated_by: Mapped[Optional[str]] = mapped_column(String(100))
    validation_method: Mapped[str] = mapped_column(String(100), default="")

    # Dedup hash
    hash: Mapped[Optional[str]] = mapped_column(String(64))

    # Tags & metadata
    tags: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)
    metadata_: Mapped[Dict[str, Any]] = mapped_column("metadata", JSON, default=dict)

    # Timeline
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Relationships
    mission = relationship("MissionModel", back_populates="evidence_list")
    asset = relationship("AssetModel", back_populates="evidence_list")


# ─── Finding ──────────────────────────────────────────────────────────────


class FindingModel(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    mission_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("missions.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    status: Mapped[str] = mapped_column(String(20), default="open")

    # Asset
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id"))
    asset_value: Mapped[str] = mapped_column(String(255), default="")
    asset_type: Mapped[str] = mapped_column(String(50), default="")

    # Evidence
    evidence_ids: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)

    # Vuln references
    cve_id: Mapped[Optional[str]] = mapped_column(String(20))
    cwe_id: Mapped[Optional[str]] = mapped_column(String(20))
    cvss_score: Mapped[Optional[float]] = mapped_column(Float)
    cvss_vector: Mapped[str] = mapped_column(String(100), default="")
    mitre_technique_id: Mapped[Optional[str]] = mapped_column(String(20))
    mitre_tactic: Mapped[Optional[str]] = mapped_column(String(50))

    # Remediation
    remediation_steps: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)
    remediation_effort: Mapped[str] = mapped_column(String(50), default="")
    remediation_deadline: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    proof_of_concept: Mapped[str] = mapped_column(Text, default="")

    # Context
    affected_component: Mapped[str] = mapped_column(String(255), default="")
    affected_url: Mapped[str] = mapped_column(Text, default="")
    affected_port: Mapped[Optional[int]] = mapped_column(Integer)
    business_impact: Mapped[str] = mapped_column(Text, default="")
    data_classification: Mapped[str] = mapped_column(String(50), default="")
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False)
    authentication_required: Mapped[bool] = mapped_column(Boolean, default=False)

    # Risk
    risk_score: Mapped[Optional[float]] = mapped_column(Float)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)

    # Audit
    discovered_by: Mapped[str] = mapped_column(String(100), default="")
    assigned_to: Mapped[Optional[str]] = mapped_column(String(100))
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # Timeline
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Tags & metadata
    tags: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)
    metadata_: Mapped[Dict[str, Any]] = mapped_column("metadata", JSON, default=dict)


# ─── Event Log ────────────────────────────────────────────────────────────


class EventLogModel(Base):
    __tablename__ = "event_log"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    mission_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("missions.id"))
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    source: Mapped[str] = mapped_column(String(100), default="")
    data: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(100))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


__all__ = [
    "Base",
    "OrganizationModel",
    "UserModel",
    "MissionModel",
    "AssetModel",
    "EvidenceModel",
    "FindingModel",
    "EventLogModel",
]
