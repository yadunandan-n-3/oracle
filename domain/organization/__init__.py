"""
Organization Domain Model
=========================

Organization, project, and team management.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class OrganizationTier(str, Enum):
    """Pricing/service tier for an organization."""

    FREE = "free"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"


class Organization(BaseModel):
    """
    An organization using ORACLE.
    """

    id: UUID = Field(default_factory=uuid4)
    name: str
    slug: str = ""
    description: str = ""
    tier: OrganizationTier = OrganizationTier.FREE
    is_active: bool = True
    settings: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)


class Project(BaseModel):
    """
    A project within an organization.
    Projects group missions, assets, and findings.
    """

    id: UUID = Field(default_factory=uuid4)
    organization_id: UUID
    name: str
    description: str = ""
    is_active: bool = True
    tags: List[str] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)


__all__ = [
    "OrganizationTier",
    "Organization",
    "Project",
]
