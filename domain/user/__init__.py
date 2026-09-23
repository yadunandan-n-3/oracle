"""
User Domain Model
=================

User accounts, authentication, and authorization.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class UserRole(str, Enum):
    """Roles within the ORACLE system."""

    ADMIN = "admin"
    SECURITY_ENGINEER = "security_engineer"
    ANALYST = "analyst"
    VIEWER = "viewer"
    AUDITOR = "auditor"


class User(BaseModel):
    """
    A user of the ORACLE system.
    """

    id: UUID = Field(default_factory=uuid4)
    email: str
    name: str = ""
    role: UserRole = UserRole.VIEWER
    organization_id: Optional[UUID] = None
    is_active: bool = True
    is_verified: bool = False
    permissions: List[str] = Field(default_factory=list)
    preferences: Dict[str, Any] = Field(default_factory=dict)
    last_login_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)


class Session(BaseModel):
    """
    An authenticated user session.
    """

    id: UUID = Field(default_factory=uuid4)
    user_id: UUID
    token: str = ""
    refresh_token: str = ""
    expires_at: datetime
    ip_address: str = ""
    user_agent: str = ""
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.now)


__all__ = [
    "UserRole",
    "User",
    "Session",
]
