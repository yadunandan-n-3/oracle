"""
Asset Domain Model
==================

Represents a digital asset discovered or managed by ORACLE.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, IPvAnyAddress


class AssetType(str, Enum):
    """Types of assets ORACLE can discover and manage."""

    HOST = "host"
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    SUBNET = "subnet"
    WEB_APPLICATION = "web_application"
    API = "api"
    ENDPOINT = "endpoint"
    CONTAINER = "container"
    CLOUD_INSTANCE = "cloud_instance"
    CLOUD_SERVICE = "cloud_service"
    DATABASE = "database"
    STORAGE = "storage"
    CERTIFICATE = "certificate"
    DNS_RECORD = "dns_record"
    LOAD_BALANCER = "load_balancer"
    FIREWALL = "firewall"


class AssetCriticality(str, Enum):
    """Criticality level of an asset."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"
    NONE = "none"


class AssetStatus(str, Enum):
    """Status of an asset."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    MAINTENANCE = "maintenance"
    DECOMMISSIONED = "decommissioned"
    UNKNOWN = "unknown"


class Asset(BaseModel):
    """
    Represents a digital asset discovered or managed by ORACLE.

    Assets are the core entities that ORACLE discovers during missions.
    They can be hosts, domains, services, or other digital resources.
    """

    id: UUID = Field(default_factory=uuid4)
    asset_type: AssetType
    value: str
    label: str = ""
    description: str = ""
    status: AssetStatus = AssetStatus.ACTIVE
    criticality: AssetCriticality = AssetCriticality.UNKNOWN
    ip_addresses: List[str] = Field(default_factory=list)
    hostnames: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    open_ports: List[int] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    technologies: Dict[str, List[str]] = Field(default_factory=dict)
    mac_address: Optional[str] = None
    os: Optional[str] = None
    os_version: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    first_seen_at: datetime = Field(default_factory=datetime.now)
    last_seen_at: datetime = Field(default_factory=datetime.now)
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)

    model_config = {"extra": "allow"}


__all__ = [
    "AssetType",
    "AssetCriticality",
    "AssetStatus",
    "Asset",
]
