"""
Finding Domain Model
====================

A finding is a validated, risk-assessed piece of evidence.
Findings are what get reported to users.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class FindingStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"


class Finding(BaseModel):
    """A validated security finding."""

    id: UUID = Field(default_factory=uuid4)
    title: str
    description: str = ""
    severity: FindingSeverity = FindingSeverity.MEDIUM
    status: FindingStatus = FindingStatus.OPEN
    asset_id: Optional[UUID] = None
    asset_value: str = ""
    asset_type: str = ""
    evidence_ids: List[UUID] = Field(default_factory=list)
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    mitre_technique_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    remediation_steps: List[str] = Field(default_factory=list)
    remediation_effort: str = ""
    remediation_deadline: Optional[datetime] = None
    proof_of_concept: str = ""
    affected_component: str = ""
    affected_url: str = ""
    affected_port: Optional[int] = None
    business_impact: str = ""
    data_classification: str = ""
    internet_exposed: bool = False
    authentication_required: bool = False
    mission_id: Optional[UUID] = None
    project_id: Optional[UUID] = None
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    resolved_at: Optional[datetime] = None
    assigned_to: Optional[str] = None
    discovered_by: str = ""

    model_config = {"extra": "allow"}


__all__ = ["FindingSeverity", "FindingStatus", "Finding"]
