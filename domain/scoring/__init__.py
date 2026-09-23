"""
Scoring Domain Models
=====================

Models for the Oracle Risk Engine V2 — the 0-100 explainable risk
scoring system that combines CVSS, confidence, exposure, asset
criticality, exploit availability, and business importance.

Also includes the Asset Intelligence model that tracks cumulative
risk state per asset over time.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class RiskLevelV2(str, Enum):
    """Risk levels for the 0-100 scoring system."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class RiskFactorV2(BaseModel):
    """
    A single factor contributing to a risk score in V2.

    Each factor has a name, a raw value (0.0-1.0), a weight,
    an evidence string explaining why this value was assigned,
    and a source identifier.
    """

    name: str
    value: float  # 0.0 to 1.0
    weight: float  # 0.0 to 1.0, sum of all weights = 1.0
    evidence: str = ""
    source: str = ""


class RiskExplanation(BaseModel):
    """
    Human-readable explanation of a risk score.

    Provides the factor breakdown, the overall score, and
    natural-language reasoning for why the score is what it is.
    """

    summary: str
    score: float
    level: RiskLevelV2
    top_factors: List[str] = Field(default_factory=list)
    factor_details: List[RiskFactorV2] = Field(default_factory=list)
    reasoning: str = ""


class OracleRiskScoreV2(BaseModel):
    """
    A calculated risk score using the V2 engine (0-100 scale).

    Includes all contributing factors, the overall score, and
    a human-readable explanation.
    """

    id: UUID = Field(default_factory=uuid4)
    score: float  # 0.0 to 100.0
    level: RiskLevelV2
    factors: List[RiskFactorV2] = Field(default_factory=list)
    calculated_at: datetime = Field(default_factory=datetime.now)
    calculated_by: str = "risk_engine_v2"

    # Context
    asset_id: Optional[UUID] = None
    finding_id: Optional[UUID] = None
    mission_id: Optional[UUID] = None

    # Computed components
    cvss_score: Optional[float] = None
    confidence: float = 0.0
    exposure_score: float = 0.0
    asset_criticality_score: float = 0.0
    internet_facing_score: float = 0.0
    exploit_availability_score: float = 0.0
    business_importance_score: float = 0.0

    # Explanation
    explanation: Optional[RiskExplanation] = None


class AssetIntelligence(BaseModel):
    """
    Tracks the cumulative intelligence state for an asset.

    Instead of findings existing independently, each asset gradually
    accumulates technologies, findings, risk scores, and intelligence
    over time. This is the model that the dashboard and attack path
    analysis will query in Sprint 6+.
    """

    id: UUID = Field(default_factory=uuid4)
    asset_id: UUID
    asset_value: str
    asset_type: str = ""
    mission_id: Optional[UUID] = None

    # Technologies detected
    technologies: Dict[str, str] = Field(default_factory=dict)  # tech -> version
    operating_system: Optional[str] = None
    open_ports: List[int] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    hostnames: List[str] = Field(default_factory=list)
    ip_addresses: List[str] = Field(default_factory=list)

    # Internet facing
    internet_facing: bool = False

    # Findings and risk
    finding_ids: List[UUID] = Field(default_factory=list)
    finding_count: int = 0
    critical_finding_count: int = 0
    high_finding_count: int = 0
    oracle_risk_v1: Optional[float] = None  # 0-10
    oracle_risk_v2: Optional[float] = None  # 0-100
    risk_level: str = "none"

    # Intelligence
    cve_ids: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)

    # Timestamps
    first_seen: datetime = Field(default_factory=datetime.now)
    last_seen: datetime = Field(default_factory=datetime.now)
    last_scan: Optional[datetime] = None

    # Metadata
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "allow"}


class FindingRevision(BaseModel):
    """
    A single revision of a finding over time.

    Enables change tracking and continuous monitoring — you can see
    when a finding was first discovered, when it was last seen, when
    it was remediated, and how its risk score changed over time.
    """

    id: UUID = Field(default_factory=uuid4)
    finding_id: UUID
    version: int = 1
    status: str = "open"  # open, in_progress, resolved, false_positive
    severity: str = "medium"
    risk_score_v1: Optional[float] = None
    risk_score_v2: Optional[float] = None
    risk_level: str = "none"
    evidence_ids: List[UUID] = Field(default_factory=list)
    changed_fields: List[str] = Field(default_factory=list)
    change_reason: str = ""
    captured_at: datetime = Field(default_factory=datetime.now)
    captured_by: str = ""

    model_config = {"extra": "allow"}


class VersionedFinding(BaseModel):
    """
    A finding with its full revision history.

    Wraps a finding and its revisions so you can query the current
    state and the change history in one object.
    """

    finding_id: UUID
    current_version: int = 1
    revisions: List[FindingRevision] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)

    def add_revision(self, revision: FindingRevision) -> None:
        """Add a new revision and bump version."""
        self.revisions.append(revision)
        self.current_version = revision.version
        self.updated_at = datetime.now()

    def get_latest(self) -> Optional[FindingRevision]:
        """Get the most recent revision."""
        if self.revisions:
            return self.revisions[-1]
        return None


__all__ = [
    "RiskLevelV2",
    "RiskFactorV2",
    "RiskExplanation",
    "OracleRiskScoreV2",
    "AssetIntelligence",
    "FindingRevision",
    "VersionedFinding",
]
