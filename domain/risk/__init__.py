"""
Risk Domain Model
=================

Contextual risk assessment for findings, assets, and missions.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Risk levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class RiskFactor(BaseModel):
    """A single factor contributing to a risk score."""

    name: str
    value: float  # 0.0 to 1.0
    weight: float  # 0.0 to 1.0, sum of all weights = 1.0
    evidence: str = ""
    source: str = ""


class RiskScore(BaseModel):
    """
    A calculated risk score for an asset, finding, or mission.
    """

    id: UUID = Field(default_factory=uuid4)
    score: float  # 0.0 to 10.0
    level: RiskLevel
    factors: List[RiskFactor] = Field(default_factory=list)
    calculated_at: datetime = Field(default_factory=datetime.now)
    calculated_by: str = "risk_engine"

    # Context
    asset_id: Optional[UUID] = None
    finding_id: Optional[UUID] = None
    mission_id: Optional[UUID] = None

    # Components
    likelihood: float = 0.0  # 0.0 to 1.0
    impact: float = 0.0  # 0.0 to 1.0
    cvss_score: Optional[float] = None
    exploit_maturity: str = "unknown"  # none, proof_of_concept, weaponized, active
    threat_intelligence_score: Optional[float] = None


class RiskAssessment(BaseModel):
    """
    Full risk assessment for a mission.
    """

    id: UUID = Field(default_factory=uuid4)
    mission_id: UUID
    overall_score: float = 0.0
    overall_level: RiskLevel = RiskLevel.NONE
    asset_risk_scores: Dict[str, float] = Field(default_factory=dict)
    finding_risk_scores: Dict[str, float] = Field(default_factory=dict)
    top_risks: List[RiskScore] = Field(default_factory=list)
    risk_distribution: Dict[str, int] = Field(default_factory=dict)
    assessed_at: datetime = Field(default_factory=datetime.now)


__all__ = [
    "RiskLevel",
    "RiskFactor",
    "RiskScore",
    "RiskAssessment",
]
