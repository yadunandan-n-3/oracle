"""
Intelligence Domain Models
==========================

Business objects for threat intelligence, enrichment, and the
Security Intelligence Service layer.

These models bridge raw evidence to enriched findings that are
consumed by the Risk Engine, AI Explanation Engine, and Report Generator.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class CVSSSeverity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CVEInfo(BaseModel):
    """Information about a specific CVE."""

    cve_id: str
    description: str = ""
    cvss_score: Optional[float] = None
    cvss_severity: CVSSSeverity = CVSSSeverity.NONE
    cvss_vector: str = ""
    cwe_ids: List[str] = Field(default_factory=list)
    affected_software: List[str] = Field(default_factory=list)
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None
    published_date: Optional[datetime] = None
    last_modified_date: Optional[datetime] = None
    references: List[str] = Field(default_factory=list)
    source: str = "nvd"

    model_config = {"extra": "allow"}


class CWEInfo(BaseModel):
    """Information about a specific CWE."""

    cwe_id: str
    name: str = ""
    description: str = ""
    extended_description: str = ""
    likelihood_of_exploit: str = "unknown"
    detection_methods: List[str] = Field(default_factory=list)
    remediation_phases: List[str] = Field(default_factory=list)

    model_config = {"extra": "allow"}


class OWASPInfo(BaseModel):
    """OWASP Top 10 mapping for a CWE or weakness."""

    owasp_id: str  # e.g., "A01:2021"
    category: str = ""
    description: str = ""
    cwe_mappings: List[str] = Field(default_factory=list)
    risk_rating: str = ""

    model_config = {"extra": "allow"}


class EPSSInfo(BaseModel):
    """Exploit Prediction Scoring System information."""

    cve_id: str
    epss_score: float = 0.0  # 0.0 to 1.0
    percentile: float = 0.0  # 0.0 to 1.0
    date: Optional[datetime] = None
    source: str = "first"

    model_config = {"extra": "allow"}


class KEVInfo(BaseModel):
    """CISA Known Exploited Vulnerabilities catalog entry."""

    cve_id: str
    vendor_project: str = ""
    product: str = ""
    vulnerability_name: str = ""
    date_added: Optional[datetime] = None
    short_description: str = ""
    required_action: str = ""
    due_date: Optional[datetime] = None
    known_ransomware_use: bool = False
    notes: str = ""

    model_config = {"extra": "allow"}


class MitreIntelInfo(BaseModel):
    """MITRE ATT&CK intelligence for a finding."""

    technique_id: str
    technique_name: str = ""
    tactic: str = ""
    tactic_id: str = ""
    confidence: float = 0.0
    matched_on: List[str] = Field(default_factory=list)

    model_config = {"extra": "allow"}


class ThreatIntelligence(BaseModel):
    """
    Aggregated threat intelligence for a single CVE or finding.
    Combines CVE, CWE, OWASP, EPSS, KEV, and MITRE data.
    """

    cve: Optional[CVEInfo] = None
    cwe: Optional[CWEInfo] = None
    owasp: Optional[OWASPInfo] = None
    epss: Optional[EPSSInfo] = None
    kev: Optional[KEVInfo] = None
    mitre: List[MitreIntelInfo] = Field(default_factory=list)
    enriched_at: datetime = Field(default_factory=datetime.now)

    model_config = {"extra": "allow"}


class EnrichedFinding(BaseModel):
    """
    A finding enriched with threat intelligence, correlation metadata,
    risk scoring, and AI explanation.

    This is the central object produced by the Security Intelligence Service
    and consumed by the Risk Engine, AI Explanation Engine, and Report Generator.
    It avoids each downstream component performing its own enrichment logic.
    """

    id: UUID = Field(default_factory=uuid4)
    finding_id: UUID
    mission_id: Optional[UUID] = None
    asset_id: Optional[UUID] = None

    # Original finding data
    title: str
    description: str = ""
    severity: str = "medium"
    confidence: float = 0.0
    asset_value: str = ""
    asset_type: str = ""
    evidence_ids: List[UUID] = Field(default_factory=list)

    # Technology & service context
    technology: Optional[str] = None
    version: Optional[str] = None
    service: Optional[str] = None
    port: Optional[int] = None
    protocol: str = "tcp"
    hostname: Optional[str] = None
    ip_address: Optional[str] = None

    # Correlation
    correlation_confidence: float = 0.0
    correlation_sources: List[str] = Field(default_factory=list)

    # Threat intelligence
    threat_intelligence: Optional[ThreatIntelligence] = None

    # Risk
    risk_score_v1: Optional[float] = None  # 0-10 from RiskEngine
    risk_score_v2: Optional[float] = None  # 0-100 from RiskEngineV2
    risk_level: str = "none"

    # AI explanation
    ai_explanation: Optional[Dict[str, Any]] = None

    # Business context
    internet_exposed: bool = False
    authentication_required: bool = False
    asset_criticality: str = "unknown"
    business_importance: str = "medium"
    data_classification: str = "internal"

    # Remediation
    remediation_steps: List[str] = Field(default_factory=list)
    remediation_effort: str = ""

    # Tags and metadata
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)

    model_config = {"extra": "allow"}


__all__ = [
    "CVSSSeverity",
    "CVEInfo",
    "CWEInfo",
    "OWASPInfo",
    "EPSSInfo",
    "KEVInfo",
    "MitreIntelInfo",
    "ThreatIntelligence",
    "EnrichedFinding",
]

