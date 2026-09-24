"""
Mission Domain Model
====================

Missions are ORACLE's defining concept.
Users create Missions, not scans. Everything starts from a Mission.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class MissionType(str, Enum):
    """Types of missions ORACLE can execute."""

    EXTERNAL_ATTACK_SURFACE = "external_attack_surface"
    INTERNAL_PENTEST = "internal_pentest"
    API_SECURITY_ASSESSMENT = "api_security_assessment"
    WEB_APPLICATION_SCAN = "web_application_scan"
    CLOUD_AUDIT = "cloud_audit"
    INCIDENT_INVESTIGATION = "incident_investigation"
    THREAT_HUNT = "threat_hunt"
    MALWARE_ANALYSIS = "malware_analysis"
    COMPLIANCE_CHECK = "compliance_check"
    CONTINUOUS_MONITORING = "continuous_monitoring"
    CUSTOM = "custom"


class MissionPriority(str, Enum):
    """Priority level of a mission."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class MissionStatus(str, Enum):
    """Status of a mission in its lifecycle."""

    DRAFT = "draft"
    PENDING = "pending"
    PLANNING = "planning"
    IN_PROGRESS = "in_progress"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class MissionGoal(BaseModel):
    """A single goal within a mission."""

    id: UUID = Field(default_factory=uuid4)
    description: str
    priority: MissionPriority = MissionPriority.MEDIUM
    completed: bool = False
    completed_at: Optional[datetime] = None
    evidence_count: int = 0
    finding_count: int = 0


class MissionTarget(BaseModel):
    """Target scope for a mission."""

    domains: List[str] = Field(default_factory=list)
    ip_ranges: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    api_endpoints: List[str] = Field(default_factory=list)
    cloud_accounts: List[str] = Field(default_factory=list)
    repositories: List[str] = Field(default_factory=list)
    excluded_targets: List[str] = Field(default_factory=list)


class Mission(BaseModel):
    """
    A mission in ORACLE.

    Missions are the highest-level abstraction.
    Users describe what they want to accomplish,
    ORACLE plans and executes the investigation.
    """

    id: UUID = Field(default_factory=uuid4)
    name: str
    description: str = ""
    mission_type: MissionType
    priority: MissionPriority = MissionPriority.MEDIUM
    status: MissionStatus = MissionStatus.DRAFT

    # Goals and scope
    goals: List[MissionGoal] = Field(default_factory=list)
    target: MissionTarget = Field(default_factory=MissionTarget)

    # Organization
    organization_id: Optional[UUID] = None
    project_id: Optional[UUID] = None
    created_by: Optional[str] = None
    assigned_to: Optional[str] = None

    # Policy
    policy_id: Optional[UUID] = None
    allowed_techniques: List[str] = Field(default_factory=list)
    restricted_techniques: List[str] = Field(default_factory=list)

    # Execution
    max_duration_minutes: Optional[int] = None
    schedule: Optional[str] = None  # Cron expression for recurring missions
    auto_remediate: bool = False

    # Results summary
    total_assets_discovered: int = 0
    total_evidence: int = 0
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    overall_risk_score: Optional[float] = None

    # Timeline
    created_at: datetime = Field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    updated_at: datetime = Field(default_factory=datetime.now)

    # Tags
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "allow"}


class MissionTemplate(BaseModel):
    """
    Pre-defined mission template for common security assessments.
    """

    id: UUID = Field(default_factory=uuid4)
    name: str
    description: str
    mission_type: MissionType
    default_goals: List[str] = Field(default_factory=list)
    required_capabilities: List[str] = Field(default_factory=list)
    estimated_duration_minutes: int = 60
    risk_level: str = "low"


# Common mission templates
MISSION_TEMPLATES: List[MissionTemplate] = [
    MissionTemplate(
        name="External Attack Surface Assessment",
        description="Discover and assess all externally-facing assets, services, and vulnerabilities.",
        mission_type=MissionType.EXTERNAL_ATTACK_SURFACE,
        default_goals=[
            "Discover all subdomains and associated IP addresses",
            "Identify open ports and running services",
            "Detect web technologies and frameworks",
            "Find API endpoints and documentation",
            "Identify SSL/TLS misconfigurations",
            "Scan for critical vulnerabilities",
        ],
        required_capabilities=["asset_discovery", "port_scanning", "technology_detection", "vulnerability_scanning"],
        estimated_duration_minutes=120,
    ),
    MissionTemplate(
        name="API Security Assessment",
        description="Comprehensive security assessment of API endpoints including authentication, authorization, and business logic.",
        mission_type=MissionType.API_SECURITY_ASSESSMENT,
        default_goals=[
            "Discover and enumerate API endpoints",
            "Test authentication mechanisms",
            "Test authorization controls",
            "Inspect request/response for sensitive data exposure",
            "Test for common API vulnerabilities (OWASP API Top 10)",
            "Validate rate limiting and input validation",
        ],
        required_capabilities=["api_discovery", "authentication_testing", "fuzzing"],
        estimated_duration_minutes=180,
    ),
    MissionTemplate(
        name="Cloud Security Audit",
        description="Audit cloud infrastructure for misconfigurations, exposed services, and compliance violations.",
        mission_type=MissionType.CLOUD_AUDIT,
        default_goals=[
            "Enumerate cloud resources and services",
            "Identify exposed storage buckets",
            "Review IAM policies and permissions",
            "Check for public-facing resources",
            "Validate encryption and logging configurations",
            "Assess compliance with CIS benchmarks",
        ],
        required_capabilities=["cloud_discovery", "iam_analysis", "compliance_checking"],
        estimated_duration_minutes=240,
    ),
    MissionTemplate(
        name="Incident Investigation",
        description="Investigate a security incident using collected evidence, logs, and indicators of compromise.",
        mission_type=MissionType.INCIDENT_INVESTIGATION,
        default_goals=[
            "Collect and analyze relevant logs",
            "Identify indicators of compromise",
            "Trace attacker movement and techniques",
            "Determine scope of compromise",
            "Recommend containment and remediation steps",
        ],
        required_capabilities=["log_analysis", "ioc_matching", "threat_intelligence"],
        estimated_duration_minutes=120,
    ),
]


__all__ = [
    "MissionType",
    "MissionPriority",
    "MissionStatus",
    "MissionGoal",
    "MissionTarget",
    "Mission",
    "MissionTemplate",
    "MISSION_TEMPLATES",
]
