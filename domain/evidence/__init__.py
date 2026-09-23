"""
Evidence Domain Model
=====================

The universal data model for ORACLE.
Everything becomes evidence — raw output, parsed findings, validated results.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class EvidenceType(str, Enum):
    """Types of evidence in the ORACLE system."""

    # Network evidence
    OPEN_PORT = "open_port"
    SERVICE = "service"
    BANNER = "banner"
    CERTIFICATE = "certificate"
    DNS_RECORD = "dns_record"

    # Web evidence
    HTTP_ENDPOINT = "http_endpoint"
    API_ENDPOINT = "api_endpoint"
    FORM = "form"
    COOKIE = "cookie"
    HEADER = "header"
    JAVASCRIPT = "javascript"
    TECHNOLOGY = "technology"

    # Vulnerability evidence
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    EXPOSURE = "exposure"
    WEAK_CREDENTIAL = "weak_credential"

    # Cloud evidence
    OPEN_BUCKET = "open_bucket"
    UNRESTRICTED_SG = "unrestricted_security_group"
    EXPOSED_SECRET = "exposed_secret"
    IAM_ISSUE = "iam_issue"

    # Application evidence
    DEPENDENCY = "dependency"
    SECRET_SCAN = "secret_scan"
    CODE_ISSUE = "code_issue"

    # Malware evidence
    MALWARE_SAMPLE = "malware_sample"
    IOC = "ioc"
    YARA_MATCH = "yara_match"

    # Generic
    RAW_OUTPUT = "raw_output"
    CORRELATED = "correlated"
    MANUAL = "manual"


class EvidenceConfidence(str, Enum):
    """Confidence level of evidence."""

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"
    DISPUTED = "disputed"
    FALSE_POSITIVE = "false_positive"


class EvidenceSource(BaseModel):
    """Provenance information for evidence."""

    tool_name: str
    tool_version: str = ""
    command: str = ""
    arguments: Dict[str, Any] = Field(default_factory=dict)
    agent_name: str = ""
    execution_id: Optional[UUID] = None
    raw_output_hash: Optional[str] = None


class EvidenceStatus(str, Enum):
    """Status of evidence in lifecycle."""

    COLLECTED = "collected"
    VALIDATED = "validated"
    CORRELATED = "correlated"
    DISPUTED = "disputed"
    CONFIRMED = "confirmed"


class Evidence(BaseModel):
    """
    Universal evidence model.

    Every finding, observation, and data point in ORACLE
    is represented as Evidence.
    """

    id: UUID = Field(default_factory=uuid4)
    evidence_type: EvidenceType
    status: EvidenceStatus = EvidenceStatus.COLLECTED
    title: str
    description: str = ""
    confidence: float = 0.0
    severity: str = "informational"
    source: EvidenceSource = Field(default_factory=lambda: EvidenceSource(tool_name="unknown"))
    asset_id: Optional[UUID] = None
    asset_value: str = ""
    mission_id: Optional[UUID] = None
    project_id: Optional[UUID] = None
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    normalized_data: Dict[str, Any] = Field(default_factory=dict)
    collected_at: datetime = Field(default_factory=datetime.now)
    validated_at: Optional[datetime] = None
    validated_by: Optional[str] = None
    validation_method: str = ""
    correlated_evidence_ids: List[UUID] = Field(default_factory=list)
    cve_ids: List[str] = Field(default_factory=list)
    cwe_ids: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    hash: str = ""

    model_config = {"extra": "allow"}


class EvidenceCorrelation(BaseModel):
    """Defines how multiple pieces of evidence relate."""

    evidence_ids: List[UUID]
    correlation_type: str
    description: str = ""
    correlation_score: float = 0.0
    created_at: datetime = Field(default_factory=datetime.now)


def from_agent_evidence(agent_evidence: Any, mission_id: Optional[UUID] = None) -> "Evidence":
    """
    Convert a lightweight `core.interfaces.Evidence` (what agents and tool
    plugins yield) into a full `domain.evidence.Evidence` (what the
    Validator and the rest of the runtime pipeline expect).

    This bridges a real gap: `core.interfaces.Evidence.evidence_type` and
    `.source` are plain strings, and it has no `status`/`metadata`/
    `raw_data` fields at all — while the Validator reads
    `evidence.evidence_type.value`, `evidence.source.tool_name`,
    `evidence.raw_data`, and `evidence.metadata`. Passing an agent evidence
    object straight into `Validator.validate_evidence()` raises an
    AttributeError on the very first check. Every agent (DiscoveryAgent,
    and any future agent) should route its yielded evidence through this
    function before handing it to `runtime.process_evidence()`.

    Unknown `evidence_type` strings (e.g. "port", "host", "os" from the
    Nmap plugin, or "error" from an agent's own failure path) are mapped to
    `EvidenceType.RAW_OUTPUT` and the original string is preserved in
    `metadata["source_evidence_type"]` so nothing is silently dropped.
    """
    # Local import avoids a hard import-time dependency on core.interfaces
    # from this module for callers that don't need the conversion.
    from core.interfaces import Evidence as AgentEvidence

    if isinstance(agent_evidence, Evidence):
        # Already a domain Evidence — nothing to convert.
        return agent_evidence

    if not isinstance(agent_evidence, AgentEvidence):
        raise TypeError(
            f"from_agent_evidence expected core.interfaces.Evidence or domain.evidence.Evidence, "
            f"got {type(agent_evidence).__name__}"
        )

    raw_type = agent_evidence.evidence_type
    try:
        evidence_type = EvidenceType(raw_type)
    except ValueError:
        evidence_type = EvidenceType.RAW_OUTPUT

    metadata: Dict[str, Any] = {"source_evidence_type": raw_type}

    return Evidence(
        evidence_type=evidence_type,
        title=agent_evidence.title or f"{agent_evidence.source}: {agent_evidence.asset_value}",
        description=agent_evidence.description,
        confidence=agent_evidence.confidence,
        severity=agent_evidence.severity,
        source=EvidenceSource(tool_name=agent_evidence.source),
        asset_value=agent_evidence.asset_value,
        mission_id=mission_id,
        raw_data=agent_evidence.data,
        cve_ids=list(agent_evidence.cve_ids),
        mitre_techniques=list(agent_evidence.mitre_techniques),
        tags=list(agent_evidence.tags),
        metadata=metadata,
    )


__all__ = [
    "EvidenceType",
    "EvidenceConfidence",
    "EvidenceSource",
    "EvidenceStatus",
    "Evidence",
    "EvidenceCorrelation",
    "from_agent_evidence",
]
