"""
Report Domain Model
===================

Reports are the output of ORACLE missions.
They contain findings, evidence, risk scores, and recommendations.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class ReportFormat(str, Enum):
    """Output formats for reports."""

    PDF = "pdf"
    HTML = "html"
    MARKDOWN = "markdown"
    JSON = "json"
    CSV = "csv"
    DASHBOARD = "dashboard"


class ReportType(str, Enum):
    """Types of reports ORACLE can generate."""

    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_DETAIL = "technical_detail"
    COMPLIANCE = "compliance"
    RISK_ASSESSMENT = "risk_assessment"
    REMEDIATION_PLAN = "remediation_plan"
    METRICS_DASHBOARD = "metrics_dashboard"


class ReportSection(BaseModel):
    """A section within a report."""

    id: UUID = Field(default_factory=uuid4)
    title: str
    content: str = ""
    section_type: str = "text"  # text, table, chart, finding_list, evidence_list
    order: int = 0
    data: Dict[str, Any] = Field(default_factory=dict)


class Report(BaseModel):
    """
    A generated report from an ORACLE mission.
    """

    id: UUID = Field(default_factory=uuid4)
    title: str
    report_type: ReportType = ReportType.EXECUTIVE_SUMMARY
    format: ReportFormat = ReportFormat.JSON

    # Mission context
    mission_id: Optional[UUID] = None
    mission_name: str = ""
    project_id: Optional[UUID] = None

    # Content
    executive_summary: str = ""
    sections: List[ReportSection] = Field(default_factory=list)
    findings_summary: Dict[str, int] = Field(default_factory=dict)
    risk_score: Optional[float] = None
    risk_level: str = ""

    # Recommendations
    critical_recommendations: List[str] = Field(default_factory=list)
    high_recommendations: List[str] = Field(default_factory=list)
    medium_recommendations: List[str] = Field(default_factory=list)
    low_recommendations: List[str] = Field(default_factory=list)

    # Metrics
    total_assets: int = 0
    total_findings: int = 0
    total_critical: int = 0
    total_high: int = 0
    total_medium: int = 0
    total_low: int = 0
    total_info: int = 0
    average_cvss: Optional[float] = None
    mitigation_percentage: Optional[float] = None

    # Generation
    generated_by: str = ""
    generated_at: datetime = Field(default_factory=datetime.now)
    mission_duration_seconds: Optional[int] = None

    # Export
    exported_formats: List[ReportFormat] = Field(default_factory=list)
    exported_at: Dict[str, datetime] = Field(default_factory=dict)

    # Metadata
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "allow"}


__all__ = [
    "ReportFormat",
    "ReportType",
    "ReportSection",
    "Report",
]
