"""Canonical output contract for one executed planner task."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import UUID

from domain.asset import Asset
from domain.evidence import Evidence
from domain.finding import Finding
from domain.intelligence import EnrichedFinding
from domain.scoring import OracleRiskScoreV2


@dataclass
class TaskExecutionResult:
    """Normalized agent output before runtime-owned ingestion."""

    mission_id: UUID
    task_id: UUID
    capability: str
    success: bool = True
    assets: List[Asset] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class IngestionResult:
    """Records actually accepted by the runtime production pipeline."""

    mission_id: UUID
    task_id: UUID
    assets: List[Asset] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    enriched_findings: List[EnrichedFinding] = field(default_factory=list)
    risk_scores: List[OracleRiskScoreV2] = field(default_factory=list)
    persisted: bool = False
    graph_projected: bool = False
    degraded_dependencies: List[str] = field(default_factory=list)


__all__ = ["IngestionResult", "TaskExecutionResult"]
