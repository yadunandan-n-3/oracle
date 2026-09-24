"""
State Manager
=============

Every investigation has a live state.

The State Manager maintains the complete state of every active mission:
- Current goals and completed tasks
- Discovered assets and evidence
- Running tasks and their status
- Knowledge graph state
- Memory for agent context

Every agent reads and writes the same state object.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from core.events import EventType, OracleEvent
from core.logging import get_logger
from domain.asset import Asset
from domain.evidence import Evidence
from domain.finding import Finding
from domain.mission import Mission, MissionStatus
from domain.scoring import FindingRevision, VersionedFinding
from runtime.event_bus import get_event_bus
from runtime.planner import Plan, Task

logger = get_logger(__name__)


@dataclass
class MissionState:
    """
    Complete live state for a single mission.

    This is the single source of truth for everything happening
    in an investigation. All components read and write here.
    """

    mission: Mission
    plan: Optional[Plan] = None

    # Execution state
    active_tasks: Dict[UUID, Task] = field(default_factory=dict)
    completed_tasks: Dict[UUID, Task] = field(default_factory=dict)
    failed_tasks: Dict[UUID, Task] = field(default_factory=dict)

    # Discovered entities
    assets: Dict[str, Asset] = field(default_factory=dict)  # keyed by value (IP, domain)
    evidence: Dict[UUID, Evidence] = field(default_factory=dict)
    findings: Dict[UUID, Finding] = field(default_factory=dict)
    finding_versions: Dict[UUID, VersionedFinding] = field(default_factory=dict)

    # Context for agents
    context: Dict[str, Any] = field(default_factory=dict)
    agent_memory: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Timeline
    events: List[Dict[str, Any]] = field(default_factory=list)

    # Metadata
    started_at: Optional[datetime] = None
    last_updated: datetime = field(default_factory=datetime.now)

    @property
    def total_assets(self) -> int:
        return len(self.assets)

    @property
    def total_evidence(self) -> int:
        return len(self.evidence)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def progress_percentage(self) -> float:
        """Calculate mission progress as a percentage."""
        if not self.plan or not self.plan.tasks:
            return 0.0
        total = len(self.plan.tasks)
        completed = len(self.completed_tasks)
        failed = len(self.failed_tasks)
        return ((completed + failed) / total) * 100.0


class StateManager:
    """
    Manages the live state of all active ORACLE missions.

    Provides:
    - State storage and retrieval for missions
    - Asset, evidence, and finding tracking
    - Agent context management
    - State persistence hooks
    - State querying for the dashboard
    """

    def __init__(self) -> None:
        self._states: Dict[UUID, MissionState] = {}
        self._event_bus = get_event_bus()

    # ─── Mission State Lifecycle ───────────────────────────────────────────

    async def initialize_mission_state(
        self,
        mission: Mission,
        plan: Optional[Plan] = None,
    ) -> MissionState:
        """Create a new state object for a mission."""
        state = MissionState(
            mission=mission,
            plan=plan,
            started_at=datetime.now(timezone.utc),
        )
        self._states[mission.id] = state

        logger.info(
            "state.initialized",
            mission_id=str(mission.id),
        )
        return state

    async def get_mission_state(self, mission_id: UUID) -> Optional[MissionState]:
        """Get the live state for a mission."""
        return self._states.get(mission_id)

    async def archive_mission_state(self, mission_id: UUID) -> None:
        """Archive and remove the live state for a completed/failed mission."""
        state = self._states.pop(mission_id, None)
        if state:
            logger.info(
                "state.archived",
                mission_id=str(mission_id),
                total_assets=state.total_assets,
                total_findings=state.total_findings,
            )

    def get_active_missions(self) -> List[MissionState]:
        """Get all active mission states."""
        return [
            state for state in self._states.values()
            if state.mission.status in {
                MissionStatus.PLANNING,
                MissionStatus.IN_PROGRESS,
            }
        ]

    def get_mission_ids(self) -> List[UUID]:
        """Get all active mission IDs (public accessor for _states)."""
        return list(self._states.keys())

    def get_all_states(self) -> Dict[UUID, MissionState]:
        """Get all mission states (public accessor for encapsulated access)."""
        return dict(self._states)

    # ─── Task State Management ─────────────────────────────────────────────

    async def register_active_task(
        self,
        mission_id: UUID,
        task: Task,
    ) -> None:
        """Register a task as actively running."""
        state = self._states.get(mission_id)
        if state:
            state.active_tasks[task.id] = task
            state.last_updated = datetime.now(timezone.utc)

    async def complete_task(
        self,
        mission_id: UUID,
        task: Task,
    ) -> None:
        """Mark a task as completed."""
        state = self._states.get(mission_id)
        if state:
            state.active_tasks.pop(task.id, None)
            state.completed_tasks[task.id] = task
            state.last_updated = datetime.now(timezone.utc)

    async def fail_task(
        self,
        mission_id: UUID,
        task: Task,
    ) -> None:
        """Mark a task as failed."""
        state = self._states.get(mission_id)
        if state:
            state.active_tasks.pop(task.id, None)
            state.failed_tasks[task.id] = task
            state.last_updated = datetime.now(timezone.utc)

    # ─── Asset Management ──────────────────────────────────────────────────

    async def add_asset(
        self,
        mission_id: UUID,
        asset: Asset,
    ) -> Asset:
        """Add or update an asset in the mission state."""
        state = self._states.get(mission_id)
        if state:
            key = asset.value
            if key in state.assets:
                # Update existing
                existing = state.assets[key]
                existing.label = asset.label or existing.label
                existing.description = asset.description or existing.description
                existing.ip_addresses = sorted(set(existing.ip_addresses + asset.ip_addresses))
                existing.hostnames = sorted(set(existing.hostnames + asset.hostnames))
                existing.domains = sorted(set(existing.domains + asset.domains))
                existing.open_ports = sorted(set(existing.open_ports + asset.open_ports))
                existing.services = sorted(set(existing.services + asset.services))
                existing.technologies.update(asset.technologies)
                existing.tags = sorted(set(existing.tags + asset.tags))
                existing.os = asset.os or existing.os
                existing.os_version = asset.os_version or existing.os_version
                existing.metadata.update(asset.metadata)
                existing.last_seen_at = datetime.now(timezone.utc)
            else:
                state.assets[key] = asset

            self._sync_mission_counters(state)
            state.last_updated = datetime.now(timezone.utc)
            return state.assets[key]
        return asset

    def get_assets(
        self,
        mission_id: UUID,
        asset_type: Optional[str] = None,
    ) -> List[Asset]:
        """Get assets for a mission, optionally filtered by type."""
        state = self._states.get(mission_id)
        if not state:
            return []
        if asset_type:
            return [a for a in state.assets.values() if a.asset_type.value == asset_type]
        return list(state.assets.values())

    def get_asset_by_value(self, mission_id: UUID, value: str) -> Optional[Asset]:
        """Get an asset by its value (IP, domain, URL)."""
        state = self._states.get(mission_id)
        if not state:
            return None
        return state.assets.get(value)

    # ─── Evidence Management ───────────────────────────────────────────────

    async def add_evidence(
        self,
        mission_id: UUID,
        evidence: Evidence,
    ) -> None:
        """Add evidence to the mission state."""
        state = self._states.get(mission_id)
        if state:
            state.evidence[evidence.id] = evidence
            self._sync_mission_counters(state)
            state.last_updated = datetime.now(timezone.utc)

            # Publish evidence event
            await self._event_bus.publish(OracleEvent(
                event_type=EventType.EVIDENCE_COLLECTED,
                source="state_manager",
                mission_id=mission_id,
                data={
                    "evidence_id": str(evidence.id),
                    "evidence_type": evidence.evidence_type.value,
                    "asset_value": evidence.asset_value,
                },
            ))

    def get_evidence(
        self,
        mission_id: UUID,
        evidence_type: Optional[str] = None,
        asset_id: Optional[UUID] = None,
    ) -> List[Evidence]:
        """Get evidence for a mission with optional filtering."""
        state = self._states.get(mission_id)
        if not state:
            return []

        results = list(state.evidence.values())
        if evidence_type:
            results = [e for e in results if e.evidence_type.value == evidence_type]
        if asset_id:
            results = [e for e in results if e.asset_id == asset_id]
        return results

    # ─── Finding Management ────────────────────────────────────────────────

    async def add_finding(
        self,
        mission_id: UUID,
        finding: Finding,
    ) -> None:
        """Add a finding to the mission state."""
        state = self._states.get(mission_id)
        if state:
            previous = state.findings.get(finding.id)
            changed_fields: List[str] = []
            if previous:
                for field_name in (
                    "title", "description", "severity", "status", "asset_id",
                    "evidence_ids", "cve_id", "cwe_id", "confidence",
                    "risk_score", "risk_level", "risk_factors",
                ):
                    if getattr(previous, field_name) != getattr(finding, field_name):
                        changed_fields.append(field_name)
                if not changed_fields:
                    return

            state.findings[finding.id] = finding
            versioned = state.finding_versions.setdefault(
                finding.id,
                VersionedFinding(finding_id=finding.id),
            )
            revision = FindingRevision(
                finding_id=finding.id,
                version=(versioned.current_version + 1 if versioned.revisions else 1),
                status=finding.status.value,
                severity=finding.severity.value,
                risk_score_v2=finding.risk_score,
                risk_level=finding.risk_level,
                evidence_ids=list(finding.evidence_ids),
                changed_fields=changed_fields,
                change_reason=("Finding updated from correlated evidence" if previous else "Finding created from correlated evidence"),
                captured_by=finding.discovered_by,
            )
            versioned.add_revision(revision)
            self._sync_mission_counters(state)
            state.last_updated = datetime.now(timezone.utc)

    def get_findings(
        self,
        mission_id: UUID,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Finding]:
        """Get findings with optional filtering."""
        state = self._states.get(mission_id)
        if not state:
            return []

        results = list(state.findings.values())
        if severity:
            results = [f for f in results if f.severity.value == severity]
        if status:
            results = [f for f in results if f.status.value == status]
        return results

    @staticmethod
    def _sync_mission_counters(state: MissionState) -> None:
        """Derive cached counters from the records in mission state."""
        mission = state.mission
        findings = list(state.findings.values())
        mission.total_assets_discovered = len(state.assets)
        mission.total_evidence = len(state.evidence)
        mission.total_findings = len(findings)
        mission.critical_findings = sum(f.severity.value == "critical" for f in findings)
        mission.high_findings = sum(f.severity.value == "high" for f in findings)
        mission.medium_findings = sum(f.severity.value == "medium" for f in findings)
        mission.low_findings = sum(f.severity.value == "low" for f in findings)
        mission.overall_risk_score = max(
            (f.risk_score for f in findings if f.risk_score is not None),
            default=None,
        )

    # ─── Context Management ────────────────────────────────────────────────

    async def update_context(
        self,
        mission_id: UUID,
        updates: Dict[str, Any],
    ) -> None:
        """Update the shared context for a mission."""
        state = self._states.get(mission_id)
        if state:
            state.context.update(updates)
            state.last_updated = datetime.now(timezone.utc)

    async def update_agent_memory(
        self,
        mission_id: UUID,
        agent_name: str,
        memory: Dict[str, Any],
    ) -> None:
        """Update memory for a specific agent in a mission."""
        state = self._states.get(mission_id)
        if state:
            state.agent_memory[agent_name] = memory
            state.last_updated = datetime.now(timezone.utc)

    def get_agent_memory(
        self,
        mission_id: UUID,
        agent_name: str,
    ) -> Dict[str, Any]:
        """Get memory for a specific agent."""
        state = self._states.get(mission_id)
        if state:
            return state.agent_memory.get(agent_name, {})
        return {}

    # ─── Event Logging ─────────────────────────────────────────────────────

    async def log_event(
        self,
        mission_id: UUID,
        event_type: str,
        data: Dict[str, Any],
    ) -> None:
        """Log an event to the mission timeline."""
        state = self._states.get(mission_id)
        if state:
            state.events.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": event_type,
                "data": data,
            })
            state.last_updated = datetime.now(timezone.utc)

    def get_timeline(
        self,
        mission_id: UUID,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get the event timeline for a mission."""
        state = self._states.get(mission_id)
        if not state:
            return []
        return state.events[-limit:]

    # ─── Query / Summary ───────────────────────────────────────────────────

    def get_mission_summary(self, mission_id: UUID) -> Optional[Dict[str, Any]]:
        """Get a summary of the mission state for the dashboard."""
        state = self._states.get(mission_id)
        if not state:
            return None

        return {
            "mission_id": str(mission_id),
            "mission_name": state.mission.name,
            "mission_type": state.mission.mission_type.value,
            "status": state.mission.status.value,
            "progress_percentage": state.progress_percentage,
            "total_tasks": len(state.plan.tasks) if state.plan else 0,
            "active_tasks": len(state.active_tasks),
            "completed_tasks": len(state.completed_tasks),
            "failed_tasks": len(state.failed_tasks),
            "total_assets": state.total_assets,
            "total_evidence": state.total_evidence,
            "total_findings": state.total_findings,
            "critical_findings": state.mission.critical_findings,
            "high_findings": state.mission.high_findings,
            "medium_findings": state.mission.medium_findings,
            "low_findings": state.mission.low_findings,
            "duration_seconds": (
                datetime.now(timezone.utc) - state.started_at
            ).total_seconds() if state.started_at else 0,
        }


__all__ = ["StateManager", "MissionState"]
