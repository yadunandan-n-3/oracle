"""
ORACLE Runtime Kernel
=====================

The operating system kernel for ORACLE.

This is THE most important piece of engineering in the entire project.

The Runtime is not just an orchestrator — it is the operating system
that all ORACLE components run on top of. Every service, agent, tool,
and plugin communicates through the Runtime.

Architecture:
    Runtime
    ├── Event Bus (pub/sub messaging)
    ├── Mission Manager (mission lifecycle)
    ├── Planner (goal → tasks)
    ├── Scheduler (priority queue, dispatch)
    ├── Workflow Engine (orchestration)
    ├── State Manager (live state)
    ├── Policy Engine (governance)
    ├── Resource Manager (compute, rate limits)
    ├── Validator (evidence validation)
    └── Telemetry (observability)
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional
from uuid import NAMESPACE_URL, UUID, uuid5

from core.config import settings
from core.events import EventType, OracleEvent
from core.exceptions import IntegrationError, InvalidStateError
from core.logging import get_logger, get_mission_logger, setup_logging
from core.resilience.degraded_mode import DependencyStatus, get_degraded_mode_manager
from core.telemetry import telemetry
from core.tool_manager import ToolManager, get_tool_manager
from domain.asset import Asset
from domain.correlation import CorrelationResult, EvidenceCorrelator
from domain.correlation.rules import (
    ApacheCorrelationRule,
    GenericTechCveCorrelationRule,
    HttpServiceCorrelationRule,
    PortServiceCorrelationRule,
    SSHCveCorrelationRule,
)
from domain.evidence import Evidence as EvidenceDomain, EvidenceType
from domain.evidence import from_agent_evidence
from domain.finding import Finding, FindingSeverity
from domain.intelligence.pipeline import FindingIntelligencePipeline
from domain.mission import Mission, MissionStatus, MissionTarget, MissionType
from knowledge import get_knowledge_graph, KnowledgeGraphService
from runtime.event_bus import EventBus, get_event_bus
from runtime.execution_result import IngestionResult, TaskExecutionResult
from runtime.ingestion import asset_from_evidence, coalesce_assets, merge_assets
from runtime.mission_manager import MissionManager
from runtime.planner import Planner, Task
from runtime.policy_engine import PolicyEngine
from runtime.resource_manager import ResourceManager, ResourceQuota
from runtime.scheduler import Scheduler
from runtime.state_manager import StateManager
from runtime.validator import Validator
from runtime.workflow import WorkflowEngine, WorkflowResult
from tools.nmap import NmapPlugin
from tools.nuclei import NucleiPlugin

logger = get_logger(__name__)
mission_logger = get_mission_logger()


class OracleRuntime:
    """
    The ORACLE Runtime kernel.

    This is the central orchestrator for the entire ORACLE system.
    It initializes all subsystems and provides the main API for
    creating and managing missions.
    """

    def __init__(self) -> None:
        self._running = False
        self._event_bus: EventBus = get_event_bus()
        self.mission_manager = MissionManager()
        self.planner = Planner()
        self.scheduler = Scheduler(max_concurrent=settings.max_concurrent_tasks)
        self.state_manager = StateManager()
        self.policy_engine = PolicyEngine()
        self.resource_manager = ResourceManager()
        self.validator = Validator()
        self.workflow_engine = WorkflowEngine(
            scheduler=self.scheduler,
            state_manager=self.state_manager,
            planner=self.planner,
        )

        # Persistence
        self.mission_service: Optional[any] = None
        self._database_available = False
        self._degraded_mode = get_degraded_mode_manager()

        # Knowledge Graph
        self.knowledge_graph: KnowledgeGraphService = get_knowledge_graph()

        # Tool Manager
        self.tool_manager: ToolManager = get_tool_manager()

        # Registry
        self._registered_handlers: Dict[str, Any] = {}
        self._discovery_agents: Dict[UUID, Any] = {}
        self._ingestion_locks: Dict[UUID, asyncio.Lock] = {}
        self._correlation_rules = [
            ApacheCorrelationRule(),
            SSHCveCorrelationRule(),
            HttpServiceCorrelationRule(),
            GenericTechCveCorrelationRule(),
            PortServiceCorrelationRule(),
        ]
        self.intelligence_pipeline = FindingIntelligencePipeline()
        self._started_at: Optional[datetime] = None

    # ─── Lifecycle ────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the ORACLE Runtime and all subsystems."""
        if self._running:
            logger.warning("runtime.already_running")
            return

        setup_logging()
        telemetry.initialize()
        self._running = True
        self._started_at = datetime.now(timezone.utc)

        await self._event_bus.start()

        # Task handlers and scheduler callbacks must exist before the worker
        # can dispatch any queued task.
        self._register_tools()
        self._register_capability_handlers()
        self._register_event_handlers()
        await self.scheduler.start()

        # Initialize database
        try:
            async def _init_database() -> None:
                from backend.database import init_database
                await init_database()

            await asyncio.wait_for(_init_database(), timeout=2.0)
            self._database_available = True
            self._degraded_mode.update_status("postgresql", DependencyStatus.HEALTHY)
            logger.info("runtime.database_initialized")
        except asyncio.TimeoutError:
            logger.warning("runtime.database_init_timeout")
            self._database_available = False
            self._degraded_mode.update_status("postgresql", DependencyStatus.UNAVAILABLE)
        except Exception as e:
            logger.warning("runtime.database_unavailable", error=str(e))
            self._database_available = False
            self._degraded_mode.update_status("postgresql", DependencyStatus.UNAVAILABLE)

        # Initialize knowledge graph
        try:
            await asyncio.wait_for(self.knowledge_graph.initialize(), timeout=2.0)
            if self.knowledge_graph.is_available:
                self._degraded_mode.update_status("neo4j", DependencyStatus.HEALTHY)
                logger.info("runtime.knowledge_graph_initialized")
            else:
                self._degraded_mode.update_status("neo4j", DependencyStatus.UNAVAILABLE)
                logger.warning("runtime.knowledge_graph_unavailable")
        except asyncio.TimeoutError:
            self._degraded_mode.update_status("neo4j", DependencyStatus.UNAVAILABLE)
            logger.warning("runtime.knowledge_graph_init_timeout")
        except Exception as e:
            self._degraded_mode.update_status("neo4j", DependencyStatus.UNAVAILABLE)
            logger.warning("runtime.knowledge_graph_init_failed", error=str(e))

        await self._event_bus.publish(OracleEvent(
            event_type=EventType.SYSTEM_STARTUP,
            source="runtime",
            data={"version": "0.1.0", "environment": settings.environment.value},
        ))

        logger.info("runtime.started", environment=settings.environment.value, max_concurrent=settings.max_concurrent_tasks)

    async def stop(self) -> None:
        """Gracefully stop the Runtime."""
        if not self._running:
            return
        self._running = False
        logger.info("runtime.shutting_down")

        await self._event_bus.publish(OracleEvent(
            event_type=EventType.SYSTEM_SHUTDOWN,
            source="runtime",
            data={"uptime_seconds": (datetime.now(timezone.utc) - self._started_at).total_seconds() if self._started_at else 0},
        ))

        await self.scheduler.stop()
        await self._event_bus.stop()

        if self.knowledge_graph:
            await self.knowledge_graph.close()

        await self.intelligence_pipeline.close()

        try:
            from backend.database import close_database
            await close_database()
        except Exception:
            pass

        uptime = (datetime.now(timezone.utc) - self._started_at).total_seconds() if self._started_at else 0
        logger.info("runtime.stopped", uptime_seconds=uptime)

    async def health(self) -> Dict[str, Any]:
        """Get health status of all subsystems."""
        event_bus_health = await self._event_bus.health()
        scheduler_health = await self.scheduler.health()
        kg_health = {"healthy": False}
        try:
            kg_health = await self.knowledge_graph.health_check()
        except Exception:
            pass

        return {
            "status": "healthy" if self._running else "stopped",
            "running": self._running,
            "uptime_seconds": (datetime.now(timezone.utc) - self._started_at).total_seconds() if self._started_at else 0,
            "subsystems": {
                "event_bus": event_bus_health,
                "scheduler": scheduler_health,
                "knowledge_graph": kg_health,
                "active_missions": len(self.state_manager.get_active_missions()),
                "active_workflows": len(self.workflow_engine.get_active_workflows()),
                "dependencies": self._degraded_mode.get_health_summary(),
            },
        }

    # ─── Mission API ──────────────────────────────────────────────────────

    async def create_mission(self, name: str, mission_type: MissionType, target: MissionTarget,
                             description: str = "", goals: Optional[List[str]] = None,
                             priority: str = "medium", created_by: Optional[str] = None,
                             organization_id: Optional[UUID] = None, project_id: Optional[UUID] = None) -> Mission:
        """Create a new mission and persist it."""
        mission = await self.mission_manager.create_mission(
            name=name, mission_type=mission_type, target=target,
            description=description, goals=goals, priority=priority,
            created_by=created_by, organization_id=organization_id, project_id=project_id,
        )

        mission_logger.log_mission_created(
            mission_id=str(mission.id),
            mission_type=mission_type.value,
            name=name,
            goal_count=len(mission.goals),
        )

        self.resource_manager.set_quota(
            str(mission.id), ResourceQuota(max_concurrent_tools=5, max_duration_minutes=120),
        )

        try:
            async with self._persistence_scope() as service:
                if service:
                    await service.create_mission(mission)
                else:
                    self._mark_persistence_degraded(mission)
        except Exception as e:
            self._degraded_mode.update_status("postgresql", DependencyStatus.UNAVAILABLE)
            self._mark_persistence_degraded(mission, str(e))
            logger.error("runtime.persist_mission_failed", error=str(e))

        if self.knowledge_graph.is_available:
            try:
                await self.knowledge_graph.create_mission_node(mission.id, mission.name, mission.mission_type.value)
            except Exception as e:
                logger.error("runtime.graph_mission_failed", error=str(e))

        logger.info("runtime.mission_created", mission_id=str(mission.id), mission_type=mission_type.value)
        return mission

    async def execute_mission(self, mission_id: UUID) -> Optional[WorkflowResult]:
        """Execute a mission end-to-end (policy -> plan -> execute -> persist)."""
        mission = self.mission_manager.get_mission(mission_id)
        if not mission:
            logger.error("runtime.mission_not_found", mission_id=str(mission_id))
            return None

        mission_id_str = str(mission_id)
        mission_logger.start_timer("mission_total")

        # Policy check
        mission_logger.log("policy.checking", mission_id=mission_id_str)
        policy_results = await self.policy_engine.check_mission(mission)
        blocking_issues = [r for r in policy_results if not r.passed and r.effect.value == "deny"]
        if blocking_issues:
            for issue in blocking_issues:
                mission_logger.log("policy.blocked", mission_id=mission_id_str, status="failure",
                                   error=issue.message, details={"policy": issue.policy_name})
            await self.mission_manager.fail_mission(mission_id, f"Policy blocked: {blocking_issues[0].message}")
            await self._persist_mission_status(mission_id, MissionStatus.FAILED)
            ms = mission_logger.elapsed_ms("mission_total") or 0.0
            mission_logger.log_mission_failed(mission_id_str, blocking_issues[0].message, ms)
            return None

        # Start mission
        mission_logger.log("mission.started", mission_id=mission_id_str)
        await self.mission_manager.start_mission(mission_id)
        await self._persist_mission_status(mission_id, MissionStatus.PLANNING)
        await self._log_event(mission_id, "mission.started", {"mission_id": mission_id_str})

        # Plan
        mission_logger.log("mission.planner_started", mission_id=mission_id_str)
        try:
            plan = await self.planner.create_plan(mission)
        except Exception as e:
            logger.exception("Planner failed while creating plan", mission_id=mission_id_str, error=str(e))
            ms = mission_logger.elapsed_ms("mission_total") or 0.0
            mission_logger.log_mission_failed(mission_id_str, str(e), ms)
            await self.mission_manager.fail_mission(mission_id, str(e))
            await self._persist_mission_status(mission_id, MissionStatus.FAILED)
            raise

        await self._log_event(mission_id, "mission.planned", {"total_tasks": plan.total_tasks})
        mission_logger.log("mission.planned", mission_id=mission_id_str,
                           details={"total_tasks": plan.total_tasks})

        # Execute
        mission_logger.log("mission.executing", mission_id=mission_id_str,
                           details={"total_tasks": plan.total_tasks})
        mission.status = MissionStatus.IN_PROGRESS
        mission.updated_at = datetime.now(timezone.utc)
        await self._persist_mission_status(mission_id, MissionStatus.IN_PROGRESS)
        try:
            workflow_timeout = float((mission.max_duration_minutes or 120) * 60)
            result = await self.workflow_engine.execute_plan(
                plan,
                mission,
                timeout_seconds=workflow_timeout,
            )
        except Exception as e:
            ms = mission_logger.elapsed_ms("mission_total") or 0.0
            mission_logger.log_mission_failed(mission_id_str, str(e), ms)
            await self.mission_manager.fail_mission(mission_id, str(e))
            await self._persist_mission_status(mission_id, MissionStatus.FAILED)
            self._discovery_agents.pop(mission_id, None)
            raise

        if not result.succeeded:
            error = result.error or f"Workflow ended with status {result.status.value}"
            ms = mission_logger.elapsed_ms("mission_total") or 0.0
            mission_logger.log_mission_failed(mission_id_str, error, ms)
            await self.mission_manager.fail_mission(mission_id, error)
            await self._persist_mission_status(mission_id, MissionStatus.FAILED)
            self._discovery_agents.pop(mission_id, None)
            return result

        # Complete
        await self.mission_manager.complete_mission(mission_id)
        await self._persist_mission_status(mission_id, MissionStatus.COMPLETED)
        await self._log_event(mission_id, "mission.completed", {"mission_id": mission_id_str})
        duration_ms = mission_logger.stop_timer("mission_total") or 0.0
        mission_logger.log_mission_completed(
            mission_id_str, plan.total_tasks,
            len(self.state_manager.get_evidence(mission_id)),
            duration_ms,
        )

        if self.knowledge_graph.is_available:
            try:
                await self.knowledge_graph.update_mission_status(mission_id, MissionStatus.COMPLETED.value)
            except Exception as e:
                logger.error("runtime.graph_update_failed", error=str(e))

        self._discovery_agents.pop(mission_id, None)
        return result

    async def cancel_mission(self, mission_id: UUID) -> None:
        """Cancel a running mission."""
        await self.workflow_engine.cancel_workflow(mission_id)
        await self.mission_manager.cancel_mission(mission_id)
        await self.state_manager.archive_mission_state(mission_id)
        await self._persist_mission_status(mission_id, MissionStatus.CANCELLED)

    def get_mission(self, mission_id: UUID) -> Optional[Mission]:
        return self.mission_manager.get_mission(mission_id)

    def list_missions(self, organization_id: Optional[UUID] = None, project_id: Optional[UUID] = None,
                      status: Optional[MissionStatus] = None, mission_type: Optional[MissionType] = None,
                      limit: int = 50, offset: int = 0) -> List[Mission]:
        return self.mission_manager.list_missions(
            organization_id=organization_id, project_id=project_id,
            status=status, mission_type=mission_type, limit=limit, offset=offset,
        )

    def get_mission_state(self, mission_id: UUID) -> Optional[Dict[str, Any]]:
        return self.state_manager.get_mission_summary(mission_id)

    def get_mission_templates(self) -> list:
        return self.mission_manager.get_mission_templates()

    def get_system_stats(self) -> Dict[str, Any]:
        return {
            "active_missions": len(self.state_manager.get_active_missions()),
            "scheduler": self.scheduler.get_queue_stats(),
            "uptime_seconds": (datetime.now(timezone.utc) - self._started_at).total_seconds() if self._started_at else 0,
        }

    def register_capability_handler(self, capability: str, handler: Any) -> None:
        self._registered_handlers[capability] = handler
        self.workflow_engine.register_handler(capability, handler)
        logger.info("runtime.handler_registered", capability=capability)

    # ─── Asset / Evidence / Finding Production Pipeline ─────────────────

    async def process_execution_result(
        self,
        result: TaskExecutionResult,
    ) -> IngestionResult:
        """Validate, persist, project, correlate, and publish one task result."""
        if not result.success:
            raise IntegrationError(
                message="Cannot ingest an unsuccessful task result",
                service="execution",
                details={"task_id": str(result.task_id), "errors": result.errors},
            )

        lock = self._ingestion_locks.setdefault(result.mission_id, asyncio.Lock())
        async with lock:
            state = await self.state_manager.get_mission_state(result.mission_id)
            if state is None:
                raise InvalidStateError(
                    message=f"Mission state is not initialized: {result.mission_id}",
                    current_state="missing",
                    expected_state="initialized",
                )

            mission_logger.start_timer(f"ingestion_{result.task_id}")
            validated_evidence: List[EvidenceDomain] = []
            derived_assets: List[Asset] = list(result.assets)

            for evidence in result.evidence:
                evidence.mission_id = result.mission_id
                evidence.task_id = result.task_id
                evidence.source.execution_id = result.task_id
                evidence.metadata["task_id"] = str(result.task_id)
                evidence.metadata["capability"] = result.capability
                source_type = evidence.metadata.get("source_evidence_type")
                if source_type == "port":
                    evidence.evidence_type = EvidenceType.OPEN_PORT
                elif source_type == "service":
                    evidence.evidence_type = EvidenceType.SERVICE

                validated = await self.validator.validate_evidence(evidence)
                validated_evidence.append(validated)
                asset = asset_from_evidence(result.mission_id, validated)
                if asset:
                    derived_assets.append(asset)

            assets = coalesce_assets(result.mission_id, derived_assets)
            assets = self._merge_with_state_assets(result.mission_id, assets)

            for evidence in validated_evidence:
                observed_asset = asset_from_evidence(result.mission_id, evidence)
                if observed_asset:
                    evidence.asset_id = observed_asset.id

            mission_evidence = {
                evidence.id: evidence for evidence in self.state_manager.get_evidence(result.mission_id)
            }
            mission_evidence.update({evidence.id: evidence for evidence in validated_evidence})
            findings = await self._produce_findings(
                result.mission_id,
                list(mission_evidence.values()),
                [*self.state_manager.get_assets(result.mission_id), *assets],
            )
            produced_findings = findings

            # Intelligence is an optional enhancement to the durable P1
            # finding path. Provider outages are captured on the finding and
            # never convert real evidence into a failed ingestion.
            evidence_by_id = {
                item.id: item for item in mission_evidence.values()
            }
            enriched_findings = []
            risk_scores = []
            for finding in produced_findings:
                supporting = [
                    evidence_by_id[evidence_id]
                    for evidence_id in finding.evidence_ids
                    if evidence_id in evidence_by_id
                ]
                try:
                    intelligence = await self.intelligence_pipeline.process(
                        finding,
                        supporting,
                    )
                    enriched_findings.append(intelligence.enriched_finding)
                    risk_scores.append(intelligence.risk_score)
                except Exception as exc:
                    finding.metadata["intelligence_status"] = "failed"
                    finding.metadata["intelligence_error"] = str(exc)
                    logger.warning(
                        "runtime.finding_intelligence_failed",
                        finding_id=str(finding.id),
                        error=str(exc),
                    )

            projected_assets = {
                asset.value: asset for asset in self.state_manager.get_assets(result.mission_id)
            }
            projected_assets.update({asset.value: asset for asset in assets})
            projected_findings = {
                finding.id: finding for finding in self.state_manager.get_findings(result.mission_id)
            }
            projected_findings.update({finding.id: finding for finding in produced_findings})
            counter_values = self._counter_values(
                projected_assets.values(),
                mission_evidence.values(),
                projected_findings.values(),
            )

            outcome = IngestionResult(
                mission_id=result.mission_id,
                task_id=result.task_id,
                assets=assets,
                evidence=validated_evidence,
                findings=produced_findings,
                enriched_findings=enriched_findings,
                risk_scores=risk_scores,
            )

            try:
                async with self._persistence_scope() as service:
                    if service:
                        for asset in assets:
                            await service.upsert_asset(result.mission_id, asset)
                        for evidence in validated_evidence:
                            await service.create_evidence(result.mission_id, evidence)
                        for finding in produced_findings:
                            await service.upsert_finding(result.mission_id, finding)
                        await service.sync_mission_counters(
                            result.mission_id,
                            **counter_values,
                        )
                        outcome.persisted = True
                        self._degraded_mode.update_status(
                            "postgresql", DependencyStatus.HEALTHY
                        )
                    else:
                        self._degraded_mode.update_status(
                            "postgresql", DependencyStatus.UNAVAILABLE
                        )
                        outcome.degraded_dependencies.append("postgresql")
                        self._mark_persistence_degraded(state.mission)
            except Exception as exc:
                result.success = False
                result.errors.append(str(exc))
                self._degraded_mode.update_status(
                    "postgresql", DependencyStatus.UNAVAILABLE
                )
                self._mark_persistence_degraded(state.mission, str(exc))
                logger.error(
                    "runtime.persistence_failed",
                    mission_id=str(result.mission_id),
                    task_id=str(result.task_id),
                    error=str(exc),
                )
                raise IntegrationError(
                    message=f"PostgreSQL persistence failed: {exc}",
                    service="postgresql",
                    details={"mission_id": str(result.mission_id), "task_id": str(result.task_id)},
                ) from exc

            # State changes occur only after the PostgreSQL transaction has
            # committed (or after an explicit state-only degraded decision).
            for asset in assets:
                await self.state_manager.add_asset(result.mission_id, asset)
            for evidence in validated_evidence:
                await self.state_manager.add_evidence(result.mission_id, evidence)
            for finding in produced_findings:
                await self.state_manager.add_finding(result.mission_id, finding)

            await self._project_ingestion_to_graph(outcome)
            result.assets = assets
            result.evidence = validated_evidence
            result.metadata["finding_ids"] = [str(finding.id) for finding in produced_findings]
            result.metadata["persistence"] = "persisted" if outcome.persisted else "degraded"

            duration_ms = mission_logger.stop_timer(f"ingestion_{result.task_id}") or 0.0
            mission_logger.log(
                "execution_result.ingested",
                mission_id=str(result.mission_id),
                task_id=str(result.task_id),
                status="completed",
                duration_ms=duration_ms,
                details={
                    "assets": len(assets),
                    "evidence": len(validated_evidence),
                    "findings": len(produced_findings),
                    "persisted": outcome.persisted,
                },
            )
            return outcome

    async def process_evidence(
        self,
        evidence: EvidenceDomain,
        mission_id: UUID,
    ) -> IngestionResult:
        """Compatibility entry point routed through the production pipeline."""
        task_id = evidence.task_id or evidence.source.execution_id or UUID(int=0)
        return await self.process_execution_result(TaskExecutionResult(
            mission_id=mission_id,
            task_id=task_id,
            capability=evidence.metadata.get("capability", "direct_evidence"),
            evidence=[evidence],
        ))

    def _merge_with_state_assets(
        self,
        mission_id: UUID,
        observed_assets: List[Asset],
    ) -> List[Asset]:
        existing = {
            asset.value: asset
            for asset in self.state_manager.get_assets(mission_id)
        }
        merged: List[Asset] = []
        for asset in observed_assets:
            key = asset.value
            merged.append(merge_assets(existing[key], asset) if key in existing else asset)
        return merged

    async def _produce_findings(
        self,
        mission_id: UUID,
        evidence: List[EvidenceDomain],
        assets: List[Asset],
    ) -> List[Finding]:
        correlator = EvidenceCorrelator()
        for rule in self._correlation_rules:
            correlator.register_rule(rule)
        correlations = await correlator.correlate(evidence, mission_id=mission_id, assets=assets)

        evidence_by_id = {item.id: item for item in evidence}
        asset_by_id = {asset.id: asset for asset in assets}
        asset_by_value = {asset.value: asset for asset in assets}
        findings: Dict[UUID, Finding] = {}
        correlated_evidence_ids: set[UUID] = set()

        for correlation in correlations:
            supporting = [
                evidence_by_id[evidence_id]
                for evidence_id in correlation.evidence_ids
                if evidence_id in evidence_by_id
            ]
            if not supporting:
                continue
            correlated_evidence_ids.update(item.id for item in supporting)
            finding = self._finding_from_correlation(
                mission_id,
                correlation,
                supporting,
                asset_by_id,
                asset_by_value,
            )
            findings[finding.id] = finding

        # A positive vulnerability matcher is itself explicit finding support,
        # even when no multi-evidence correlation rule matched it.
        for item in evidence:
            if item.evidence_type != EvidenceType.VULNERABILITY:
                continue
            if item.id in correlated_evidence_ids:
                continue
            finding_id = uuid5(
                NAMESPACE_URL,
                f"oracle:{mission_id}:vulnerability:{item.id}",
            )
            asset = asset_by_id.get(item.asset_id) if item.asset_id else None
            severity = self._finding_severity([item])
            findings[finding_id] = Finding(
                id=finding_id,
                mission_id=mission_id,
                title=item.title,
                description=item.description,
                severity=severity,
                confidence=item.confidence,
                asset_id=item.asset_id,
                asset_value=item.asset_value,
                asset_type=asset.asset_type.value if asset else "",
                evidence_ids=[item.id],
                cve_id=item.cve_ids[0] if item.cve_ids else None,
                cwe_id=item.cwe_ids[0] if item.cwe_ids else None,
                mitre_technique_id=(
                    item.mitre_techniques[0] if item.mitre_techniques else None
                ),
                discovered_by=f"tool:{item.source.tool_name}",
                tags=list(item.tags),
                metadata={"source": "explicit_vulnerability_evidence"},
            )
        return list(findings.values())

    def _finding_from_correlation(
        self,
        mission_id: UUID,
        correlation: CorrelationResult,
        supporting: List[EvidenceDomain],
        asset_by_id: Dict[UUID, Asset],
        asset_by_value: Dict[str, Asset],
    ) -> Finding:
        evidence_ids = sorted((item.id for item in supporting), key=str)
        finding_id = uuid5(
            NAMESPACE_URL,
            "oracle:{}:correlation:{}:{}:{}:{}".format(
                mission_id,
                correlation.rule_name,
                correlation.asset_value,
                f"{correlation.port or ''}:{correlation.technology or correlation.service or ''}",
                ",".join(sorted(correlation.cve_ids)),
            ),
        )
        asset = None
        if correlation.asset_id:
            asset = asset_by_id.get(correlation.asset_id)
        if asset is None:
            asset = asset_by_value.get(correlation.asset_value)
        if asset is None:
            asset = next(
                (asset_by_id[item.asset_id] for item in supporting if item.asset_id in asset_by_id),
                None,
            )
        cwe_ids = [cwe for item in supporting for cwe in item.cwe_ids]
        techniques = [technique for item in supporting for technique in item.mitre_techniques]
        title = correlation.description or f"{correlation.rule_name} correlation"
        return Finding(
            id=finding_id,
            mission_id=mission_id,
            title=title,
            description=correlation.reasoning or correlation.description,
            severity=self._finding_severity(supporting),
            confidence=correlation.confidence,
            asset_id=asset.id if asset else supporting[0].asset_id,
            asset_value=correlation.asset_value or supporting[0].asset_value,
            asset_type=asset.asset_type.value if asset else "",
            evidence_ids=evidence_ids,
            cve_id=correlation.cve_ids[0] if correlation.cve_ids else None,
            cwe_id=cwe_ids[0] if cwe_ids else None,
            mitre_technique_id=techniques[0] if techniques else None,
            affected_port=correlation.port,
            affected_component=correlation.technology or correlation.service or "",
            discovered_by=f"correlation:{correlation.rule_name}",
            metadata={
                "correlation_id": str(correlation.id),
                "correlation_type": correlation.correlation_type.value,
                "matched_on": correlation.matched_on,
            },
        )

    @staticmethod
    def _finding_severity(evidence: List[EvidenceDomain]) -> FindingSeverity:
        order = {
            "informational": 0,
            "info": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }
        observed = max(
            (str(item.severity).lower() for item in evidence),
            key=lambda value: order.get(value, 0),
            default="informational",
        )
        if observed == "info":
            observed = "informational"
        return FindingSeverity(observed) if observed in {s.value for s in FindingSeverity} else FindingSeverity.INFO

    @staticmethod
    def _counter_values(
        assets: Any,
        evidence: Any,
        findings: Any,
    ) -> Dict[str, Any]:
        asset_list = list(assets)
        evidence_list = list(evidence)
        finding_list = list(findings)
        return {
            "total_assets": len(asset_list),
            "total_evidence": len(evidence_list),
            "total_findings": len(finding_list),
            "critical_findings": sum(f.severity == FindingSeverity.CRITICAL for f in finding_list),
            "high_findings": sum(f.severity == FindingSeverity.HIGH for f in finding_list),
            "medium_findings": sum(f.severity == FindingSeverity.MEDIUM for f in finding_list),
            "low_findings": sum(f.severity == FindingSeverity.LOW for f in finding_list),
            "overall_risk_score": max(
                (f.risk_score for f in finding_list if f.risk_score is not None),
                default=None,
            ),
        }

    async def _project_ingestion_to_graph(self, outcome: IngestionResult) -> None:
        if not self.knowledge_graph.is_available:
            self._degraded_mode.update_status("neo4j", DependencyStatus.UNAVAILABLE)
            outcome.degraded_dependencies.append("neo4j")
            return
        try:
            for asset in outcome.assets:
                await self.knowledge_graph.create_asset_node(
                    asset.id,
                    outcome.mission_id,
                    asset.asset_type.value,
                    asset.value,
                    asset.label,
                    asset.ip_addresses,
                    asset.hostnames,
                    asset.open_ports,
                    asset.os or "",
                )
            for evidence in outcome.evidence:
                await self.knowledge_graph.create_evidence_node(
                    evidence.id,
                    outcome.mission_id,
                    evidence.asset_id,
                    evidence.evidence_type.value,
                    evidence.title,
                    evidence.confidence,
                )
            for finding in outcome.findings:
                await self.knowledge_graph.create_finding_node(
                    finding.id,
                    finding.asset_id,
                    finding.title,
                    finding.severity.value,
                    finding.cve_id or "",
                    finding.mitre_technique_id or "",
                    mission_id=outcome.mission_id,
                    evidence_ids=finding.evidence_ids,
                    cwe_id=finding.cwe_id or "",
                    risk_score=finding.risk_score,
                    risk_level=finding.risk_level,
                    risk_id=finding.risk_calculation_metadata.get("risk_id", ""),
                )
            outcome.graph_projected = True
            self._degraded_mode.update_status("neo4j", DependencyStatus.HEALTHY)
        except Exception as exc:
            self._degraded_mode.update_status("neo4j", DependencyStatus.DEGRADED)
            outcome.degraded_dependencies.append("neo4j")
            logger.error(
                "runtime.graph_projection_failed",
                mission_id=str(outcome.mission_id),
                task_id=str(outcome.task_id),
                error=str(exc),
            )

    @asynccontextmanager
    async def _persistence_scope(self) -> AsyncIterator[Optional[Any]]:
        """Yield an injected adapter or a fresh PostgreSQL transaction."""
        if self.mission_service is not None:
            yield self.mission_service
            return
        if not self._database_available:
            yield None
            return

        from backend.database import session_scope
        from backend.services import MissionService

        async with session_scope() as session:
            yield MissionService(session)

    async def get_authoritative_findings(
        self,
        mission_id: Optional[UUID] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Optional[List[Any]]:
        """Read PostgreSQL findings, or signal that state fallback is required."""
        try:
            async with self._persistence_scope() as service:
                loader = getattr(service, "list_findings", None) if service else None
                if loader:
                    return await loader(
                        mission_id=mission_id,
                        severity=severity,
                        status=status,
                    )
        except Exception as exc:
            logger.warning("runtime.persisted_findings_read_failed", error=str(exc))
        return None

    async def get_authoritative_finding(self, finding_id: UUID) -> Optional[Any]:
        """Read one PostgreSQL finding when durable persistence is available."""
        try:
            async with self._persistence_scope() as service:
                loader = getattr(service, "get_finding", None) if service else None
                if loader:
                    return await loader(finding_id)
        except Exception as exc:
            logger.warning(
                "runtime.persisted_finding_read_failed",
                finding_id=str(finding_id),
                error=str(exc),
            )
        return None

    async def get_authoritative_missions(self) -> Optional[List[Any]]:
        """Read persisted missions for completed-mission API paths."""
        try:
            async with self._persistence_scope() as service:
                loader = getattr(service, "list_missions", None) if service else None
                if loader:
                    return await loader(limit=10000, offset=0)
        except Exception as exc:
            logger.warning("runtime.persisted_missions_read_failed", error=str(exc))
        return None

    async def get_authoritative_mission(self, mission_id: UUID) -> Optional[Any]:
        """Read one persisted mission for restart-safe report retrieval."""
        try:
            async with self._persistence_scope() as service:
                loader = getattr(service, "get_mission", None) if service else None
                if loader:
                    return await loader(mission_id)
        except Exception as exc:
            logger.warning(
                "runtime.persisted_mission_read_failed",
                mission_id=str(mission_id),
                error=str(exc),
            )
        return None

    async def get_authoritative_assets(self, mission_id: UUID) -> Optional[List[Any]]:
        """Read persisted assets for dashboard/report completed-mission paths."""
        try:
            async with self._persistence_scope() as service:
                loader = getattr(service, "list_assets", None) if service else None
                if loader:
                    return await loader(mission_id, limit=10000, offset=0)
        except Exception as exc:
            logger.warning(
                "runtime.persisted_assets_read_failed",
                mission_id=str(mission_id),
                error=str(exc),
            )
        return None

    @staticmethod
    def _mark_persistence_degraded(mission: Mission, error: Optional[str] = None) -> None:
        mission.metadata["persistence"] = {
            "postgresql": "unavailable",
            "durable": False,
            **({"error": error} if error else {}),
        }

    # ─── Internal ────────────────────────────────────────────────────────

    def _register_tools(self) -> None:
        """Register all available tools in the ToolManager."""
        registered: List[str] = []
        try:
            self.tool_manager.register_tool(
                "nmap", NmapPlugin, capabilities=["port_scanning", "service_detection", "os_detection"]
            )
            registered.append("nmap")
        except Exception as e:
            logger.warning("runtime.tool_registration_failed", tool="nmap", error=str(e))

        try:
            self.tool_manager.register_tool(
                "nuclei", NucleiPlugin, capabilities=["vulnerability_scanning", "template_scanning"]
            )
            registered.append("nuclei")
        except Exception as e:
            logger.warning("runtime.tool_registration_failed", tool="nuclei", error=str(e))

        logger.info("runtime.tools_registered", tools=registered)

    def _register_capability_handlers(self) -> None:
        """Register capability handlers for the WorkflowEngine."""
        from ai.agents.discovery_agent import DiscoveryAgent

        for capability in DiscoveryAgent.capabilities:
            async def handler(task: Task, cap=capability) -> Any:
                agent = self._discovery_agents.setdefault(task.mission_id, DiscoveryAgent())
                execution_result = TaskExecutionResult(
                    mission_id=task.mission_id,
                    task_id=task.id,
                    capability=task.capability or cap.name,
                    metadata={"task_name": task.name},
                )
                context = {
                    "mission_id": task.mission_id,
                    "task": task.__dict__,
                    "capability": task.capability or cap.name,
                    "target": task.target,
                    "params": task.params,
                    "config": task.config,
                }
                async for raw_evidence in agent.execute(context):
                    if raw_evidence.evidence_type == "error":
                        execution_result.success = False
                        execution_result.errors.append(
                            raw_evidence.data.get("error", "Discovery task failed")
                        )
                        raise RuntimeError(
                            raw_evidence.data.get("error", "Discovery task failed")
                        )
                    evidence = from_agent_evidence(raw_evidence, task.mission_id)
                    execution_result.evidence.append(evidence)
                execution_result.completed_at = datetime.now(timezone.utc)
                if execution_result.assets or execution_result.evidence:
                    await self.process_execution_result(execution_result)
                return execution_result

            self.register_capability_handler(capability.name, handler)

    def _register_event_handlers(self) -> None:
        """Register internal event handlers."""
        async def on_evidence_collected(event: OracleEvent) -> None:
            evidence_id = event.data.get("evidence_id")
            if evidence_id and event.mission_id:
                logger.debug("runtime.evidence_collected", evidence_id=evidence_id, mission_id=str(event.mission_id))

        async def on_mission_completed(event: OracleEvent) -> None:
            mission_id = event.mission_id
            if mission_id:
                logger.info("runtime.mission_completed", mission_id=str(mission_id))
                asyncio.create_task(self._delayed_archive(mission_id))

        self._event_bus.subscribe("runtime.evidence_handler", {EventType.EVIDENCE_COLLECTED}, on_evidence_collected, "Handle evidence collection events")
        self._event_bus.subscribe("runtime.mission_completion_handler", {EventType.MISSION_COMPLETED, EventType.MISSION_FAILED, EventType.MISSION_CANCELLED}, on_mission_completed, "Handle mission lifecycle completion events")

    async def _delayed_archive(self, mission_id: UUID, delay: int = 300) -> None:
        await asyncio.sleep(delay)
        await self.state_manager.archive_mission_state(mission_id)

    async def _persist_mission_status(self, mission_id: UUID, status: MissionStatus) -> None:
        try:
            async with self._persistence_scope() as service:
                if service:
                    await service.update_mission_status(mission_id, status)
        except Exception as e:
            self._degraded_mode.update_status("postgresql", DependencyStatus.UNAVAILABLE)
            mission = self.mission_manager.get_mission(mission_id)
            if mission:
                self._mark_persistence_degraded(mission, str(e))
            logger.error("runtime.persist_status_failed", error=str(e))
        if self.knowledge_graph.is_available:
            try:
                await self.knowledge_graph.update_mission_status(mission_id, status.value)
            except Exception as e:
                logger.error("runtime.graph_status_failed", error=str(e))

    async def _log_event(self, mission_id: UUID, event_type: str, data: Dict[str, Any]) -> None:
        await self.state_manager.log_event(mission_id, event_type, data)
        try:
            async with self._persistence_scope() as service:
                if service:
                    await service.log_event(mission_id, event_type, data=data)
        except Exception as e:
            self._degraded_mode.update_status("postgresql", DependencyStatus.DEGRADED)
            logger.error("runtime.persist_event_failed", error=str(e))


# Global Runtime instance
_runtime: Optional[OracleRuntime] = None


def get_runtime() -> OracleRuntime:
    """Get or create the global Runtime singleton."""
    global _runtime
    if _runtime is None:
        _runtime = OracleRuntime()
    return _runtime


__all__ = ["OracleRuntime", "get_runtime"]
