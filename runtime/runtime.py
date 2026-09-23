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
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from core.config import settings
from core.events import EventType, OracleEvent
from core.logging import get_logger, get_mission_logger, setup_logging
from core.telemetry import telemetry
from core.tool_manager import ToolManager, get_tool_manager
from domain.asset import Asset
from domain.evidence import Evidence as EvidenceDomain
from domain.evidence import from_agent_evidence
from domain.mission import Mission, MissionStatus, MissionTarget, MissionType
from knowledge import get_knowledge_graph, KnowledgeGraphService
from runtime.event_bus import EventBus, get_event_bus
from runtime.mission_manager import MissionManager
from runtime.planner import Planner, Plan, Task
from runtime.policy_engine import PolicyEngine
from runtime.resource_manager import ResourceManager, ResourceQuota
from runtime.scheduler import Scheduler
from runtime.state_manager import StateManager
from runtime.validator import Validator
from runtime.workflow import WorkflowEngine
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
        self.workflow_engine = WorkflowEngine(scheduler=self.scheduler, state_manager=self.state_manager)

        # Persistence
        self.mission_service: Optional[any] = None
        self._db_session = None
        self._db_session_gen = None

        # Knowledge Graph
        self.knowledge_graph: KnowledgeGraphService = get_knowledge_graph()

        # Tool Manager
        self.tool_manager: ToolManager = get_tool_manager()

        # Registry
        self._registered_handlers: Dict[str, Any] = {}
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
        await self.scheduler.start()

        # Initialize database
        try:
            async def _init_database() -> None:
                from backend.database import init_database, get_session
                await init_database()
                from backend.services import MissionService
                session_gen = get_session()
                session = await anext(session_gen)
                self.mission_service = MissionService(session)
                self._db_session = session
                self._db_session_gen = session_gen

            await asyncio.wait_for(_init_database(), timeout=2.0)
            logger.info("runtime.database_initialized")
        except asyncio.TimeoutError:
            logger.warning("runtime.database_init_timeout")
            self.mission_service = None
        except Exception as e:
            logger.warning("runtime.database_unavailable", error=str(e))
            self.mission_service = None

        # Initialize knowledge graph
        try:
            await asyncio.wait_for(self.knowledge_graph.initialize(), timeout=2.0)
            if self.knowledge_graph.is_available:
                logger.info("runtime.knowledge_graph_initialized")
            else:
                logger.warning("runtime.knowledge_graph_unavailable")
        except asyncio.TimeoutError:
            logger.warning("runtime.knowledge_graph_init_timeout")
        except Exception as e:
            logger.warning("runtime.knowledge_graph_init_failed", error=str(e))

        self._register_tools()
        self._register_capability_handlers()
        self._register_event_handlers()

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

        if self.mission_service:
            try:
                await self.mission_service.create_mission(mission)
            except Exception as e:
                logger.error("runtime.persist_mission_failed", error=str(e))

        if self.knowledge_graph.is_available:
            try:
                await self.knowledge_graph.create_mission_node(mission.id, mission.name, mission.mission_type.value)
            except Exception as e:
                logger.error("runtime.graph_mission_failed", error=str(e))

        logger.info("runtime.mission_created", mission_id=str(mission.id), mission_type=mission_type.value)
        return mission

    async def execute_mission(self, mission_id: UUID) -> None:
        """Execute a mission end-to-end (policy -> plan -> execute -> persist)."""
        mission = self.mission_manager.get_mission(mission_id)
        if not mission:
            logger.error("runtime.mission_not_found", mission_id=str(mission_id))
            return

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
            return

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
        await self._persist_mission_status(mission_id, MissionStatus.IN_PROGRESS)
        try:
            await self.workflow_engine.execute_plan(plan, mission)
        except Exception as e:
            ms = mission_logger.elapsed_ms("mission_total") or 0.0
            mission_logger.log_mission_failed(mission_id_str, str(e), ms)
            await self.mission_manager.fail_mission(mission_id, str(e))
            await self._persist_mission_status(mission_id, MissionStatus.FAILED)
            raise

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

    async def cancel_mission(self, mission_id: UUID) -> None:
        """Cancel a running mission."""
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

    # ─── Evidence Pipeline ───────────────────────────────────────────────

    async def process_evidence(self, evidence: EvidenceDomain, mission_id: UUID) -> None:
        """Process evidence through the pipeline: validate -> persist -> graph."""
        mission_id_str = str(mission_id)
        mission_logger.start_timer("evidence_pipeline")

        validated = await self.validator.validate_evidence(evidence)

        if self.mission_service:
            try:
                await self.mission_service.create_evidence(mission_id, validated)
            except Exception as e:
                logger.error("runtime.persist_evidence_failed", error=str(e))

        if self.knowledge_graph.is_available:
            try:
                await self.knowledge_graph.create_evidence_node(
                    evidence_id=validated.id, mission_id=mission_id,
                    asset_id=validated.asset_id,
                    evidence_type=validated.evidence_type.value if hasattr(validated.evidence_type, 'value') else str(validated.evidence_type),
                    title=validated.title or "",
                    confidence=validated.confidence,
                )
            except Exception as e:
                logger.error("runtime.graph_evidence_failed", error=str(e))

        await self.state_manager.add_evidence(mission_id, validated)

        duration_ms = mission_logger.stop_timer("evidence_pipeline") or 0.0
        mission_logger.log("evidence.processed", mission_id=mission_id_str,
                           details={"evidence_type": validated.evidence_type.value if hasattr(validated.evidence_type, 'value') else str(validated.evidence_type),
                                    "confidence": validated.confidence,
                                    "duration_ms": duration_ms})

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
        discovery_agent = DiscoveryAgent()

        for capability in discovery_agent.capabilities:
            async def handler(task: Task, agent=discovery_agent, cap=capability) -> Any:
                context = {
                    "mission_id": task.mission_id,
                    "task": task.__dict__,
                    "capability": cap.name,
                    "config": task.config,
                }
                results = []
                async for raw_evidence in agent.execute(context):
                    evidence = from_agent_evidence(raw_evidence, task.mission_id)
                    await self.process_evidence(evidence, task.mission_id)
                    results.append(evidence)
                return results

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
        if self.mission_service:
            try:
                await self.mission_service.update_mission_status(mission_id, status)
            except Exception as e:
                logger.error("runtime.persist_status_failed", error=str(e))
        if self.knowledge_graph.is_available:
            try:
                await self.knowledge_graph.update_mission_status(mission_id, status.value)
            except Exception as e:
                logger.error("runtime.graph_status_failed", error=str(e))

    async def _log_event(self, mission_id: UUID, event_type: str, data: Dict[str, Any]) -> None:
        await self.state_manager.log_event(mission_id, event_type, data)
        if self.mission_service:
            try:
                await self.mission_service.log_event(mission_id, event_type, data)
            except Exception:
                pass


# Global Runtime instance
_runtime: Optional[OracleRuntime] = None


def get_runtime() -> OracleRuntime:
    """Get or create the global Runtime singleton."""
    global _runtime
    if _runtime is None:
        _runtime = OracleRuntime()
    return _runtime


__all__ = ["OracleRuntime", "get_runtime"]
