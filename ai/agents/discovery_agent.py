"""
Discovery Agent
===============

The first vertical slice agent for ORACLE.

The Discovery Agent is responsible for:
1. Port scanning (via Nmap)
2. Service identification
3. Technology detection
4. Asset enumeration
5. Evidence collection and normalization

This is the reference implementation for all future agents.
"""

from __future__ import annotations

from typing import Any, AsyncIterator, Dict, List, Optional, Tuple
from uuid import UUID

from core.events import EventType, OracleEvent
from core.interfaces import AgentStatus, Capability, Evidence, OracleAgent
from core.logging import get_logger, get_mission_logger
from domain.asset import Asset, AssetType, AssetCriticality
from domain.mission import Mission
from runtime.event_bus import get_event_bus
from runtime.state_manager import StateManager
from tools.common import HostInfo
from tools.nmap import NmapPlugin
from tools.nuclei import NucleiPlugin

logger = get_logger(__name__)
mission_logger = get_mission_logger()


class DiscoveryAgent(OracleAgent):
    """
    Discovery Agent — finds and enumerates assets.

    This agent performs:
    - Port scanning (TCP SYN, UDP)
    - Service version detection
    - OS fingerprinting
    - Technology identification
    - Asset relationship mapping

    It publishes events at each stage so other components
    (Knowledge Graph, Risk Engine) can react in real-time.
    """

    name = "discovery_agent"
    version = "0.1.0"
    description = "Discovers and enumerates network assets, services, and technologies"

    capabilities = [
        Capability(
            name="port_scanning",
            description="Scan targets for open TCP/UDP ports",
            tools=["nmap"],
            confidence_threshold=0.8,
        ),
        Capability(
            name="service_discovery",
            description="Identify services running on open ports",
            tools=["nmap"],
            confidence_threshold=0.85,
        ),
        Capability(
            name="os_detection",
            description="Detect operating systems of target hosts",
            tools=["nmap"],
            confidence_threshold=0.6,
        ),
        Capability(
            name="technology_detection",
            description="Identify technologies and frameworks in use",
            tools=["nmap"],
            confidence_threshold=0.7,
        ),
        Capability(
            name="vulnerability_scanning",
            description="Run template-based vulnerability scans against discovered HTTP(S) services",
            tools=["nuclei"],
            confidence_threshold=0.75,
        ),
    ]

    def __init__(self) -> None:
        self._status = AgentStatus.IDLE
        self._nmap = NmapPlugin()
        self._nuclei = NucleiPlugin()
        self._event_bus = get_event_bus()
        self._state_manager = StateManager()
        self._current_mission_id: Optional[UUID] = None
        self._discovered_assets: Dict[str, Asset] = {}
        self._discovered_hosts: Dict[str, HostInfo] = {}

    async def initialize(self) -> None:
        """Initialize the agent and its tools."""
        health = await self._nmap.health_check()
        if not health["healthy"]:
            logger.warning(
                "discovery_agent.nmap_not_available",
                error=health.get("error", "Unknown"),
            )
        else:
            logger.info(
                "discovery_agent.initialized",
                nmap_version=health.get("version", "unknown"),
            )

        nuclei_health = await self._nuclei.health_check()
        if not nuclei_health["healthy"]:
            logger.warning(
                "discovery_agent.nuclei_not_available",
                error=nuclei_health.get("error", "Unknown"),
            )
        else:
            logger.info(
                "discovery_agent.nuclei_initialized",
                nuclei_version=nuclei_health.get("version", "unknown"),
            )

        self._status = AgentStatus.IDLE

    async def plan(self, mission: Mission) -> List[Dict[str, Any]]:
        """
        Create a plan for asset discovery.

        The plan breaks the mission goal into executable tasks based on
        the target scope and configured capabilities.

        Args:
            mission: The mission to plan for

        Returns:
            List of task descriptions to execute
        """
        tasks = []
        target = mission.target

        # Task 1: Health check
        tasks.append({
            "id": "health_check",
            "capability": "port_scanning",
            "description": "Verify tool availability",
            "priority": 1,
            "depends_on": [],
        })

        # Task 2: Port scanning for each target
        all_targets = []
        all_targets.extend(target.domains)
        all_targets.extend(target.ip_ranges)
        all_targets.extend(target.urls)

        for i, target_str in enumerate(all_targets):
            tasks.append({
                "id": f"port_scan_{i}",
                "capability": "port_scanning",
                "description": f"Scan {target_str} for open ports",
                "priority": 2,
                "depends_on": ["health_check"],
                "target": target_str,
                "params": {
                    "ports": "1-10000",
                    "scan_type": "syn",
                    "timing": 4,
                },
            })

        # Task 3: Service detection on discovered ports
        tasks.append({
            "id": "service_discovery",
            "capability": "service_discovery",
            "description": "Identify services on discovered ports",
            "priority": 3,
            "depends_on": [f"port_scan_{i}" for i in range(len(all_targets))],
            "params": {
                "service_detection": True,
                "os_detection": True,
            },
        })

        # Task 4: Vulnerability scanning on discovered HTTP(S) services
        tasks.append({
            "id": "vulnerability_scan",
            "capability": "vulnerability_scanning",
            "description": "Run Nuclei templates against discovered HTTP(S) services",
            "priority": 4,
            "depends_on": ["service_discovery"],
            "params": {
                "severity": ["critical", "high", "medium", "low"],
            },
        })

        # Task 5: Asset compilation
        tasks.append({
            "id": "asset_compilation",
            "capability": "technology_detection",
            "description": "Compile and normalize all discovered assets",
            "priority": 5,
            "depends_on": ["service_discovery", "vulnerability_scan"],
        })

        logger.info(
            "discovery_agent.plan_created",
            mission_id=str(mission.id),
            tasks=len(tasks),
        )

        return tasks

    async def execute(self, context: Dict[str, Any]) -> AsyncIterator[Evidence]:
        """
        Execute the discovery plan.

        This method is called by the Workflow Engine with task context.
        It yields Evidence objects as they are discovered.

        Args:
            context: Task execution context with mission, task, and params

        Yields:
            Evidence objects as assets are discovered
        """
        task = context.get("task", {})
        task_id = str(task.get("id", "unknown"))
        capability = context.get("capability") or task.get("capability")
        params = context.get("params") or task.get("params") or {}

        self._status = AgentStatus.RUNNING
        self._current_mission_id = context.get("mission_id")

        logger.info("discovery_agent.executing", task_id=task_id)
        mission_logger.log("agent.started", mission_id=str(self._current_mission_id) if self._current_mission_id else "", task_id=task_id, agent=self.name, status="started")

        try:
            # Canonical runtime tasks are routed by capability. The semantic
            # string IDs remain as an adapter for the agent's standalone plan.
            if capability == "port_scanning":
                explicit_target = context.get("target") or task.get("target")
                config = context.get("config") or task.get("config") or {}
                targets = [explicit_target] if explicit_target else []
                if not targets:
                    targets.extend(config.get("target_domains", []))
                    targets.extend(config.get("target_ip_ranges", []))
                    targets.extend(config.get("target_ips", []))
                    targets.extend(config.get("target_urls", []))
                if not targets:
                    raise ValueError("port_scanning task has no target")
                for target in targets:
                    async for evidence in self._execute_port_scan(context, target, params):
                        yield evidence

            elif capability in {"service_discovery", "os_detection"}:
                async for evidence in self._execute_service_discovery(context):
                    yield evidence

            elif capability == "vulnerability_scanning":
                async for evidence in self._execute_vulnerability_scan(context, params):
                    yield evidence

            elif capability == "technology_detection":
                yield await self._execute_asset_compilation(context)

            elif task_id == "health_check":
                yield await self._execute_health_check(context)

            elif task_id.startswith("port_scan_"):
                target = task.get("target", "")
                async for evidence in self._execute_port_scan(context, target, params):
                    yield evidence

            elif task_id == "service_discovery":
                async for evidence in self._execute_service_discovery(context):
                    yield evidence

            elif task_id == "vulnerability_scan":
                async for evidence in self._execute_vulnerability_scan(context, params):
                    yield evidence

            elif task_id == "asset_compilation":
                yield await self._execute_asset_compilation(context)

            else:
                raise ValueError(
                    f"Unsupported discovery task {task_id!r} with capability {capability!r}"
                )

        except Exception as e:
            logger.error(
                "discovery_agent.task_failed",
                task_id=task_id,
                error=str(e),
            )
            mission_logger.log("agent.failed", mission_id=str(self._current_mission_id) if self._current_mission_id else "", task_id=task_id, agent=self.name, status="failure", error=str(e))
            yield Evidence(
                source="discovery_agent",
                evidence_type="error",
                asset_value="",
                data={"task_id": task_id, "error": str(e)},
                confidence=0.0,
            )

        finally:
            self._status = AgentStatus.IDLE
            mission_logger.log("agent.completed", mission_id=str(self._current_mission_id) if self._current_mission_id else "", agent=self.name, status="completed")

    async def validate(self, evidence: Evidence) -> Tuple[bool, str]:
        """
        Validate a piece of evidence.

        Checks for:
        - Reasonable confidence level
        - Consistent data format
        - No known false positives

        Args:
            evidence: The evidence to validate

        Returns:
            Tuple of (is_valid, reason)
        """
        if evidence.confidence < 0.1:
            return False, "Confidence too low"

        if not evidence.asset_value:
            return False, "Missing asset value"

        # IP address validation
        if evidence.evidence_type == "port":
            import re
            ip_pattern = re.compile(
                r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+/(tcp|udp)$"
            )
            if not ip_pattern.match(evidence.asset_value):
                return False, "Invalid port format"

        return True, "Evidence validated"

    async def explain(self, evidence: Evidence) -> str:
        """
        Generate a human-readable explanation of evidence.

        Args:
            evidence: The evidence to explain

        Returns:
            Human-readable explanation string
        """
        if evidence.evidence_type == "port":
            data = evidence.data
            return (
                f"Open port {data.get('port')}/{data.get('protocol', 'tcp')} "
                f"on {evidence.asset_value} "
                f"running {data.get('service', 'unknown service')} "
                f"{data.get('service_version', '')}".strip()
            )
        elif evidence.evidence_type == "host":
            return f"Host {evidence.asset_value} is online"
        elif evidence.evidence_type == "os":
            return f"OS detected on {evidence.asset_value}: {evidence.data.get('os', 'unknown')}"
        elif evidence.evidence_type == "vulnerability":
            data = evidence.data
            cve_suffix = f" ({', '.join(data.get('cve_ids', []))})" if data.get("cve_ids") else ""
            return (
                f"[{evidence.severity.upper()}] {evidence.title}{cve_suffix} "
                f"at {evidence.asset_value}"
            )
        else:
            return f"{evidence.evidence_type}: {evidence.asset_value}"

    async def get_status(self) -> AgentStatus:
        """Get current agent status."""
        return self._status

    # ─── Internal Execution Methods ──────────────────────────────────

    async def _execute_health_check(self, context: Dict[str, Any]) -> Evidence:
        """Check tool health."""
        health = await self._nmap.health_check()
        return Evidence(
            source="discovery_agent",
            evidence_type="health_check",
            asset_value="system",
            data=health,
            confidence=1.0,
        )

    async def _execute_port_scan(
        self,
        context: Dict[str, Any],
        target: str,
        params: Dict[str, Any],
    ) -> AsyncIterator[Evidence]:
        """Execute a port scan against a target."""
        # Emit scan started event
        await self._event_bus.publish(OracleEvent(
            event_type=EventType.SCAN_STARTED,
            source="discovery_agent",
            mission_id=self._current_mission_id,
            data={"target": target, "params": params},
        ))

        logger.info("discovery_agent.scanning", target=target, params=params)
        mission_logger.log("scan.started", mission_id=str(self._current_mission_id) if self._current_mission_id else "", agent=self.name, tool="nmap", status="started", details={"target": target, "ports": params.get("ports", "1-1000")})

        # Execute Nmap scan
        raw_output = b""
        async for chunk in self._nmap.execute(
            targets=[target],
            ports=params.get("ports", "1-1000"),
            scan_type=params.get("scan_type", "syn"),
            timing=params.get("timing", 3),
            service_detection=True,
        ):
            raw_output += chunk

        # Parse results
        hosts = await self._nmap.parse(raw_output)

        if not hosts:
            logger.info("discovery_agent.no_hosts_found", target=target)
            yield Evidence(
                source="discovery_agent",
                evidence_type="scan_result",
                asset_value=target,
                data={"hosts_found": 0, "target": target},
                confidence=0.5,
            )
            return

        # Yield evidence for each host and port
        for host in hosts:
            self._discovered_hosts[host.ip] = host

            # Host evidence
            host_evidence = Evidence(
                source="discovery_agent",
                evidence_type="host",
                asset_value=host.ip,
                data=host.to_evidence_data(),
                confidence=0.95 if host.status == "up" else 0.5,
                tags=["host", "discovered"],
            )
            yield host_evidence

            # Track asset
            asset = Asset(
                asset_type=AssetType.HOST,
                value=host.ip,
                label=host.hostnames[0] if host.hostnames else host.ip,
                ip_addresses=[host.ip],
                hostnames=host.hostnames,
                open_ports=[p.port for p in host.ports if p.state == "open"],
                criticality=AssetCriticality.UNKNOWN,
            )
            self._discovered_assets[host.ip] = asset

            # Port evidence
            for port in host.ports:
                if port.state == "open":
                    port_evidence = Evidence(
                        source="discovery_agent",
                        evidence_type="port",
                        asset_value=f"{host.ip}:{port.port}/{port.protocol}",
                        data=port.to_evidence_data(),
                        confidence=0.9,
                        tags=[port.service, "open_port"] if port.service else ["open_port"],
                        cve_ids=[],
                        mitre_techniques=["T1046"],  # Network Service Discovery
                    )
                    yield port_evidence

            # OS detection evidence
            if host.os:
                os_evidence = Evidence(
                    source="discovery_agent",
                    evidence_type="os",
                    asset_value=host.ip,
                    data={"os": host.os, "accuracy": host.os_accuracy},
                    confidence=host.os_accuracy / 100.0,
                    tags=["os_detection"],
                )
                yield os_evidence

        mission_logger.log("scan.completed", mission_id=str(self._current_mission_id) if self._current_mission_id else "", agent=self.name, tool="nmap", status="completed", details={"target": target, "hosts_found": len(hosts), "ports_found": sum(len(h.ports) for h in hosts)})

        # Emit scan completed event
        await self._event_bus.publish(OracleEvent(
            event_type=EventType.SCAN_COMPLETED,
            source="discovery_agent",
            mission_id=self._current_mission_id,
            data={
                "target": target,
                "hosts_found": len(hosts),
                "ports_found": sum(len(h.ports) for h in hosts),
            },
        ))

    async def _execute_service_discovery(self, context: Dict[str, Any]) -> AsyncIterator[Evidence]:
        """Perform deep service discovery on found ports."""
        logger.info("discovery_agent.service_discovery")

        # For each discovered host, do deeper service detection
        for asset_value, asset in self._discovered_assets.items():
            if not asset.open_ports:
                continue

            # Deep scan on found ports
            ports_str = ",".join(str(p) for p in asset.open_ports)

            raw_output = b""
            async for chunk in self._nmap.execute(
                targets=[asset_value],
                ports=ports_str,
                scan_type="comprehensive",
                service_detection=True,
                os_detection=True,
                nse_scripts=["banner", "http-title", "ssl-cert"],
            ):
                raw_output += chunk

            hosts = await self._nmap.parse(raw_output)

            for host in hosts:
                self._discovered_hosts[host.ip] = host
                for port in host.ports:
                    if port.state == "open" and (
                        port.service_version or port.service_product
                    ):
                        service_evidence = Evidence(
                            source="discovery_agent",
                            evidence_type="service",
                            asset_value=f"{host.ip}:{port.port}",
                            data=port.to_evidence_data(),
                            confidence=0.85,
                            tags=[port.service, "verified"],
                        )
                        yield service_evidence

    async def _execute_vulnerability_scan(
        self,
        context: Dict[str, Any],
        params: Dict[str, Any],
    ) -> AsyncIterator[Evidence]:
        """Run Nuclei against discovered HTTP(S) services."""
        targets = self._nuclei.build_targets_from_hosts(list(self._discovered_hosts.values()))

        if not targets:
            logger.info("discovery_agent.no_http_targets_for_nuclei")
            yield Evidence(
                source="discovery_agent",
                evidence_type="scan_result",
                asset_value="vulnerability_scan",
                data={"targets_found": 0},
                confidence=0.5,
            )
            return

        await self._event_bus.publish(OracleEvent(
            event_type=EventType.SCAN_STARTED,
            source="discovery_agent",
            mission_id=self._current_mission_id,
            data={"tool": "nuclei", "targets": targets},
        ))
        mission_logger.log(
            "scan.started",
            mission_id=str(self._current_mission_id) if self._current_mission_id else "",
            agent=self.name,
            tool="nuclei",
            status="started",
            details={"target_count": len(targets)},
        )

        raw_output = b""
        try:
            async for chunk in self._nuclei.execute(
                targets=targets,
                severity=params.get("severity"),
            ):
                raw_output += chunk
        except Exception as e:
            # Tool failures are execution failures, not evidence. The outer
            # agent boundary converts this into an error result so the task
            # and workflow cannot report success.
            logger.error("discovery_agent.nuclei_scan_failed", error=str(e))
            raise

        findings = await self._nuclei.parse(raw_output)
        evidence_list = await self._nuclei.normalize(findings)

        for evidence in evidence_list:
            yield evidence

        mission_logger.log(
            "scan.completed",
            mission_id=str(self._current_mission_id) if self._current_mission_id else "",
            agent=self.name,
            tool="nuclei",
            status="completed",
            details={"target_count": len(targets), "findings": len(evidence_list)},
        )
        await self._event_bus.publish(OracleEvent(
            event_type=EventType.SCAN_COMPLETED,
            source="discovery_agent",
            mission_id=self._current_mission_id,
            data={"tool": "nuclei", "targets_scanned": len(targets), "findings": len(evidence_list)},
        ))

    async def _execute_asset_compilation(self, context: Dict[str, Any]) -> Evidence:
        """Compile all discovered assets into a summary."""
        logger.info(
            "discovery_agent.compiling_assets",
            total=len(self._discovered_assets),
        )

        summary = {
            "total_hosts": len(self._discovered_assets),
            "total_ports": sum(
                len(a.open_ports) for a in self._discovered_assets.values()
            ),
            "ip_addresses": list(self._discovered_assets.keys()),
        }

        return Evidence(
            source="discovery_agent",
            evidence_type="asset_summary",
            asset_value="compilation",
            data=summary,
            confidence=1.0,
            tags=["summary", "compilation"],
        )
