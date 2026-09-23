"""
Nmap Plugin
===========

Enterprise-grade Nmap integration for ORACLE.

Executes Nmap scans, parses XML output, and normalizes
results into structured Evidence objects.

Pipeline:
    Target
    ↓
    Run nmap (XML output)
    ↓
    Parse XML
    ↓
    Normalize → Evidence objects
    ↓
    Validator
    ↓
    Database + Knowledge Graph
"""

from __future__ import annotations

import asyncio
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

from core.exceptions import ToolUnavailableError
from core.interfaces import Evidence, SecurityTool
from core.logging import get_logger, get_mission_logger
from core.telemetry import telemetry
from tools.common import (
    HostInfo,
    PortInfo,
    ToolResult,
    check_tool_available,
    execute_command,
    execute_command_stream,
)

logger = get_logger(__name__)
mission_logger = get_mission_logger()


class NmapPlugin(SecurityTool):
    """
    ORACLE Nmap Integration Plugin.

    Provides:
    - Health check (version verification)
    - Full scan execution (SYN, TCP connect, UDP, comprehensive)
    - XML output parsing
    - Result normalization → HostInfo → Evidence
    - Script output extraction (NSE)
    """

    name = "nmap"
    version = "7.95"
    description = "Network Mapper — port scanning, service detection, OS fingerprinting"

    # Version string regex patterns
    VERSION_PATTERNS = [
        r"Nmap version (\d+\.\d+)",
        r"Nmap (\d+\.\d+)",
    ]

    def __init__(self) -> None:
        self._available: Optional[bool] = None
        self._version: str = "unknown"
        self._binary: str = "nmap"

    # ─── Health Check ─────────────────────────────────────────────────────

    async def health_check(self) -> Dict[str, Any]:
        """
        Check if Nmap is available and functional.

        Returns:
            Dict with healthy, version, and error keys
        """
        if not check_tool_available(self._binary):
            self._available = False
            return {
                "healthy": False,
                "available": False,
                "version": None,
                "error": f"Nmap binary '{self._binary}' not found in PATH. "
                         "Install Nmap from https://nmap.org/download.html",
            }

        try:
            exit_code, stdout, stderr = await execute_command(
                [self._binary, "--version"],
                timeout=10,
            )

            if exit_code != 0:
                self._available = False
                return {
                    "healthy": False,
                    "available": True,
                    "version": None,
                    "error": f"Nmap version check failed: {stderr[:200]}",
                }

            # Parse version
            import re
            for pattern in self.VERSION_PATTERNS:
                match = re.search(pattern, stdout)
                if match:
                    self._version = match.group(1)
                    break

            self._available = True
            return {
                "healthy": True,
                "available": True,
                "version": self._version,
                "error": None,
            }

        except ToolUnavailableError:
            self._available = False
            return {
                "healthy": False,
                "available": False,
                "version": None,
                "error": f"Nmap binary '{self._binary}' not found in PATH",
            }
        except Exception as e:
            self._available = False
            return {
                "healthy": False,
                "available": True,
                "version": None,
                "error": str(e),
            }

    # ─── Execution ────────────────────────────────────────────────────────

    async def execute(
        self,
        targets: List[str],
        ports: str = "1-1000",
        scan_type: str = "syn",
        timing: int = 3,
        service_detection: bool = True,
        os_detection: bool = False,
        nse_scripts: Optional[List[str]] = None,
        output_xml: bool = True,
        additional_args: Optional[List[str]] = None,
    ) -> AsyncIterator[bytes]:
        """
        Execute an Nmap scan against targets.

        Args:
            targets: List of target IPs, domains, or CIDR ranges
            ports: Port range or comma-separated list (e.g., "80,443,8080" or "1-10000")
            scan_type: Type of scan (syn, connect, udp, comprehensive)
            timing: Nmap timing template (0=paranoid ... 5=insane)
            service_detection: Enable -sV service version detection
            os_detection: Enable -O OS detection
            nse_scripts: List of NSE scripts to run
            output_xml: Output in XML format (-oX -)
            additional_args: Additional Nmap arguments

        Yields:
            Raw output bytes as they are produced
        """
        if not targets:
            raise ValueError("At least one target is required")

        if not self._available:
            health = await self.health_check()
            if not health["healthy"]:
                raise ToolUnavailableError(
                    tool_name=self._binary,
                    message=health.get("error", "Nmap is not available"),
                )

        # Build command
        cmd = [self._binary]

        # Scan type
        if scan_type == "syn":
            cmd.append("-sS")
        elif scan_type == "connect":
            cmd.append("-sT")
        elif scan_type == "udp":
            cmd.append("-sU")
        elif scan_type == "comprehensive":
            cmd.extend(["-sS", "-sV", "-O", "--traceroute"])
        else:
            cmd.append("-sS")  # Default SYN scan

        # Port specification
        cmd.extend(["-p", ports])

        # Timing
        cmd.extend(["-T", str(timing)])

        # Service detection
        if service_detection and scan_type != "comprehensive":
            cmd.append("-sV")

        # OS detection
        if os_detection and scan_type != "comprehensive":
            cmd.append("-O")

        # NSE scripts
        if nse_scripts:
            cmd.extend(["--script", ",".join(nse_scripts)])

        # XML output to stdout
        if output_xml:
            cmd.extend(["-oX", "-"])

        # Additional arguments
        if additional_args:
            cmd.extend(additional_args)

        # Add targets
        cmd.extend(targets)

        logger.info(
            "nmap.executing",
            command=" ".join(cmd),
            targets=targets,
            ports=ports,
            scan_type=scan_type,
        )

        # Execute and stream output
        try:
            async for chunk in execute_command_stream(cmd, timeout=600):
                yield chunk
        except ToolUnavailableError:
            raise
        except Exception as e:
            logger.error("nmap.execution_failed", error=str(e))
            raise

    # ─── Parsing ─────────────────────────────────────────────────────────

    async def parse(self, raw_output: bytes) -> List[HostInfo]:
        """
        Parse Nmap XML output into structured HostInfo objects.

        Args:
            raw_output: Raw Nmap XML output

        Returns:
            List of HostInfo objects with discovered hosts, ports, and services
        """
        if not raw_output or len(raw_output.strip()) == 0:
            logger.warning("nmap.parse.empty_output")
            return []

        # Try XML parsing first
        try:
            return self._parse_xml(raw_output)
        except ET.ParseError as e:
            logger.warning(
                "nmap.parse.xml_failed",
                error=str(e),
                trying="text_parse",
            )
            # Fall back to text parsing
            return self._parse_text(raw_output.decode("utf-8", errors="replace"))

    def _parse_xml(self, raw_output: bytes) -> List[HostInfo]:
        """Parse Nmap XML output."""
        root = ET.fromstring(raw_output)
        hosts: List[HostInfo] = []

        for host_elem in root.findall("host"):
            host_info = self._parse_host_xml(host_elem)
            if host_info:
                hosts.append(host_info)

        logger.info(
            "nmap.parse.completed",
            hosts_found=len(hosts),
            total_ports=sum(len(h.ports) for h in hosts),
        )

        return hosts

    def _parse_host_xml(self, host_elem: ET.Element) -> Optional[HostInfo]:
        """Parse a single host element from Nmap XML."""
        # Get host status
        status_elem = host_elem.find("status")
        if status_elem is None:
            return None

        status = status_elem.get("state", "unknown")
        reason = status_elem.get("reason", "")

        # Get IP address
        address_elem = host_elem.find("address")
        if address_elem is None:
            return None

        ip = address_elem.get("addr", "")
        addr_type = address_elem.get("addrtype", "ipv4")
        mac_address = ""

        # Check for MAC address in additional address elements
        for addr in host_elem.findall("address"):
            if addr.get("addrtype") == "mac":
                mac_address = addr.get("addr", "")

        # Get hostnames
        hostnames: List[str] = []
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            for hn in hostnames_elem.findall("hostname"):
                name = hn.get("name", "")
                if name:
                    hostnames.append(name)

        # Get ports
        ports: List[PortInfo] = []
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                port_info = self._parse_port_xml(port_elem)
                if port_info:
                    ports.append(port_info)

        # Get OS detection
        os_name = ""
        os_accuracy = 0
        os_family = ""
        os_gen = ""
        os_elem = host_elem.find("os")
        if os_elem is not None:
            osmatch_elem = os_elem.find("osmatch")
            if osmatch_elem is not None:
                os_name = osmatch_elem.get("name", "")
                os_accuracy_str = osmatch_elem.get("accuracy", "0")
                os_accuracy = int(os_accuracy_str) if os_accuracy_str.isdigit() else 0

                # Try to get family/generation
                osclass_elem = osmatch_elem.find("osclass")
                if osclass_elem is not None:
                    os_family = osclass_elem.get("family", "")
                    os_gen = osclass_elem.get("gen", "")

        # Get uptime
        uptime = ""
        last_boot = ""
        uptime_elem = host_elem.find("uptime")
        if uptime_elem is not None:
            uptime = uptime_elem.get("seconds", "")
            last_boot = uptime_elem.get("lastboot", "")

        # Get distance (traceroute hops)
        distance = 0
        distance_elem = host_elem.find("distance")
        if distance_elem is not None:
            distance_str = distance_elem.get("value", "0")
            distance = int(distance_str) if distance_str.isdigit() else 0

        # Get host scripts
        scripts = {}
        for script_elem in host_elem.findall("hostscript/script") or []:
            script_id = script_elem.get("id", "")
            script_output = script_elem.get("output", "")
            if script_id:
                scripts[script_id] = script_output

        return HostInfo(
            ip=ip,
            status=status,
            hostnames=hostnames,
            ports=ports,
            os=os_name,
            os_accuracy=os_accuracy,
            os_family=os_family,
            os_gen=os_gen,
            mac_address=mac_address,
            distance=distance,
            uptime=uptime,
            last_boot=last_boot,
            scripts=scripts,
        )

    def _parse_port_xml(self, port_elem: ET.Element) -> Optional[PortInfo]:
        """Parse a single port element from Nmap XML."""
        protocol = port_elem.get("protocol", "tcp")
        port_str = port_elem.get("portid", "0")

        try:
            port = int(port_str)
        except ValueError:
            return None

        # Get state
        state_elem = port_elem.find("state")
        if state_elem is None:
            return None

        state = state_elem.get("state", "unknown")
        reason = state_elem.get("reason", "")

        # Get service
        service = ""
        service_product = ""
        service_version = ""
        service_extra_info = ""
        cpe = ""
        service_elem = port_elem.find("service")
        if service_elem is not None:
            service = service_elem.get("name", "")
            service_product = service_elem.get("product", "")
            service_version = service_elem.get("version", "")
            service_extra_info = service_elem.get("extrainfo", "")
            cpe_elem = service_elem.find("cpe")
            if cpe_elem is not None:
                cpe = cpe_elem.text or ""
            else:
                cpe = service_elem.get("cpe", "")

        # Get NSE scripts for this port
        scripts = {}
        for script_elem in port_elem.findall("script"):
            script_id = script_elem.get("id", "")
            script_output = script_elem.get("output", "")
            if script_id:
                # Parse structured script output if available
                scripts[script_id] = script_output

        return PortInfo(
            port=port,
            protocol=protocol,
            state=state,
            reason=reason,
            service=service,
            service_product=service_product,
            service_version=service_version,
            service_extra_info=service_extra_info,
            cpe=cpe,
            scripts=scripts,
            confidence=0.95 if state == "open" else (0.7 if state == "filtered" else 0.5),
        )

    def _parse_text(self, text_output: str) -> List[HostInfo]:
        """
        Fallback text parser for Nmap output.

        Used when XML output is not available.
        This is a simplified parser — prefers XML.
        """
        hosts: List[HostInfo] = []
        current_host: Optional[HostInfo] = None
        current_ports: List[PortInfo] = []

        import re

        for line in text_output.split("\n"):
            line = line.strip()

            # Detect host (e.g., "Nmap scan report for 192.168.1.1")
            host_match = re.match(r"Nmap scan report for\s+(\S+)", line)
            if host_match:
                if current_host:
                    current_host.ports = current_ports
                    hosts.append(current_host)
                ip = host_match.group(1)
                # Strip DNS name if present (e.g., "hostname (1.2.3.4)")
                ip = re.sub(r".*\((\d+\.\d+\.\d+\.\d+)\)", r"\1", ip)
                current_host = HostInfo(ip=ip)
                current_ports = []
                continue

            # Detect port (e.g., "80/tcp   open  http  Apache httpd 2.4.41")
            port_match = re.match(
                r"(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)?\s*(.*)?",
                line,
            )
            if port_match and current_host:
                port = int(port_match.group(1))
                protocol = port_match.group(2)
                state = port_match.group(3)
                service = port_match.group(4) or ""
                extra = port_match.group(5) or ""

                port_info = PortInfo(
                    port=port,
                    protocol=protocol,
                    state=state,
                    service=service,
                    service_extra_info=extra,
                )
                current_ports.append(port_info)
                continue

        # Don't forget the last host
        if current_host:
            current_host.ports = current_ports
            hosts.append(current_host)

        return hosts

    # ─── Normalization ──────────────────────────────────────────────────

    async def normalize(
        self,
        parsed_results: List[Dict[str, Any]],
    ) -> List[Evidence]:
        """
        Normalize parsed Nmap results into Evidence objects.

        Args:
            parsed_results: List of parsed host dictionaries

        Returns:
            List of Evidence objects ready for the pipeline
        """
        evidence_list: List[Evidence] = []

        for result in parsed_results:
            if isinstance(result, dict):
                host = HostInfo(**result)
            elif isinstance(result, HostInfo):
                host = result
            else:
                continue

            # Host evidence
            evidence_list.append(Evidence(
                source="nmap",
                evidence_type="host",
                asset_value=host.ip,
                data=host.to_evidence_data(),
                confidence=0.95 if host.status == "up" else 0.5,
                tags=["host", "discovered"],
            ))

            # Port evidence for each open port
            for port in host.open_ports:
                evidence_list.append(Evidence(
                    source="nmap",
                    evidence_type="port",
                    asset_value=f"{host.ip}:{port.port}/{port.protocol}",
                    data=port.to_evidence_data(),
                    confidence=port.confidence,
                    tags=[port.service, "open_port"] if port.service else ["open_port"],
                    mitre_techniques=["T1046"],  # Network Service Discovery
                ))

            # OS evidence
            if host.os:
                evidence_list.append(Evidence(
                    source="nmap",
                    evidence_type="os",
                    asset_value=host.ip,
                    data={
                        "os": host.os,
                        "accuracy": host.os_accuracy,
                        "family": host.os_family,
                        "gen": host.os_gen,
                    },
                    confidence=host.os_accuracy / 100.0 if host.os_accuracy > 0 else 0.5,
                    tags=["os_detection"],
                ))

        logger.info(
            "nmap.normalized",
            evidence_count=len(evidence_list),
        )

        return evidence_list

    # ─── Utility Methods ────────────────────────────────────────────────

    def build_target_spec(
        self,
        domains: Optional[List[str]] = None,
        ips: Optional[List[str]] = None,
        urls: Optional[List[str]] = None,
    ) -> List[str]:
        """
        Build a list of targets from mission target components.

        Args:
            domains: List of domain names
            ips: List of IP addresses or CIDR ranges
            urls: List of URLs

        Returns:
            List of target strings suitable for Nmap
        """
        targets: List[str] = []

        if domains:
            targets.extend(domains)
        if ips:
            targets.extend(ips)
        if urls:
            # Extract hostnames from URLs
            from urllib.parse import urlparse
            for url in urls:
                parsed = urlparse(url)
                if parsed.hostname:
                    targets.append(parsed.hostname)

        return targets

    def suggest_ports_for_service(self, service_name: str) -> str:
        """
        Suggest common ports for a given service.

        Args:
            service_name: Service name (e.g., "http", "mysql", "ssh")

        Returns:
            Comma-separated port list
        """
        common_ports = {
            "http": "80,443,8080,8443,8000,8888",
            "https": "443,8443,9443",
            "ssh": "22",
            "ftp": "21",
            "mysql": "3306",
            "postgresql": "5432",
            "mongodb": "27017,27018",
            "redis": "6379",
            "elasticsearch": "9200,9300",
            "dns": "53",
            "smtp": "25,465,587",
            "pop3": "110,995",
            "imap": "143,993",
            "ldap": "389,636",
            "rdp": "3389",
            "vnc": "5900,5901",
            "smb": "445,139",
            "snmp": "161,162",
            "ntp": "123",
            "dhcp": "67,68",
            "kerberos": "88",
            "nfs": "2049",
            "rsync": "873",
            "kafka": "9092",
            "rabbitmq": "5672",
        }
        return common_ports.get(service_name.lower(), "1-10000")


__all__ = ["NmapPlugin"]
