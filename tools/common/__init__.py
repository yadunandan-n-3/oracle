"""
Common Tool Utilities
=====================

Shared data types and helpers for all security tools in ORACLE.
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

from core.exceptions import ToolUnavailableError
from core.exceptions import TimeoutError as OracleTimeoutError
from core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class PortInfo:
    """Information about a discovered port."""

    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    service_product: str = ""
    service_version: str = ""
    service_extra_info: str = ""
    reason: str = ""
    confidence: float = 0.9
    cpe: str = ""
    scripts: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "service_product": self.service_product,
            "service_version": self.service_version,
            "service_extra_info": self.service_extra_info,
            "reason": self.reason,
            "confidence": self.confidence,
            "cpe": self.cpe,
        }

    def to_evidence_data(self) -> Dict[str, Any]:
        """Convert to evidence data format."""
        return self.to_dict()


@dataclass
class HostInfo:
    """Information about a discovered host."""

    ip: str
    status: str = "up"
    hostnames: List[str] = field(default_factory=list)
    ports: List[PortInfo] = field(default_factory=list)
    os: str = ""
    os_accuracy: int = 0
    os_family: str = ""
    os_gen: str = ""
    mac_address: str = ""
    distance: int = 0
    uptime: str = ""
    last_boot: str = ""
    scripts: Dict[str, Any] = field(default_factory=dict)
    extra_info: Dict[str, Any] = field(default_factory=dict)

    @property
    def open_ports(self) -> List[PortInfo]:
        """Get only open ports."""
        return [p for p in self.ports if p.state == "open"]

    @property
    def service_names(self) -> List[str]:
        """Get unique service names."""
        return list(set(p.service for p in self.ports if p.service))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "ip": self.ip,
            "status": self.status,
            "hostnames": self.hostnames,
            "ports": [p.to_dict() for p in self.ports],
            "os": self.os,
            "os_accuracy": self.os_accuracy,
            "os_family": self.os_family,
            "os_gen": self.os_gen,
            "mac_address": self.mac_address,
            "distance": self.distance,
            "uptime": self.uptime,
            "last_boot": self.last_boot,
            "open_port_count": len(self.open_ports),
            "service_count": len(self.service_names),
        }

    def to_evidence_data(self) -> Dict[str, Any]:
        """Convert to evidence data format."""
        return self.to_dict()


@dataclass
class ServiceInfo:
    """Identified service information."""

    host: str
    port: int
    protocol: str = "tcp"
    service_name: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    confidence: float = 0.7
    cpe: str = ""
    technologies: List[str] = field(default_factory=list)
    banners: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "service_name": self.service_name,
            "product": self.product,
            "version": self.version,
            "extra_info": self.extra_info,
            "confidence": self.confidence,
            "cpe": self.cpe,
            "technologies": self.technologies,
            "banners": self.banners,
        }


@dataclass
class VulnerabilityInfo:
    """
    Information about a single vulnerability finding from a template-based
    or signature-based scanner (Nuclei, ZAP, etc.).

    Kept generic on purpose so multiple scanners can normalize into the
    same shape rather than each plugin inventing its own finding schema.
    """

    template_id: str
    name: str
    severity: str = "info"  # critical, high, medium, low, info
    host: str = ""
    matched_at: str = ""
    description: str = ""
    tags: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    references: List[str] = field(default_factory=list)
    extracted_results: List[str] = field(default_factory=list)
    curl_command: str = ""
    matcher_name: str = ""
    confidence: float = 0.85  # template-matched findings default to high confidence
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "template_id": self.template_id,
            "name": self.name,
            "severity": self.severity,
            "host": self.host,
            "matched_at": self.matched_at,
            "description": self.description,
            "tags": self.tags,
            "cve_ids": self.cve_ids,
            "cwe_ids": self.cwe_ids,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "references": self.references,
            "extracted_results": self.extracted_results,
            "matcher_name": self.matcher_name,
            "confidence": self.confidence,
        }

    def to_evidence_data(self) -> Dict[str, Any]:
        """Convert to evidence data format."""
        return self.to_dict()


@dataclass
class ToolResult:
    """
    Standard result container for tool execution.

    Normalized output that all tools produce.
    """

    tool_name: str
    command: str = ""
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    raw_output: bytes = field(default_factory=bytes)
    parsed_results: List[Any] = field(default_factory=list)
    hosts: List[HostInfo] = field(default_factory=list)
    duration_seconds: float = 0.0
    error: Optional[str] = None
    success: bool = True
    warnings: List[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary (excluding raw binary)."""
        return {
            "tool_name": self.tool_name,
            "command": self.command,
            "exit_code": self.exit_code,
            "stdout_length": len(self.stdout),
            "stderr_length": len(self.stderr),
            "hosts_count": len(self.hosts),
            "ports_count": sum(len(h.ports) for h in self.hosts),
            "duration_seconds": self.duration_seconds,
            "error": self.error,
            "success": self.success,
            "warnings": self.warnings,
        }


async def execute_command(
    cmd: List[str],
    timeout: int = 300,
    env: Optional[Dict[str, str]] = None,
) -> Tuple[int, str, str]:
    """
    Execute a shell command asynchronously.

    Args:
        cmd: Command and arguments as a list
        timeout: Maximum execution time in seconds
        env: Optional environment variables

    Returns:
        Tuple of (exit_code, stdout, stderr)

    Raises:
        ToolUnavailableError: If the tool binary is not found
    """
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise OracleTimeoutError(
                operation=" ".join(cmd[:2]),
                timeout_seconds=timeout,
            )

        return process.returncode or 0, stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")

    except FileNotFoundError:
        raise ToolUnavailableError(
            tool_name=cmd[0],
            message=f"Tool '{cmd[0]}' is not installed or not in PATH",
        )
    except asyncio.TimeoutError:
        raise
    except Exception as e:
        logger.error("command.execution_failed", cmd=str(cmd), error=str(e))
        return -1, "", str(e)


async def execute_command_stream(
    cmd: List[str],
    timeout: int = 300,
) -> AsyncIterator[bytes]:
    """
    Execute a command and stream output as it's produced.

    Args:
        cmd: Command and arguments as a list
        timeout: Maximum execution time in seconds

    Yields:
        Chunks of stdout as they become available
    """
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        async def read_stream(stream: asyncio.StreamReader) -> AsyncIterator[bytes]:
            while True:
                chunk = await stream.read(4096)
                if not chunk:
                    break
                yield chunk

        async for chunk in read_stream(process.stdout):  # type: ignore
            yield chunk

        await process.wait()

    except FileNotFoundError:
        raise ToolUnavailableError(
            tool_name=cmd[0],
            message=f"Tool '{cmd[0]}' is not installed or not in PATH",
        )
    except Exception as e:
        logger.error("command.stream_failed", cmd=str(cmd), error=str(e))


def check_tool_available(tool_name: str) -> bool:
    """
    Check if a tool is available in the system PATH.

    Args:
        tool_name: Name of the tool binary

    Returns:
        True if the tool is available
    """
    import shutil
    return shutil.which(tool_name) is not None


__all__ = [
    "PortInfo",
    "HostInfo",
    "ServiceInfo",
    "VulnerabilityInfo",
    "ToolResult",
    "execute_command",
    "execute_command_stream",
    "check_tool_available",
]
