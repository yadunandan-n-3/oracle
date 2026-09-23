"""
Abstract Interfaces
===================

Core interfaces that all ORACLE components must implement.
Defines the contract for agents, tools, plugins, and services.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator, Dict, Generic, List, Optional, Tuple, TypeVar
from uuid import UUID, uuid4


class AgentStatus(str, Enum):
    """Status of an ORACLE agent."""

    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    ERROR = "error"


class CapabilityCategory(str, Enum):
    """Categories of agent capabilities."""

    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    ANALYSIS = "analysis"
    REPORTING = "reporting"
    REMEDIATION = "remediation"


@dataclass
class Capability:
    """A capability that an agent can perform."""

    name: str
    description: str = ""
    category: CapabilityCategory = CapabilityCategory.ANALYSIS
    tools: List[str] = field(default_factory=list)
    confidence_threshold: float = 0.7
    required_permissions: List[str] = field(default_factory=list)
    estimated_duration_seconds: int = 60

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("Capability name is required")


@dataclass
class Evidence:
    """
    A piece of evidence discovered by an agent.

    This is the output of any tool or agent operation.
    All evidence flows through the Evidence Pipeline.
    """

    source: str
    evidence_type: str
    asset_value: str
    data: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5
    severity: str = "informational"
    title: str = ""
    description: str = ""
    tags: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    raw_output: bytes = b""


class OracleAgent(ABC):
    """
    Abstract base class for all ORACLE agents.

    Every agent must implement:
    - plan(): Break mission goals into executable steps
    - execute(): Run the agent's tasks
    - validate(): Validate findings
    - explain(): Human-readable reasoning
    """

    name: str = "base_agent"
    version: str = "0.1.0"
    description: str = "Base ORACLE agent"
    capabilities: List[Capability] = []

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the agent and its tools."""
        ...

    @abstractmethod
    async def plan(self, mission: Any) -> List[Dict[str, Any]]:
        """
        Create a plan for accomplishing mission goals.

        Args:
            mission: The mission to plan for

        Returns:
            List of task descriptions
        """
        ...

    @abstractmethod
    async def execute(self, context: Dict[str, Any]) -> AsyncIterator[Evidence]:
        """
        Execute the agent's tasks.

        Args:
            context: Task execution context

        Yields:
            Evidence objects as they are discovered
        """
        ...
        if False:  # pragma: no cover
            yield Evidence(source="", evidence_type="", asset_value="")

    @abstractmethod
    async def validate(self, evidence: Evidence) -> Tuple[bool, str]:
        """
        Validate a piece of evidence.

        Args:
            evidence: The evidence to validate

        Returns:
            Tuple of (is_valid, reason)
        """
        ...

    @abstractmethod
    async def explain(self, evidence: Evidence) -> str:
        """
        Generate a human-readable explanation of evidence.

        Args:
            evidence: The evidence to explain

        Returns:
            Human-readable explanation string
        """
        ...

    async def get_status(self) -> AgentStatus:
        """Get current agent status."""
        return AgentStatus.IDLE


class SecurityTool(ABC):
    """
    Abstract base class for security tools in ORACLE.

    All security tools (Nmap, Nuclei, ZAP, etc.) implement this interface.
    Tools are discovered and executed through the ToolManager.
    """

    name: str = "base_tool"
    version: str = "0.1.0"
    description: str = "Base security tool"

    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """Check if the tool is available and functional."""
        ...

    @abstractmethod
    async def execute(
        self,
        targets: List[str],
        **kwargs: Any,
    ) -> AsyncIterator[bytes]:
        """
        Execute the tool against targets.

        Args:
            targets: List of target strings (IPs, domains, URLs)
            **kwargs: Tool-specific parameters

        Yields:
            Raw output chunks as they are produced
        """
        ...
        if False:  # pragma: no cover
            yield b""

    @abstractmethod
    async def parse(self, raw_output: bytes) -> List[Dict[str, Any]]:
        """
        Parse tool output into structured results.

        Args:
            raw_output: Raw tool output

        Returns:
            List of parsed result dictionaries
        """
        ...

    async def normalize(
        self,
        parsed_results: List[Dict[str, Any]],
    ) -> List[Evidence]:
        """
        Normalize parsed results into Evidence objects.

        Args:
            parsed_results: Parsed tool output

        Returns:
            List of Evidence objects
        """
        return []


class OraclePlugin(ABC):
    """
    Abstract base class for ORACLE plugins.

    Plugins extend ORACLE with new capabilities.
    They can be tools, data sources, or integrations.
    """

    name: str = "base_plugin"
    version: str = "0.1.0"
    description: str = "Base ORACLE plugin"

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the plugin."""
        ...

    @abstractmethod
    async def shutdown(self) -> None:
        """Gracefully shutdown the plugin."""
        ...


RepositoryEntity = TypeVar("RepositoryEntity")


class Repository(ABC, Generic[RepositoryEntity]):
    """
    Abstract base class for all repositories.

    Repositories provide a clean persistence abstraction.
    The runtime never calls SQLAlchemy directly.
    """

    @abstractmethod
    async def create(self, entity: Any) -> Any:
        """Create a new entity."""
        ...

    @abstractmethod
    async def get(self, id: UUID) -> Optional[Any]:
        """Get an entity by ID."""
        ...

    @abstractmethod
    async def update(self, id: UUID, data: Dict[str, Any]) -> Optional[Any]:
        """Update an entity."""
        ...

    @abstractmethod
    async def delete(self, id: UUID) -> bool:
        """Delete an entity."""
        ...

    @abstractmethod
    async def list(
        self,
        limit: int = 50,
        offset: int = 0,
        **filters: Any,
    ) -> List[Any]:
        """List entities with filtering."""
        ...


__all__ = [
    "AgentStatus",
    "CapabilityCategory",
    "Capability",
    "Evidence",
    "OracleAgent",
    "SecurityTool",
    "OraclePlugin",
    "Repository",
]
