"""
Tool Manager
============

Dynamic plugin registry for security tools in ORACLE.

The Tool Manager discovers, registers, and manages all security tools.
Agents never call tools directly — they go through the Tool Manager.

Architecture:
    Discovery Agent
        ↓
    Tool Manager
        ↓
    Plugin Registry → NmapPlugin
                   → NucleiPlugin
                   → ZAPPlugin
                   → SemgrepPlugin
                   → ... (future)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Type

from core.interfaces import SecurityTool
from core.logging import get_logger

logger = get_logger(__name__)


class ToolManager:
    """
    Central registry and manager for all security tools.

    Features:
    - Dynamic tool registration
    - Tool discovery by capability
    - Health checks for all registered tools
    - Lifecycle management (initialize/shutdown)
    - Tool availability tracking
    """

    def __init__(self) -> None:
        self._tools: Dict[str, SecurityTool] = {}
        self._tool_classes: Dict[str, Type[SecurityTool]] = {}
        self._capability_tool_map: Dict[str, List[str]] = {}
        self._initialized: bool = False

    # ─── Registration ─────────────────────────────────────────────────────

    def register_tool(
        self,
        tool_name: str,
        tool_class: Type[SecurityTool],
        capabilities: Optional[List[str]] = None,
    ) -> None:
        """
        Register a tool class with the manager.

        Args:
            tool_name: Unique name for the tool (e.g., "nmap", "nuclei")
            tool_class: The SecurityTool subclass to register
            capabilities: Optional list of capabilities this tool provides
        """
        if tool_name in self._tool_classes:
            logger.warning(
                "tool_manager.tool_exists",
                tool_name=tool_name,
                message="Overwriting existing tool registration",
            )

        self._tool_classes[tool_name] = tool_class

        # Map capabilities to this tool
        if capabilities:
            for cap in capabilities:
                if cap not in self._capability_tool_map:
                    self._capability_tool_map[cap] = []
                self._capability_tool_map[cap].append(tool_name)

        logger.info(
            "tool_manager.tool_registered",
            tool_name=tool_name,
            capabilities=capabilities,
        )

    async def initialize_tool(self, tool_name: str) -> SecurityTool:
        """
        Initialize a registered tool.

        Creates an instance and runs its health check.

        Args:
            tool_name: Name of the tool to initialize

        Returns:
            Initialized tool instance

        Raises:
            KeyError: If tool is not registered
        """
        if tool_name in self._tools:
            return self._tools[tool_name]

        tool_class = self._tool_classes.get(tool_name)
        if not tool_class:
            raise KeyError(f"Tool '{tool_name}' is not registered")

        tool = tool_class()
        await tool.initialize() if hasattr(tool, 'initialize') else None
        self._tools[tool_name] = tool

        logger.info(
            "tool_manager.tool_initialized",
            tool_name=tool_name,
        )

        return tool

    async def initialize_all(self) -> Dict[str, bool]:
        """
        Initialize all registered tools.

        Returns:
            Dict mapping tool name to initialization success
        """
        results = {}
        for tool_name in self._tool_classes:
            try:
                await self.initialize_tool(tool_name)
                results[tool_name] = True
            except Exception as e:
                logger.error(
                    "tool_manager.init_failed",
                    tool_name=tool_name,
                    error=str(e),
                )
                results[tool_name] = False

        self._initialized = True
        return results

    # ─── Tool Access ──────────────────────────────────────────────────────

    def get_tool(self, tool_name: str) -> SecurityTool:
        """
        Get an initialized tool instance.

        Args:
            tool_name: Name of the tool

        Returns:
            Tool instance

        Raises:
            KeyError: If tool is not registered or initialized
        """
        if tool_name not in self._tools:
            # Auto-initialize if registered but not yet initialized
            if tool_name in self._tool_classes:
                import asyncio
                try:
                    loop = asyncio.get_running_loop()
                    if loop.is_running():
                        # Cannot await here — caller must handle
                        raise KeyError(
                            f"Tool '{tool_name}' registered but not initialized. "
                            f"Call await tool_manager.initialize_tool('{tool_name}') first."
                        )
                except RuntimeError:
                    pass

            raise KeyError(
                f"Tool '{tool_name}' is not registered or initialized. "
                f"Available tools: {list(self._tool_classes.keys())}"
            )

        return self._tools[tool_name]

    def get_tools_by_capability(self, capability: str) -> List[SecurityTool]:
        """
        Get all tools that provide a specific capability.

        Args:
            capability: Capability name (e.g., "port_scanning", "vulnerability_scanning")

        Returns:
            List of tool instances providing this capability
        """
        tool_names = self._capability_tool_map.get(capability, [])
        tools = []
        for name in tool_names:
            try:
                tools.append(self.get_tool(name))
            except KeyError:
                continue
        return tools

    def list_tools(self) -> List[Dict[str, Any]]:
        """List all registered tools with their status."""
        result = []
        for name, tool_class in self._tool_classes.items():
            instance = self._tools.get(name)
            result.append({
                "name": name,
                "class": tool_class.__name__,
                "initialized": instance is not None,
                "description": getattr(tool_class, "description", ""),
                "version": getattr(tool_class, "version", "unknown"),
            })
        return result

    # ─── Health ──────────────────────────────────────────────────────────

    async def check_tool_health(self, tool_name: str) -> Dict[str, Any]:
        """
        Check health of a specific tool.

        Args:
            tool_name: Name of the tool

        Returns:
            Health check result dict
        """
        try:
            tool = self.get_tool(tool_name)
            return await tool.health_check()
        except KeyError:
            return {
                "healthy": False,
                "error": f"Tool '{tool_name}' is not registered",
            }

    async def check_all_health(self) -> Dict[str, Dict[str, Any]]:
        """Check health of all initialized tools."""
        results = {}
        for name, tool in self._tools.items():
            try:
                results[name] = await tool.health_check()
            except Exception as e:
                results[name] = {
                    "healthy": False,
                    "error": str(e),
                }
        return results

    # ─── Lifecycle ────────────────────────────────────────────────────────

    async def shutdown_all(self) -> None:
        """Shutdown all initialized tools."""
        for name, tool in self._tools.items():
            try:
                if hasattr(tool, 'shutdown') and callable(tool.shutdown):
                    await tool.shutdown()
            except Exception as e:
                logger.error(
                    "tool_manager.shutdown_failed",
                    tool_name=name,
                    error=str(e),
                )

        self._tools.clear()
        self._initialized = False
        logger.info("tool_manager.all_tools_shutdown")


# Global ToolManager instance
_tool_manager: Optional["ToolManager"] = None


def get_tool_manager() -> ToolManager:
    """Get or create the global ToolManager singleton."""
    global _tool_manager
    if _tool_manager is None:
        _tool_manager = ToolManager()
    return _tool_manager


__all__ = ["ToolManager", "get_tool_manager"]
