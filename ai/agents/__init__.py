"""
Agent SDK
=========

Standard interface for all ORACLE agents.

Every agent follows the OracleAgent protocol:
- plan(): Break mission goals into executable steps
- execute(): Run the agent's tasks
- validate(): Validate findings
- explain(): Human-readable reasoning
"""

from __future__ import annotations

from typing import Any, AsyncIterator, Dict, List, Optional
from uuid import UUID

from core.interfaces import OracleAgent, Capability, AgentStatus, Evidence

__all__ = ["OracleAgent", "Capability", "AgentStatus"]
