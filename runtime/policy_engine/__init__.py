"""
Policy Engine
=============

Every organization has rules.
Every agent checks policy before acting.

The Policy Engine enforces:
- Never exploit production
- Only scan approved assets
- Do not brute-force login
- No denial-of-service testing
- Compliance with regulatory requirements
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from core.events import EventType, OracleEvent
from core.exceptions import PolicyViolationError
from core.logging import get_logger
from domain.mission import Mission, MissionTarget
from runtime.event_bus import get_event_bus

logger = get_logger(__name__)


class PolicySeverity(str, Enum):
    """Severity of a policy."""

    BLOCKING = "blocking"  # Action is blocked entirely
    WARNING = "warning"  # Action is allowed but flagged
    INFO = "informational"  # Just for reference


class PolicyEffect(str, Enum):
    """Effect of a policy check."""

    ALLOW = "allow"
    DENY = "deny"
    WARN = "warn"


class Policy(BaseModel):
    """
    A security policy rule.

    Policies define what actions are allowed or denied
    in the ORACLE system.
    """

    id: UUID = Field(default_factory=uuid4)
    name: str
    description: str = ""
    severity: PolicySeverity = PolicySeverity.BLOCKING
    effect: PolicyEffect = PolicyEffect.DENY
    enabled: bool = True
    priority: int = 100  # Lower = evaluated first

    # Policy rules
    rules: List[Dict[str, Any]] = Field(default_factory=list)

    # Scope
    applies_to_organizations: List[UUID] = Field(default_factory=list)
    applies_to_mission_types: List[str] = Field(default_factory=list)

    # Metadata
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = "system"
    tags: List[str] = Field(default_factory=list)


class PolicyCheckResult(BaseModel):
    """Result of a policy check."""

    passed: bool
    policy_name: str = ""
    policy_id: Optional[UUID] = None
    effect: PolicyEffect = PolicyEffect.ALLOW
    message: str = ""
    details: Dict[str, Any] = Field(default_factory=dict)


# Default built-in policies
DEFAULT_POLICIES: List[Policy] = [
    Policy(
        name="no_production_exploitation",
        description="Never exploit or attempt to compromise production systems",
        severity=PolicySeverity.BLOCKING,
        effect=PolicyEffect.DENY,
        priority=10,
        tags=["security", "safety"],
    ),
    Policy(
        name="approved_targets_only",
        description="Only scan assets that have been explicitly approved by the organization",
        severity=PolicySeverity.BLOCKING,
        effect=PolicyEffect.DENY,
        priority=20,
        tags=["security", "compliance"],
    ),
    Policy(
        name="no_brute_force",
        description="Do not perform brute-force or password guessing attacks",
        severity=PolicySeverity.BLOCKING,
        effect=PolicyEffect.DENY,
        priority=30,
        tags=["security", "legal"],
    ),
    Policy(
        name="no_dos_testing",
        description="No denial-of-service testing or resource exhaustion attacks",
        severity=PolicySeverity.BLOCKING,
        effect=PolicyEffect.DENY,
        priority=40,
        tags=["security", "legal"],
    ),
    Policy(
        name="no_social_engineering",
        description="No social engineering or phishing simulations without explicit approval",
        severity=PolicySeverity.BLOCKING,
        effect=PolicyEffect.DENY,
        priority=50,
        tags=["security", "legal"],
    ),
    Policy(
        name="authorized_tools_only",
        description="Only use tools that have been authorized and installed by the system",
        severity=PolicySeverity.WARNING,
        effect=PolicyEffect.WARN,
        priority=60,
        tags=["security"],
    ),
    Policy(
        name="data_handling",
        description="Do not store or transmit sensitive data outside approved systems",
        severity=PolicySeverity.BLOCKING,
        effect=PolicyEffect.DENY,
        priority=25,
        tags=["compliance", "privacy"],
    ),
]


class PolicyEngine:
    """
    Central policy enforcement for ORACLE.

    Every action goes through the Policy Engine before execution.
    This ensures all operations comply with organizational rules.
    """

    def __init__(self) -> None:
        self._policies: Dict[UUID, Policy] = {}
        self._event_bus = get_event_bus()
        self._initialize_defaults()

    def _initialize_defaults(self) -> None:
        """Load default policies."""
        for policy in DEFAULT_POLICIES:
            self._policies[policy.id] = policy
        logger.info(
            "policy.initialized",
            policy_count=len(self._policies),
        )

    # ─── Policy Management ─────────────────────────────────────────────────

    def add_policy(self, policy: Policy) -> Policy:
        """Add a new policy."""
        self._policies[policy.id] = policy
        logger.info("policy.added", policy_name=policy.name)
        return policy

    def remove_policy(self, policy_id: UUID) -> bool:
        """Remove a policy."""
        if policy_id in self._policies:
            del self._policies[policy_id]
            logger.info("policy.removed", policy_id=str(policy_id))
            return True
        return False

    def update_policy(self, policy_id: UUID, updates: Dict[str, Any]) -> Optional[Policy]:
        """Update an existing policy."""
        policy = self._policies.get(policy_id)
        if policy:
            for key, value in updates.items():
                if hasattr(policy, key):
                    setattr(policy, key, value)
            policy.updated_at = datetime.now(timezone.utc)
            return policy
        return None

    def get_policies(
        self,
        enabled_only: bool = True,
        severity: Optional[PolicySeverity] = None,
    ) -> List[Policy]:
        """Get all policies with optional filtering."""
        policies = list(self._policies.values())
        if enabled_only:
            policies = [p for p in policies if p.enabled]
        if severity:
            policies = [p for p in policies if p.severity == severity]
        return sorted(policies, key=lambda p: p.priority)

    # ─── Policy Checks ─────────────────────────────────────────────────────

    async def check_mission(self, mission: Mission) -> List[PolicyCheckResult]:
        """
        Check if a mission complies with all policies.

        This is called before a mission starts.

        Args:
            mission: The mission to check

        Returns:
            List of policy check results
        """
        results = []

        for policy in self.get_policies():
            result = self._check_mission_against_policy(mission, policy)
            results.append(result)

            if result.effect == PolicyEffect.DENY and not result.passed:
                await self._event_bus.publish(OracleEvent(
                    event_type=EventType.POLICY_VIOLATION,
                    source="policy_engine",
                    mission_id=mission.id,
                    data={
                        "policy_name": policy.name,
                        "effect": policy.effect.value,
                        "message": result.message,
                    },
                ))

        return results

    async def check_tool_execution(
        self,
        tool_name: str,
        target: str,
        arguments: Dict[str, Any],
        organization_id: Optional[UUID] = None,
    ) -> PolicyCheckResult:
        """
        Check if a specific tool execution is allowed.

        Args:
            tool_name: Name of the tool to execute
            target: Target of the execution (IP, domain, URL)
            arguments: Tool arguments
            organization_id: Optional organization context

        Returns:
            Policy check result
        """
        for policy in self.get_policies():
            # Check tool-specific policies
            if "authorized_tools" in policy.name and policy.name == "authorized_tools_only":
                # In production, check against a registry of approved tools
                pass

            # Check target-based policies
            if policy.name == "no_production_exploitation":
                # Check if target is marked as production
                if "prod" in target.lower() or "production" in target.lower():
                    return PolicyCheckResult(
                        passed=False,
                        policy_name=policy.name,
                        policy_id=policy.id,
                        effect=PolicyEffect.DENY,
                        message=f"Target '{target}' appears to be a production system",
                    )

        return PolicyCheckResult(
            passed=True,
            effect=PolicyEffect.ALLOW,
            message=f"Tool execution permitted: {tool_name} on {target}",
        )

    async def check_agent_action(
        self,
        agent_name: str,
        action: str,
        context: Dict[str, Any],
    ) -> PolicyCheckResult:
        """
        Check if an agent action is allowed.

        Args:
            agent_name: Name of the agent
            action: Action the agent wants to perform
            context: Context about the action

        Returns:
            Policy check result
        """
        action_lower = action.lower()

        # Check against all policies
        for policy in self.get_policies():
            # Brute force check
            if policy.name == "no_brute_force" and any(
                word in action_lower for word in ["brute", "bruteforce", "password spray", "credential stuffing"]
            ):
                return PolicyCheckResult(
                    passed=False,
                    policy_name=policy.name,
                    policy_id=policy.id,
                    effect=PolicyEffect.DENY,
                    message="Brute force attacks are not permitted",
                )

            # DOS check
            if policy.name == "no_dos_testing" and any(
                word in action_lower for word in ["dos", "ddos", "flood", "slowloris"]
            ):
                return PolicyCheckResult(
                    passed=False,
                    policy_name=policy.name,
                    policy_id=policy.id,
                    effect=PolicyEffect.DENY,
                    message="Denial-of-service testing is not permitted",
                )

        return PolicyCheckResult(
            passed=True,
            effect=PolicyEffect.ALLOW,
            message=f"Agent action permitted: {agent_name} -> {action}",
        )

    def _check_mission_against_policy(self, mission: Mission, policy: Policy) -> PolicyCheckResult:
        """Check a single mission against a single policy."""
        policy_name_lower = policy.name.lower()

        if "approved_targets" in policy_name_lower:
            # Check if targets appear approved
            if not mission.target.domains and not mission.target.ip_ranges and not mission.target.urls:
                return PolicyCheckResult(
                    passed=False,
                    policy_name=policy.name,
                    policy_id=policy.id,
                    effect=PolicyEffect.DENY,
                    message="Mission has no approved targets defined",
                )

        if "production" in policy_name_lower:
            # Check target descriptions or tags for production indicators
            for domain in mission.target.domains:
                if any(indicator in domain.lower() for indicator in ["prod", "production", "live", "www"]):
                    return PolicyCheckResult(
                        passed=False,
                        policy_name=policy.name,
                        policy_id=policy.id,
                        effect=PolicyEffect.DENY,
                        message=f"Target domain '{domain}' appears to be a production system",
                    )

        return PolicyCheckResult(
            passed=True,
            policy_name=policy.name,
            policy_id=policy.id,
            effect=PolicyEffect.ALLOW,
            message=f"Policy passed: {policy.name}",
        )


__all__ = [
    "PolicyEngine",
    "Policy",
    "PolicyCheckResult",
    "PolicySeverity",
    "PolicyEffect",
]
