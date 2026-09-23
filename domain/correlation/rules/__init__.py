"""
Correlation Rules
=================

Extensible correlation rules that match evidence patterns across
multiple security tools (Nmap, Nuclei, etc.) to produce unified findings.

Each rule:
1. Takes a set of evidence objects
2. Looks for specific patterns (Apache 2.4.49 + CVE-2021-41773, SSH + CVE, etc.)
3. Returns CorrelationResult with confidence and reasoning

Rules are designed to be composable — a single finding may be produced
by multiple rules reinforcing each other.
"""

from __future__ import annotations

from domain.correlation import CorrelationRule, CorrelationResult, CorrelationType

from .apache_rule import ApacheCorrelationRule
from .ssh_rule import SSHCveCorrelationRule
from .http_rule import HttpServiceCorrelationRule
from .generic_rule import GenericTechCveCorrelationRule
from .port_service_rule import PortServiceCorrelationRule

__all__ = [
    "ApacheCorrelationRule",
    "SSHCveCorrelationRule",
    "HttpServiceCorrelationRule",
    "GenericTechCveCorrelationRule",
    "PortServiceCorrelationRule",
]

