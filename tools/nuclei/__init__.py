"""
Nuclei Plugin
=============

Template-based vulnerability scanning integration for ORACLE.

Executes Nuclei scans, parses JSON Lines output, and normalizes
results into structured Evidence objects.

Pipeline (v0.2 Sprint 1):
    Mission
    ↓
    Discovery (Nmap)
    ↓
    Nuclei (this plugin)
    ↓
    Evidence
    ↓
    Validator
    ↓
    Findings

Nuclei is typically run against the HTTP(S) services Nmap already found,
so `build_targets_from_hosts()` below takes discovered HostInfo objects
and produces the http(s):// target URLs Nuclei expects.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional

from core.exceptions import ToolUnavailableError
from core.interfaces import Evidence, SecurityTool
from core.logging import get_logger, get_mission_logger
from core.telemetry import telemetry
from tools.common import (
    HostInfo,
    VulnerabilityInfo,
    check_tool_available,
    execute_command,
    execute_command_stream,
)

logger = get_logger(__name__)
mission_logger = get_mission_logger()

# Nuclei severity -> ORACLE's finding/evidence severity vocabulary.
# Nuclei already uses these exact strings, but we map explicitly rather
# than trusting the tool output, since template authors occasionally use
# unexpected casing or synonyms ("informational" vs "info").
SEVERITY_MAP: Dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "informational",
    "informational": "informational",
    "unknown": "informational",
}

# MITRE ATT&CK techniques commonly associated with template tags.
# Deliberately conservative — only mapped where the tag directly implies
# the technique, so we don't manufacture mappings that aren't traceable
# back to the evidence that triggered them.
TAG_TO_MITRE: Dict[str, str] = {
    "rce": "T1190",  # Exploit Public-Facing Application
    "sqli": "T1190",
    "lfi": "T1190",
    "cve": "T1190",
    "exposure": "T1592",  # Gather Victim Org Information
    "config": "T1552",  # Unsecured Credentials
    "default-login": "T1078",  # Valid Accounts
    "takeover": "T1584",  # Compromise Infrastructure
}


class NucleiPlugin(SecurityTool):
    """
    ORACLE Nuclei Integration Plugin.

    Provides:
    - Health check (version verification)
    - Template-based scan execution against HTTP(S) targets
    - JSON Lines output parsing
    - Result normalization -> VulnerabilityInfo -> Evidence
    """

    name = "nuclei"
    version = "3.3"
    description = "Nuclei — fast, template-based vulnerability scanner"

    def __init__(self) -> None:
        self._available: Optional[bool] = None
        self._version: str = "unknown"
        self._binary: str = "nuclei"

    # ─── Health Check ─────────────────────────────────────────────────────

    async def health_check(self) -> Dict[str, Any]:
        """
        Check if Nuclei is available and functional.

        Returns:
            Dict with healthy, available, version, and error keys
        """
        if not check_tool_available(self._binary):
            self._available = False
            return {
                "healthy": False,
                "available": False,
                "version": None,
                "error": f"Nuclei binary '{self._binary}' not found in PATH. "
                         "Install from https://github.com/projectdiscovery/nuclei",
            }

        try:
            exit_code, stdout, stderr = await execute_command(
                [self._binary, "-version"],
                timeout=10,
            )

            # Nuclei prints its version banner to stderr and exits 0.
            combined_output = f"{stdout}\n{stderr}"

            if exit_code != 0:
                self._available = False
                return {
                    "healthy": False,
                    "available": True,
                    "version": None,
                    "error": f"Nuclei version check failed: {stderr[:200]}",
                }

            import re
            match = re.search(r"[Vv]ersion[:\s]+v?(\d+\.\d+\.\d+)", combined_output)
            self._version = match.group(1) if match else "unknown"

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
                "error": f"Nuclei binary '{self._binary}' not found in PATH",
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
        templates: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        exclude_tags: Optional[List[str]] = None,
        severity: Optional[List[str]] = None,
        rate_limit: int = 150,
        concurrency: int = 25,
        timeout_per_request: int = 10,
        retries: int = 1,
        additional_args: Optional[List[str]] = None,
    ) -> AsyncIterator[bytes]:
        """
        Execute a Nuclei scan against targets.

        Args:
            targets: List of target URLs (http:// or https://)
            templates: Specific template paths/IDs to run (default: all)
            tags: Only run templates matching these tags (e.g. ["cve", "exposure"])
            exclude_tags: Skip templates matching these tags (e.g. ["dos", "fuzz"])
            severity: Only run templates of these severities (e.g. ["critical", "high"])
            rate_limit: Max requests per second
            concurrency: Number of templates to run concurrently
            timeout_per_request: Per-request timeout in seconds
            retries: Number of retries for failed requests
            additional_args: Additional Nuclei arguments

        Yields:
            Raw JSONL output bytes as they are produced
        """
        if not targets:
            raise ValueError("At least one target is required")

        if not self._available:
            health = await self.health_check()
            if not health["healthy"]:
                raise ToolUnavailableError(
                    tool_name=self._binary,
                    message=health.get("error", "Nuclei is not available"),
                )

        cmd = [self._binary, "-silent", "-jsonl"]

        # Targets: -u for a single target, -l/- for a list. We pass each
        # target with its own -u flag, which nuclei accepts repeated.
        for target in targets:
            cmd.extend(["-u", target])

        if templates:
            cmd.extend(["-t", ",".join(templates)])

        if tags:
            cmd.extend(["-tags", ",".join(tags)])

        if exclude_tags:
            cmd.extend(["-etags", ",".join(exclude_tags)])

        if severity:
            cmd.extend(["-severity", ",".join(severity)])

        cmd.extend(["-rate-limit", str(rate_limit)])
        cmd.extend(["-c", str(concurrency)])
        cmd.extend(["-timeout", str(timeout_per_request)])
        cmd.extend(["-retries", str(retries)])

        if additional_args:
            cmd.extend(additional_args)

        logger.info(
            "nuclei.executing",
            command=" ".join(cmd),
            target_count=len(targets),
            tags=tags,
            severity=severity,
        )

        try:
            async for chunk in execute_command_stream(cmd, timeout=1800):
                yield chunk
        except ToolUnavailableError:
            raise
        except Exception as e:
            logger.error("nuclei.execution_failed", error=str(e))
            raise

    # ─── Parsing ─────────────────────────────────────────────────────────

    async def parse(self, raw_output: bytes) -> List[VulnerabilityInfo]:
        """
        Parse Nuclei JSON Lines output into structured VulnerabilityInfo objects.

        Nuclei's `-jsonl` flag emits one JSON object per line, one per
        matched finding. Malformed lines are logged and skipped rather
        than failing the whole scan — a single bad line shouldn't discard
        every other finding in the run.

        Args:
            raw_output: Raw Nuclei JSONL output

        Returns:
            List of VulnerabilityInfo objects, one per matched finding
        """
        if not raw_output or len(raw_output.strip()) == 0:
            logger.warning("nuclei.parse.empty_output")
            return []

        findings: List[VulnerabilityInfo] = []
        text = raw_output.decode("utf-8", errors="replace")
        skipped = 0

        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            finding = self._parse_finding(record)
            if finding:
                findings.append(finding)

        if skipped:
            logger.warning("nuclei.parse.skipped_lines", skipped=skipped)

        logger.info(
            "nuclei.parse.completed",
            findings_found=len(findings),
        )

        return findings

    def _parse_finding(self, record: Dict[str, Any]) -> Optional[VulnerabilityInfo]:
        """Parse a single JSON record from Nuclei's JSONL output."""
        template_id = record.get("template-id", record.get("templateID", ""))
        if not template_id:
            return None

        info = record.get("info", {}) or {}
        classification = info.get("classification", {}) or {}

        raw_severity = str(info.get("severity", "unknown")).lower()
        severity = SEVERITY_MAP.get(raw_severity, "informational")

        cve_ids = classification.get("cve-id", []) or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        cwe_ids = classification.get("cwe-id", []) or []
        if isinstance(cwe_ids, str):
            cwe_ids = [cwe_ids]

        cvss_score = classification.get("cvss-score")
        try:
            cvss_score = float(cvss_score) if cvss_score is not None else None
        except (TypeError, ValueError):
            cvss_score = None

        tags = info.get("tags", []) or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]

        extracted = record.get("extracted-results", []) or []

        # Template-matched findings are inherently higher-confidence than a
        # raw port scan, since a matcher had to positively fire — but we
        # still shade confidence down slightly for info/low severity noise
        # (fingerprinting templates) versus a firm CVE/RCE match.
        confidence = 0.9 if severity in ("critical", "high", "medium") else 0.6

        return VulnerabilityInfo(
            template_id=template_id,
            name=info.get("name", template_id),
            severity=severity,
            host=record.get("host", ""),
            matched_at=record.get("matched-at", record.get("host", "")),
            description=info.get("description", ""),
            tags=tags,
            cve_ids=cve_ids,
            cwe_ids=cwe_ids,
            cvss_score=cvss_score,
            cvss_vector=classification.get("cvss-metrics", ""),
            references=info.get("reference", []) or [],
            extracted_results=[str(r) for r in extracted],
            curl_command=record.get("curl-command", ""),
            matcher_name=record.get("matcher-name", ""),
            confidence=confidence,
            raw=record,
        )

    # ─── Normalization ──────────────────────────────────────────────────

    async def normalize(
        self,
        parsed_results: List[Any],
    ) -> List[Evidence]:
        """
        Normalize parsed Nuclei findings into Evidence objects.

        Args:
            parsed_results: List of VulnerabilityInfo (or equivalent dicts)

        Returns:
            List of Evidence objects ready for the pipeline
        """
        evidence_list: List[Evidence] = []

        for result in parsed_results:
            if isinstance(result, dict):
                finding = VulnerabilityInfo(**{
                    k: v for k, v in result.items() if k in VulnerabilityInfo.__dataclass_fields__
                })
            elif isinstance(result, VulnerabilityInfo):
                finding = result
            else:
                continue

            mitre_techniques = sorted({
                TAG_TO_MITRE[tag] for tag in finding.tags if tag in TAG_TO_MITRE
            })
            # A CVE in the classification block is a strong enough signal
            # on its own to warrant the generic exploitation technique,
            # even if the template wasn't tagged "cve".
            if finding.cve_ids and "T1190" not in mitre_techniques:
                mitre_techniques.append("T1190")

            evidence_list.append(Evidence(
                source="nuclei",
                evidence_type="vulnerability",
                asset_value=finding.matched_at or finding.host,
                data=finding.to_evidence_data(),
                confidence=finding.confidence,
                severity=finding.severity,
                title=finding.name,
                description=finding.description,
                tags=["nuclei", finding.template_id, *finding.tags],
                cve_ids=finding.cve_ids,
                mitre_techniques=mitre_techniques,
            ))

        logger.info(
            "nuclei.normalized",
            evidence_count=len(evidence_list),
        )

        return evidence_list

    # ─── Utility Methods ────────────────────────────────────────────────

    def build_targets_from_hosts(self, hosts: List[HostInfo]) -> List[str]:
        """
        Build Nuclei target URLs from Nmap-discovered hosts.

        Only ports whose service name looks like HTTP(S) are considered —
        Nuclei's HTTP-based templates need a URL, not a bare host:port.

        Args:
            hosts: HostInfo objects, typically produced by NmapPlugin.parse()

        Returns:
            List of target URLs suitable for Nuclei's `-u` flag
        """
        https_hints = {"https", "ssl", "https-alt"}
        http_hints = {"http", "http-alt", "http-proxy"}
        targets: List[str] = []

        for host in hosts:
            for port in host.open_ports:
                service = (port.service or "").lower()
                if service in https_hints or port.port in (443, 8443, 9443):
                    scheme = "https"
                elif service in http_hints or port.port in (80, 8080, 8000, 8888):
                    scheme = "http"
                else:
                    continue

                default_port = 443 if scheme == "https" else 80
                netloc = host.ip if port.port == default_port else f"{host.ip}:{port.port}"
                targets.append(f"{scheme}://{netloc}")

        return targets


__all__ = ["NucleiPlugin"]
