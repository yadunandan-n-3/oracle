"""
Benchmarking API Routes
=======================

Measurement endpoints for mission execution time, correlation time,
threat intelligence enrichment, risk scoring, and AI explanation latency.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from core.logging import get_logger
from domain.evidence import Evidence, EvidenceType, EvidenceSource
from domain.finding import Finding, FindingSeverity
from domain.intelligence import EnrichedFinding, ThreatIntelligence, CVEInfo, EPSSInfo, KEVInfo
from domain.scoring import OracleRiskScoreV2
from runtime.runtime import get_runtime, OracleRuntime

logger = get_logger(__name__)

router = APIRouter()


class BenchmarkResult(BaseModel):
    operation: str
    duration_ms: float
    success: bool
    error: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


@router.get("/run")
async def run_benchmarks(
    runtime: OracleRuntime = Depends(get_runtime),
) -> Dict[str, Any]:
    """Run all benchmarks and return results."""
    results: List[BenchmarkResult] = []

    # 1. Evidence Pipeline Benchmark
    result = await _benchmark_evidence_pipeline(runtime)
    results.append(result)

    # 2. Correlation Benchmark
    result = await _benchmark_correlation(runtime)
    results.append(result)

    # 3. Risk Engine Benchmark
    result = await _benchmark_risk_engine()
    results.append(result)

    # 4. State Manager Benchmark
    result = await _benchmark_state_manager(runtime)
    results.append(result)

    # 5. Knowledge Graph Benchmark (if available)
    if runtime.knowledge_graph.is_available:
        result = await _benchmark_knowledge_graph(runtime)
        results.append(result)

    # Calculate aggregate metrics
    total_duration = sum(r.duration_ms for r in results)
    success_count = sum(1 for r in results if r.success)
    avg_duration = total_duration / len(results) if results else 0

    return {
        "benchmark_results": [r.model_dump() for r in results],
        "summary": {
            "total_operations": len(results),
            "successful": success_count,
            "failed": len(results) - success_count,
            "total_duration_ms": round(total_duration, 2),
            "average_duration_ms": round(avg_duration, 2),
            "timestamp": __import__("datetime").datetime.now(timezone.utc).isoformat(),
        },
    }


@router.get("/evidence-pipeline")
async def benchmark_evidence_pipeline(
    runtime: OracleRuntime = Depends(get_runtime),
) -> Dict[str, Any]:
    """Benchmark the evidence validation and processing pipeline."""
    result = await _benchmark_evidence_pipeline(runtime)
    return result.model_dump()


@router.get("/correlation")
async def benchmark_correlation(
    runtime: OracleRuntime = Depends(get_runtime),
) -> Dict[str, Any]:
    """Benchmark the evidence correlation engine."""
    result = await _benchmark_correlation(runtime)
    return result.model_dump()


@router.get("/risk-engine")
async def benchmark_risk_engine() -> Dict[str, Any]:
    """Benchmark the risk engine V2 scoring."""
    result = await _benchmark_risk_engine()
    return result.model_dump()


# ─── Individual Benchmarks ──────────────────────────────────────────────


async def _benchmark_evidence_pipeline(runtime: OracleRuntime) -> BenchmarkResult:
    """Benchmark evidence creation and validation."""
    try:
        # Create test evidence
        evidence = Evidence(
            evidence_type=EvidenceType.OPEN_PORT,
            title="Benchmark Test Evidence",
            description="Test evidence for benchmarking",
            confidence=0.95,
            severity="medium",
            source=EvidenceSource(tool_name="benchmark"),
            asset_value="192.168.1.1:80/tcp",
            raw_data={"port": 80, "service": "http", "protocol": "tcp"},
        )

        start = time.perf_counter()
        iterations = 100

        for _ in range(iterations):
            validated = await runtime.validator.validate_evidence(evidence)

        duration = (time.perf_counter() - start) * 1000  # ms
        avg = duration / iterations

        return BenchmarkResult(
            operation="evidence_pipeline",
            duration_ms=round(avg, 3),
            success=True,
            details={"iterations": iterations, "total_ms": round(duration, 2)},
        )
    except Exception as e:
        return BenchmarkResult(
            operation="evidence_pipeline",
            duration_ms=0,
            success=False,
            error=str(e),
        )


async def _benchmark_correlation(runtime: OracleRuntime) -> BenchmarkResult:
    """Benchmark evidence correlation."""
    try:
        from domain.correlation import EvidenceCorrelator
        from domain.correlation.rules.generic_rule import GenericCorrelationRule

        correlator = EvidenceCorrelator()
        correlator.register_rule(GenericCorrelationRule())

        # Create test evidence
        evidence_list = [
            Evidence(
                evidence_type=EvidenceType.OPEN_PORT,
                title=f"Port {i}",
                confidence=0.9,
                severity="medium",
                source=EvidenceSource(tool_name="nmap"),
                asset_value=f"10.0.0.{i}:{80 + i}/tcp",
                raw_data={"port": 80 + i, "service": "http", "ip_address": f"10.0.0.{i}"},
            )
            for i in range(10)
        ]

        start = time.perf_counter()
        iterations = 50

        for _ in range(iterations):
            results = await correlator.correlate(evidence_list)

        duration = (time.perf_counter() - start) * 1000
        avg = duration / iterations

        return BenchmarkResult(
            operation="correlation",
            duration_ms=round(avg, 3),
            success=True,
            details={"iterations": iterations, "total_ms": round(duration, 2), "evidence_count": len(evidence_list)},
        )
    except Exception as e:
        return BenchmarkResult(
            operation="correlation",
            duration_ms=0,
            success=False,
            error=str(e),
        )


async def _benchmark_risk_engine() -> BenchmarkResult:
    """Benchmark the risk engine V2 scoring."""
    try:
        from domain.risk.engine_v2 import RiskEngineV2

        engine = RiskEngineV2()

        # Create test enriched finding
        enriched = EnrichedFinding(
            finding_id=UUID(int=1),
            title="Test Finding",
            severity="critical",
            confidence=0.95,
            asset_value="10.0.0.1",
            asset_type="host",
            internet_exposed=True,
            asset_criticality="critical",
            business_importance="high",
            threat_intelligence=ThreatIntelligence(
                cve=CVEInfo(cve_id="CVE-2024-0001", cvss_score=9.8, cvss_severity="critical"),
                epss=EPSSInfo(cve_id="CVE-2024-0001", epss_score=0.95, percentile=0.99),
                kev=KEVInfo(cve_id="CVE-2024-0001", vendor_project="Test", product="Test"),
            ),
            metadata={"exploit_maturity": "weaponized"},
        )

        start = time.perf_counter()
        iterations = 100

        for _ in range(iterations):
            risk = await engine.score_enriched_finding(enriched)

        duration = (time.perf_counter() - start) * 1000
        avg = duration / iterations

        return BenchmarkResult(
            operation="risk_engine_v2",
            duration_ms=round(avg, 3),
            success=True,
            details={
                "iterations": iterations,
                "total_ms": round(duration, 2),
                "score": risk.score,
                "level": risk.level.value,
            },
        )
    except Exception as e:
        return BenchmarkResult(
            operation="risk_engine_v2",
            duration_ms=0,
            success=False,
            error=str(e),
        )


async def _benchmark_state_manager(runtime: OracleRuntime) -> BenchmarkResult:
    """Benchmark state manager operations."""
    try:
        state_manager = runtime.state_manager

        start = time.perf_counter()
        iterations = 100

        for _ in range(iterations):
            _ = state_manager.get_active_missions()

        duration = (time.perf_counter() - start) * 1000
        avg = duration / iterations

        return BenchmarkResult(
            operation="state_manager_query",
            duration_ms=round(avg, 3),
            success=True,
            details={"iterations": iterations, "total_ms": round(duration, 2)},
        )
    except Exception as e:
        return BenchmarkResult(
            operation="state_manager_query",
            duration_ms=0,
            success=False,
            error=str(e),
        )


async def _benchmark_knowledge_graph(runtime: OracleRuntime) -> BenchmarkResult:
    """Benchmark knowledge graph query."""
    try:
        kg = runtime.knowledge_graph

        start = time.perf_counter()
        iterations = 10

        for _ in range(iterations):
            health = await kg.health_check()

        duration = (time.perf_counter() - start) * 1000
        avg = duration / iterations

        return BenchmarkResult(
            operation="knowledge_graph_health_check",
            duration_ms=round(avg, 3),
            success=health.get("healthy", False),
            details={"iterations": iterations, "total_ms": round(duration, 2)},
        )
    except Exception as e:
        return BenchmarkResult(
            operation="knowledge_graph_health_check",
            duration_ms=0,
            success=False,
            error=str(e),
        )


from datetime import timezone

