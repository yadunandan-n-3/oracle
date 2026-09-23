"""
Telemetry Service
=================

OpenTelemetry-based telemetry for distributed tracing,
metrics collection, and structured observability.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, AsyncIterator, Dict, Optional
from uuid import UUID

from opentelemetry import trace, metrics
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.resources import Resource
from opentelemetry.semconv.resource import ResourceAttributes

from core.config import settings
from core.logging import get_logger

logger = get_logger(__name__)


class TelemetryClient:
    """
    Central telemetry client for ORACLE.

    Provides:
    - Distributed tracing spans
    - Metrics (counters, histograms, gauges)
    - Structured event logging
    """

    def __init__(self) -> None:
        self._tracer: Optional[trace.Tracer] = None
        self._meter: Optional[metrics.Meter] = None
        self._initialized = False

    def initialize(self, service_name: Optional[str] = None) -> None:
        """Initialize OpenTelemetry providers."""
        if self._initialized:
            return

        resource = Resource.create({
            ResourceAttributes.SERVICE_NAME: service_name or settings.service_name,
            ResourceAttributes.SERVICE_VERSION: "0.1.0",
            ResourceAttributes.DEPLOYMENT_ENVIRONMENT: settings.environment.value,
        })

        trace_provider = TracerProvider(resource=resource)
        meter_provider = MeterProvider(resource=resource)

        trace.set_tracer_provider(trace_provider)
        metrics.set_meter_provider(meter_provider)

        self._tracer = trace.get_tracer(__name__)
        self._meter = metrics.get_meter(__name__)
        self._initialized = True

        logger.info("telemetry.initialized", service=service_name or settings.service_name)

    @property
    def tracer(self) -> trace.Tracer:
        if not self._tracer:
            self.initialize()
        return self._tracer  # type: ignore

    @property
    def meter(self) -> metrics.Meter:
        if not self._meter:
            self.initialize()
        return self._meter  # type: ignore

    @asynccontextmanager
    async def start_span(
        self,
        name: str,
        attributes: Optional[Dict[str, Any]] = None,
        mission_id: Optional[UUID] = None,
    ) -> AsyncIterator[trace.Span]:
        """
        Create a tracing span for distributed tracing.

        Args:
            name: Span name (e.g., "mission.execute", "tool.nmap.scan")
            attributes: Span attributes for context
            mission_id: Optional mission ID for correlation

        Yields:
            An OpenTelemetry span
        """
        attrs = dict(attributes or {})
        if mission_id:
            attrs["mission.id"] = str(mission_id)

        with self.tracer.start_as_current_span(name, attributes=attrs) as span:
            try:
                yield span
            except Exception as e:
                span.record_exception(e)
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                raise

    def increment_counter(
        self,
        name: str,
        value: int = 1,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Increment a counter metric."""
        counter = self.meter.create_counter(name)
        counter.add(value, attributes or {})

    def record_histogram(
        self,
        name: str,
        value: float,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record a histogram observation."""
        histogram = self.meter.create_histogram(name)
        histogram.record(value, attributes or {})

    def set_gauge(
        self,
        name: str,
        value: float,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Set a gauge value."""
        gauge = self.meter.create_gauge(name)
        gauge.set(value, attributes or {})


# Singleton
telemetry = TelemetryClient()

__all__ = ["TelemetryClient", "telemetry"]
