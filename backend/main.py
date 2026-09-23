"""
FastAPI Application Entry Point
================================

The main FastAPI application for ORACLE.
Exposes REST API endpoints for the dashboard and MCP server for AI integrations.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from core.config import settings
from core.exceptions import OracleError
from core.logging import setup_logging, get_logger
from runtime.runtime import get_runtime

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifecycle manager."""
    # Startup
    setup_logging()
    logger.info("backend.starting", environment=settings.environment.value)

    runtime = get_runtime()
    await runtime.start()

    yield

    # Shutdown
    logger.info("backend.shutting_down")
    await runtime.stop()


# Create FastAPI application
app = FastAPI(
    title="ORACLE API",
    description="AI-native Operating System for Cybersecurity",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global Exception Handler

@app.exception_handler(OracleError)
async def oracle_error_handler(request: Request, exc: OracleError) -> JSONResponse:
    """Handle ORACLE-specific errors."""
    logger.error(
        "api.error",
        path=request.url.path,
        error=exc.code,
        message=exc.message,
    )
    return JSONResponse(
        status_code=_http_status_for_code(exc.code),
        content=exc.to_dict(),
    )


def _http_status_for_code(code: str) -> int:
    """Map ORACLE error codes to HTTP status codes."""
    mapping = {
        "CONFIGURATION_ERROR": 500,
        "RESOURCE_NOT_FOUND": 404,
        "VALIDATION_ERROR": 422,
        "AUTHENTICATION_ERROR": 401,
        "AUTHORIZATION_ERROR": 403,
        "RATE_LIMIT_ERROR": 429,
        "INTEGRATION_ERROR": 502,
        "TIMEOUT_ERROR": 504,
        "POLICY_VIOLATION": 403,
        "INVALID_STATE": 409,
    }
    return mapping.get(code, 500)


# Health Check

@app.get("/api/health")
async def health_check() -> dict:
    """Health check endpoint."""
    runtime = get_runtime()
    return await runtime.health()


# Import and register routers
from backend.api.missions import router as missions_router
from backend.api.assets import router as assets_router
from backend.api.auth import router as auth_router
from backend.api.findings import router as findings_router
from backend.api.reports import router as reports_router
from backend.api.graph import router as graph_router
from backend.api.timeline import router as timeline_router
from backend.api.search import router as search_router
from backend.api.statistics import router as statistics_router
from backend.api.dashboard import router as dashboard_router
from backend.api.copilot import router as copilot_router
from backend.api.benchmark import router as benchmark_router

app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])
app.include_router(missions_router, prefix="/api/missions", tags=["Missions"])
app.include_router(assets_router, prefix="/api/assets", tags=["Assets"])
app.include_router(findings_router, prefix="/api/findings", tags=["Findings"])
app.include_router(reports_router, prefix="/api/reports", tags=["Reports"])
app.include_router(graph_router, prefix="/api/graph", tags=["Knowledge Graph"])
app.include_router(timeline_router, prefix="/api/timeline", tags=["Timeline"])
app.include_router(search_router, prefix="/api/search", tags=["Search"])
app.include_router(statistics_router, prefix="/api/statistics", tags=["Statistics"])
app.include_router(dashboard_router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(copilot_router, prefix="/api/copilot", tags=["AI Copilot"])
app.include_router(benchmark_router, prefix="/api/benchmark", tags=["Benchmark"])


@app.get("/")
async def root() -> dict:
    """Root endpoint."""
    return {
        "service": "ORACLE API",
        "version": "0.1.0",
        "docs": "/docs",
        "endpoints": {
            "auth": "/api/auth",
            "missions": "/api/missions",
            "assets": "/api/assets",
            "findings": "/api/findings",
            "reports": "/api/reports",
            "graph": "/api/graph",
            "timeline": "/api/timeline",
            "search": "/api/search",
            "statistics": "/api/statistics",
            "dashboard": "/api/dashboard",
            "copilot": "/api/copilot",
            "benchmark": "/api/benchmark",
            "openapi": "/docs",
        },
    }
