"""
Backend Configuration
=====================

Environment-specific configuration for the FastAPI backend.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic_settings import BaseSettings


class BackendSettings(BaseSettings):
    """Backend-specific settings."""

    backend_host: str = "0.0.0.0"
    backend_port: int = 8000
    backend_workers: int = 4

    allowed_origins: List[str] = [
        "http://localhost:3000",
        "http://localhost:8000",
    ]

    cors_allow_credentials: bool = True
    cors_allow_methods: List[str] = ["*"]
    cors_allow_headers: List[str] = ["*"]

    # Database
    database_url: str = "postgresql+asyncpg://oracle:oracle@localhost:5432/oracle"
    database_pool_size: int = 20
    database_max_overflow: int = 10
    database_echo: bool = False

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Rate limiting
    rate_limit_enabled: bool = True
    rate_limit_requests: int = 100
    rate_limit_window: int = 60  # seconds

    model_config = {"env_prefix": "ORACLE_"}


backend_settings = BackendSettings()
