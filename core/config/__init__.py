"""
Configuration Management
========================

Centralized configuration using Pydantic Settings.
Reads from environment variables, .env files, and secrets.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, SecretStr
from typing import Optional, List
from enum import Enum


class Environment(str, Enum):
    """Deployment environment."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class OracleSettings(BaseSettings):
    """
    Global ORACLE configuration.

    All settings are loaded from environment variables with prefix ORACLE_.
    Example: ORACLE_DATABASE_URL, ORACLE_OPENAI_API_KEY
    """

    model_config = SettingsConfigDict(
        env_prefix="ORACLE_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        secrets_dir="/run/secrets",
    )

    # --- General ---
    environment: Environment = Environment.DEVELOPMENT
    debug: bool = False
    log_level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    service_name: str = "oracle"

    # --- Database ---
    database_url: str = Field(
        default="postgresql+asyncpg://oracle:oracle@localhost:5432/oracle",
        description="PostgreSQL DSN for primary database",
    )
    database_pool_size: int = 20
    database_max_overflow: int = 10

    # --- Redis ---
    redis_url: str = Field(default="redis://localhost:6379/0")
    redis_max_connections: int = 50

    # --- Neo4j ---
    neo4j_uri: str = Field(default="bolt://localhost:7687")
    neo4j_user: str = Field(default="neo4j")
    neo4j_password: SecretStr = Field(default=SecretStr("oracle"))

    # --- MinIO ---
    minio_endpoint: str = Field(default="localhost:9000")
    minio_access_key: str = Field(default="oracle")
    minio_secret_key: SecretStr = Field(default=SecretStr("oracle123"))
    minio_bucket: str = Field(default="oracle-evidence")
    minio_secure: bool = False

    # --- JWT ---
    jwt_secret: str = Field(default="change-me-in-production")
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 60
    jwt_refresh_token_expire_minutes: int = 1440

    # --- API ---
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    allowed_origins: List[str] = Field(default_factory=lambda: ["http://localhost:3000", "http://localhost:8000"])

    # --- Runtime ---
    max_concurrent_tasks: int = Field(default=10, description="Max concurrent tasks in the scheduler")
    max_concurrent_missions: int = Field(default=5, description="Max concurrent missions")
    default_task_timeout_seconds: int = Field(default=300, description="Default timeout for tasks")
    mission_archive_delay_seconds: int = Field(default=300, description="Delay before archiving completed missions")

    # --- AI / LLM ---
    openai_api_key: Optional[SecretStr] = Field(default=None)
    openai_model: str = Field(default="gpt-4")
    openai_max_tokens: int = 4096
    openai_temperature: float = 0.1

    # --- Agent Configuration ---
    agent_poll_interval: float = Field(default=1.0, description="Poll interval for agents")
    agent_max_retries: int = Field(default=3, description="Max retries for agent tasks")

    # --- Tool Configuration ---
    nmap_binary_path: str = Field(default="nmap", description="Path to nmap binary")
    nmap_timeout_seconds: int = Field(default=600, description="Nmap scan timeout")
    nuclei_binary_path: str = Field(default="nuclei", description="Path to nuclei binary")

    # --- Feature Flags ---
    enable_neo4j: bool = Field(default=True, description="Enable Neo4j knowledge graph")
    enable_minio: bool = Field(default=True, description="Enable MinIO file storage")
    enable_telemetry: bool = Field(default=False, description="Enable OpenTelemetry")
    enable_reporting: bool = Field(default=True, description="Enable report generation")

    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment == Environment.PRODUCTION

    @property
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.environment == Environment.DEVELOPMENT


# Global settings instance
settings = OracleSettings()


__all__ = ["OracleSettings", "Environment", "settings"]
