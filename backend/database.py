"""
Database Session Management
===========================

Async SQLAlchemy engine and session factory for ORACLE.
"""

from __future__ import annotations

from typing import AsyncIterator, Optional

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from core.config import settings
from core.logging import get_logger
from backend.models import Base

logger = get_logger(__name__)

# Global engine and session factory
_engine = None
_session_factory = None


def get_database_url() -> str:
    """Get the database URL from settings."""
    return settings.database_url


async def init_database() -> None:
    """Initialize the database engine and create tables."""
    global _engine, _session_factory

    if _engine is not None:
        return

    database_url = get_database_url()
    _engine = create_async_engine(
        database_url,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        echo=settings.debug,
        pool_pre_ping=True,
    )

    _session_factory = async_sessionmaker(
        _engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    # Create tables
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    logger.info(
        "database.initialized",
        pool_size=settings.database_pool_size,
    )


async def close_database() -> None:
    """Close the database engine."""
    global _engine, _session_factory

    if _engine:
        await _engine.dispose()
        _engine = None
        _session_factory = None
        logger.info("database.closed")


async def get_session() -> AsyncIterator[AsyncSession]:
    """
    Get an async database session.

    Yields:
        An async SQLAlchemy session
    """
    global _session_factory

    if _session_factory is None:
        await init_database()

    session = _session_factory()  # type: ignore
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency for database sessions."""
    async for session in get_session():
        yield session


__all__ = [
    "init_database",
    "close_database",
    "get_session",
    "get_db",
]
