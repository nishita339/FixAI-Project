"""
FixAI Backend — Async Database Engine & Connection Pool
======================================================

Supports:
1. SQLite (aiosqlite) for zero-dependency instant local development.
2. PostgreSQL (asyncpg) with enterprise connection pooling for production cloud
   deployments (Neon, Supabase, Render PostgreSQL, Railway, AWS RDS).
3. Automatic URL normalization: handles 'postgres://' and 'postgresql://' prefixes
   and translates 'sslmode=require' to asyncpg SSL parameters.
4. Active connection pool pre-pinging (pool_pre_ping=True) and pool recycling (300s).
"""

from collections.abc import AsyncGenerator
import logging
import urllib.parse
from typing import Any, Dict, Tuple

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy import text

from app.config import settings

logger = logging.getLogger("fixai.database")


def normalize_database_url(raw_url: str) -> Tuple[str, Dict[str, Any]]:
    """
    Normalizes cloud-provided database URLs for SQLAlchemy + asyncpg / aiosqlite.
    Translates 'postgres://' to 'postgresql+asyncpg://' and extracts SSL parameters.
    """
    url = raw_url.strip()
    connect_args: Dict[str, Any] = {}

    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        return url, connect_args

    # Normalize PostgreSQL URL scheme
    if url.startswith("postgres://"):
        url = "postgresql+asyncpg://" + url[len("postgres://"):]
    elif url.startswith("postgresql://") and not url.startswith("postgresql+asyncpg://"):
        url = "postgresql+asyncpg://" + url[len("postgresql://"):]

    # Handle SSL mode query parameters for asyncpg
    parsed = urllib.parse.urlsplit(url)
    if parsed.query:
        query_params = urllib.parse.parse_qs(parsed.query)
        # asyncpg prefers ssl="require" or ssl=True rather than sslmode query param
        if "sslmode" in query_params:
            sslmode = query_params["sslmode"][0].lower()
            if sslmode in ("require", "verify-ca", "verify-full"):
                connect_args["ssl"] = "require"
            del query_params["sslmode"]

            # Reconstruct URL without raw sslmode query parameter
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            url = urllib.parse.urlunsplit((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                new_query,
                parsed.fragment,
            ))

    return url, connect_args


# Compute normalized connection settings
NORMALIZED_URL, CONNECT_ARGS = normalize_database_url(settings.DATABASE_URL)

engine_kwargs: Dict[str, Any] = {
    "echo": False,
    "future": True,
    "connect_args": CONNECT_ARGS,
}

# Apply enterprise connection pooling for PostgreSQL
if NORMALIZED_URL.startswith("postgresql"):
    engine_kwargs.update({
        "pool_size": 10,
        "max_overflow": 20,
        "pool_timeout": 30,
        "pool_recycle": 300,
        "pool_pre_ping": True,
    })
    logger.info("Initializing PostgreSQL engine with asyncpg connection pool (size=10, pre-ping=True)")
else:
    logger.info("Initializing local SQLite engine (aiosqlite)")

engine = create_async_engine(NORMALIZED_URL, **engine_kwargs)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)

Base = declarative_base()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency that provides an async database session per request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def check_database_health() -> Dict[str, Any]:
    """
    Performs an active database ping to verify pool health and connectivity.
    """
    dialect = "sqlite" if NORMALIZED_URL.startswith("sqlite") else "postgresql"
    pool_info = {
        "dialect": dialect,
        "status": "HEALTHY",
        "pool_pre_ping": True,
    }

    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(text("SELECT 1"))
            val = result.scalar()
            if val == 1:
                pool_info["ping"] = "OK"
                pool_info["connection_state"] = "ACTIVE"
            else:
                pool_info["ping"] = "UNEXPECTED_RESULT"
                pool_info["status"] = "DEGRADED"
    except Exception as e:
        pool_info["status"] = "OFFLINE"
        pool_info["error"] = str(e)

    return pool_info
