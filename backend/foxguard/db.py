"""Database engine and session plumbing.

Synchronous SQLAlchemy on purpose: FastAPI runs ``def`` endpoints in a thread
pool, the workload here is tiny, and sync sessions are far easier to reason
about and to test than async ones for a single-maintainer project.
"""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from .config import get_settings

_settings = get_settings()

engine = create_engine(
    _settings.database_url,
    pool_pre_ping=True,
    future=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    future=True,
)


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a session. **Routes commit explicitly.**

    Committing here instead would be a correctness bug, not a style choice:
    FastAPI runs the teardown of a ``yield`` dependency *after* the response has
    been sent, so the client is told "201 Created" before the transaction is
    durable. A caller that reads immediately after writing -- a provisioning
    script, or the admin UI refreshing a list after a POST -- reliably sees
    stale data. Measured at 40/40 misses before this was changed.

    So: mutating routes call ``session.commit()`` before returning, and this
    dependency only guarantees rollback-on-exception and cleanup.
    """
    session = SessionLocal()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
