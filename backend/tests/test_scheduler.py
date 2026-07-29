"""The advisory lock that makes the sweeper safe to run more than once.

Needs a real PostgreSQL: ``pg_try_advisory_xact_lock`` is the whole subject, and
faking it would test nothing. Skips itself without
``FOXGUARD_TEST_DATABASE_URL`` like the other database-backed tests.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from foxguard.config import Settings
from foxguard.models import Base
from foxguard.services.scheduler import SESSION_SWEEP_LOCK, SessionSweeper, advisory_lock


@pytest.fixture()
def engine(database_url: str):
    engine = create_engine(database_url, future=True)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    try:
        yield engine
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.fixture()
def factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@pytest.fixture()
def two_connections(factory) -> Iterator[tuple]:
    """Two sessions on *different* connections, standing in for two workers."""
    first, second = factory(), factory()
    try:
        yield first, second
    finally:
        first.rollback()
        first.close()
        second.rollback()
        second.close()


def settings(**overrides) -> Settings:
    return Settings(dev_mode=True, **overrides)


# --------------------------------------------------------------------------- #
# the lock
# --------------------------------------------------------------------------- #


def test_one_holder_at_a_time(two_connections):
    """Two workers ticking together must not both sweep."""
    first, second = two_connections
    with advisory_lock(first, SESSION_SWEEP_LOCK) as mine:
        assert mine is True
        with advisory_lock(second, SESSION_SWEEP_LOCK) as theirs:
            assert theirs is False


def test_the_lock_never_blocks(two_connections):
    """A colliding tick is skipped, not queued -- otherwise workers pile up."""
    first, second = two_connections
    with advisory_lock(first, SESSION_SWEEP_LOCK):
        # Would hang here rather than return if we used the blocking variant.
        with advisory_lock(second, SESSION_SWEEP_LOCK) as theirs:
            assert theirs is False


def test_committing_releases_the_lock(two_connections):
    first, second = two_connections
    with advisory_lock(first, SESSION_SWEEP_LOCK) as mine:
        assert mine is True
    first.commit()

    with advisory_lock(second, SESSION_SWEEP_LOCK) as theirs:
        assert theirs is True


def test_a_crashed_sweep_does_not_strand_the_lock(two_connections):
    """Transaction-scoped on purpose: a rollback frees it, so a failure mid-sweep
    cannot wedge expiry until someone restarts PostgreSQL."""
    first, second = two_connections
    with pytest.raises(RuntimeError):
        with advisory_lock(first, SESSION_SWEEP_LOCK) as mine:
            assert mine is True
            raise RuntimeError("boom")
    first.rollback()

    with advisory_lock(second, SESSION_SWEEP_LOCK) as theirs:
        assert theirs is True


def test_different_keys_do_not_contend(two_connections):
    first, second = two_connections
    with advisory_lock(first, SESSION_SWEEP_LOCK):
        with advisory_lock(second, SESSION_SWEEP_LOCK + 1) as other:
            assert other is True


# --------------------------------------------------------------------------- #
# the sweeper
# --------------------------------------------------------------------------- #


def test_a_sweep_with_an_empty_database_is_a_no_op(factory):
    result = SessionSweeper(settings(), session_factory=factory).run_once()
    assert not result
    assert result.regenerated is False


def test_a_worker_that_cannot_take_the_lock_skips_its_tick(factory, two_connections):
    holder, _ = two_connections
    with advisory_lock(holder, SESSION_SWEEP_LOCK) as mine:
        assert mine is True
        result = SessionSweeper(settings(), session_factory=factory).run_once()
    assert result.expired == ()
    assert result.regenerated is False


def test_the_sweeper_releases_the_lock_between_ticks(factory):
    sweeper = SessionSweeper(settings(), session_factory=factory)
    sweeper.run_once()
    # Would deadlock against itself if the previous tick had held on.
    assert sweeper.run_once().expired == ()
