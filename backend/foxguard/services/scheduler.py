"""The timer that drives session expiry.

An in-process asyncio task rather than APScheduler or a systemd timer: the job
is one query and a ruleset regeneration, it must run on the box that owns the
database anyway, and a scheduler dependency would be a third moving part in a
path that can take away network access.

Two problems come with running it in-process, and both are solved here rather
than documented away:

**Several workers would each run it.** Unlike the rate limiter, this one is
fixable without shared state, because PostgreSQL already has the primitive:
``pg_try_advisory_xact_lock``. A worker that cannot take the lock skips the tick
instead of duplicating the work. The transaction-scoped variant is used on
purpose -- it is released by the commit or the rollback, so a crash mid-sweep
cannot strand the lock and wedge expiry forever. The same guard makes an
external cron safe to run alongside the internal timer.

**A database outage must not kill the API.** The loop catches everything,
logs it, and tries again on the next tick. An expiry sweep that stops silently
is how peers stay authenticated for a week.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import zlib
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import Settings
from ..db import SessionLocal
from . import expiry

logger = logging.getLogger(__name__)

__all__ = ["SESSION_SWEEP_LOCK", "SessionSweeper", "advisory_lock"]

#: Stable and arbitrary. Advisory locks share one namespace per database, so the
#: value only has to be unlikely to collide with another application's.
SESSION_SWEEP_LOCK = zlib.crc32(b"foxguard.session_sweep")


@contextmanager
def advisory_lock(session: Session, key: int) -> Iterator[bool]:
    """Try to take a transaction-scoped advisory lock. Yields whether we got it.

    Never blocks: a tick that collides with another worker's is a tick worth
    skipping, not waiting for.
    """
    acquired = bool(
        session.execute(select(func.pg_try_advisory_xact_lock(key))).scalar_one()
    )
    # No release here on purpose -- the lock is bound to the transaction and
    # PostgreSQL drops it at commit or rollback, including after a crash.
    yield acquired


class SessionSweeper:
    """Runs :func:`foxguard.services.expiry.sweep` on a timer."""

    def __init__(
        self,
        settings: Settings,
        *,
        session_factory: Callable[[], Session] = SessionLocal,
    ) -> None:
        self._settings = settings
        self._session_factory = session_factory
        self._task: asyncio.Task | None = None

    # ------------------------------------------------------------------ one tick

    def run_once(self) -> expiry.SweepResult:
        """Synchronous single pass. Also what the admin endpoint and cron call."""
        session = self._session_factory()
        try:
            with advisory_lock(session, SESSION_SWEEP_LOCK) as acquired:
                if not acquired:
                    logger.debug("session sweep already running elsewhere; skipping")
                    return expiry.SweepResult()
                result = expiry.sweep(session, self._settings)
                session.commit()
                return result
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # -------------------------------------------------------------------- loop

    async def _loop(self) -> None:
        interval = self._settings.session_sweep_interval_seconds
        logger.info("session sweeper started (every %ss)", interval)
        while True:
            try:
                await asyncio.sleep(interval)
                # The ORM is synchronous; running it on the event loop would
                # stall every request for the duration of the sweep.
                result = await asyncio.to_thread(self.run_once)
                if result:
                    logger.info(
                        "session sweep quarantined %d peer(s)", len(result.expired)
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                # Never let one bad tick end the loop: a sweeper that dies
                # quietly leaves everyone authenticated indefinitely.
                logger.exception("session sweep failed; retrying next tick")

    async def start(self) -> None:
        if not self._settings.session_sweep_enabled:
            logger.warning(
                "session expiry is DISABLED; user peers will stay active until "
                "they log out or an admin intervenes"
            )
            return
        self._task = asyncio.create_task(self._loop(), name="foxguard-session-sweeper")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None
        logger.info("session sweeper stopped")
