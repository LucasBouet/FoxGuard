"""Throttling for the endpoints a confined peer can already reach.

A peer in quarantine has, by design, network access to the portal, and a peer in
staging has network access to the enrollment endpoint. Both are therefore
reachable by anyone holding a WireGuard key -- including someone who stole a
laptop and is guessing its owner's password. Rate limiting is what stops that
from being an offline-speed attack.

Why a hand-rolled limiter rather than slowapi/FastAPI-limiter: those exist to
share counters across processes via Redis. Foxguard's portal is one uvicorn
process on a gateway that authenticates a handful of humans per hour, so the
dependency would buy nothing and add a moving part to a security control.

**Scope caveat.** The counters live in this process. Running the API with
several uvicorn workers multiplies the effective budget by the worker count.
The documented deployment is a single worker; if you scale it out, move this
behind a shared store rather than raising the limit.

A *sliding log* rather than a fixed window: fixed windows let an attacker spend
the whole budget at the end of one window and again at the start of the next,
which doubles the real rate at exactly the moment that matters. With the small
budgets used here, keeping the timestamps is cheap and exact.

Only **failures** are counted. A user who authenticates successfully several
times in a row (session refresh) is not an attacker, and throttling them would
turn a security control into an outage.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable

__all__ = ["RateLimited", "RateLimiter"]

#: Beyond this many tracked keys we drop the ones that can no longer block
#: anybody. Bounds memory if something ever hammers the portal from many
#: addresses; in normal operation the key space is the WireGuard pool.
_MAX_KEYS = 4096


class RateLimited(Exception):
    """The caller has spent its budget. ``retry_after`` is in whole seconds."""

    def __init__(self, key: str, retry_after: int) -> None:
        self.key = key
        self.retry_after = retry_after
        super().__init__(f"too many attempts for {key!r}; retry in {retry_after}s")


class RateLimiter:
    """Sliding-log limiter, safe to share across threads.

    FastAPI runs ``def`` endpoints in a thread pool, so two logins can land
    concurrently; the lock keeps the deques consistent.
    """

    def __init__(
        self,
        *,
        max_attempts: int,
        window_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        self._max = max_attempts
        self._window = float(window_seconds)
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ internals

    def _prune(self, key: str, now: float) -> deque[float]:
        """Drop timestamps that have aged out of the window."""
        hits = self._hits.get(key)
        if hits is None:
            hits = deque()
            self._hits[key] = hits
        cutoff = now - self._window
        while hits and hits[0] <= cutoff:
            hits.popleft()
        return hits

    def _collect(self, now: float) -> None:
        if len(self._hits) <= _MAX_KEYS:
            return
        cutoff = now - self._window
        for key in [k for k, v in self._hits.items() if not v or v[-1] <= cutoff]:
            del self._hits[key]

    # -------------------------------------------------------------------- public

    def check(self, key: str) -> None:
        """Raise :class:`RateLimited` if ``key`` has no budget left.

        Call *before* doing the expensive part -- an argon2 verification is
        ~100ms of CPU, so letting a throttled caller reach it would make the
        limiter a denial-of-service amplifier rather than a defence.
        """
        with self._lock:
            now = self._clock()
            hits = self._prune(key, now)
            if len(hits) >= self._max:
                retry_after = max(1, int(hits[0] + self._window - now) + 1)
                raise RateLimited(key, retry_after)

    def record_failure(self, key: str) -> None:
        with self._lock:
            now = self._clock()
            self._prune(key, now).append(now)
            self._collect(now)

    def reset(self, key: str) -> None:
        """Forget a key's failures. Called after a successful authentication."""
        with self._lock:
            self._hits.pop(key, None)

    def remaining(self, key: str) -> int:
        """Attempts left before the next :meth:`check` raises. For tests/headers."""
        with self._lock:
            return max(0, self._max - len(self._prune(key, self._clock())))
