"""The throttle that keeps a stolen laptop from becoming an offline attack.

The clock is injected everywhere, so none of this sleeps.
"""

from __future__ import annotations

import threading

import pytest

from foxguard.services.ratelimit import RateLimited, RateLimiter


class FakeClock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture()
def clock() -> FakeClock:
    return FakeClock()


def limiter(clock: FakeClock, *, max_attempts: int = 3, window: float = 60.0):
    return RateLimiter(max_attempts=max_attempts, window_seconds=window, clock=clock)


# --------------------------------------------------------------------------- #
# the budget
# --------------------------------------------------------------------------- #


def test_failures_are_allowed_up_to_the_budget_then_refused(clock):
    limit = limiter(clock)
    for _ in range(3):
        limit.check("peer")
        limit.record_failure("peer")
    with pytest.raises(RateLimited):
        limit.check("peer")


def test_checking_does_not_itself_consume_budget(clock):
    """Otherwise merely loading the login page would lock a user out."""
    limit = limiter(clock)
    for _ in range(50):
        limit.check("peer")
    assert limit.remaining("peer") == 3


def test_a_successful_login_clears_the_failures(clock):
    limit = limiter(clock)
    limit.record_failure("peer")
    limit.record_failure("peer")
    limit.reset("peer")
    assert limit.remaining("peer") == 3
    limit.check("peer")


def test_keys_are_independent(clock):
    limit = limiter(clock)
    for _ in range(3):
        limit.record_failure("peer-a")
    with pytest.raises(RateLimited):
        limit.check("peer-a")
    limit.check("peer-b")


# --------------------------------------------------------------------------- #
# the window slides
# --------------------------------------------------------------------------- #


def test_budget_returns_once_the_window_has_passed(clock):
    limit = limiter(clock)
    for _ in range(3):
        limit.record_failure("peer")
    with pytest.raises(RateLimited):
        limit.check("peer")

    clock.advance(61)
    limit.check("peer")


def test_the_window_slides_rather_than_resetting_in_blocks(clock):
    """A fixed window lets an attacker spend two budgets back to back.

    Three failures at t=0 and three more just after t=60 would be six attempts
    in barely over a minute with fixed windows. With a sliding log the first
    batch only ages out one at a time.
    """
    limit = limiter(clock)
    for _ in range(3):
        limit.record_failure("peer")

    clock.advance(30)
    with pytest.raises(RateLimited):
        limit.check("peer")

    # The three original failures expire together at t=60...
    clock.advance(31)
    limit.check("peer")
    limit.record_failure("peer")
    # ...and this newest one is still counted.
    assert limit.remaining("peer") == 2


def test_retry_after_is_positive_and_within_the_window(clock):
    limit = limiter(clock)
    for _ in range(3):
        limit.record_failure("peer")
    clock.advance(10)
    with pytest.raises(RateLimited) as excinfo:
        limit.check("peer")
    assert 0 < excinfo.value.retry_after <= 60


# --------------------------------------------------------------------------- #
# hygiene
# --------------------------------------------------------------------------- #


def test_stale_keys_do_not_accumulate_forever(clock):
    """Memory must not grow with the number of addresses ever seen."""
    limit = limiter(clock)
    for index in range(5000):
        limit.record_failure(f"peer-{index}")
    clock.advance(61)
    limit.record_failure("trigger-the-sweep")
    assert len(limit._hits) < 5000


@pytest.mark.parametrize(
    "kwargs", [{"max_attempts": 0}, {"window_seconds": 0}, {"window_seconds": -1}]
)
def test_nonsensical_configuration_is_refused_at_construction(kwargs):
    params = {"max_attempts": 3, "window_seconds": 60.0} | kwargs
    with pytest.raises(ValueError):
        RateLimiter(**params)


def test_concurrent_failures_are_all_counted():
    """FastAPI runs sync endpoints in a thread pool, so this really happens."""
    limit = RateLimiter(max_attempts=1000, window_seconds=60.0)
    threads = [
        threading.Thread(target=lambda: [limit.record_failure("peer") for _ in range(50)])
        for _ in range(8)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert limit.remaining("peer") == 1000 - 400
