import asyncio

import pytest

from mcp_gateway.ratelimit import Limit, RateLimiter


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def limiter(max_keys: int = 100) -> tuple[RateLimiter, Clock]:
    clock = Clock()
    return RateLimiter(clock=clock, max_keys=max_keys), clock


LIMIT = Limit(per_minute=60, burst=3)  # 1 token/second, bucket of 3


def test_burst_then_denied_then_refills() -> None:
    rl, clock = limiter()
    assert [rl.check("k", LIMIT).allowed for _ in range(3)] == [True, True, True]
    denied = rl.check("k", LIMIT)
    assert not denied.allowed
    assert denied.retry_after == pytest.approx(1.0)
    assert denied.retry_after_seconds == 1
    clock.t += 1.0
    assert rl.check("k", LIMIT).allowed
    assert not rl.check("k", LIMIT).allowed  # only one token came back


def test_refill_is_capped_at_burst() -> None:
    rl, clock = limiter()
    rl.check("k", LIMIT)
    clock.t += 10_000  # a long idle period must not bank unlimited calls
    assert sum(rl.check("k", LIMIT).allowed for _ in range(10)) == 3


def test_keys_are_independent() -> None:
    rl, _ = limiter()
    for _ in range(3):
        rl.check(("alice", "run_query"), LIMIT)
    assert not rl.check(("alice", "run_query"), LIMIT).allowed
    assert rl.check(("bob", "run_query"), LIMIT).allowed  # another user is unaffected
    assert rl.check(("alice", "update_record"), LIMIT).allowed  # another tool is unaffected


def test_slow_sustained_rate_is_allowed_fast_is_not() -> None:
    rl, clock = limiter()
    for _ in range(3):
        rl.check("k", LIMIT)
    allowed = 0
    for _ in range(120):  # one call per 1.2 s: below the 1/s refill, so always allowed
        clock.t += 1.2
        allowed += rl.check("k", LIMIT).allowed
    assert allowed == 120
    denied = 0
    for _ in range(120):  # ten calls per second: far above the refill rate
        clock.t += 0.1
        denied += not rl.check("k", LIMIT).allowed
    assert denied > 100


def test_retry_after_reflects_the_refill_rate() -> None:
    rl, _ = limiter()
    slow = Limit(per_minute=6, burst=1)  # one token every 10 s
    rl.check("k", slow)
    d = rl.check("k", slow)
    assert not d.allowed
    assert d.retry_after == pytest.approx(10.0)
    assert d.retry_after_seconds == 10


def test_retry_after_is_never_below_one_second() -> None:
    rl, _ = limiter()
    fast = Limit(per_minute=100_000, burst=1)
    rl.check("k", fast)
    d = rl.check("k", fast)
    assert not d.allowed
    assert d.retry_after_seconds == 1


def test_clock_going_backwards_never_creates_tokens() -> None:
    rl, clock = limiter()
    for _ in range(3):
        rl.check("k", LIMIT)
    clock.t -= 500
    assert not rl.check("k", LIMIT).allowed


def test_memory_is_bounded_by_lru_eviction() -> None:
    rl, _ = limiter(max_keys=50)
    for i in range(5_000):  # a flood of distinct subjects
        rl.check(("user", i), LIMIT)
    assert len(rl) == 50


def test_recently_used_keys_survive_eviction() -> None:
    rl, _ = limiter(max_keys=3)
    for _ in range(3):
        rl.check("hot", LIMIT)
    assert not rl.check("hot", LIMIT).allowed
    for i in range(2):
        rl.check(f"cold{i}", LIMIT)
        rl.check("hot", LIMIT)  # keep touching it
    assert not rl.check("hot", LIMIT).allowed  # bucket was not evicted and reset


async def test_concurrent_callers_cannot_exceed_the_burst() -> None:
    rl, _ = limiter()

    async def call() -> bool:
        await asyncio.sleep(0)
        return rl.check("k", LIMIT).allowed

    results = await asyncio.gather(*[call() for _ in range(50)])
    assert sum(results) == 3
