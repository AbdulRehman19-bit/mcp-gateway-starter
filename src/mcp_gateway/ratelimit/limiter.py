"""Token-bucket rate limiting (in-memory, single process).

Why: a compromised or runaway client must not be able to hammer the database, the approval
queue, an upstream API, or the audit table. Each (subject, tool) pair gets its own bucket, so
one noisy user cannot starve another.

Memory is bounded: at most `max_keys` buckets are kept (least recently used evicted), so a
flood of distinct keys cannot grow it without limit. Eviction only ever resets a bucket to
full for the evicted key, which requires that many distinct authenticated subjects.

State lives in this process. With several gateway replicas each enforces its own limits; a
shared store (Redis) is out of scope for v1.
"""

import math
import time
from collections import OrderedDict
from collections.abc import Callable, Hashable
from dataclasses import dataclass


@dataclass(frozen=True)
class Limit:
    per_minute: int  # sustained refill rate
    burst: int  # bucket capacity: how many calls may happen back to back


@dataclass(frozen=True)
class Decision:
    allowed: bool
    retry_after: float = 0.0  # seconds until one more call would be allowed

    @property
    def retry_after_seconds(self) -> int:
        return max(1, math.ceil(self.retry_after))


class RateLimiter:
    def __init__(
        self, *, clock: Callable[[], float] = time.monotonic, max_keys: int = 10_000
    ) -> None:
        self._clock = clock
        self._max_keys = max_keys
        # key -> (tokens, last_refill_time)
        self._buckets: OrderedDict[Hashable, tuple[float, float]] = OrderedDict()

    def check(self, key: Hashable, limit: Limit) -> Decision:
        """Take one token if available. No awaits in here, so it is atomic on the event loop."""
        now = self._clock()
        rate = limit.per_minute / 60.0
        tokens, last = self._buckets.get(key, (float(limit.burst), now))
        tokens = min(float(limit.burst), tokens + max(0.0, now - last) * rate)
        if tokens >= 1.0:
            self._store(key, tokens - 1.0, now)
            return Decision(True)
        self._store(key, tokens, now)
        return Decision(False, retry_after=(1.0 - tokens) / rate)

    def _store(self, key: Hashable, tokens: float, now: float) -> None:
        self._buckets[key] = (tokens, now)
        self._buckets.move_to_end(key)
        while len(self._buckets) > self._max_keys:
            self._buckets.popitem(last=False)

    def __len__(self) -> int:
        return len(self._buckets)
