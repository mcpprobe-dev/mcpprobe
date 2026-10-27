"""A small asyncio token-bucket rate limiter.

The default scan budget is 5 requests per second. Every outbound request the
scanner makes (including well-known lookups and opt-out checks) passes through
one limiter so the cap is global, not per check.
"""

from __future__ import annotations

import asyncio
import time

DEFAULT_RATE = 5.0


class RateLimiter:
    """Token bucket: ``rate`` tokens per second, burst of ``burst`` tokens."""

    def __init__(self, rate: float = DEFAULT_RATE, burst: int | None = None) -> None:
        if rate <= 0:
            raise ValueError("rate must be positive")
        self.rate = float(rate)
        self.capacity = float(burst if burst is not None else max(1, int(rate)))
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()
        self.total_waits = 0.0
        self.requests = 0

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._updated
        self._updated = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)

    async def acquire(self) -> None:
        """Wait until a token is available, then consume it."""
        async with self._lock:
            self._refill()
            if self._tokens < 1.0:
                wait = (1.0 - self._tokens) / self.rate
                self.total_waits += wait
                await asyncio.sleep(wait)
                self._refill()
            self._tokens -= 1.0
            self.requests += 1
