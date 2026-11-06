"""Sliding-window rate limits per principal and tool. In-process, so one worker only."""

import time
from collections import defaultdict, deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass

_WINDOW_SECONDS = 60.0


@dataclass(frozen=True)
class RateLimitHit:
    rule_id: str
    retry_after_seconds: int


class RateLimiter:
    def __init__(
        self,
        per_minute: Mapping[str, int],
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._per_minute = per_minute
        self._clock = clock
        self._calls: defaultdict[tuple[str, str], deque[float]] = defaultdict(deque)

    def check(self, principal_id: str, tool: str) -> RateLimitHit | None:
        """Record a call if it is within the limit; otherwise return the limit it hit."""
        key = tool if tool in self._per_minute else "default"
        limit = self._per_minute[key]
        now = self._clock()
        calls = self._calls[(principal_id, tool)]
        while calls and now - calls[0] >= _WINDOW_SECONDS:
            calls.popleft()
        if len(calls) >= limit:
            wait = _WINDOW_SECONDS - (now - calls[0])
            return RateLimitHit(f"rate_limits.{key}", max(1, int(wait) + 1))
        calls.append(now)
        return None
