from repoward.ratelimit import RateLimiter


class Clock:
    now = 0.0

    def __call__(self) -> float:
        return self.now


def test_limit_applies_per_tool_and_principal() -> None:
    clock = Clock()
    limiter = RateLimiter({"default": 1, "special": 2}, clock)
    assert limiter.check("a", "special") is None
    assert limiter.check("a", "special") is None
    hit = limiter.check("a", "special")
    assert hit is not None
    assert hit.rule_id == "rate_limits.special"
    assert limiter.check("b", "special") is None
    assert limiter.check("a", "other") is None
    other = limiter.check("a", "other")
    assert other is not None
    assert other.rule_id == "rate_limits.default"


def test_window_slides() -> None:
    clock = Clock()
    limiter = RateLimiter({"default": 1}, clock)
    assert limiter.check("a", "t") is None
    clock.now = 59.0
    hit = limiter.check("a", "t")
    assert hit is not None
    assert hit.retry_after_seconds == 2
    clock.now = 60.0
    assert limiter.check("a", "t") is None


def test_refused_calls_do_not_extend_the_window() -> None:
    clock = Clock()
    limiter = RateLimiter({"default": 1}, clock)
    limiter.check("a", "t")
    clock.now = 30.0
    limiter.check("a", "t")
    clock.now = 60.0
    assert limiter.check("a", "t") is None
