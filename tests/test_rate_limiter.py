from datetime import timedelta
import pytest

from portal.systems.rate_limiter import RateLimiter, RateLimitError
from portal.extensions import db

def test_no_limit(rate_limiter: RateLimiter):
    limit = 10
    for i in range(limit):
        rate_limiter.rate_limit("limit_key", limit, timedelta(seconds=10))

def test_hit_limit(rate_limiter: RateLimiter):
    limit = 10
    for i in range(limit):
        rate_limiter.rate_limit("limit_key", limit, timedelta(seconds=10))
    with pytest.raises(RateLimitError):
        rate_limiter.rate_limit("limit_key", limit, timedelta(seconds=10))

def test_limit_expiry(rate_limiter: RateLimiter):
    # Expire in the past so the limiter should never limit
    rate_limiter.rate_limit("limit_key", 1, timedelta(seconds=-10))
    rate_limiter.rate_limit("limit_key", 1, timedelta(seconds=-10))

def test_multiple_keys(rate_limiter: RateLimiter):
    rate_limiter.rate_limit("key1", 1, timedelta(seconds=10))
    rate_limiter.rate_limit("key2", 1, timedelta(seconds=10))

    with pytest.raises(RateLimitError):
        rate_limiter.rate_limit("key1", 1, timedelta(seconds=10))

    with pytest.raises(RateLimitError):
        rate_limiter.rate_limit("key2", 1, timedelta(seconds=10))

def test_reset_rate_limit(rate_limiter: RateLimiter):
    rate_limiter.rate_limit("limit_key", 2, timedelta(seconds=10))
    rate_limiter.rate_limit("limit_key", 2, timedelta(seconds=10))

    rate_limiter.reset_rate_limit("limit_key")

    rate_limiter.rate_limit("limit_key", 2, timedelta(seconds=10))