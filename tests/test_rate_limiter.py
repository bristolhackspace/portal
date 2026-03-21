import pytest

from portal.systems.rate_limiter import RateLimiter

@pytest.fixture()
def rate_limiter(app_context):
    rl = RateLimiter(app_context)
    return rl

def test_make_rate_limiter(rate_limiter):
    pass