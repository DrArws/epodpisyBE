"""
Tests for rate limiter.
"""
import time
import pytest

from app.utils.rate_limiter import RateLimiter


class TestRateLimiter:
    """Tests for token bucket rate limiter."""

    def test_allows_within_limit(self):
        """Requests within limit are allowed."""
        limiter = RateLimiter(max_requests=5, window_seconds=60)

        for i in range(5):
            allowed, retry_after = limiter.is_allowed("test-key")
            assert allowed is True
            assert retry_after == 0

    def test_blocks_over_limit(self):
        """Requests over limit are blocked."""
        limiter = RateLimiter(max_requests=3, window_seconds=60)

        # Use up all tokens
        for _ in range(3):
            limiter.is_allowed("test-key")

        # Next request should be blocked
        allowed, retry_after = limiter.is_allowed("test-key")
        assert allowed is False
        assert retry_after > 0

    def test_different_keys_independent(self):
        """Different keys have independent limits."""
        limiter = RateLimiter(max_requests=2, window_seconds=60)

        # Use up key1
        limiter.is_allowed("key1")
        limiter.is_allowed("key1")

        # key2 should still be allowed
        allowed, _ = limiter.is_allowed("key2")
        assert allowed is True

    def test_refills_over_time(self):
        """Tokens refill over time."""
        limiter = RateLimiter(max_requests=1, window_seconds=1)

        # Use the token
        limiter.is_allowed("test-key")

        # Immediately blocked
        allowed1, _ = limiter.is_allowed("test-key")
        assert allowed1 is False

        # Wait for refill
        time.sleep(1.1)

        # Should be allowed again
        allowed2, _ = limiter.is_allowed("test-key")
        assert allowed2 is True

    def test_reset_clears_bucket(self):
        """Reset clears the bucket for a key."""
        limiter = RateLimiter(max_requests=2, window_seconds=60)

        # Use up tokens
        limiter.is_allowed("test-key")
        limiter.is_allowed("test-key")

        # Reset
        limiter.reset("test-key")

        # Should be allowed again
        allowed, _ = limiter.is_allowed("test-key")
        assert allowed is True

    def test_get_remaining(self):
        """Get remaining tokens."""
        limiter = RateLimiter(max_requests=5, window_seconds=60)

        assert limiter.get_remaining("test-key") == 5

        limiter.is_allowed("test-key")
        assert limiter.get_remaining("test-key") == 4

        limiter.is_allowed("test-key")
        limiter.is_allowed("test-key")
        assert limiter.get_remaining("test-key") == 2
