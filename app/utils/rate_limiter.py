"""
In-memory token bucket rate limiter.
For production with multiple Cloud Run instances, consider Redis/Memorystore.
"""
import time
import threading
from collections import defaultdict
from typing import Dict, Tuple
from dataclasses import dataclass


@dataclass
class TokenBucket:
    """Token bucket for rate limiting."""
    tokens: float
    last_update: float
    max_tokens: int
    refill_rate: float  # tokens per second


class RateLimiter:
    """
    In-memory token bucket rate limiter.
    Thread-safe implementation for single-instance deployment.

    For multi-instance Cloud Run deployments, replace with Redis-based limiter.
    """

    def __init__(self, max_requests: int = 5, window_seconds: int = 300):
        """
        Initialize rate limiter.

        Args:
            max_requests: Maximum requests allowed in the time window
            window_seconds: Time window in seconds
        """
        self.max_tokens = max_requests
        self.refill_rate = max_requests / window_seconds
        self._buckets: Dict[str, TokenBucket] = {}
        self._lock = threading.Lock()
        self._cleanup_interval = 3600  # Cleanup old buckets every hour
        self._last_cleanup = time.time()

    def _get_bucket(self, key: str) -> TokenBucket:
        """Get or create a token bucket for the given key."""
        if key not in self._buckets:
            self._buckets[key] = TokenBucket(
                tokens=float(self.max_tokens),
                last_update=time.time(),
                max_tokens=self.max_tokens,
                refill_rate=self.refill_rate
            )
        return self._buckets[key]

    def _refill_bucket(self, bucket: TokenBucket) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - bucket.last_update
        bucket.tokens = min(
            bucket.max_tokens,
            bucket.tokens + elapsed * bucket.refill_rate
        )
        bucket.last_update = now

    def _cleanup_old_buckets(self) -> None:
        """Remove buckets that haven't been used for a while."""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return

        cutoff = now - self._cleanup_interval
        keys_to_remove = [
            key for key, bucket in self._buckets.items()
            if bucket.last_update < cutoff
        ]
        for key in keys_to_remove:
            del self._buckets[key]

        self._last_cleanup = now

    def is_allowed(self, key: str) -> Tuple[bool, int]:
        """
        Check if request is allowed for the given key.

        Args:
            key: Unique identifier (e.g., IP address, phone number)

        Returns:
            Tuple of (allowed: bool, retry_after_seconds: int)
        """
        with self._lock:
            self._cleanup_old_buckets()
            bucket = self._get_bucket(key)
            self._refill_bucket(bucket)

            if bucket.tokens >= 1:
                bucket.tokens -= 1
                return True, 0
            else:
                # Calculate time until next token is available
                retry_after = int((1 - bucket.tokens) / bucket.refill_rate) + 1
                return False, retry_after

    def get_remaining(self, key: str) -> int:
        """Get remaining tokens for the given key."""
        with self._lock:
            bucket = self._get_bucket(key)
            self._refill_bucket(bucket)
            return int(bucket.tokens)

    def reset(self, key: str) -> None:
        """Reset the bucket for a given key (e.g., after successful verification)."""
        with self._lock:
            if key in self._buckets:
                del self._buckets[key]


# Global rate limiter instances
otp_rate_limiter = RateLimiter(max_requests=5, window_seconds=300)  # 5 OTP requests per 5 minutes
verify_rate_limiter = RateLimiter(max_requests=10, window_seconds=60)  # 10 verify requests per minute per IP


def get_otp_rate_limiter() -> RateLimiter:
    """Get the OTP rate limiter instance."""
    return otp_rate_limiter


def get_verify_rate_limiter() -> RateLimiter:
    """Get the verification rate limiter instance."""
    return verify_rate_limiter
