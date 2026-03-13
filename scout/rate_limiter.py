"""Rate limiter for API requests.

This module provides rate limiting functionality to ensure we respect
API rate limits, especially for providers like Ethplorer (2 req/sec).
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from threading import Lock
from typing import Optional

LOGGER = logging.getLogger(__name__)


@dataclass
class RateLimit:
    """Rate limit configuration."""

    requests_per_second: float
    requests_per_minute: Optional[float] = None
    burst: int = 5  # Allow burst of requests up to this limit


class TokenBucket:
    """Token bucket rate limiter implementation.

    Allows bursts up to a maximum capacity, then refills at a constant rate.
    """

    def __init__(self, rate: float, capacity: int = 5):
        """Initialize token bucket.

        Args:
            rate: Tokens added per second
            capacity: Maximum number of tokens (burst size)
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = float(capacity)
        self.last_update = time.time()
        self._lock = Lock()

    def _refill(self) -> None:
        """Refill tokens based on time passed."""
        now = time.time()
        elapsed = now - self.last_update

        if elapsed > 0:
            # Add tokens based on elapsed time
            self.tokens = min(
                self.capacity,
                self.tokens + elapsed * self.rate
            )
            self.last_update = now

    def acquire(self, tokens: float = 1.0) -> bool:
        """Try to acquire tokens from the bucket.

        Args:
            tokens: Number of tokens to acquire

        Returns:
            True if tokens were acquired, False if not enough tokens available
        """
        with self._lock:
            self._refill()

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True

            return False

    def wait(self, tokens: float = 1.0) -> None:
        """Wait until tokens are available.

        Args:
            tokens: Number of tokens needed
        """
        while not self.acquire(tokens):
            # Calculate wait time needed
            with self._lock:
                self._refill()
                needed = tokens - self.tokens
                wait_time = needed / self.rate if self.rate > 0 else 0.1

            LOGGER.debug(f"Rate limit: waiting {wait_time:.2f}s for {tokens} tokens")
            time.sleep(wait_time)


class SlidingWindowRateLimiter:
    """Sliding window rate limiter.

    Tracks requests within a time window and enforces limits.
    """

    def __init__(self, max_requests: int, window_seconds: float = 60.0):
        """Initialize sliding window rate limiter.

        Args:
            max_requests: Maximum number of requests allowed in window
            window_seconds: Time window in seconds (default: 60 seconds)
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: deque = deque()
        self._lock = Lock()

    def acquire(self) -> bool:
        """Try to acquire permission to make a request.

        Returns:
            True if request is allowed, False if rate limit exceeded
        """
        with self._lock:
            now = time.time()

            # Remove old requests outside the window
            while self._requests and self._requests[0] < now - self.window_seconds:
                self._requests.popleft()

            # Check if under limit
            if len(self._requests) < self.max_requests:
                self._requests.append(now)
                return True

            return False

    def wait(self) -> None:
        """Wait until a request is allowed."""
        while not self.acquire():
            # Calculate wait time until oldest request expires
            with self._lock:
                if self._requests:
                    oldest = self._requests[0]
                    wait_time = (oldest + self.window_seconds) - time.time()
                    if wait_time > 0:
                        LOGGER.debug(f"Rate limit: waiting {wait_time:.2f}s")
                        time.sleep(wait_time)


class RateLimiter:
    """Combined rate limiter with per-second and per-minute limits.

    Example:
        # Ethplorer free tier: 2 req/sec, ~120 req/min
        limiter = RateLimiter(requests_per_second=2, requests_per_minute=120)

        # Use in code
        limiter.acquire_or_wait("Ethplorer")
        # Make API request...
    """

    def __init__(
        self,
        requests_per_second: float = 2.0,
        requests_per_minute: Optional[float] = None,
        burst: int = 5,
    ):
        """Initialize rate limiter.

        Args:
            requests_per_second: Maximum requests per second
            requests_per_minute: Maximum requests per minute (optional)
            burst: Maximum burst size (default: 5)
        """
        self.requests_per_second = requests_per_second
        self.requests_per_minute = requests_per_minute

        # Token bucket for per-second limiting
        self._token_bucket = TokenBucket(
            rate=requests_per_second,
            capacity=burst
        )

        # Sliding window for per-minute limiting (if specified)
        self._minute_limiter: Optional[SlidingWindowRateLimiter] = None
        if requests_per_minute is not None:
            self._minute_limiter = SlidingWindowRateLimiter(
                max_requests=int(requests_per_minute),
                window_seconds=60.0
            )

    def acquire(self) -> bool:
        """Try to acquire permission to make a request.

        Returns:
            True if request is allowed, False if rate limit exceeded
        """
        # Check per-minute limit first
        if self._minute_limiter and not self._minute_limiter.acquire():
            return False

        # Check per-second limit with token bucket
        return self._token_bucket.acquire()

    def wait(self) -> None:
        """Wait until a request is allowed."""
        # Check per-minute limit
        if self._minute_limiter:
            self._minute_limiter.wait()

        # Check per-second limit
        self._token_bucket.wait()

    def acquire_or_wait(self, provider_name: str = "API") -> None:
        """Acquire permission, waiting if necessary.

        Args:
            provider_name: Name of the provider (for logging)
        """
        if not self.acquire():
            LOGGER.debug(f"Rate limit: waiting for {provider_name}")
            self.wait()
            LOGGER.debug(f"Rate limit: proceeding for {provider_name}")


class AsyncRateLimiter:
    """Async version of rate limiter for async/await code.

    Example:
        limiter = AsyncRateLimiter(requests_per_second=2)

        async def fetch_data():
            await limiter.acquire_or_wait("Ethplorer")
            # Make async API request...
    """

    def __init__(
        self,
        requests_per_second: float = 2.0,
        requests_per_minute: Optional[float] = None,
        burst: int = 5,
    ):
        """Initialize async rate limiter.

        Args:
            requests_per_second: Maximum requests per second
            requests_per_minute: Maximum requests per minute (optional)
            burst: Maximum burst size (default: 5)
        """
        self.requests_per_second = requests_per_second
        self.requests_per_minute = requests_per_minute

        # Use the sync rate limiter internally
        self._limiter = RateLimiter(
            requests_per_second=requests_per_second,
            requests_per_minute=requests_per_minute,
            burst=burst,
        )

    async def acquire(self) -> bool:
        """Try to acquire permission to make a request.

        Returns:
            True if request is allowed, False if rate limit exceeded
        """
        return self._limiter.acquire()

    async def wait(self) -> None:
        """Wait until a request is allowed (async)."""
        # Check if we can acquire immediately
        if self._limiter.acquire():
            return

        # Calculate wait time needed
        # Token bucket needs to refill enough tokens
        # Wait time = (needed_tokens - current_tokens) / rate
        needed = 1.0 - self._limiter._token_bucket.tokens
        wait_time = max(0, needed / self._limiter._token_bucket.rate)

        # Check per-minute limit as well
        if self._limiter._minute_limiter:
            now = time.time()
            # Find oldest request
            if self._limiter._minute_limiter._requests:
                oldest = self._limiter._minute_limiter._requests[0]
                minute_wait = (oldest + self._limiter._minute_limiter.window_seconds) - now
                wait_time = max(wait_time, minute_wait)

        if wait_time > 0:
            LOGGER.debug(f"Rate limiter: waiting {wait_time:.2f}s")
            await asyncio.sleep(wait_time)

        # Try to acquire after waiting
        while not self._limiter.acquire():
            await asyncio.sleep(0.1)

    async def acquire_or_wait(self, provider_name: str = "API") -> None:
        """Acquire permission, waiting if necessary (async).

        Args:
            provider_name: Name of the provider (for logging)
        """
        if not await self.acquire():
            LOGGER.debug(f"Rate limit: waiting for {provider_name}")
            await self.wait()
            LOGGER.debug(f"Rate limit: proceeding for {provider_name}")


# Provider-specific rate limit configurations
PROVIDER_RATE_LIMITS = {
    "Ethplorer": {
        "free": RateLimit(requests_per_second=2, requests_per_minute=120, burst=2),
        "paid": RateLimit(requests_per_second=10, requests_per_minute=600, burst=10),
    },
    "NodeReal": {
        "free": RateLimit(requests_per_second=5, requests_per_minute=300, burst=10),
        "paid": RateLimit(requests_per_second=10, requests_per_minute=600, burst=20),
    },
    "Moralis": {
        "free": RateLimit(requests_per_second=3, requests_per_minute=180, burst=5),
        "paid": RateLimit(requests_per_second=10, requests_per_minute=600, burst=20),
    },
    "CoinGecko": {
        "free": RateLimit(requests_per_second=5, requests_per_minute=300, burst=10),
        "paid": RateLimit(requests_per_second=10, requests_per_minute=600, burst=20),
    },
}


def get_rate_limiter(
    provider_name: str,
    is_free_tier: bool = True,
) -> AsyncRateLimiter:
    """Get rate limiter for a specific provider.

    Args:
        provider_name: Name of the provider (Ethplorer, NodeReal, etc.)
        is_free_tier: Whether using free tier (default: True)

    Returns:
        AsyncRateLimiter configured for the provider
    """
    if provider_name not in PROVIDER_RATE_LIMITS:
        # Default rate limits for unknown providers
        LOGGER.warning(f"No rate limit configured for {provider_name}, using defaults")
        return AsyncRateLimiter(requests_per_second=5, burst=10)

    tier = "free" if is_free_tier else "paid"
    config = PROVIDER_RATE_LIMITS[provider_name][tier]

    return AsyncRateLimiter(
        requests_per_second=config.requests_per_second,
        requests_per_minute=config.requests_per_minute,
        burst=config.burst,
    )
