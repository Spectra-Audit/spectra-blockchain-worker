"""Cache manager for holder API data with TTL support.

This module provides a simple in-memory cache with time-based expiration
for caching holder data to reduce redundant API calls.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

LOGGER = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """A cache entry with value and expiration time."""

    value: Any
    expires_at: float
    created_at: float = field(default_factory=time.time)

    def is_expired(self) -> bool:
        """Check if this cache entry has expired."""
        return time.time() > self.expires_at

    def age_seconds(self) -> float:
        """Get the age of this cache entry in seconds."""
        return time.time() - self.created_at


class CacheManager:
    """Thread-safe cache manager with TTL support.

    Example:
        cache = CacheManager(default_ttl=3600)  # 1 hour default

        # Set a value with default TTL
        cache.set("my_key", {"data": "value"})

        # Set a value with custom TTL
        cache.set("my_key", {"data": "value"}, ttl=600)  # 10 minutes

        # Get a value (returns None if expired or not found)
        value = cache.get("my_key")

        # Check if a key exists and is not expired
        if cache.has("my_key"):
            print("Key exists and is fresh")

        # Clear all cache
        cache.clear()

        # Clear expired entries only
        cache.cleanup()
    """

    def __init__(
        self,
        default_ttl: float = 3600.0,  # 1 hour default
        max_size: int = 1000,  # Maximum number of entries
    ) -> None:
        """Initialize the cache manager.

        Args:
            default_ttl: Default time-to-live in seconds (default: 1 hour)
            max_size: Maximum number of cache entries (default: 1000)
        """
        self.default_ttl = default_ttl
        self.max_size = max_size
        self._cache: Dict[str, CacheEntry] = {}
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """Set a value in the cache.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds (uses default_ttl if None)
        """
        with self._lock:
            # Enforce max size by removing oldest entries if needed
            if len(self._cache) >= self.max_size and key not in self._cache:
                self._evict_oldest()

            ttl = ttl if ttl is not None else self.default_ttl
            self._cache[key] = CacheEntry(
                value=value,
                expires_at=time.time() + ttl
            )
            LOGGER.debug(f"Cache set: {key} (TTL: {ttl}s)")

    def get(self, key: str) -> Optional[Any]:
        """Get a value from the cache.

        Returns None if the key doesn't exist or has expired.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        with self._lock:
            entry = self._cache.get(key)

            if entry is None:
                self._misses += 1
                return None

            if entry.is_expired():
                # Remove expired entry
                del self._cache[key]
                self._misses += 1
                LOGGER.debug(f"Cache miss (expired): {key}")
                return None

            self._hits += 1
            LOGGER.debug(f"Cache hit: {key} (age: {entry.age_seconds():.1f}s)")
            return entry.value

    def has(self, key: str) -> bool:
        """Check if a key exists in the cache and is not expired.

        Args:
            key: Cache key

        Returns:
            True if key exists and is not expired
        """
        with self._lock:
            entry = self._cache.get(key)
            return entry is not None and not entry.is_expired()

    def delete(self, key: str) -> bool:
        """Delete a key from the cache.

        Args:
            key: Cache key

        Returns:
            True if key was deleted, False if it didn't exist
        """
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                LOGGER.debug(f"Cache deleted: {key}")
                return True
            return False

    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            LOGGER.info(f"Cache cleared: {count} entries removed")

    def cleanup(self) -> int:
        """Remove all expired entries from the cache.

        Returns:
            Number of entries removed
        """
        with self._lock:
            expired_keys = [
                key for key, entry in self._cache.items()
                if entry.is_expired()
            ]

            for key in expired_keys:
                del self._cache[key]

            if expired_keys:
                LOGGER.info(f"Cache cleanup: {len(expired_keys)} expired entries removed")

            return len(expired_keys)

    def _evict_oldest(self) -> None:
        """Evict the oldest cache entry to make room."""
        if not self._cache:
            return

        # Find the oldest entry
        oldest_key = min(
            self._cache.keys(),
            key=lambda k: self._cache[k].created_at
        )

        del self._cache[oldest_key]
        LOGGER.debug(f"Cache evicted (oldest): {oldest_key}")

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics.

        Returns:
            Dictionary with cache stats including size, hits, misses, hit rate
        """
        with self._lock:
            total = self._hits + self._misses
            hit_rate = (self._hits / total * 100) if total > 0 else 0

            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": f"{hit_rate:.1f}%",
                "default_ttl": self.default_ttl,
            }

    def __len__(self) -> int:
        """Get the number of entries in the cache."""
        with self._lock:
            return len(self._cache)

    def __contains__(self, key: str) -> bool:
        """Check if a key exists in the cache (using 'in' operator)."""
        return self.has(key)


class HolderDataCache(CacheManager):
    """Specialized cache for holder API data.

    Uses composite keys for caching holder data:
    - "holder_count:{token_address}:{chain_id}"
    - "top_holders:{token_address}:{chain_id}:{limit}"

    Example:
        cache = HolderDataCache(default_ttl=3600)

        # Cache holder count
        cache.set_holder_count("0x...", 1, 1000)

        # Get holder count
        count = cache.get_holder_count("0x...", 1)

        # Cache top holders
        cache.set_top_holders("0x...", 1, holders, limit=100)

        # Get top holders
        holders = cache.get_top_holders("0x...", 1, limit=100)
    """

    def _holder_count_key(self, token_address: str, chain_id: int) -> str:
        """Generate cache key for holder count."""
        return f"holder_count:{token_address.lower()}:{chain_id}"

    def _top_holders_key(self, token_address: str, chain_id: int, limit: int) -> str:
        """Generate cache key for top holders."""
        return f"top_holders:{token_address.lower()}:{chain_id}:{limit}"

    def set_holder_count(
        self,
        token_address: str,
        chain_id: int,
        count: int,
        ttl: Optional[float] = None,
    ) -> None:
        """Cache holder count for a token.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            count: Holder count to cache
            ttl: Time-to-live in seconds (uses default_ttl if None)
        """
        key = self._holder_count_key(token_address, chain_id)
        self.set(key, count, ttl=ttl)
        LOGGER.debug(f"Cached holder count: {key} = {count}")

    def get_holder_count(
        self,
        token_address: str,
        chain_id: int,
    ) -> Optional[int]:
        """Get cached holder count for a token.

        Args:
            token_address: Token contract address
            chain_id: Chain ID

        Returns:
            Cached holder count or None if not found/expired
        """
        key = self._holder_count_key(token_address, chain_id)
        return self.get(key)

    def set_top_holders(
        self,
        token_address: str,
        chain_id: int,
        holders: list,
        limit: int = 100,
        ttl: Optional[float] = None,
    ) -> None:
        """Cache top holders for a token.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            holders: List of holders to cache
            limit: Limit used for fetching holders
            ttl: Time-to-live in seconds (uses default_ttl if None)
        """
        key = self._top_holders_key(token_address, chain_id, limit)
        self.set(key, holders, ttl=ttl)
        LOGGER.debug(f"Cached top holders: {key} (count: {len(holders)})")

    def get_top_holders(
        self,
        token_address: str,
        chain_id: int,
        limit: int = 100,
    ) -> Optional[list]:
        """Get cached top holders for a token.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            limit: Limit used for fetching holders

        Returns:
            Cached list of holders or None if not found/expired
        """
        key = self._top_holders_key(token_address, chain_id, limit)
        return self.get(key)
