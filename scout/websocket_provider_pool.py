"""Shared pool of WebSocket providers reused across scout instances."""

from __future__ import annotations

import contextlib
import inspect
import logging
import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Sequence, Tuple

from .async_runner import get_shared_async_runner

LOGGER = logging.getLogger(__name__)


Hook = Optional[Callable[[], Any]]


@dataclass
class _ProviderEntry:
    provider: Any
    cleanup_name: Optional[str]
    cleanup_hook: Hook
    handshake_hook: Hook
    lock: threading.Lock
    valid: bool = True


class ProviderSession:
    """Context manager yielding an exclusive handle to a pooled provider."""

    def __init__(self, pool: "WebSocketProviderPool", url: str, entry: _ProviderEntry) -> None:
        self._pool = pool
        self._url = url
        self._entry = entry
        self._invalidate_on_exit = False

    def __enter__(self) -> "ProviderSession":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[override]
        invalidate = self._invalidate_on_exit or exc_type is not None
        if invalidate:
            self._entry.valid = False
        self._entry.lock.release()
        if invalidate:
            self._pool._invalidate_entry(self._url, self._entry)

    @property
    def provider(self) -> Any:
        return self._entry.provider

    def perform_cleanup(self) -> None:
        performed_disconnect = False
        if self._entry.cleanup_hook is not None:
            self._pool._resolve_provider_response(self._entry.cleanup_hook())
            performed_disconnect = self._entry.cleanup_name == "disconnect"
        if not performed_disconnect:
            disconnect = getattr(self._entry.provider, "disconnect", None)
            if callable(disconnect):
                self._pool._resolve_provider_response(disconnect())
        ws = getattr(self._entry.provider, "ws", None)
        close = getattr(ws, "close", None)
        if callable(close):
            close()

    def invalidate(self) -> None:
        """Mark the underlying provider as defunct once the session ends."""

        self._invalidate_on_exit = True
        self._entry.valid = False


class WebSocketProviderHandle:
    """Lightweight handle bound to a websocket RPC endpoint."""

    def __init__(self, pool: "WebSocketProviderPool", url: str) -> None:
        self._pool = pool
        self._url = url
        self._closed = False

    @property
    def url(self) -> str:
        return self._url

    def checkout(self) -> ProviderSession:
        if self._closed:
            raise RuntimeError("Cannot checkout from a closed provider handle")
        return self._pool._checkout(self._url)

    def close(self) -> None:
        if self._closed:
            return
        self._pool._detach(self._url)
        self._closed = True


class WebSocketProviderPool:
    """Pool that caches a single WebSocket provider per RPC URL."""

    def __init__(
        self,
        provider_class: Optional[type] = None,
        provider_resolver: Optional[Callable[[], Optional[type]]] = None,
    ) -> None:
        self._provider_class = provider_class
        self._provider_resolver = provider_resolver
        self._pool_lock = threading.Lock()
        self._entries: Dict[str, _ProviderEntry] = {}
        self._ref_counts: Dict[str, int] = {}

    def get_provider_class(self) -> Optional[type]:
        if self._provider_class is None and self._provider_resolver is not None:
            self._provider_class = self._provider_resolver()
        return self._provider_class

    def attach(self, url: str) -> WebSocketProviderHandle:
        if not url:
            raise ValueError("WebSocket URL must be non-empty")
        if self.get_provider_class() is None:
            raise RuntimeError("Websocket provider class unavailable")
        with self._pool_lock:
            self._ref_counts[url] = self._ref_counts.get(url, 0) + 1
        return WebSocketProviderHandle(self, url)

    def set_provider_class(self, provider_class: Optional[type]) -> None:
        with self._pool_lock:
            if provider_class is self._provider_class:
                self._provider_class = provider_class
                return
            old_entries = list(self._entries.values())
            self._entries.clear()
            self._provider_class = provider_class
        for entry in old_entries:
            self._teardown_entry(entry)

    def _checkout(self, url: str) -> ProviderSession:
        while True:
            entry = self._get_or_create_entry(url)
            entry.lock.acquire()
            if not entry.valid:
                entry.lock.release()
                self._invalidate_entry(url, entry)
                continue
            try:
                if entry.handshake_hook is not None:
                    self._resolve_provider_response(entry.handshake_hook())
                return ProviderSession(self, url, entry)
            except Exception:
                entry.lock.release()
                self._invalidate_entry(url, entry)
                raise

    def _detach(self, url: str) -> None:
        entry: Optional[_ProviderEntry] = None
        with self._pool_lock:
            count = self._ref_counts.get(url, 0)
            if count <= 1:
                self._ref_counts.pop(url, None)
                entry = self._entries.pop(url, None)
            else:
                self._ref_counts[url] = count - 1
        if entry is not None:
            LOGGER.debug("Detaching websocket provider", extra={"url": url})
            self._teardown_entry(entry)

    def _get_or_create_entry(self, url: str) -> _ProviderEntry:
        with self._pool_lock:
            entry = self._entries.get(url)
            if entry is None or not entry.valid:
                entry = self._create_entry(url)
                self._entries[url] = entry
            return entry

    def _create_entry(self, url: str) -> _ProviderEntry:
        provider_class = self.get_provider_class()
        if provider_class is None:
            raise RuntimeError("Websocket provider class unavailable")

        provider_kwargs: Dict[str, Any] = {}
        signature_target = None

        init = getattr(provider_class, "__init__", None)
        if init is not None and (inspect.isfunction(init) or inspect.ismethod(init)):
            signature_target = init
        elif inspect.isfunction(provider_class) or inspect.ismethod(provider_class):
            signature_target = provider_class

        if signature_target is not None:
            with contextlib.suppress(TypeError, ValueError):
                signature = inspect.signature(signature_target)
                if "websocket_timeout" in signature.parameters:
                    provider_kwargs["websocket_timeout"] = 30

        provider = provider_class(url, **provider_kwargs)
        cleanup_name: Optional[str] = None
        cleanup_hook: Hook = None

        def _select_hook(names: Sequence[str]) -> Tuple[Optional[str], Hook]:
            for hook_name in names:
                hook = getattr(provider, hook_name, None)
                if callable(hook):
                    return hook_name, hook
            return None, None

        handshake_candidates: Sequence[Tuple[str, Sequence[str]]] = (
            ("socket_connect", ("socket_disconnect", "disconnect", "close")),
            ("connect", ("disconnect", "close")),
            ("start", ("stop", "close", "disconnect")),
            ("open", ("close", "disconnect")),
        )

        handshake_hook: Hook = None

        for candidate_name, cleanup_candidates in handshake_candidates:
            hook = getattr(provider, candidate_name, None)
            if callable(hook):
                handshake_hook = hook
                cleanup_name, cleanup_hook = _select_hook(cleanup_candidates)
                break

        if handshake_hook is None:
            for attribute in dir(provider):
                if attribute.startswith("_"):
                    continue
                lowered = attribute.lower()
                if "connect" not in lowered or "disconnect" in lowered:
                    continue
                hook = getattr(provider, attribute, None)
                if callable(hook):
                    handshake_hook = hook
                    cleanup_name, cleanup_hook = _select_hook(("disconnect", "close", "stop", "socket_disconnect"))
                    break

        return _ProviderEntry(
            provider=provider,
            cleanup_name=cleanup_name,
            cleanup_hook=cleanup_hook,
            handshake_hook=handshake_hook,
            lock=threading.Lock(),
        )

    def _invalidate_entry(self, url: str, entry: _ProviderEntry) -> None:
        with self._pool_lock:
            current = self._entries.get(url)
            if current is not entry:
                return
            self._entries.pop(url, None)
        self._teardown_entry(entry)
        LOGGER.debug("Invalidated websocket provider", extra={"url": url})

    def _teardown_entry(self, entry: _ProviderEntry) -> None:
        with contextlib.suppress(Exception):
            entry.lock.acquire()
        try:
            performed_disconnect = False
            with contextlib.suppress(Exception):
                if entry.cleanup_hook is not None:
                    self._resolve_provider_response(entry.cleanup_hook())
                    performed_disconnect = entry.cleanup_name == "disconnect"
            with contextlib.suppress(Exception):
                if not performed_disconnect:
                    disconnect = getattr(entry.provider, "disconnect", None)
                    if callable(disconnect):
                        self._resolve_provider_response(disconnect())
            with contextlib.suppress(Exception):
                ws = getattr(entry.provider, "ws", None)
                close = getattr(ws, "close", None)
                if callable(close):
                    close()
        finally:
            with contextlib.suppress(Exception):
                entry.lock.release()

    @staticmethod
    def _resolve_provider_response(response: Any) -> Any:
        if inspect.isawaitable(response):
            return get_shared_async_runner().run(response)
        return response

