"""Utilities for consuming websocket providers across web3 releases."""

from __future__ import annotations

import inspect
import queue
from typing import Any, Callable, Iterable, Iterator, Optional

try:  # pragma: no cover - optional dependency
    from web3.providers import persistent as _persistent_module
except Exception:  # pragma: no cover - gracefully handle missing web3
    _persistent_module = None  # type: ignore[assignment]


MessageGetter = Callable[[float], Any]


def _call_with_optional_timeout(func: Callable[..., Any], timeout: float) -> Any:
    """Invoke *func* using ``timeout`` when supported."""

    try:
        return func(timeout=timeout)
    except TypeError:
        try:
            return func(timeout)
        except TypeError:
            return func()


def _iter_from_ws_object(ws: Any, stop_event: Any) -> Iterator[Any]:
    while not stop_event.is_set():
        yield ws.recv()


def _resolve_message_getter(provider: Any) -> Optional[MessageGetter]:
    get_message = getattr(provider, "get_message", None)
    if callable(get_message):
        return lambda timeout: _call_with_optional_timeout(get_message, timeout)

    message_queue = getattr(provider, "ws_messages", None)
    if message_queue is None:
        message_queue = getattr(provider, "message_queue", None)
    if message_queue is not None and hasattr(message_queue, "get"):
        return lambda timeout: message_queue.get(timeout=timeout)

    iterator = getattr(provider, "__iter__", None)
    if callable(iterator):
        iterator_obj = iterator()
        return lambda timeout: next(iterator_obj)

    return None


def _is_persistent_provider(provider: Any) -> bool:
    provider_cls = provider.__class__
    if _persistent_module is None:
        return provider_cls.__module__.startswith("web3.providers.persistent")

    for name in ("WebSocketProvider", "PersistentWebSocketProvider"):
        candidate = getattr(_persistent_module, name, None)
        if inspect.isclass(candidate) and issubclass(provider_cls, candidate):
            return True

    return provider_cls.__module__.startswith("web3.providers.persistent")


def iter_websocket_messages(
    provider: Any,
    stop_event: Any,
    poll_interval: float = 0.5,
) -> Iterable[Any]:
    """Yield websocket payloads for both legacy and persistent providers."""

    ws = getattr(provider, "ws", None)
    if ws is not None and hasattr(ws, "recv"):
        yield from _iter_from_ws_object(ws, stop_event)
        return

    getter = _resolve_message_getter(provider)
    if getter is None and _is_persistent_provider(provider):
        getter = _resolve_message_getter(provider)

    if getter is None:
        raise RuntimeError("Websocket provider does not expose a supported message interface")

    while not stop_event.is_set():
        try:
            message = getter(poll_interval)
        except queue.Empty:
            continue
        except StopIteration:
            break
        if not message:
            continue
        yield message


__all__ = ["iter_websocket_messages"]
