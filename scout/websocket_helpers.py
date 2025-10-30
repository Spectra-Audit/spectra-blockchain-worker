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
    visited: set[int] = set()

    def _wrap_queue(message_queue: Any) -> Optional[MessageGetter]:
        get = getattr(message_queue, "get", None)
        if callable(get):
            return lambda timeout: _call_with_optional_timeout(get, timeout)

        get_nowait = getattr(message_queue, "get_nowait", None)
        if callable(get_nowait):
            return lambda timeout: get_nowait()

        return None

    def _wrap_get_message(get_message: Callable[..., Any]) -> MessageGetter:
        return lambda timeout: _call_with_optional_timeout(get_message, timeout)

    def _search(obj: Any, allow_iterator: bool = False) -> Optional[MessageGetter]:
        if obj is None:
            return None

        obj_id = id(obj)
        if obj_id in visited:
            return None
        visited.add(obj_id)

        if isinstance(obj, (str, bytes, bytearray)):
            return None

        get_message = getattr(obj, "get_message", None)
        if callable(get_message):
            return _wrap_get_message(get_message)

        queue_getter = _wrap_queue(obj)
        if queue_getter is not None:
            return queue_getter

        if isinstance(obj, dict):
            for value in obj.values():
                getter = _search(value)
                if getter is not None:
                    return getter

        if isinstance(obj, (list, tuple, set, frozenset)):
            for value in obj:
                getter = _search(value)
                if getter is not None:
                    return getter

        if allow_iterator:
            iterator = getattr(obj, "__iter__", None)
            if callable(iterator):
                iterator_obj = iterator()
                return lambda timeout: next(iterator_obj)

        attribute_names: set[str] = set()
        try:
            attribute_names.update(vars(obj).keys())
        except TypeError:
            pass

        for attr_name in getattr(obj, "__slots__", ()):  # type: ignore[attr-defined]
            if isinstance(attr_name, str):
                attribute_names.add(attr_name)

        if not attribute_names:
            attribute_names.update(
                name
                for name in dir(obj)
                if not name.startswith("__") and not name.endswith("__")
            )

        for attr_name in attribute_names:
            try:
                nested = getattr(obj, attr_name)
            except AttributeError:
                continue
            except Exception:
                continue

            if inspect.ismethod(nested) or inspect.isfunction(nested):
                continue

            getter = _search(nested)
            if getter is not None:
                return getter

        return None

    getter = _search(provider, allow_iterator=True)
    if getter is not None:
        return getter

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
