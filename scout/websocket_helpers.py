"""Utilities for consuming websocket providers using the async Web3 client."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import queue
import threading
from typing import Any, AsyncIterator, Callable, Iterable, Optional

try:  # pragma: no cover - optional dependency
    from web3 import AsyncWeb3 as _AsyncWeb3
    from web3.providers.async_rpc import AsyncWebsocketProvider as _AsyncWebsocketProvider
except Exception:  # pragma: no cover - gracefully handle missing web3
    _AsyncWeb3 = None  # type: ignore[assignment]
    _AsyncWebsocketProvider = None  # type: ignore[assignment]


MessageCallback = Optional[Callable[[], None]]


class _CompositeEvent:
    """Combine multiple threading events into a single facade."""

    def __init__(self, *events: threading.Event) -> None:
        self._events = events

    def is_set(self) -> bool:
        return any(event.is_set() for event in self._events)


async def _await_if_awaitable(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


async def _unsubscribe_from_subscription(web3: Any, subscription: Any) -> None:
    """Attempt to unsubscribe from *subscription* using the available API."""

    unsubscribe = getattr(subscription, "unsubscribe", None)
    if callable(unsubscribe):
        await _await_if_awaitable(unsubscribe())
        return

    subscription_id = getattr(subscription, "subscription_id", None) or getattr(
        subscription, "filter_id", None
    )
    if subscription_id is not None:
        unsubscribe_fn = getattr(web3.eth, "unsubscribe", None)
        if callable(unsubscribe_fn):
            await _await_if_awaitable(unsubscribe_fn(subscription_id))


@contextlib.asynccontextmanager
async def _managed_subscription(web3: Any, filter_params: Optional[dict[str, Any]]) -> AsyncIterator[Any]:
    """Create and tear down a websocket log subscription."""

    if filter_params is None:
        filter_params = {}

    subscription_resource = web3.eth.subscribe("logs", filter_params)
    subscription = await _await_if_awaitable(subscription_resource)

    if hasattr(subscription, "__aenter__") and hasattr(subscription, "__aexit__"):
        async with subscription as iterator:
            yield iterator
            return

    try:
        yield subscription
    finally:
        await _unsubscribe_from_subscription(web3, subscription)


async def async_iter_websocket_messages(
    provider: Any,
    stop_event: Any,
    *,
    subscription_params: Optional[dict[str, Any]] = None,
    on_connect: MessageCallback = None,
    on_disconnect: MessageCallback = None,
) -> AsyncIterator[Any]:
    """Yield websocket payloads using :class:`web3.AsyncWeb3` subscriptions."""

    if stop_event.is_set():
        return

    if _AsyncWeb3 is None or _AsyncWebsocketProvider is None:
        raise RuntimeError("web3 async websocket provider is not available")

    endpoint_uri = getattr(provider, "endpoint_uri", None) or getattr(
        provider, "url", None
    )
    if not endpoint_uri:
        raise RuntimeError("Websocket provider is missing an endpoint URI")

    websocket_kwargs = getattr(provider, "websocket_kwargs", None)
    async_provider = _AsyncWebsocketProvider(endpoint_uri, websocket_kwargs=websocket_kwargs)
    web3 = _AsyncWeb3(async_provider)

    try:
        async with _managed_subscription(web3, subscription_params) as subscription:
            if on_connect is not None:
                on_connect()
            async for payload in subscription:
                if stop_event.is_set():
                    break
                yield payload
    finally:
        if on_disconnect is not None:
            on_disconnect()
        disconnect = getattr(async_provider, "disconnect", None)
        if callable(disconnect):
            await _await_if_awaitable(disconnect())


class _AsyncErrorWrapper:
    def __init__(self, exc: BaseException) -> None:
        self.exc = exc


_SENTINEL = object()


def iter_websocket_messages(
    provider: Any,
    stop_event: Any,
    poll_interval: float = 0.5,
    *,
    subscription_params: Optional[dict[str, Any]] = None,
    on_connect: MessageCallback = None,
    on_disconnect: MessageCallback = None,
) -> Iterable[Any]:
    """Yield websocket payloads via a synchronous iterator."""

    bridge_stop = threading.Event()
    composite_event = _CompositeEvent(stop_event, bridge_stop)
    message_queue: "queue.Queue[Any]" = queue.Queue()

    def _runner() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def _consume() -> None:
            try:
                async for payload in async_iter_websocket_messages(
                    provider,
                    composite_event,
                    subscription_params=subscription_params,
                    on_connect=on_connect,
                    on_disconnect=on_disconnect,
                ):
                    message_queue.put(payload)
            except Exception as exc:  # noqa: BLE001 - propagate to caller
                message_queue.put(_AsyncErrorWrapper(exc))
            finally:
                message_queue.put(_SENTINEL)

        try:
            loop.run_until_complete(_consume())
        finally:
            with contextlib.suppress(Exception):
                loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()

    thread = threading.Thread(target=_runner, name="WebsocketMessageBridge", daemon=True)
    thread.start()

    try:
        while True:
            if stop_event.is_set() and message_queue.empty() and not thread.is_alive():
                break
            try:
                item = message_queue.get(timeout=poll_interval)
            except queue.Empty:
                if stop_event.is_set():
                    continue
                if not thread.is_alive():
                    break
                continue
            if item is _SENTINEL:
                break
            if isinstance(item, _AsyncErrorWrapper):
                raise item.exc
            yield item
    finally:
        bridge_stop.set()
        thread.join(timeout=1)


__all__ = ["async_iter_websocket_messages", "iter_websocket_messages"]
