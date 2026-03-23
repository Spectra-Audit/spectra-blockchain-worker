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
except Exception:  # pragma: no cover - gracefully handle missing web3
    _AsyncWeb3 = None  # type: ignore[assignment]

try:  # pragma: no cover - optional dependency
    from web3.providers.persistent.websocket import WebSocketProvider as _WebsocketProviderFactory
except Exception:  # pragma: no cover - gracefully handle missing implementations
    try:
        from web3.providers.websocket import WebsocketProviderV2 as _WebsocketProviderFactory
    except Exception:
        try:
            from web3.providers.websocket import WebSocketProvider as _WebsocketProviderFactory
        except Exception:
            try:
                from web3.providers.async_rpc import AsyncWebsocketProvider as _WebsocketProviderFactory
            except Exception:
                _WebsocketProviderFactory = None  # type: ignore[assignment]


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


def _normalize_subscription_id(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return "0x" + value.hex()
    hex_method = getattr(value, "hex", None)
    if callable(hex_method):
        try:
            return hex_method()
        except TypeError:
            pass
    return str(value)


def _payload_subscription_id(payload: Any) -> Optional[str]:
    if isinstance(payload, dict):
        if "subscription" in payload:
            return _normalize_subscription_id(payload["subscription"])
        params = payload.get("params")
        if isinstance(params, dict) and "subscription" in params:
            return _normalize_subscription_id(params["subscription"])
    return None


def _payload_result(payload: Any) -> Any:
    if isinstance(payload, dict):
        if "result" in payload:
            return payload["result"]
        params = payload.get("params")
        if isinstance(params, dict) and "result" in params:
            return params["result"]
    return payload


def _filtered_subscription_iterator(
    iterator: Any, subscription_id: Optional[str]
) -> AsyncIterator[Any]:
    async def _generator() -> AsyncIterator[Any]:
        async for payload in iterator:
            if subscription_id is not None:
                payload_subscription = _payload_subscription_id(payload)
                if (
                    payload_subscription is not None
                    and payload_subscription != subscription_id
                ):
                    continue
            yield _payload_result(payload)

    return _generator()


async def _subscription_event_iterator(web3: Any, subscription: Any) -> AsyncIterator[Any]:
    process_subscriptions = getattr(web3.ws, "process_subscriptions", None)
    if process_subscriptions is None:
        raise RuntimeError("web3 websocket connection is missing process_subscriptions")

    try:
        iterator = process_subscriptions(subscription)
    except TypeError as exc:
        if "positional argument" not in str(exc):
            raise
        iterator = process_subscriptions()
        iterator = await _await_if_awaitable(iterator)
        subscription_id = _normalize_subscription_id(
            getattr(subscription, "subscription_id", None)
            or getattr(subscription, "filter_id", None)
        )
        return _filtered_subscription_iterator(iterator, subscription_id)

    return await _await_if_awaitable(iterator)


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

    if _AsyncWeb3 is None or _WebsocketProviderFactory is None:
        raise RuntimeError("web3 async websocket provider is not available")

    endpoint_uri = getattr(provider, "endpoint_uri", None) or getattr(
        provider, "url", None
    )
    if not endpoint_uri:
        raise RuntimeError("Websocket provider is missing an endpoint URI")

    websocket_kwargs = getattr(provider, "websocket_kwargs", None)
    provider_kwargs: dict[str, Any] = {}
    if websocket_kwargs is not None:
        provider_kwargs["websocket_kwargs"] = websocket_kwargs

    async_provider = _WebsocketProviderFactory(endpoint_uri, **provider_kwargs)

    try:
        # web3.py v7: Create AsyncWeb3 instance directly with WebSocketProvider
        # web3.py v6: Use persistent_websocket context manager
        web3 = _AsyncWeb3(async_provider)

        # Connect the provider (web3.py v7 WebSocketProvider needs explicit connect)
        if hasattr(web3.provider, 'connect') and callable(web3.provider.connect):
            await web3.provider.connect()

        try:
            async with _managed_subscription(web3, subscription_params) as subscription:
                if on_connect is not None:
                    on_connect()
                iterator = await _subscription_event_iterator(web3, subscription)
                async for payload in iterator:
                    if stop_event.is_set():
                        break
                    yield payload
        finally:
            # Disconnect the provider
            if hasattr(web3.provider, 'disconnect') and callable(web3.provider.disconnect):
                await web3.provider.disconnect()
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
