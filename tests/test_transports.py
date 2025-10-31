import asyncio
import importlib
import json
import queue
import sys
import time
import threading
import types
from typing import Any, Dict, List, Optional

import pytest

import scout.websocket_helpers as websocket_helpers
from scout.websocket_helpers import async_iter_websocket_messages, iter_websocket_messages
from scout.websocket_provider_pool import WebSocketProviderPool


class FakeAttributeDict(dict):
    """Minimal stand-in for :class:`web3.datastructures.AttributeDict`."""

    def __getattr__(self, item):
        try:
            return self[item]
        except KeyError as exc:
            raise AttributeError(item) from exc


class FakeHex:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def hex(self) -> str:
        return "0x" + self._data.hex()


class FakeEvent:
    def __init__(self, name: str):
        self.name = name

    def __call__(self):
        return self

    def processLog(self, log):  # noqa: N802 - mimic Web3 API
        return types.SimpleNamespace(event=self.name, args={})


class FakeEth:
    def __init__(self, web3: "FakeWeb3") -> None:
        self._web3 = web3
        self._block_number = FakeWeb3.default_block_number
        self.logs = list(FakeWeb3.default_logs)

    def contract(self, address, abi):  # noqa: ANN001 - signature matches Web3
        events = types.SimpleNamespace()
        for entry in abi:
            setattr(events, entry["name"], FakeEvent(entry["name"]))
        return types.SimpleNamespace(events=events)

    def get_logs(self, params):  # noqa: ANN001 - mimic Web3 signature
        failures = FakeWeb3.failure_sequence.get(self._web3.provider.url, [])
        if failures and failures[0] == "get_logs":
            failures.pop(0)
            raise RuntimeError("get_logs failure")
        return list(self.logs)

    @property
    def block_number(self) -> int:
        failures = FakeWeb3.failure_sequence.get(self._web3.provider.url, [])
        if failures and failures[0] == "block_number":
            failures.pop(0)
            raise RuntimeError("block_number failure")
        return self._block_number

    @block_number.setter
    def block_number(self, value: int) -> None:
        self._block_number = value


class FakeHTTPProvider:
    def __init__(self, url: str, request_kwargs=None):
        self.url = url
        self.request_kwargs = request_kwargs or {}


class FakeWeb3:
    HTTPProvider = FakeHTTPProvider
    default_block_number = 10
    default_logs: List[Any] = []
    failure_sequence: Dict[str, List[str]] = {}

    def __init__(self, provider):  # noqa: ANN001 - mimic Web3 signature
        self.provider = provider
        self.eth = FakeEth(self)
        self.codec = object()

    def keccak(self, text: str):
        return FakeHex(text.encode("utf-8"))

    def is_connected(self):
        return True

    @staticmethod
    def to_checksum_address(address: str) -> str:
        return address

    @staticmethod
    def to_hex(value):  # noqa: ANN001 - mimic Web3 signature
        if isinstance(value, str):
            return value
        if isinstance(value, (bytes, bytearray)):
            return "0x" + bytes(value).hex()
        if hasattr(value, "hex") and callable(getattr(value, "hex")):
            return value.hex()
        raise TypeError(f"Unsupported value for to_hex: {value!r}")


class FakeWebsocketProvider:
    def __init__(self, *args, **kwargs):
        self.ws = types.SimpleNamespace(recv=lambda: None, close=lambda: None)

    def make_request(self, method, params):  # noqa: ANN001 - mimic Web3 signature
        if method == "eth_subscribe":
            return {"result": "sub"}
        if method == "eth_unsubscribe":
            return {"result": True}
        return {"result": None}

    def disconnect(self):
        return None


class FakeKeepaliveWebsocketProvider:
    def __init__(self, endpoint_uri, websocket_kwargs=None, **_kwargs):
        self.endpoint_uri = endpoint_uri
        self._received_websocket_kwargs = websocket_kwargs
        self.connect_calls = 0
        self.disconnect_calls = 0

    def connect(self):
        self.connect_calls += 1

    def disconnect(self):
        self.disconnect_calls += 1


def test_websocket_provider_pool_injects_keepalive_kwargs():
    pool = WebSocketProviderPool(provider_class=FakeKeepaliveWebsocketProvider)
    handle = pool.attach("wss://example")
    provider = None
    expected = {"ping_interval": 20, "ping_timeout": 20}

    try:
        with handle.checkout() as session:
            provider = session.provider
            assert provider._received_websocket_kwargs == expected
            assert getattr(provider, "websocket_kwargs") == expected
            assert provider.connect_calls == 1
    finally:
        handle.close()

    assert provider is not None
    assert provider.disconnect_calls == 1


class PersistentFakeWebsocketProvider:
    instances: List["PersistentFakeWebsocketProvider"] = []
    default_messages: List[Any] = []

    def __init__(self, url: str, **kwargs: Any) -> None:
        self.url = url
        self.kwargs = kwargs
        self.ws_messages: "queue.Queue[Any]" = queue.Queue()
        for message in type(self).default_messages:
            self.ws_messages.put(message)
        self.handshake_calls = 0
        self.cleanup_calls = 0
        type(self).instances.append(self)

    def socket_connect(self) -> None:
        self.handshake_calls += 1

    def socket_disconnect(self) -> None:
        self.cleanup_calls += 1

    def make_request(self, method, params):  # noqa: ANN001 - mimic Web3 signature
        if method == "eth_subscribe":
            return {"result": "sub"}
        if method == "eth_unsubscribe":
            return {"result": True}
        return {"result": None}

    def disconnect(self):
        return None


class FakeAsyncSubscription:
    def __init__(self, messages):
        self._messages = iter(messages)
        self.unsubscribe_calls = 0
        self.subscription_id = "fake-sub"

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return next(self._messages)
        except StopIteration as exc:
            raise StopAsyncIteration from exc

    async def unsubscribe(self):
        self.unsubscribe_calls += 1


class FakeAsyncEth:
    def __init__(self, messages):
        self._messages = messages
        self.subscribe_calls: List[Any] = []
        self.unsubscribe_calls: List[Any] = []
        self.subscription: Optional[FakeAsyncSubscription] = None

    async def subscribe(self, method, params):
        self.subscribe_calls.append((method, params))
        self.subscription = FakeAsyncSubscription(self._messages)
        return self.subscription

    async def unsubscribe(self, subscription_id):  # noqa: ANN001 - mimic Web3 signature
        self.unsubscribe_calls.append(subscription_id)
        return True


class FakeWebsocketProviderV2:
    instances: List["FakeWebsocketProviderV2"] = []

    def __init__(self, endpoint_uri, websocket_kwargs=None):  # noqa: ANN001 - mimic Web3 signature
        self.endpoint_uri = endpoint_uri
        self.websocket_kwargs = websocket_kwargs
        self.disconnect_calls = 0
        self.socket_connect_calls = 0
        self.socket_disconnect_calls = 0
        type(self).instances.append(self)

    def socket_connect(self):
        self.socket_connect_calls += 1

    def socket_disconnect(self):
        self.socket_disconnect_calls += 1

    async def disconnect(self):
        self.disconnect_calls += 1


def test_async_iter_websocket_messages_uses_async_web3(monkeypatch):
    messages = ["payload-1", "payload-2"]
    stop_event = threading.Event()
    FakeWebsocketProviderV2.instances.clear()

    class FakeAsyncWeb3:
        instances: List["FakeAsyncWeb3"] = []

        def __init__(self, provider):
            self.provider = provider
            self.eth = FakeAsyncEth(messages)
            self.ws = FakeAsyncWS(messages)
            type(self).instances.append(self)

        @classmethod
        def persistent_websocket(cls, provider):
            class _Manager:
                async def __aenter__(self_inner):
                    provider.socket_connect()
                    self_inner.instance = cls(provider)
                    return self_inner.instance

                async def __aexit__(self_inner, exc_type, exc, tb):
                    provider.socket_disconnect()

            return _Manager()

    class FakeAsyncWS:
        def __init__(self, items):
            self._items = list(items)
            self.process_calls: List[Any] = []

        async def process_subscriptions(self, subscription):
            self.process_calls.append(subscription)
            for item in self._items:
                yield item

    monkeypatch.setattr(websocket_helpers, "_AsyncWeb3", FakeAsyncWeb3)
    monkeypatch.setattr(websocket_helpers, "_WebsocketProviderFactory", FakeWebsocketProviderV2)

    connected = 0
    disconnected = 0

    def on_connect():
        nonlocal connected
        connected += 1

    def on_disconnect():
        nonlocal disconnected
        disconnected += 1

    async def collect():
        received = []
        async for payload in async_iter_websocket_messages(
            types.SimpleNamespace(endpoint_uri="wss://example", websocket_kwargs={"ping": 1}),
            stop_event,
            subscription_params={"topics": ["topic"]},
            on_connect=on_connect,
            on_disconnect=on_disconnect,
        ):
            received.append(payload)
            if len(received) == len(messages):
                stop_event.set()
        return received

    results = asyncio.run(collect())

    assert results == messages
    assert connected == 1
    assert disconnected == 1

    assert FakeWebsocketProviderV2.instances
    provider_instance = FakeWebsocketProviderV2.instances[-1]
    assert provider_instance.endpoint_uri == "wss://example"
    assert provider_instance.websocket_kwargs == {"ping": 1}
    assert provider_instance.socket_connect_calls == 1
    assert provider_instance.socket_disconnect_calls == 1
    assert provider_instance.disconnect_calls == 1

    web3_instance = FakeAsyncWeb3.instances[-1]
    assert web3_instance.eth.subscribe_calls == [("logs", {"topics": ["topic"]})]
    assert web3_instance.eth.subscription is not None
    assert web3_instance.eth.subscription.unsubscribe_calls == 1
    assert web3_instance.ws.process_calls == [web3_instance.eth.subscription]


def test_iter_websocket_messages_bridges_async_iterator(monkeypatch):
    stop_event = threading.Event()
    messages = ["message-1", "message-2"]
    received_params = []

    async def fake_async_iter(
        provider,
        stop_event_param,
        *,
        subscription_params=None,
        on_connect=None,
        on_disconnect=None,
    ):
        received_params.append(subscription_params)
        if on_connect is not None:
            on_connect()
        for payload in messages:
            yield payload
        if on_disconnect is not None:
            on_disconnect()

    monkeypatch.setattr(websocket_helpers, "async_iter_websocket_messages", fake_async_iter)

    connected = 0
    disconnected = 0

    def on_connect():
        nonlocal connected
        connected += 1

    def on_disconnect():
        nonlocal disconnected
        disconnected += 1

    iterator = iter_websocket_messages(
        provider=object(),
        stop_event=stop_event,
        poll_interval=0.01,
        subscription_params={"foo": "bar"},
        on_connect=on_connect,
        on_disconnect=on_disconnect,
    )

    assert list(iterator) == messages
    assert received_params == [{"foo": "bar"}]
    assert connected == 1
    assert disconnected == 1


def install_web3_stub(monkeypatch):
    modules = {}
    for name in list(sys.modules):
        if name.startswith("web3"):
            modules[name] = sys.modules.pop(name)

    web3_module = types.ModuleType("web3")
    web3_module.Web3 = FakeWeb3
    web3_module.HTTPProvider = FakeHTTPProvider
    FakeWeb3.default_block_number = 10
    FakeWeb3.default_logs = []
    FakeWeb3.failure_sequence = {}

    utils_module = types.ModuleType("web3._utils")
    events_module = types.ModuleType("web3._utils.events")

    def get_event_data(codec, event_abi, log):  # noqa: ANN001
        return {"event": event_abi["name"], "args": {}}

    events_module.get_event_data = get_event_data
    utils_module.events = events_module

    datastructures_module = types.ModuleType("web3.datastructures")
    datastructures_module.AttributeDict = FakeAttributeDict

    types_module = types.ModuleType("web3.types")
    types_module.FilterParams = dict
    types_module.LogReceipt = dict
    types_module.EventData = dict

    providers_module = types.ModuleType("web3.providers")
    websocket_module = types.ModuleType("web3.providers.websocket")
    websocket_module.WebsocketProvider = FakeWebsocketProvider
    websocket_module.WebsocketProviderV2 = FakeWebsocketProvider
    websocket_module.WebSocketProvider = FakeWebsocketProvider
    providers_module.websocket = websocket_module

    persistent_module = types.ModuleType("web3.providers.persistent")
    persistent_module.WebSocketProvider = PersistentFakeWebsocketProvider
    persistent_module.AsyncWebSocketProvider = FakeWebsocketProvider
    providers_module.persistent = persistent_module

    contract_module = types.ModuleType("web3.contract")
    contract_module.Contract = type("Contract", (), {})
    contract_module.ContractEvent = type("ContractEvent", (), {})

    class StubAsyncSubscription:
        def __init__(self, provider):
            self.provider = provider
            self.unsubscribe_calls = 0
            self.subscription_id = "stub"

        async def unsubscribe(self):
            self.unsubscribe_calls += 1

    class StubAsyncEth:
        def __init__(self, provider):
            self.provider = provider
            self.subscribe_calls: List[Any] = []

        async def subscribe(self, method, params):
            self.subscribe_calls.append((method, params))
            return StubAsyncSubscription(self.provider)

    class StubAsyncWS:
        def __init__(self, provider):
            self.provider = provider
            self.process_calls: List[Any] = []

        async def process_subscriptions(self, subscription):
            self.process_calls.append(subscription)
            queue_source = getattr(self.provider, "ws_messages", None)
            if queue_source is None:
                request_processor = getattr(self.provider, "_request_processor", None)
                queue_source = getattr(request_processor, "ws_messages", None)
            if queue_source is None:
                return
            while True:
                try:
                    yield queue_source.get_nowait()
                except queue.Empty:
                    break

    class StubAsyncWeb3:
        def __init__(self, provider):
            self.provider = provider
            self.eth = StubAsyncEth(provider)
            self.ws = StubAsyncWS(provider)

        @classmethod
        def persistent_websocket(cls, provider):
            class _Manager:
                async def __aenter__(self_inner):
                    connect = getattr(provider, "socket_connect", None)
                    if callable(connect):
                        connect()
                    self_inner.instance = cls(provider)
                    return self_inner.instance

                async def __aexit__(self_inner, exc_type, exc, tb):
                    disconnect = getattr(provider, "socket_disconnect", None)
                    if callable(disconnect):
                        disconnect()

            return _Manager()

    monkeypatch.setitem(sys.modules, "web3", web3_module)
    monkeypatch.setitem(sys.modules, "web3._utils", utils_module)
    monkeypatch.setitem(sys.modules, "web3._utils.events", events_module)
    monkeypatch.setitem(sys.modules, "web3.datastructures", datastructures_module)
    monkeypatch.setitem(sys.modules, "web3.types", types_module)
    monkeypatch.setitem(sys.modules, "web3.providers", providers_module)
    monkeypatch.setitem(sys.modules, "web3.providers.websocket", websocket_module)
    monkeypatch.setitem(sys.modules, "web3.providers.persistent", persistent_module)
    monkeypatch.setitem(sys.modules, "web3.contract", contract_module)

    monkeypatch.setattr(
        websocket_helpers,
        "_WebsocketProviderFactory",
        PersistentFakeWebsocketProvider,
        raising=False,
    )
    monkeypatch.setattr(
        websocket_helpers,
        "_AsyncWeb3",
        StubAsyncWeb3,
        raising=False,
    )

    return modules


@pytest.fixture
def scout_modules(monkeypatch):
    previous = install_web3_stub(monkeypatch)
    for module_name in ["scout.featured_scout", "scout.pro_scout"]:
        sys.modules.pop(module_name, None)
    featured = importlib.import_module("scout.featured_scout")
    pro = importlib.import_module("scout.pro_scout")
    yield featured, pro
    for module_name in ["scout.featured_scout", "scout.pro_scout"]:
        sys.modules.pop(module_name, None)
    for name, module in previous.items():
        sys.modules[name] = module


def test_featured_scout_topics_are_hex_prefixed(tmp_path, scout_modules):
    featured, _ = scout_modules
    config = featured.ScoutConfig(
        rpc_http_urls=("http://rpc",),
        rpc_ws_urls=(),
        contract_address="0xabc",
        chain_id=None,
        api_root="http://api",
        admin_token="token",
        admin_refresh_token="refresh",
        admin_wallet_address="0x0000000000000000000000000000000000000001",
        admin_wallet_private_key="0x01",
        project_id_resolver_url=None,
        db_path=str(tmp_path / "featured_topics.db"),
        poll_interval_sec=1,
        reorg_confirmations=1,
        start_block=None,
        start_block_latest=True,
    )
    scout = featured.FeaturedScout(config, once=True)
    topics = list(scout._event_topic_map.keys())
    assert topics, "Expected FeaturedScout to register event topics"
    assert all(topic.startswith("0x") for topic in topics)

    topic_key = topics[0]
    scout._handle_round_finalized = lambda *args, **kwargs: True  # type: ignore[assignment]
    scout._handle_paid = lambda *args, **kwargs: True  # type: ignore[assignment]

    log_entry = FakeAttributeDict(
        {
            "transactionHash": bytes.fromhex("06" * 32),
            "logIndex": 0,
            "blockNumber": 7,
            "topics": [bytes.fromhex(topic_key[2:])],
        }
    )
    assert scout._handle_log(log_entry) is True


def test_featured_scout_processes_http_and_websocket_logs(tmp_path, scout_modules):
    featured, _ = scout_modules
    config = featured.ScoutConfig(
        rpc_http_urls=("http://rpc",),
        rpc_ws_urls=("ws://rpc",),
        contract_address="0xabc",
        chain_id=None,
        api_root="http://api",
        admin_token="token",
        admin_refresh_token="refresh",
        admin_wallet_address="0x0000000000000000000000000000000000000001",
        admin_wallet_private_key="0x01",
        project_id_resolver_url=None,
        db_path=str(tmp_path / "featured.db"),
        poll_interval_sec=1,
        reorg_confirmations=1,
        start_block=None,
        start_block_latest=True,
    )
    scout = featured.FeaturedScout(config, once=True)
    scout._handle_log = lambda *args, **kwargs: True  # type: ignore[assignment]

    http_log = FakeAttributeDict(
        {
            "transactionHash": bytes.fromhex("01" * 32),
            "logIndex": 0,
            "blockNumber": 3,
            "topics": [bytes.fromhex("aa" * 32)],
        }
    )
    scout._web3.eth.logs = [http_log]
    assert scout._poll_once() is True

    ws_payload = {
        "params": {
            "result": {
                "transactionHash": "0x" + "02" * 32,
                "logIndex": "0x1",
                "blockNumber": "0x4",
                "transactionIndex": "0x0",
                "address": "0xabc",
                "data": "0x",
                "topics": ["0x" + "bb" * 32],
            }
        }
    }
    scout._handle_ws_payload(ws_payload)

    with scout._db.read_connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM processed_logs").fetchone()[0]
    assert count == 2

    scout._handle_ws_payload({"params": {"result": {"removed": True}}})
    with scout._db.read_connection() as conn:
        count_after = conn.execute("SELECT COUNT(*) FROM processed_logs").fetchone()[0]
    assert count_after == 2


def test_featured_scout_pauses_http_when_websocket_healthy(tmp_path, scout_modules):
    featured, _ = scout_modules

    config = featured.ScoutConfig(
        rpc_http_urls=("http://rpc",),
        rpc_ws_urls=("ws://rpc",),
        contract_address="0xabc",
        chain_id=None,
        api_root="http://api",
        admin_token="token",
        admin_refresh_token="refresh",
        admin_wallet_address="0x0000000000000000000000000000000000000001",
        admin_wallet_private_key="0x01",
        project_id_resolver_url=None,
        db_path=str(tmp_path / "featured_pause.db"),
        poll_interval_sec=1,
        reorg_confirmations=1,
        start_block=None,
        start_block_latest=True,
    )

    scout = featured.FeaturedScout(config, once=True)
    scout._handle_log = lambda *args, **kwargs: True  # type: ignore[assignment]

    http_log = FakeAttributeDict(
        {
            "transactionHash": bytes.fromhex("08" * 32),
            "logIndex": 0,
            "blockNumber": 10,
            "topics": [bytes.fromhex("aa" * 32)],
        }
    )
    scout._web3.eth.logs = [http_log]
    assert scout._poll_once() is True

    assert scout._poll_gate.is_set()
    scout._notify_ws_connected()
    assert not scout._poll_gate.is_set()

    with scout._ws_state_lock:
        scout._ws_last_message = time.time() - (scout._ws_stale_threshold + 1)
    scout._evaluate_polling_state()
    assert scout._poll_gate.is_set()

    scout._notify_ws_connected()
    assert not scout._poll_gate.is_set()

    scout._notify_ws_disconnected()
    assert scout._poll_gate.is_set()


def test_featured_scout_http_catch_up_synchronizes_ws_progress(
    tmp_path, scout_modules, caplog
):
    featured, _ = scout_modules

    config = featured.ScoutConfig(
        rpc_http_urls=("http://rpc",),
        rpc_ws_urls=("ws://rpc",),
        contract_address="0xabc",
        chain_id=None,
        api_root="http://api",
        admin_token="token",
        admin_refresh_token="refresh",
        admin_wallet_address="0x0000000000000000000000000000000000000001",
        admin_wallet_private_key="0x01",
        project_id_resolver_url=None,
        db_path=str(tmp_path / "featured_sync.db"),
        poll_interval_sec=1,
        reorg_confirmations=1,
        start_block=None,
        start_block_latest=True,
    )

    scout = featured.FeaturedScout(config, once=True)
    scout._handle_log = lambda *args, **kwargs: True  # type: ignore[assignment]

    caplog.set_level("INFO")
    assert scout._poll_once() is True
    scout._notify_ws_connected()
    assert not scout._poll_gate.is_set()

    scout._web3.eth.block_number = scout._last_block + 1
    scout._web3.eth.logs = []
    scout._resume_http_polling()
    caplog.clear()

    assert scout._poll_once() is True
    assert "HTTP poller caught up; relying on websocket stream" in caplog.messages
    assert not scout._poll_gate.is_set()
    with scout._ws_state_lock:
        assert scout._ws_last_block == scout._last_block


def test_pro_scout_processes_http_and_websocket_logs(tmp_path, scout_modules):
    _, pro = scout_modules

    class DummyBackendClient:
        base_url = "http://api"

        def patch(self, *args, **kwargs):
            return types.SimpleNamespace(status_code=200, text="")

    service = pro.ProScout(
        rpc_http_urls=("http://rpc",),
        rpc_ws_urls=["ws://rpc"],
        api_base_url="http://api",
        admin_access_token="token",
        admin_refresh_token="refresh",
        contract_address="0xabc",
        db_path=str(tmp_path / "pro.db"),
        backend_client=DummyBackendClient(),
        poll_interval=1,
        reorg_conf=0,
    )

    handler = lambda *args, **kwargs: True  # noqa: E731 - simple stub
    service._handle_stake_started = handler  # type: ignore[assignment]
    service._handle_tier_upgraded = handler  # type: ignore[assignment]
    service._handle_unstake_requested = handler  # type: ignore[assignment]
    service.event_handlers = {
        "StakeStarted": service._handle_stake_started,
        "TierUpgraded": service._handle_tier_upgraded,
        "UnstakeRequested": service._handle_unstake_requested,
    }

    topic_key = next(iter(service._topic_to_event))
    topic_bytes = bytes.fromhex(topic_key[2:] if topic_key.startswith("0x") else topic_key)

    http_log = FakeAttributeDict(
        {
            "transactionHash": bytes.fromhex("03" * 32),
            "logIndex": 0,
            "blockNumber": 5,
            "topics": [topic_bytes],
        }
    )
    service.web3.eth.logs = [http_log]
    service._poll_once()

    ws_payload = {
        "params": {
            "result": {
                "transactionHash": "0x" + "04" * 32,
                "logIndex": "0x1",
                "blockNumber": "0x6",
                "transactionIndex": "0x0",
                "address": "0xabc",
                "data": "0x",
                "topics": [topic_key],
            }
        }
    }
    service._handle_ws_payload(ws_payload)

    with service.db_manager.read_connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM processed_logs").fetchone()[0]
    assert count == 2

    service._handle_ws_payload({"params": {"result": {"removed": True}}})
    with service.db_manager.read_connection() as conn:
        count_after = conn.execute("SELECT COUNT(*) FROM processed_logs").fetchone()[0]
    assert count_after == 2


def test_pro_scout_pauses_http_when_websocket_healthy(tmp_path, scout_modules):
    _, pro = scout_modules

    class DummyBackendClient:
        base_url = "http://api"

        def patch(self, *args, **kwargs):
            return types.SimpleNamespace(status_code=200, text="")

    service = pro.ProScout(
        rpc_http_urls=("http://rpc",),
        rpc_ws_urls=["ws://rpc"],
        api_base_url="http://api",
        admin_access_token="token",
        admin_refresh_token="refresh",
        contract_address="0xabc",
        db_path=str(tmp_path / "pro_pause.db"),
        backend_client=DummyBackendClient(),
        poll_interval=1,
        reorg_conf=0,
    )

    handler = lambda *args, **kwargs: True  # noqa: E731 - simple stub
    service._handle_stake_started = handler  # type: ignore[assignment]
    service._handle_tier_upgraded = handler  # type: ignore[assignment]
    service._handle_unstake_requested = handler  # type: ignore[assignment]
    service.event_handlers = {
        "StakeStarted": service._handle_stake_started,
        "TierUpgraded": service._handle_tier_upgraded,
        "UnstakeRequested": service._handle_unstake_requested,
    }

    topic_key = next(iter(service._topic_to_event))
    topic_bytes = bytes.fromhex(topic_key[2:] if topic_key.startswith("0x") else topic_key)

    http_log = FakeAttributeDict(
        {
            "transactionHash": bytes.fromhex("07" * 32),
            "logIndex": 0,
            "blockNumber": 10,
            "topics": [topic_bytes],
        }
    )
    service.web3.eth.logs = [http_log]
    service._poll_once()

    assert service._poll_gate.is_set()
    service._notify_ws_connected()
    assert not service._poll_gate.is_set()

    with service._ws_state_lock:
        service._ws_last_message = time.time() - (service._ws_stale_threshold + 1)
    service._evaluate_polling_state()
    assert service._poll_gate.is_set()

    service._notify_ws_connected()
    assert not service._poll_gate.is_set()

    service._notify_ws_disconnected()
    assert service._poll_gate.is_set()


def test_featured_scout_rotates_rpc_endpoints(tmp_path, scout_modules):
    featured, _ = scout_modules

    http_log = FakeAttributeDict(
        {
            "transactionHash": bytes.fromhex("05" * 32),
            "logIndex": 0,
            "blockNumber": 6,
            "topics": [bytes.fromhex("aa" * 32)],
        }
    )
    featured.Web3.default_logs = [http_log]
    featured.Web3.default_block_number = 6
    featured.Web3.failure_sequence = {"http://bad": ["block_number"]}

    config = featured.ScoutConfig(
        rpc_http_urls=("http://bad", "http://good"),
        rpc_ws_urls=(),
        contract_address="0xabc",
        chain_id=None,
        api_root="http://api",
        admin_token="token",
        admin_refresh_token="refresh",
        admin_wallet_address="0x0000000000000000000000000000000000000001",
        admin_wallet_private_key="0x01",
        project_id_resolver_url=None,
        db_path=str(tmp_path / "featured_rotate.db"),
        poll_interval_sec=1,
        reorg_confirmations=1,
        start_block=None,
        start_block_latest=True,
    )
    scout = featured.FeaturedScout(config, once=True)
    scout._handle_log = lambda *args, **kwargs: True  # type: ignore[assignment]

    assert scout._poll_once() is False
    assert scout._active_rpc_index == 0
    assert scout._db.get_meta("featured_active_rpc_index") is None

    featured.Web3.failure_sequence = {}
    result = scout._poll_once()
    assert result is True
    assert scout._active_rpc_index == 1
    assert scout._db.get_meta("featured_active_rpc_index") == "1"
    with scout._db.read_connection() as conn:
        processed = conn.execute("SELECT COUNT(*) FROM processed_logs").fetchone()[0]
    assert processed == 1


def test_featured_scout_batches_get_logs_requests(tmp_path, scout_modules):
    featured, _ = scout_modules

    config = featured.ScoutConfig(
        rpc_http_urls=("http://rpc",),
        rpc_ws_urls=(),
        contract_address="0xabc",
        chain_id=None,
        api_root="http://api",
        admin_token="token",
        admin_refresh_token="refresh",
        admin_wallet_address="0x0000000000000000000000000000000000000001",
        admin_wallet_private_key="0x01",
        project_id_resolver_url=None,
        db_path=str(tmp_path / "featured_batch.db"),
        poll_interval_sec=1,
        reorg_confirmations=1,
        start_block=5,
        start_block_latest=False,
        block_batch_size=2,
    )
    scout = featured.FeaturedScout(config, once=True)
    scout._handle_log = lambda *args, **kwargs: True  # type: ignore[assignment]

    scout._web3.eth.block_number = 10
    calls = []

    def fake_get_logs(params):
        calls.append((params["fromBlock"], params["toBlock"]))
        return []

    scout._web3.eth.get_logs = fake_get_logs  # type: ignore[assignment]

    assert scout._poll_once() is True
    assert calls == [("0x5", "0x6"), ("0x7", "0x8"), ("0x9", "0xa")]
    assert scout._db.get_meta("featured_last_block") == "10"


def test_featured_scout_persists_progress_across_batch_failures(
    tmp_path, scout_modules
):
    featured, _ = scout_modules

    config = featured.ScoutConfig(
        rpc_http_urls=("http://rpc",),
        rpc_ws_urls=(),
        contract_address="0xabc",
        chain_id=None,
        api_root="http://api",
        admin_token="token",
        admin_refresh_token="refresh",
        admin_wallet_address="0x0000000000000000000000000000000000000001",
        admin_wallet_private_key="0x01",
        project_id_resolver_url=None,
        db_path=str(tmp_path / "featured_batch_failure.db"),
        poll_interval_sec=1,
        reorg_confirmations=1,
        start_block=5,
        start_block_latest=False,
        block_batch_size=2,
    )
    scout = featured.FeaturedScout(config, once=True)
    scout._handle_log = lambda *args, **kwargs: True  # type: ignore[assignment]

    scout._web3.eth.block_number = 10
    calls = []

    def flaky_get_logs(params):
        calls.append((params["fromBlock"], params["toBlock"]))
        if len(calls) == 2:
            raise RuntimeError("boom")
        return []

    scout._web3.eth.get_logs = flaky_get_logs  # type: ignore[assignment]

    assert scout._poll_once() is False
    assert calls == [("0x5", "0x6"), ("0x7", "0x8")]
    assert scout._db.get_meta("featured_last_block") == "6"


def test_pro_scout_rotates_rpc_endpoints(tmp_path, scout_modules):
    _, pro = scout_modules

    class DummyBackendClient:
        base_url = "http://api"

        def patch(self, *args, **kwargs):
            return types.SimpleNamespace(status_code=200, text="")

    pro.Web3.default_block_number = 5
    pro.Web3.default_logs = []
    pro.Web3.failure_sequence = {}

    service = pro.ProScout(
        rpc_http_urls=("http://bad", "http://good"),
        rpc_ws_urls=[],
        api_base_url="http://api",
        admin_access_token="token",
        admin_refresh_token="refresh",
        contract_address="0xabc",
        db_path=str(tmp_path / "pro_rotate.db"),
        backend_client=DummyBackendClient(),
        poll_interval=1,
        reorg_conf=0,
    )

    pro.Web3.failure_sequence = {"http://bad": ["block_number"]}
    initial_last_block = service._last_block
    service._poll_once()
    assert service._active_rpc_index == 0
    assert service.db_manager.get_meta("pro_active_rpc_index") is None
    assert service._last_block == initial_last_block

    pro.Web3.failure_sequence = {}
    pro.Web3.default_block_number = 6
    service._poll_once()
    assert service._active_rpc_index == 1
    assert service.db_manager.get_meta("pro_active_rpc_index") == "1"
    assert service._last_block >= initial_last_block


def test_featured_scout_websocket_retries_before_switch(monkeypatch, tmp_path, scout_modules):
    featured, _ = scout_modules

    config = featured.ScoutConfig(
        rpc_http_urls=("http://rpc",),
        rpc_ws_urls=("ws://one", "ws://two"),
        contract_address="0xabc",
        chain_id=None,
        api_root="http://api",
        admin_token="token",
        admin_refresh_token="refresh",
        admin_wallet_address="0x0000000000000000000000000000000000000001",
        admin_wallet_private_key="0x01",
        project_id_resolver_url=None,
        db_path=str(tmp_path / "featured_ws_retries.db"),
        poll_interval_sec=1,
        reorg_confirmations=1,
        start_block=None,
        start_block_latest=True,
    )
    scout = featured.FeaturedScout(config, once=True)

    sleep_calls = []
    monkeypatch.setattr(featured.time, "sleep", lambda duration: sleep_calls.append(duration))

    call_log = []

    def fake_consume(url: str) -> None:
        attempt = sum(1 for entry in call_log if entry[0] == url) + 1
        call_log.append((url, attempt))
        if url == "ws://one" and attempt < 3:
            raise RuntimeError("fail")
        scout._stop_event.set()

    scout._consume_ws_url = fake_consume  # type: ignore[assignment]
    scout._websocket_loop()

    assert call_log == [
        ("ws://one", 1),
        ("ws://one", 2),
        ("ws://one", 3),
    ]
    assert sleep_calls == []


def test_featured_scout_ws_provider_without_timeout(monkeypatch, tmp_path, scout_modules):
    featured, _ = scout_modules

    class NoTimeoutProvider:
        last_kwargs = None

        def __init__(self, url: str):
            type(self).last_kwargs = {}
            self.url = url
            self.ws = types.SimpleNamespace(recv=lambda: None, close=lambda: None)

        def make_request(self, method, params):  # noqa: ANN001 - mimic Web3 signature
            if method == "eth_subscribe":
                return {"result": "sub"}
            if method == "eth_unsubscribe":
                return {"result": True}
            return {"result": None}

        def disconnect(self):
            return None

    config = featured.ScoutConfig(
        rpc_http_urls=("http://rpc",),
        rpc_ws_urls=("ws://one",),
        contract_address="0xabc",
        chain_id=None,
        api_root="http://api",
        admin_token="token",
        admin_refresh_token="refresh",
        admin_wallet_address="0x0000000000000000000000000000000000000001",
        admin_wallet_private_key="0x01",
        project_id_resolver_url=None,
        db_path=str(tmp_path / "featured_ws_no_timeout.db"),
        poll_interval_sec=1,
        reorg_confirmations=1,
        start_block=None,
        start_block_latest=True,
    )
    scout = featured.FeaturedScout(config, once=True)

    monkeypatch.setattr(scout, "_get_ws_provider_class", lambda: NoTimeoutProvider)

    scout._stop_event.set()
    scout._consume_ws_url("ws://one")

    assert NoTimeoutProvider.last_kwargs == {}


def test_featured_scout_consumes_persistent_provider(monkeypatch, tmp_path, scout_modules):
    featured, _ = scout_modules

    persistent_module = sys.modules["web3.providers.persistent"]
    provider_cls = persistent_module.WebSocketProvider
    provider_cls.instances.clear()

    config = featured.ScoutConfig(
        rpc_http_urls=("http://rpc",),
        rpc_ws_urls=("ws://queue",),
        contract_address="0xabc",
        chain_id=None,
        api_root="http://api",
        admin_token="token",
        admin_refresh_token="refresh",
        admin_wallet_address="0x0000000000000000000000000000000000000001",
        admin_wallet_private_key="0x01",
        project_id_resolver_url=None,
        db_path=str(tmp_path / "featured_persistent.db"),
        poll_interval_sec=1,
        reorg_confirmations=1,
        start_block=None,
        start_block_latest=True,
    )

    scout = featured.FeaturedScout(config, once=True)
    topic_key = next(iter(scout._event_topic_map))

    payload = {
        "method": "eth_subscription",
        "params": {
            "result": {
                "transactionHash": "0x" + "05" * 32,
                "logIndex": "0x2",
                "blockNumber": "0x7",
                "transactionIndex": "0x0",
                "address": "0xabc",
                "data": "0x",
                "topics": [topic_key],
            }
        },
    }

    provider_cls.default_messages = [json.dumps(payload)]

    handled = []

    def fake_handle_ws_payload(event_payload):
        handled.append(event_payload)
        scout._stop_event.set()

    monkeypatch.setattr(scout, "_handle_ws_payload", fake_handle_ws_payload)

    try:
        scout._consume_ws_url("ws://queue")
    finally:
        provider_cls.default_messages = []

    assert handled, "Expected websocket payload to be processed"
    assert provider_cls.instances and provider_cls.instances[-1].handshake_calls == 1
    assert provider_cls.instances[-1].cleanup_calls == 1


def test_featured_scout_skips_non_text_websocket_payload(
    monkeypatch, tmp_path, scout_modules
):
    featured, _ = scout_modules

    persistent_module = sys.modules["web3.providers.persistent"]
    provider_cls = persistent_module.WebSocketProvider
    provider_cls.instances.clear()

    config = featured.ScoutConfig(
        rpc_http_urls=("http://rpc",),
        rpc_ws_urls=("ws://queue",),
        contract_address="0xabc",
        chain_id=None,
        api_root="http://api",
        admin_token="token",
        admin_refresh_token="refresh",
        admin_wallet_address="0x0000000000000000000000000000000000000001",
        admin_wallet_private_key="0x01",
        project_id_resolver_url=None,
        db_path=str(tmp_path / "featured_persistent_non_text.db"),
        poll_interval_sec=1,
        reorg_confirmations=1,
        start_block=None,
        start_block_latest=True,
    )

    scout = featured.FeaturedScout(config, once=True)
    topic_key = next(iter(scout._event_topic_map))

    payload = {
        "method": "eth_subscription",
        "params": {
            "result": {
                "transactionHash": "0x" + "05" * 32,
                "logIndex": "0x2",
                "blockNumber": "0x7",
                "transactionIndex": "0x0",
                "address": "0xabc",
                "data": "0x",
                "topics": [topic_key],
            }
        },
    }

    provider_cls.default_messages = [3.14, json.dumps(payload)]

    handled = []

    def fake_handle_ws_payload(event_payload):
        handled.append(event_payload)
        scout._stop_event.set()

    monkeypatch.setattr(scout, "_handle_ws_payload", fake_handle_ws_payload)

    try:
        scout._consume_ws_url("ws://queue")
    finally:
        provider_cls.default_messages = []

    assert handled == [payload], "Expected websocket payload to be processed"
    assert provider_cls.instances and provider_cls.instances[-1].handshake_calls == 1
    assert provider_cls.instances[-1].cleanup_calls == 1


def test_pro_scout_websocket_retries_then_advances(monkeypatch, tmp_path, scout_modules):
    _, pro = scout_modules

    class DummyBackendClient:
        base_url = "http://api"

        def patch(self, *args, **kwargs):
            return types.SimpleNamespace(status_code=200, text="")

    service = pro.ProScout(
        rpc_http_urls=("http://rpc",),
        rpc_ws_urls=["ws://one", "ws://two"],
        api_base_url="http://api",
        admin_access_token="token",
        admin_refresh_token="refresh",
        contract_address="0xabc",
        db_path=str(tmp_path / "pro_ws_retries.db"),
        backend_client=DummyBackendClient(),
        poll_interval=1,
        reorg_conf=0,
    )

    sleep_calls = []
    monkeypatch.setattr(pro.time, "sleep", lambda duration: sleep_calls.append(duration))

    call_log = []

    def fake_consume(url: str) -> None:
        attempt = sum(1 for entry in call_log if entry[0] == url) + 1
        call_log.append((url, attempt))
        if url == "ws://one":
            raise RuntimeError("fail")
        service._stop_event.set()

    service._consume_ws_url = fake_consume  # type: ignore[assignment]
    service._websocket_loop()

    assert call_log == [
        ("ws://one", 1),
        ("ws://one", 2),
        ("ws://one", 3),
        ("ws://two", 1),
    ]
    assert sleep_calls == [service._ws_reconnect_delay]


def test_ws_provider_prefers_persistent(monkeypatch, scout_modules):
    featured, _ = scout_modules

    persistent_module = sys.modules["web3.providers.persistent"]

    class PersistentProvider(FakeWebsocketProvider):
        pass

    monkeypatch.setattr(
        persistent_module, "WebSocketProvider", PersistentProvider, raising=False
    )

    assert featured.resolve_ws_provider_class() is PersistentProvider


def test_featured_scout_ws_provider_fallback(monkeypatch, caplog, tmp_path, scout_modules):
    featured, _ = scout_modules

    persistent_module = sys.modules["web3.providers.persistent"]
    monkeypatch.delattr(persistent_module, "WebSocketProvider", raising=False)
    monkeypatch.delattr(persistent_module, "AsyncWebSocketProvider", raising=False)
    websocket_module = sys.modules["web3.providers.websocket"]
    monkeypatch.delattr(websocket_module, "WebsocketProvider", raising=False)

    class FallbackProvider(FakeWebsocketProvider):
        pass

    monkeypatch.setattr(websocket_module, "WebsocketProviderV2", FallbackProvider, raising=False)

    config = featured.ScoutConfig(
        rpc_http_urls=("http://rpc",),
        rpc_ws_urls=("ws://one", "ws://two"),
        contract_address="0xabc",
        chain_id=None,
        api_root="http://api",
        admin_token="token",
        admin_refresh_token="refresh",
        admin_wallet_address="0x0000000000000000000000000000000000000001",
        admin_wallet_private_key="0x01",
        project_id_resolver_url=None,
        db_path=str(tmp_path / "featured_ws_fallback.db"),
        poll_interval_sec=1,
        reorg_confirmations=1,
        start_block=None,
        start_block_latest=True,
    )
    scout = featured.FeaturedScout(config, once=True)

    class ImmediateThread:
        def __init__(self, target, name=None, daemon=None):
            self._target = target
            self._started = False

        def start(self):
            self._started = True
            try:
                self._target()
            finally:
                self._started = False

        def is_alive(self):
            return self._started

        def join(self, timeout=None):  # pragma: no cover - interface compatibility
            return None

    monkeypatch.setattr(featured.threading, "Thread", ImmediateThread)

    call_log = []

    def fake_consume(url: str) -> None:
        call_log.append(url)
        if len(call_log) >= len(scout._ws_urls):
            scout._stop_event.set()

    monkeypatch.setattr(scout, "_consume_ws_url", fake_consume)

    caplog.set_level("WARNING")
    scout._start_ws_listener()

    assert scout._ws_thread is not None
    assert scout._ws_provider_class is FallbackProvider
    assert call_log == ["ws://one", "ws://two"]
    assert not any(
        "disabling live subscriptions" in record.message for record in caplog.records
    )

    scout.stop()


def test_pro_scout_ws_provider_fallback(monkeypatch, caplog, tmp_path, scout_modules):
    _, pro = scout_modules

    persistent_module = sys.modules["web3.providers.persistent"]
    monkeypatch.delattr(persistent_module, "WebSocketProvider", raising=False)
    monkeypatch.delattr(persistent_module, "AsyncWebSocketProvider", raising=False)
    websocket_module = sys.modules["web3.providers.websocket"]
    monkeypatch.delattr(websocket_module, "WebsocketProvider", raising=False)

    class FallbackProvider(FakeWebsocketProvider):
        pass

    monkeypatch.setattr(websocket_module, "WebsocketProviderV2", FallbackProvider, raising=False)

    class DummyBackendClient:
        base_url = "http://api"

        def patch(self, *args, **kwargs):
            return types.SimpleNamespace(status_code=200, text="")

    service = pro.ProScout(
        rpc_http_urls=("http://rpc",),
        rpc_ws_urls=["ws://one", "ws://two"],
        api_base_url="http://api",
        admin_access_token="token",
        admin_refresh_token="refresh",
        contract_address="0xabc",
        db_path=str(tmp_path / "pro_ws_fallback.db"),
        backend_client=DummyBackendClient(),
        poll_interval=1,
        reorg_conf=0,
    )

    class ImmediateThread:
        def __init__(self, target, name=None, daemon=None):
            self._target = target
            self._started = False

        def start(self):
            self._started = True
            try:
                self._target()
            finally:
                self._started = False

        def is_alive(self):
            return self._started

        def join(self, timeout=None):  # pragma: no cover - interface compatibility
            return None

    monkeypatch.setattr(pro.threading, "Thread", ImmediateThread)

    call_log = []

    def fake_consume(url: str) -> None:
        call_log.append(url)
        if len(call_log) >= len(service.rpc_ws_urls):
            service._stop_event.set()

    monkeypatch.setattr(service, "_consume_ws_url", fake_consume)

    caplog.set_level("WARNING")
    service._start_ws_listener()

    assert service._ws_thread is not None
    assert service._ws_provider_class is FallbackProvider
    assert call_log == ["ws://one", "ws://two"]
    assert not any(
        "disabling live subscriptions" in record.message for record in caplog.records
    )

    service.stop()


def test_iter_websocket_messages_handles_nested_request_processor_queue(monkeypatch):
    install_web3_stub(monkeypatch)
    from scout.websocket_helpers import iter_websocket_messages

    payloads = [{"result": 1}, {"result": 2}]

    class FakeRequestProcessor:
        def __init__(self, messages):
            self.ws_messages = queue.Queue()
            for message in messages:
                self.ws_messages.put(message)

    class NestedQueuePersistentProvider:
        def __init__(self, messages):
            self._request_processor = FakeRequestProcessor(messages)
            self.url = "ws://nested"
            self.websocket_kwargs = {"queue_source": self._request_processor.ws_messages}

    NestedQueuePersistentProvider.__module__ = "web3.providers.persistent.fake"

    class QueueAwarePersistentProvider(PersistentFakeWebsocketProvider):
        def __init__(self, url: str, websocket_kwargs=None, **kwargs):  # noqa: ANN001
            super().__init__(url, **kwargs)
            queue_source = (websocket_kwargs or {}).get("queue_source")
            if queue_source is not None:
                self.ws_messages = queue_source

    monkeypatch.setattr(
        websocket_helpers,
        "_WebsocketProviderFactory",
        QueueAwarePersistentProvider,
        raising=False,
    )

    provider = NestedQueuePersistentProvider(payloads)
    collected = []
    stop_event = types.SimpleNamespace(is_set=lambda: len(collected) >= len(payloads))

    for message in iter_websocket_messages(provider, stop_event, poll_interval=0.01):
        collected.append(message)

    assert collected == payloads
