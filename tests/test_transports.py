import importlib
import sys
import types

import pytest


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
    def __init__(self) -> None:
        self.block_number = 10
        self.logs = []

    def contract(self, address, abi):  # noqa: ANN001 - signature matches Web3
        events = types.SimpleNamespace()
        for entry in abi:
            setattr(events, entry["name"], FakeEvent(entry["name"]))
        return types.SimpleNamespace(events=events)

    def get_logs(self, params):  # noqa: ANN001 - mimic Web3 signature
        return list(self.logs)


class FakeHTTPProvider:
    def __init__(self, url: str, request_kwargs=None):
        self.url = url
        self.request_kwargs = request_kwargs or {}


class FakeWeb3:
    HTTPProvider = FakeHTTPProvider

    def __init__(self, provider):  # noqa: ANN001 - mimic Web3 signature
        self.provider = provider
        self.eth = FakeEth()
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


def install_web3_stub(monkeypatch):
    modules = {}
    for name in list(sys.modules):
        if name.startswith("web3"):
            modules[name] = sys.modules.pop(name)

    web3_module = types.ModuleType("web3")
    web3_module.Web3 = FakeWeb3
    web3_module.HTTPProvider = FakeHTTPProvider

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
    providers_module.websocket = websocket_module

    contract_module = types.ModuleType("web3.contract")
    contract_module.Contract = type("Contract", (), {})
    contract_module.ContractEvent = type("ContractEvent", (), {})

    monkeypatch.setitem(sys.modules, "web3", web3_module)
    monkeypatch.setitem(sys.modules, "web3._utils", utils_module)
    monkeypatch.setitem(sys.modules, "web3._utils.events", events_module)
    monkeypatch.setitem(sys.modules, "web3.datastructures", datastructures_module)
    monkeypatch.setitem(sys.modules, "web3.types", types_module)
    monkeypatch.setitem(sys.modules, "web3.providers", providers_module)
    monkeypatch.setitem(sys.modules, "web3.providers.websocket", websocket_module)
    monkeypatch.setitem(sys.modules, "web3.contract", contract_module)

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


def test_featured_scout_processes_http_and_websocket_logs(tmp_path, scout_modules):
    featured, _ = scout_modules
    config = featured.ScoutConfig(
        rpc_url="http://rpc",
        rpc_ws_urls=("ws://rpc",),
        contract_address="0xabc",
        chain_id=None,
        api_root="http://api",
        admin_token="token",
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


def test_pro_scout_processes_http_and_websocket_logs(tmp_path, scout_modules):
    _, pro = scout_modules

    class DummyBackendClient:
        base_url = "http://api"

        def patch(self, *args, **kwargs):
            return types.SimpleNamespace(status_code=200, text="")

    service = pro.ProScout(
        rpc_http_url="http://rpc",
        rpc_ws_urls=["ws://rpc"],
        api_base_url="http://api",
        admin_access_token="token",
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
