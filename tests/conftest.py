"""Shared pytest configuration providing lightweight stubs for external deps."""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class RequestException(Exception):
    """Base exception matching ``requests.RequestException``."""


class Timeout(RequestException):
    """Stubbed timeout exception."""


class ConnectionError(RequestException):
    """Stubbed connection error."""


class HTTPError(RequestException):
    """Stubbed HTTP error."""


class Response:
    """Minimal ``requests.Response`` implementation for tests."""

    def __init__(self, status_code: int = 200) -> None:
        self.status_code = status_code
        self.headers: dict[str, str] = {}
        self._content: bytes = b""
        self.encoding: str | None = "utf-8"
        self.url: str = ""

    def raise_for_status(self) -> None:
        if 400 <= self.status_code < 600:
            raise HTTPError(f"HTTP {self.status_code}")

    def json(self) -> object:
        if not self._content:
            raise ValueError("No JSON content")
        encoding = self.encoding or "utf-8"
        return json.loads(self._content.decode(encoding))

    @property
    def text(self) -> str:
        encoding = self.encoding or "utf-8"
        return self._content.decode(encoding, errors="replace")


class Session:
    """Minimal ``requests.Session`` implementation for tests."""

    def __init__(self) -> None:
        self.headers: dict[str, str] = {}

    def request(self, *args, **kwargs):  # pragma: no cover - not used directly in tests
        raise NotImplementedError("Stub session does not implement network requests")

    def close(self) -> None:  # pragma: no cover - no resources to release
        pass


requests_stub = types.ModuleType("requests")
requests_stub.Session = Session
requests_stub.Response = Response
requests_stub.RequestException = RequestException
requests_stub.Timeout = Timeout
requests_stub.ConnectionError = ConnectionError
requests_stub.HTTPError = HTTPError

sys.modules.setdefault("requests", requests_stub)


class _Web3:
    HTTPProvider = staticmethod(lambda *args, **kwargs: object())
    to_checksum_address = staticmethod(lambda value: value)
    to_hex = staticmethod(lambda value: value if isinstance(value, str) else "0x0")

    def __init__(self, *args, **kwargs) -> None:
        self.eth = types.SimpleNamespace(
            chain_id=1,
            contract=lambda *a, **k: types.SimpleNamespace(events=types.SimpleNamespace()),
            get_logs=lambda *a, **k: [],
            block_number=0,
        )

    def is_connected(self) -> bool:  # pragma: no cover - simple stub
        return True

    def keccak(self, text: str) -> bytes:  # pragma: no cover - simple stub
        return b"\x00" * 32


web3_stub = types.ModuleType("web3")
web3_stub.Web3 = _Web3
sys.modules.setdefault("web3", web3_stub)

contract_module = types.ModuleType("web3.contract")
contract_module.Contract = type("Contract", (), {})


class _ContractEvent:
    def __call__(self, *args, **kwargs):  # pragma: no cover - simple stub
        return types.SimpleNamespace(processLog=lambda log: types.SimpleNamespace(event="", args={}))


contract_module.ContractEvent = _ContractEvent
sys.modules.setdefault("web3.contract", contract_module)

types_module = types.ModuleType("web3.types")
types_module.EventData = dict
types_module.FilterParams = dict
types_module.LogReceipt = dict
sys.modules.setdefault("web3.types", types_module)

datastructures_module = types.ModuleType("web3.datastructures")
datastructures_module.AttributeDict = dict
sys.modules.setdefault("web3.datastructures", datastructures_module)

utils_module = types.ModuleType("web3._utils")
events_module = types.ModuleType("web3._utils.events")
events_module.get_event_data = lambda *args, **kwargs: {}  # type: ignore[assignment]
sys.modules.setdefault("web3._utils", utils_module)
sys.modules.setdefault("web3._utils.events", events_module)
