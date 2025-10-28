"""Unit tests for the shared backend HTTP client and consumers."""

from __future__ import annotations

import json
import logging
import threading
from types import SimpleNamespace
from typing import Iterator
from unittest.mock import Mock

import pytest
import requests
from requests import Response, Session

from scout.backend_client import BackendClient
from scout.pro_scout import ProScout
from scout.featured_scout import FeaturedScout


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Avoid slowdowns from retry backoff in tests."""

    monkeypatch.setattr("scout.backend_client.time.sleep", lambda _seconds: None)
    yield


def _make_response(status: int, payload: dict | None = None, headers: dict | None = None) -> Response:
    response = Response()
    response.status_code = status
    response.headers.update(headers or {})
    if payload is not None:
        response._content = json.dumps(payload).encode("utf-8")
        response.headers.setdefault("Content-Type", "application/json")
    else:
        response._content = b""
    response.encoding = "utf-8"
    response.url = "http://test.local/resource"
    return response


def test_backend_client_retries_on_server_error() -> None:
    session = Mock(spec=Session)
    session.headers = {}
    session.request.side_effect = [
        _make_response(500),
        _make_response(200, {"ok": True}),
    ]
    client = BackendClient(
        "http://api.local",
        "token",
        "refresh-token",
        session=session,
        max_attempts=2,
    )

    response = client.patch("/resource", json={"key": "value"}, raise_for_status=False)

    assert response is not None
    assert response.status_code == 200
    assert session.request.call_count == 2


def test_backend_client_abort_when_should_retry_returns_false() -> None:
    session = Mock(spec=Session)
    session.headers = {}
    session.request.side_effect = requests.Timeout("boom")
    client = BackendClient(
        "http://api.local",
        "token",
        "refresh-token",
        session=session,
        max_attempts=3,
    )


def test_backend_client_refreshes_token_on_unauthorized() -> None:
    session = Mock(spec=Session)
    session.headers = {}
    session.request.side_effect = [
        _make_response(401),
        _make_response(200, {"ok": True}),
    ]
    session.post = Mock(  # type: ignore[assignment]
        return_value=_make_response(
            200,
            {
                "access_token": "new-access",
                "refresh_token": "new-refresh",
            },
        )
    )
    client = BackendClient(
        "http://api.local",
        "old-access",
        "old-refresh",
        session=session,
        max_attempts=2,
    )

    response = client.get("/resource", raise_for_status=False)

    assert response is not None
    assert response.status_code == 200
    session.post.assert_called_once_with(
        "http://api.local/auth/refresh",
        json={"refresh_token": "old-refresh"},
        timeout=10,
    )
    assert session.request.call_count == 2
    assert getattr(client, "_refresh_token") == "new-refresh"


def test_pro_scout_patch_user_uses_backend_client() -> None:
    pro = ProScout.__new__(ProScout)
    pro.logger = logging.getLogger("ProScoutTest")
    pro._stop_event = threading.Event()
    pro.api_base_url = "http://api.local"
    backend_client = Mock()
    backend_client.patch.return_value = _make_response(200)
    pro.backend_client = backend_client

    result = ProScout._patch_user(pro, "0xabc", {"tier": "gold"})

    assert result is True
    assert backend_client.patch.call_count == 1
    args, kwargs = backend_client.patch.call_args
    assert args[0] == "http://api.local/v1/user/0xabc"
    assert kwargs["json"] == {"tier": "gold"}
    assert kwargs["raise_for_status"] is False
    assert callable(kwargs["should_retry"])


def test_pro_scout_patch_user_handles_client_error(caplog: pytest.LogCaptureFixture) -> None:
    pro = ProScout.__new__(ProScout)
    pro.logger = logging.getLogger("ProScoutTest")
    pro._stop_event = threading.Event()
    pro.api_base_url = "http://api.local"
    backend_client = Mock()
    backend_client.patch.return_value = _make_response(400, payload={"error": "bad"})
    pro.backend_client = backend_client

    with caplog.at_level(logging.ERROR):
        result = ProScout._patch_user(pro, "0xabc", {"tier": "gold"})

    assert result is False
    assert any("HTTP client error" in message for message in caplog.messages)


def test_featured_scout_resolver_uses_backend_client() -> None:
    featured = FeaturedScout.__new__(FeaturedScout)
    featured._db = SimpleNamespace(  # type: ignore[attr-defined]
        get_project_mapping=lambda _key: None,
        set_project_mapping=lambda *_args, **_kwargs: None,
    )
    featured._config = SimpleNamespace(project_id_resolver_url="http://resolver.local")  # type: ignore[attr-defined]
    backend_client = Mock()
    backend_client.get.return_value = _make_response(200, {"backend_id": "proj-1"})
    featured._client = backend_client  # type: ignore[attr-defined]

    project_hex = "0x" + "1" * 64
    backend_id = FeaturedScout._resolve_backend_project_id(featured, project_hex)

    assert backend_id == "proj-1"
    backend_client.get.assert_called_once_with(
        "http://resolver.local",
        params={"project_id_hex": project_hex},
        timeout=10,
        raise_for_status=False,
    )


def test_featured_scout_resolver_handles_error_response(caplog: pytest.LogCaptureFixture) -> None:
    featured = FeaturedScout.__new__(FeaturedScout)
    featured._db = SimpleNamespace(  # type: ignore[attr-defined]
        get_project_mapping=lambda _key: None,
        set_project_mapping=lambda *_args, **_kwargs: None,
    )
    featured._config = SimpleNamespace(project_id_resolver_url="http://resolver.local")  # type: ignore[attr-defined]
    backend_client = Mock()
    backend_client.get.return_value = _make_response(404)
    featured._client = backend_client  # type: ignore[attr-defined]

    project_hex = "0x" + "2" * 64
    with caplog.at_level(logging.ERROR):
        backend_id = FeaturedScout._resolve_backend_project_id(featured, project_hex)

    assert backend_id is None
    assert any("Resolver returned error" in message for message in caplog.messages)
