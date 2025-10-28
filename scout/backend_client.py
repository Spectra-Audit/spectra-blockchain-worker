"""HTTP client utilities for communicating with the Spectra backend."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Dict, Optional

import requests
from requests import Response, Session

LOGGER = logging.getLogger(__name__)


class BackendClient:
    """Shared HTTP client with retry and auth support."""

    def __init__(
        self,
        base_url: str,
        admin_token: str,
        *,
        session: Optional[Session] = None,
        max_attempts: int = 5,
        initial_delay: float = 0.5,
        max_delay: float = 8.0,
    ) -> None:
        if not base_url:
            raise ValueError("base_url is required")
        if not admin_token:
            raise ValueError("admin_token is required")

        self.base_url = base_url.rstrip("/")
        self._session = session or requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {admin_token}",
                "Accept": "application/json",
            }
        )
        self._lock = threading.Lock()
        self._max_attempts = max(1, max_attempts)
        self._initial_delay = max(0.0, initial_delay)
        self._max_delay = max(max_delay, self._initial_delay)

    # ------------------------------------------------------------------ request API
    def patch(
        self,
        path: str,
        *,
        json: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        timeout: Optional[float] = None,
        headers: Optional[Dict[str, str]] = None,
        raise_for_status: bool = True,
        should_retry: Optional[Callable[[], bool]] = None,
    ) -> Optional[Response]:
        return self._request_with_retries(
            "patch",
            path,
            json=json,
            data=data,
            timeout=timeout,
            headers=headers,
            raise_for_status=raise_for_status,
            should_retry=should_retry,
        )

    def get(
        self,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
        headers: Optional[Dict[str, str]] = None,
        raise_for_status: bool = True,
        should_retry: Optional[Callable[[], bool]] = None,
    ) -> Optional[Response]:
        return self._request_with_retries(
            "get",
            path,
            params=params,
            timeout=timeout,
            headers=headers,
            raise_for_status=raise_for_status,
            should_retry=should_retry,
        )

    def close(self) -> None:
        with self._lock:
            self._session.close()

    # ----------------------------------------------------------------- internals
    def _request_with_retries(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        timeout: Optional[float] = None,
        headers: Optional[Dict[str, str]] = None,
        raise_for_status: bool,
        should_retry: Optional[Callable[[], bool]] = None,
    ) -> Optional[Response]:
        delay = self._initial_delay
        for attempt in range(1, self._max_attempts + 1):
            if should_retry is not None and not should_retry():
                LOGGER.debug("Retry aborted by caller", extra={"method": method, "path": path})
                return None

            url = self._build_url(path)
            try:
                with self._lock:
                    response = self._session.request(
                        method,
                        url,
                        params=params,
                        json=json,
                        data=data,
                        timeout=timeout,
                        headers=headers,
                    )
            except (requests.Timeout, requests.ConnectionError) as exc:
                LOGGER.warning(
                    "HTTP request failed", extra={"url": url, "attempt": attempt, "error": str(exc)}
                )
                if attempt == self._max_attempts:
                    raise
                self._sleep(delay)
                delay = min(delay * 2, self._max_delay)
                continue

            if response.status_code == 429:
                retry_after = self._retry_after_delay(response)
                LOGGER.warning(
                    "HTTP 429 received", extra={"url": url, "attempt": attempt, "retry_after": retry_after}
                )
                self._sleep(retry_after)
                continue

            if 500 <= response.status_code < 600:
                LOGGER.warning(
                    "HTTP server error",
                    extra={"url": url, "status": response.status_code, "attempt": attempt},
                )
                if attempt == self._max_attempts:
                    if raise_for_status:
                        response.raise_for_status()
                    return response
                self._sleep(delay)
                delay = min(delay * 2, self._max_delay)
                continue

            if raise_for_status and response.status_code >= 400:
                response.raise_for_status()
            return response
        return None

    def _build_url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if not path:
            raise ValueError("path is required")
        if path.startswith("/"):
            return f"{self.base_url}{path}"
        return f"{self.base_url}/{path}"

    @staticmethod
    def _retry_after_delay(response: Response) -> float:
        retry_after = response.headers.get("Retry-After")
        if retry_after is None:
            return 1.0
        try:
            return float(retry_after)
        except ValueError:
            return 1.0

    @staticmethod
    def _sleep(seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)
