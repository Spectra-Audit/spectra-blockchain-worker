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
        admin_token: Optional[str] = None,
        admin_refresh_token: Optional[str] = None,
        *,
        token_provider: Optional[Callable[[bool], tuple[str, str]]] = None,
        token_persistor: Optional[Callable[[str, str], None]] = None,
        session: Optional[Session] = None,
        max_attempts: int = 5,
        initial_delay: float = 0.5,
        max_delay: float = 8.0,
    ) -> None:
        if not base_url:
            raise ValueError("base_url is required")

        self.base_url = base_url.rstrip("/")
        self._session = session or requests.Session()
        self._lock = threading.Lock()
        self._token_provider = token_provider
        self._token_persistor = token_persistor
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._session.headers.update({"Accept": "application/json"})

        self._bootstrapped = False
        if admin_token and admin_refresh_token:
            self.update_tokens(admin_token, admin_refresh_token)
            self._bootstrapped = True
        else:
            if self._token_provider is None:
                raise ValueError("Authentication tokens or token_provider required")
            # Defer authentication — don't block startup if backend is not ready yet.
            # The first actual API call will trigger lazy bootstrap.
            LOGGER.info("Backend client created with lazy token bootstrap (will auth on first request)")
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

    def post(
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
            "post",
            path,
            json=json,
            data=data,
            timeout=timeout,
            headers=headers,
            raise_for_status=raise_for_status,
            should_retry=should_retry,
        )

    # ------------------------------------------------------------- audit helpers
    def store_audit_results(
        self,
        project_id: str,
        audit_data: Dict[str, Any],
    ) -> bool:
        """Store audit results for a project.

        Args:
            project_id: Project UUID
            audit_data: Audit results dictionary

        Returns:
            True if successful, False otherwise
        """
        from datetime import datetime
        import os

        endpoint = f"admin/projects/{project_id}/audit-results"
        payload = {
            "audit_data": audit_data,
            "completed_at": datetime.utcnow().isoformat(),
        }

        # Add internal API secret header for authentication
        internal_secret = os.environ.get("INTERNAL_API_SECRET")
        headers = {}
        if internal_secret:
            headers["X-Internal-Api-Secret"] = internal_secret

        try:
            response = self.patch(endpoint, json=payload, headers=headers)
            if response and response.status_code == 200:
                LOGGER.info(f"Stored audit results for project {project_id[:8]}...")
                return True

        except Exception as e:
            LOGGER.error(f"Failed to store audit results for {project_id[:8]}...: {e}")

        return False

    def get_projects_for_update(self) -> list[Dict[str, Any]]:
        """Get projects that need dynamic data updates.

        Returns:
            List of projects with token addresses
        """
        try:
            response = self.get("/projects?needs_update=true")
            if response and response.status_code == 200:
                data = response.json()
                return data.get("projects", [])

        except Exception as e:
            LOGGER.error(f"Failed to get projects for update: {e}")

        return []

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
        # Lazy token bootstrap — authenticate on first actual API call
        if not self._bootstrapped:
            with self._lock:
                if not self._bootstrapped:
                    try:
                        self._bootstrap_tokens(force=False)
                        self._bootstrapped = True
                        LOGGER.info("Lazy token bootstrap succeeded on first API call")
                    except Exception as exc:
                        LOGGER.warning("Lazy token bootstrap failed (will retry): %s", exc)
                        self._bootstrapped = False
                        raise

        delay = self._initial_delay
        token_refreshed = False
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

            if response.status_code == 401:
                if token_refreshed:
                    if raise_for_status:
                        response.raise_for_status()
                    return response
                try:
                    self._refresh_access_token()
                except Exception as exc:  # pragma: no cover - defensive
                    LOGGER.error("Failed to refresh admin token", exc_info=exc)
                    raise RuntimeError("Unable to refresh admin access token") from exc
                token_refreshed = True
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

    def get_access_token(self) -> Optional[str]:
        """Get the current access token.

        Returns:
            Current access token or None if not authenticated
        """
        with self._lock:
            return self._access_token

    def update_tokens(self, access_token: str, refresh_token: Optional[str] = None) -> None:
        if not access_token:
            raise ValueError("access_token is required")
        if refresh_token is not None and not refresh_token:
            raise ValueError("refresh_token cannot be empty")
        current_access: Optional[str]
        current_refresh: Optional[str]
        with self._lock:
            self._access_token = access_token
            if refresh_token is not None:
                self._refresh_token = refresh_token
            current_access = self._access_token
            current_refresh = self._refresh_token
            self._session.headers.update({"Authorization": f"Bearer {current_access}"})
        if self._token_persistor and current_access and current_refresh:
            self._token_persistor(current_access, current_refresh)

    def _refresh_access_token(self) -> None:
        refresh_token = self._refresh_token
        if not refresh_token:
            self._bootstrap_tokens(force=True)
            return
        url = self._build_url("auth/refresh")
        payload = {"refresh_token": refresh_token}
        headers = {
            "Authorization": f"Bearer {refresh_token}",
            "Accept": "application/json",
        }
        try:
            with self._lock:
                response = self._session.request(
                    "post",
                    url,
                    json=payload,
                    headers=headers,
                    timeout=10,
                )
        except (requests.Timeout, requests.ConnectionError) as exc:
            LOGGER.warning("Refresh request failed", extra={"error": str(exc)})
            self._bootstrap_tokens(force=True)
            return
        if response.status_code != 200:
            LOGGER.warning(
                "Refresh request returned error",
                extra={"status": response.status_code},
            )
            self._bootstrap_tokens(force=True)
            return
        try:
            data = response.json()
        except ValueError as exc:  # pragma: no cover - invalid backend response
            LOGGER.error("Invalid refresh response", exc_info=exc)
            self._bootstrap_tokens(force=True)
            return
        access_token = data.get("access_token")
        if not access_token:
            LOGGER.error("Refresh response missing access_token")
            self._bootstrap_tokens(force=True)
            return
        new_refresh = data.get("refresh_token") or refresh_token
        self.update_tokens(access_token, new_refresh)

    def _bootstrap_tokens(self, force: bool) -> None:
        if self._token_provider is None:
            raise RuntimeError("Authentication tokens unavailable")
        tokens = self._token_provider(force)
        if not isinstance(tokens, tuple) or len(tokens) != 2:
            raise RuntimeError("token_provider must return (access_token, refresh_token)")
        access_token, refresh_token = tokens
        if not access_token or not refresh_token:
            raise RuntimeError("token_provider returned invalid tokens")
        self.update_tokens(access_token, refresh_token)

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
