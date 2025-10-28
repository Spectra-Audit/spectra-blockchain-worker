"""Utilities for authenticating with the Spectra backend via SIWE."""

from __future__ import annotations

import logging
import threading
from typing import Callable, Tuple

import requests
from eth_account import Account
from eth_account.messages import encode_defunct

from .auth_wallet import AdminWallet
from .database_manager import DatabaseManager

LOGGER = logging.getLogger(__name__)

ACCESS_TOKEN_META_KEY = "admin_access_token"
REFRESH_TOKEN_META_KEY = "admin_refresh_token"


class SiweAuthenticationError(RuntimeError):
    """Raised when a SIWE authentication attempt fails."""


class SiweAuthenticator:
    """Coordinate SIWE authentication and token persistence."""

    def __init__(
        self,
        base_url: str,
        wallet: AdminWallet,
        database: DatabaseManager,
        *,
        session_factory: Callable[[], requests.Session] | None = None,
        timeout: float = 10.0,
    ) -> None:
        if not base_url:
            raise ValueError("base_url is required")
        self._base_url = base_url.rstrip("/")
        self._wallet = wallet
        self._database = database
        self._timeout = timeout
        self._session = (session_factory or requests.Session)()
        self._lock = threading.RLock()
        self._access_token = database.get_meta(ACCESS_TOKEN_META_KEY)
        self._refresh_token = database.get_meta(REFRESH_TOKEN_META_KEY)
        self._bootstrapped = False

    # ------------------------------------------------------------------ public API
    def get_tokens(self, force: bool = False) -> Tuple[str, str]:
        """Return the active access and refresh tokens."""

        with self._lock:
            if force:
                LOGGER.info("Performing forced SIWE authentication")
                self._bootstrapped = True
                return self._perform_handshake_locked()
            if not self._bootstrapped:
                self._bootstrapped = True
                if self._refresh_token:
                    try:
                        return self._refresh_tokens_locked()
                    except SiweAuthenticationError:
                        LOGGER.warning(
                            "Stored refresh token invalid, falling back to SIWE handshake"
                        )
                        return self._perform_handshake_locked()
                LOGGER.info("No cached tokens available, performing SIWE handshake")
                return self._perform_handshake_locked()
            if self._access_token and self._refresh_token:
                return self._access_token, self._refresh_token
            if self._refresh_token:
                try:
                    return self._refresh_tokens_locked()
                except SiweAuthenticationError:
                    LOGGER.warning(
                        "Refresh failed during token retrieval, performing SIWE handshake"
                    )
                    return self._perform_handshake_locked()
            LOGGER.info("Token cache empty, performing SIWE handshake")
            return self._perform_handshake_locked()

    def persist_tokens(self, access_token: str, refresh_token: str) -> None:
        """Persist *access_token* and *refresh_token* to the shared database."""

        if not access_token:
            raise ValueError("access_token is required")
        if not refresh_token:
            raise ValueError("refresh_token is required")
        with self._lock:
            self._persist_tokens_locked(access_token, refresh_token)

    # ----------------------------------------------------------------- internals
    def _perform_handshake_locked(self) -> Tuple[str, str]:
        nonce_payload = {"wallet_address": self._wallet.address}
        nonce_response = self._post("auth/nonce", json=nonce_payload)
        if nonce_response.status_code != 200:
            raise SiweAuthenticationError(
                f"Nonce request failed with status {nonce_response.status_code}"
            )
        try:
            nonce_data = nonce_response.json()
        except ValueError as exc:  # pragma: no cover - defensive
            raise SiweAuthenticationError("Nonce response missing JSON payload") from exc
        message = nonce_data.get("message")
        if not message:
            raise SiweAuthenticationError("Nonce response missing message")

        encoded = encode_defunct(text=message)
        signed = Account.sign_message(encoded, self._wallet.private_key)
        signature = signed.signature.hex()
        verify_payload = {
            "wallet_address": self._wallet.address,
            "message": message,
            "signature": signature,
        }
        verify_response = self._post("auth/verify", json=verify_payload)
        if verify_response.status_code != 200:
            raise SiweAuthenticationError(
                f"Verify request failed with status {verify_response.status_code}"
            )
        try:
            verify_data = verify_response.json()
        except ValueError as exc:  # pragma: no cover - defensive
            raise SiweAuthenticationError("Verify response missing JSON payload") from exc
        access_token = verify_data.get("access_token")
        refresh_token = verify_data.get("refresh_token")
        if not access_token or not refresh_token:
            raise SiweAuthenticationError("Verify response missing tokens")
        return self._persist_tokens_locked(access_token, refresh_token)

    def _refresh_tokens_locked(self) -> Tuple[str, str]:
        refresh_token = self._refresh_token
        if not refresh_token:
            raise SiweAuthenticationError("Refresh token unavailable")
        refresh_headers = {
            "Authorization": f"Bearer {refresh_token}",
            "Accept": "application/json",
        }
        refresh_payload = {"refresh_token": refresh_token}
        response = self._post(
            "auth/refresh",
            json=refresh_payload,
            headers=refresh_headers,
        )
        if response.status_code != 200:
            raise SiweAuthenticationError(
                f"Refresh request failed with status {response.status_code}"
            )
        try:
            data = response.json()
        except ValueError as exc:  # pragma: no cover - defensive
            raise SiweAuthenticationError("Refresh response missing JSON payload") from exc
        access_token = data.get("access_token")
        if not access_token:
            raise SiweAuthenticationError("Refresh response missing access_token")
        new_refresh = data.get("refresh_token") or refresh_token
        return self._persist_tokens_locked(access_token, new_refresh)

    def _persist_tokens_locked(self, access_token: str, refresh_token: str) -> Tuple[str, str]:
        self._database.set_meta(ACCESS_TOKEN_META_KEY, access_token)
        self._database.set_meta(REFRESH_TOKEN_META_KEY, refresh_token)
        self._access_token = access_token
        self._refresh_token = refresh_token
        self._bootstrapped = True
        return access_token, refresh_token

    def _post(self, path: str, **kwargs) -> requests.Response:
        url = self._build_url(path)
        kwargs.setdefault("timeout", self._timeout)
        try:
            if hasattr(self._session, "post"):
                return self._session.post(url, **kwargs)
            return self._session.request("post", url, **kwargs)  # pragma: no cover - fallback
        except (requests.Timeout, requests.ConnectionError) as exc:
            raise SiweAuthenticationError("Authentication request failed") from exc

    def _build_url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if path.startswith("/"):
            return f"{self._base_url}{path}"
        return f"{self._base_url}/{path}"

