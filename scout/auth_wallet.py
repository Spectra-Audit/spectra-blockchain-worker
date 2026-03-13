"""Utilities for managing the admin wallet credentials."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from eth_account import Account

from .database_manager import DatabaseManager

LOGGER = logging.getLogger(__name__)

ADMIN_WALLET_PRIVATE_KEY_META = "admin_wallet_private_key"
ADMIN_WALLET_ADDRESS_META = "admin_wallet_address"
SKIP_PROMPT_ENV_VAR = "SCOUT_SKIP_WALLET_PROMPT"
ADMIN_WALLET_ADDRESS_ENV = "ADMIN_WALLET_ADDRESS"
ADMIN_WALLET_PRIVATE_KEY_ENV = "ADMIN_WALLET_PRIVATE_KEY"


@dataclass(frozen=True)
class AdminWallet:
    """Immutable representation of the admin wallet credentials."""

    address: str
    private_key: str


def _persist_wallet(database: DatabaseManager, wallet: AdminWallet) -> None:
    database.set_meta(ADMIN_WALLET_PRIVATE_KEY_META, wallet.private_key)
    database.set_meta(ADMIN_WALLET_ADDRESS_META, wallet.address)


def _load_wallet_from_meta(database: DatabaseManager) -> AdminWallet | None:
    private_key = database.get_meta(ADMIN_WALLET_PRIVATE_KEY_META)
    address = database.get_meta(ADMIN_WALLET_ADDRESS_META)
    if not private_key:
        return None
    account = Account.from_key(private_key)
    checksum_address = account.address
    if address != checksum_address:
        database.set_meta(ADMIN_WALLET_ADDRESS_META, checksum_address)
    return AdminWallet(address=checksum_address, private_key=private_key)


def load_or_create_admin_wallet(database: DatabaseManager) -> AdminWallet:
    """Load the persisted admin wallet or create a new one.

    Priority order:
    1. Environment variables (ADMIN_WALLET_ADDRESS, ADMIN_WALLET_PRIVATE_KEY)
    2. Database metadata (for persistence across restarts)
    3. Generate new wallet (will log address for configuration)

    When creating a new wallet the operator is prompted to confirm that the
    backend has been configured with the generated address. Automated
    environments can skip the prompt by setting ``SCOUT_SKIP_WALLET_PROMPT``.
    """

    # 1. Check environment variables first (for Railway deployments)
    env_address = os.environ.get(ADMIN_WALLET_ADDRESS_ENV)
    env_private_key = os.environ.get(ADMIN_WALLET_PRIVATE_KEY_ENV)

    if env_address and env_private_key:
        LOGGER.info(f"Using admin wallet from environment variables: {env_address}")
        # Verify the private key matches the address
        account = Account.from_key(env_private_key)
        if account.address.lower() != env_address.lower():
            raise ValueError(
                f"Environment variable mismatch: ADMIN_WALLET_ADDRESS ({env_address}) "
                f"does not match private key ({account.address})"
            )
        return AdminWallet(address=env_address, private_key=env_private_key)

    # 2. Check database metadata
    wallet = _load_wallet_from_meta(database)
    if wallet is not None:
        LOGGER.info(f"Using admin wallet from database: {wallet.address}")
        return wallet

    # 3. Generate new wallet
    account = Account.create()
    private_key = account.key.hex()
    checksum_address = account.address
    wallet = AdminWallet(address=checksum_address, private_key=private_key)
    _persist_wallet(database, wallet)
    LOGGER.warning("Created new admin wallet", extra={"address": checksum_address})

    if not os.environ.get(SKIP_PROMPT_ENV_VAR):
        print(f"New admin wallet created: {checksum_address}")
        print("Ensure backend admin privileges are granted to this address.")
        input("Press Enter once backend access has been configured...")
    else:
        # Log the wallet address prominently for Railway deployments
        LOGGER.info(f"New admin wallet created: {checksum_address}")
        LOGGER.info(f"Add this address to backend ADMIN_WALLETS: {checksum_address}")
        LOGGER.info(
            "Skipping admin wallet acknowledgement prompt", extra={"env": SKIP_PROMPT_ENV_VAR}
        )

    return wallet
