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
    database.set_meta(ADMIN_WALLET_ADDRESS_META, wallet.address)
    # NOTE: Private key is NEVER stored in the database.
    # It must always come from the ADMIN_WALLET_PRIVATE_KEY env var.


def load_or_create_admin_wallet(database: DatabaseManager) -> AdminWallet:
    """Load the admin wallet or create a new one.

    Private key is ALWAYS read from environment variables only.
    Database only stores the wallet address for reference.

    Priority order:
    1. Environment variables (ADMIN_WALLET_ADDRESS, ADMIN_WALLET_PRIVATE_KEY)
    2. Generate new wallet (will log address for configuration)

    When creating a new wallet the operator is prompted to confirm that the
    backend has been configured with the generated address. Automated
    environments can skip the prompt by setting ``SCOUT_SKIP_WALLET_PROMPT``.
    """

    # 1. Check environment variables (required for private key)
    env_address = os.environ.get(ADMIN_WALLET_ADDRESS_ENV)
    env_private_key = os.environ.get(ADMIN_WALLET_PRIVATE_KEY_ENV)

    if env_private_key:
        # Private key provided via env var — derive or verify address
        account = Account.from_key(env_private_key)
        derived_address = account.address

        if env_address:
            # Both provided — verify they match
            if account.address.lower() != env_address.lower():
                raise ValueError(
                    f"Environment variable mismatch: ADMIN_WALLET_ADDRESS ({env_address}) "
                    f"does not match private key ({account.address})"
                )
            LOGGER.info(f"Using admin wallet from environment variables: {env_address}")
        else:
            # Only private key provided — derive address
            LOGGER.info(f"Using admin wallet derived from private key: {derived_address}")
            env_address = derived_address

        return AdminWallet(address=env_address, private_key=env_private_key)

    # 2. No private key in env — cannot proceed without one
    # Check if address is in DB for a helpful error message
    stored_address = database.get_meta(ADMIN_WALLET_ADDRESS_META)

    if stored_address:
        LOGGER.error(
            f"Admin wallet address found in DB ({stored_address}) but "
            f"ADMIN_WALLET_PRIVATE_KEY env var is not set. "
            f"Set the env var to continue."
        )
        raise RuntimeError(
            f"ADMIN_WALLET_PRIVATE_KEY environment variable is required. "
            f"Wallet address {stored_address} was previously used."
        )

    # 3. Generate new wallet (only used for initial setup)
    account = Account.create()
    private_key = account.key.hex()
    checksum_address = account.address
    wallet = AdminWallet(address=checksum_address, private_key=private_key)
    _persist_wallet(database, wallet)
    LOGGER.warning("Created new admin wallet", extra={"address": checksum_address})

    if not os.environ.get(SKIP_PROMPT_ENV_VAR):
        LOGGER.warning(
            "IMPORTANT: add ADMIN_WALLET_PRIVATE_KEY and ADMIN_WALLET_ADDRESS=%s "
            "to your secret manager. The private key will NOT be stored in the "
            "database on next startup.",
            checksum_address,
        )
    else:
        # Log the wallet details prominently for Railway deployments
        LOGGER.info(f"New admin wallet created: {checksum_address}")
        LOGGER.info(f"Add these to your environment:")
        LOGGER.info(f"  ADMIN_WALLET_ADDRESS={checksum_address}")
        LOGGER.info("  ADMIN_WALLET_PRIVATE_KEY=<redacted>")

    return wallet
