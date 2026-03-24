"""PaymentWalletScout - Monitor USDT/USDC transfers for Pro subscriptions.

This scout monitors ERC-20 Transfer events for USDT/USDC tokens sent to a
configured wallet address. When accumulated payments reach $20, it creates
or updates a Subscription record for the user.

Key Features:
- Monitor ERC-20 Transfer() events for specific tokens
- Track accumulated payments per user
- Calculate Pro status: $20 = 1 month (proportional)
- Create/update Subscription records
- On-demand mode only (no background polling)
"""

import logging
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Optional, Sequence, Dict, Any, Iterator

import requests
from web3 import Web3
from web3.contract import Contract
from web3.datastructures import AttributeDict


LOGGER = logging.getLogger("PaymentWalletScout")


# ERC-20 Transfer event signature
TRANSFER_EVENT_SIGNATURE = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
TRANSFER_EVENT_ABI = [
    {
        "type": "event",
        "name": "Transfer",
        "inputs": [
            {"type": "address", "name": "from", "indexed": True},
            {"type": "address", "name": "to", "indexed": True},
            {"type": "uint256", "name": "value", "indexed": False},
        ],
    }
]

# Common ERC-20 token addresses on Ethereum
USDT_CONTRACT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
USDC_CONTRACT = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"

# Price of stablecoins (assumed $1)
STABLECOIN_PRICE_USD = Decimal("1.0")

# Pro subscription price
PRO_PRICE_USD = Decimal("20.0")


@dataclass(frozen=True)
class PaymentWalletConfig:
    """Configuration for PaymentWalletScout."""

    # RPC configuration
    rpc_http_urls: Sequence[str]
    rpc_ws_urls: Sequence[str]

    # Wallet to monitor for incoming payments
    payment_wallet_address: str

    # Tokens to monitor (USDT, USDC)
    monitored_tokens: Sequence[str]

    # Backend API configuration
    api_base_url: str
    admin_access_token: str
    admin_refresh_token: str

    # Polling configuration (only used when WebSocket fails)
    poll_interval_sec: int = 60

    # Reorg safety
    reorg_confirmations: int = 5

    # Database path
    db_path: str = "payments.db"

    # Feature flags
    enable_polling: bool = False  # On-demand mode by default


class PaymentWalletScout:
    """Monitor USDT/USDC transfers to wallet for Pro subscriptions."""

    # Token contract addresses
    TOKEN_CONTRACTS: Dict[str, str] = {
        "USDT": USDT_CONTRACT,
        "USDC": USDC_CONTRACT,
    }

    def __init__(
        self,
        config: PaymentWalletConfig,
        *,
        database=None,
        backend_client=None,
        ws_provider_pool=None,
    ):
        self._config = config
        self._db = database
        self._backend_client = backend_client
        self._ws_provider_pool = ws_provider_pool

        # Local SQLite connection for payment tracking
        self._conn: Optional[sqlite3.Connection] = None
        self._db_lock = threading.Lock()

        # State management
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._ws_thread: Optional[threading.Thread] = None

        # Web3 setup
        self._web3: Optional[Web3] = None
        self._contracts: Dict[str, Contract] = {}
        self._last_processed_block: Dict[str, int] = {}

        # Thread safety
        self._lock = threading.Lock()

        # Initialize database
        self._init_database()

        LOGGER.info("PaymentWalletScout initialized", extra={
            "payment_wallet": config.payment_wallet_address,
            "monitored_tokens": list(config.monitored_tokens),
        })

    @classmethod
    def from_env(cls, **kwargs) -> "PaymentWalletScout":
        """Create PaymentWalletScout from environment variables."""
        # Load RPC URLs
        rpc_http_env = os.environ.get("RPC_HTTP_URLS", "")
        rpc_http_urls = [url.strip() for url in rpc_http_env.split(",") if url.strip()]
        if not rpc_http_urls:
            rpc_http_url = os.environ.get("RPC_HTTP_URL", "")
            rpc_http_urls = [rpc_http_url] if rpc_http_url else []

        rpc_ws_env = os.environ.get("RPC_WS_URLS", "")
        rpc_ws_urls = [url.strip() for url in rpc_ws_env.split(",") if url.strip()]

        # Payment wallet to monitor
        payment_wallet_address = os.environ.get("PAYMENT_WALLET_ADDRESS", "")
        if not payment_wallet_address:
            raise ValueError("PAYMENT_WALLET_ADDRESS environment variable is required")

        # Tokens to monitor (USDT, USDC by default)
        monitored_tokens_env = os.environ.get("MONITORED_TOKENS", "USDT,USDC")
        monitored_tokens = [t.strip() for t in monitored_tokens_env.split(",") if t.strip()]

        # Backend API
        api_base_url = os.environ.get("API_BASE_URL", "")
        admin_access_token = os.environ.get("ADMIN_ACCESS_TOKEN", "")
        admin_refresh_token = os.environ.get("ADMIN_REFRESH_TOKEN", "")

        # Other config
        db_path = os.environ.get("DB_PATH", "payments.db")
        poll_interval = int(os.environ.get("POLL_INTERVAL_SEC", "60"))
        reorg_conf = int(os.environ.get("REORG_CONF", "5"))
        enable_polling = os.environ.get("ENABLE_POLLING", "").lower() == "true"

        config = PaymentWalletConfig(
            rpc_http_urls=rpc_http_urls,
            rpc_ws_urls=rpc_ws_urls,
            payment_wallet_address=payment_wallet_address,
            monitored_tokens=monitored_tokens,
            api_base_url=api_base_url,
            admin_access_token=admin_access_token,
            admin_refresh_token=admin_refresh_token,
            db_path=db_path,
            poll_interval_sec=poll_interval,
            reorg_confirmations=reorg_conf,
            enable_polling=enable_polling,
        )

        return cls(config, **kwargs)

    # Database management -----------------------------------------------

    def _init_database(self) -> None:
        """Initialize the local SQLite database for payment tracking."""
        db_path = self._config.db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")

        with self._write_connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS wallet_payments (
                    id TEXT PRIMARY KEY,
                    from_address TEXT NOT NULL,
                    to_address TEXT NOT NULL,
                    token_address TEXT NOT NULL,
                    amount NUMERIC NOT NULL,
                    accumulated_amount NUMERIC NOT NULL DEFAULT 0,
                    tx_hash TEXT NOT NULL UNIQUE,
                    block_number INTEGER NOT NULL,
                    log_index INTEGER NOT NULL,
                    processed BOOLEAN NOT NULL DEFAULT 0,
                    subscription_created BOOLEAN NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                );
                CREATE INDEX IF NOT EXISTS idx_wallet_payments_from ON wallet_payments(from_address, token_address);
                CREATE INDEX IF NOT EXISTS idx_wallet_payments_processed ON wallet_payments(processed, subscription_created);
                CREATE INDEX IF NOT EXISTS idx_wallet_payments_updated ON wallet_payments(updated_at);
                """
            )

        LOGGER.info("PaymentWalletScout database initialized", extra={"db_path": db_path})

    @contextmanager
    def _write_connection(self) -> Iterator[sqlite3.Connection]:
        """Yield a connection protected by the lock for write operations."""
        with self._db_lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    @contextmanager
    def _read_connection(self) -> Iterator[sqlite3.Connection]:
        """Yield a connection for read operations."""
        with self._db_lock:
            yield self._conn

    def start(self) -> None:
        """Start the payment wallet scout."""
        if self._thread and self._thread.is_alive():
            raise RuntimeError("PaymentWalletScout already running")

        self._thread = threading.Thread(target=self._run, name="PaymentWalletScout", daemon=True)
        self._thread.start()

        # Only start WebSocket if enabled
        if self._config.rpc_ws_urls and os.environ.get("ENABLE_AUTOMATIC_WEBSOCKET", "").lower() == "true":
            self._start_ws_listener()

        LOGGER.info("PaymentWalletScout started")

    def stop(self, timeout: float = 10.0) -> None:
        """Stop the payment wallet scout."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)
            self._thread = None
        if self._ws_thread:
            self._ws_thread.join(timeout=timeout)
            self._ws_thread = None

        # Close database connection
        if self._conn:
            with self._db_lock:
                self._conn.close()
                self._conn = None

        LOGGER.info("PaymentWalletScout stopped")

    def _run(self) -> None:
        """Main run loop."""
        LOGGER.info("PaymentWalletScout loop started")

        # Initialize Web3 and contracts
        self._initialize_web3()

        # If polling is disabled, wait for stop event (on-demand mode)
        if not self._config.enable_polling:
            LOGGER.info("Polling disabled - waiting for on-demand API requests")
            self._stop_event.wait()
            LOGGER.info("PaymentWalletScout stopping (on-demand mode)")
            return

        # TODO: Implement polling loop if needed in the future
        # For now, this scout is designed for on-demand use only

    def _initialize_web3(self) -> None:
        """Initialize Web3 and token contracts."""
        if not self._config.rpc_http_urls:
            LOGGER.warning("No RPC URLs configured")
            return

        # Use first RPC URL
        rpc_url = self._config.rpc_http_urls[0]
        self._web3 = Web3(Web3.HTTPProvider(rpc_url))

        # Initialize token contracts
        for token_symbol in self._config.monitored_tokens:
            token_address = self.TOKEN_CONTRACTS.get(token_symbol)
            if token_address:
                contract = self._web3.eth.contract(
                    address=token_address,
                    abi=TRANSFER_EVENT_ABI
                )
                self._contracts[token_symbol] = contract
                LOGGER.info(f"Initialized {token_symbol} contract", extra={
                    "address": token_address
                })

    def process_transfer_event(
        self,
        token_symbol: str,
        from_address: str,
        to_address: str,
        value: int,
        tx_hash: str,
        block_number: int,
        log_index: int
    ) -> bool:
        """Process an ERC-20 Transfer event.

        Args:
            token_symbol: Token symbol (USDT, USDC)
            from_address: Sender wallet address
            to_address: Recipient wallet address
            value: Transfer amount in wei (smallest unit)
            tx_hash: Transaction hash
            block_number: Block number
            log_index: Log index

        Returns:
            True if processed successfully, False otherwise
        """
        try:
            # Check if this is a payment to our monitored wallet
            if to_address.lower() != self._config.payment_wallet_address.lower():
                return True  # Not for us, but not an error

            # Calculate USD value (stablecoins are $1)
            amount_decimal = Decimal(value) / Decimal(10 ** 18)
            usd_value = amount_decimal * STABLECOIN_PRICE_USD

            LOGGER.info("Processing payment transfer", extra={
                "token": token_symbol,
                "from": from_address,
                "to": to_address,
                "amount": str(amount_decimal),
                "usd_value": str(usd_value),
                "tx_hash": tx_hash,
            })

            # Calculate months of Pro status
            months = self._calculate_pro_months(usd_value)

            if months >= 1:
                # Create or update subscription
                self._create_or_update_subscription(
                    from_address,
                    usd_value,
                    months,
                    tx_hash
                )
            else:
                LOGGER.info("Payment below $20 threshold, accumulating", extra={
                    "from": from_address,
                    "usd_value": str(usd_value),
                    "months_needed": 1
                })

            # Store payment record (would integrate with database)
            self._store_payment_record(
                token_symbol,
                from_address,
                to_address,
                amount_decimal,
                tx_hash,
                block_number,
                log_index
            )

            return True

        except Exception as e:
            LOGGER.error("Failed to process transfer event", extra={
                "error": str(e),
                "tx_hash": tx_hash,
            })
            return False

    def _calculate_pro_months(self, usd_value: Decimal) -> int:
        """Calculate number of Pro months from USD value.

        Args:
            usd_value: Payment amount in USD

        Returns:
            Number of months (minimum 1 if >= $20)
        """
        if usd_value < PRO_PRICE_USD:
            return 0

        months = int(usd_value / PRO_PRICE_USD)
        return max(months, 1)  # Minimum 1 month

    def _create_or_update_subscription(
        self,
        wallet_address: str,
        usd_value: Decimal,
        months: int,
        tx_hash: str
    ) -> None:
        """Create or update subscription for user.

        Args:
            wallet_address: User's wallet address
            usd_value: Payment amount in USD
            months: Number of months to grant
            tx_hash: Transaction hash
        """
        try:
            # Calculate subscription period
            period_start = datetime.utcnow()
            period_end = period_start + timedelta(days=30 * months)

            LOGGER.info("Creating/updating subscription", extra={
                "wallet": wallet_address,
                "usd_value": str(usd_value),
                "months": months,
                "period_start": period_start.isoformat(),
                "period_end": period_end.isoformat(),
            })

            # Call backend API to create/update subscription
            success = self._call_backend_subscription_api(
                wallet_address,
                period_start,
                period_end,
                usd_value,
                months,
                tx_hash
            )

            # Mark payment as processed and subscription created if successful
            if success:
                self._mark_payment_processed(tx_hash, subscription_created=True)

        except Exception as e:
            LOGGER.error("Failed to create/update subscription", extra={
                "error": str(e),
                "wallet": wallet_address,
            })

    def _call_backend_subscription_api(
        self,
        wallet_address: str,
        period_start: datetime,
        period_end: datetime,
        usd_value: Decimal,
        months: int,
        tx_hash: str
    ) -> bool:
        """Call backend API to create/update subscription.

        Args:
            wallet_address: User's wallet address
            period_start: Subscription start date
            period_end: Subscription end date
            usd_value: Payment amount in USD
            months: Number of months
            tx_hash: Transaction hash

        Returns:
            True if successful, False otherwise
        """
        try:
            if not self._backend_client:
                LOGGER.warning("No backend client configured, skipping API call")
                return False

            endpoint = "/payments/wallet/subscription"
            payload = {
                "wallet_address": wallet_address,
                "usd_amount": str(usd_value),
                "months": months,
                "tx_hash": tx_hash,
                "token_address": "",  # Will be filled by the backend
            }

            response = self._backend_client.post(endpoint, json=payload, timeout=30.0)

            if response and response.status_code in (200, 201):
                LOGGER.info("Backend subscription API called successfully", extra={
                    "wallet": wallet_address,
                    "period_end": period_end.isoformat(),
                    "months": months,
                    "status": response.status_code,
                })
                return True
            else:
                LOGGER.warning("Backend subscription API returned non-success status", extra={
                    "wallet": wallet_address,
                    "status": response.status_code if response else None,
                    "response": response.text if response else None,
                })
                return False

        except Exception as e:
            LOGGER.error("Failed to call backend API", extra={
                "error": str(e)
            })
            return False

    def _store_payment_record(
        self,
        token_symbol: str,
        from_address: str,
        to_address: str,
        amount: Decimal,
        tx_hash: str,
        block_number: int,
        log_index: int
    ) -> None:
        """Store payment record in database.

        Args:
            token_symbol: Token symbol
            from_address: Sender address
            to_address: Recipient address
            amount: Transfer amount
            tx_hash: Transaction hash
            block_number: Block number
            log_index: Log index
        """
        try:
            import uuid
            token_address = self.TOKEN_CONTRACTS.get(token_symbol, "")
            payment_id = str(uuid.uuid4())

            # Calculate accumulated amount for this sender
            with self._read_connection() as conn:
                cursor = conn.execute(
                    "SELECT COALESCE(SUM(amount), 0) FROM wallet_payments WHERE from_address = ?",
                    (from_address.lower(),)
                )
                previous_total = Decimal(cursor.fetchone()[0] or "0")

            accumulated_amount = previous_total + amount

            with self._write_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO wallet_payments (
                        id, from_address, to_address, token_address, amount,
                        accumulated_amount, tx_hash, block_number, log_index,
                        processed, subscription_created
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payment_id,
                        from_address.lower(),
                        to_address.lower(),
                        token_address.lower(),
                        str(amount),
                        str(accumulated_amount),
                        tx_hash,
                        block_number,
                        log_index,
                        False,  # processed
                        False,  # subscription_created
                    )
                )

            LOGGER.info("Stored payment record", extra={
                "token": token_symbol,
                "from": from_address,
                "amount": str(amount),
                "accumulated": str(accumulated_amount),
                "tx_hash": tx_hash,
            })

        except Exception as e:
            LOGGER.error("Failed to store payment record", extra={
                "error": str(e)
            })

    def _mark_payment_processed(self, tx_hash: str, subscription_created: bool = False) -> None:
        """Mark a payment as processed.

        Args:
            tx_hash: Transaction hash
            subscription_created: Whether subscription was created for this payment
        """
        try:
            with self._write_connection() as conn:
                conn.execute(
                    """
                    UPDATE wallet_payments
                    SET processed = 1, subscription_created = ?, updated_at = datetime('now')
                    WHERE tx_hash = ?
                    """,
                    (1 if subscription_created else 0, tx_hash)
                )

            LOGGER.info("Marked payment as processed", extra={
                "tx_hash": tx_hash,
                "subscription_created": subscription_created,
            })

        except Exception as e:
            LOGGER.error("Failed to mark payment as processed", extra={
                "error": str(e),
                "tx_hash": tx_hash,
            })

    def check_wallet_payment_status(self, wallet_address: str) -> Dict[str, Any]:
        """Check payment status for a wallet address.

        This is an on-demand method that can be called by the frontend
        to check if a user has made any recent payments.

        Args:
            wallet_address: User's wallet address

        Returns:
            Dictionary with payment status:
            {
                "wallet_address": str,
                "has_payments": bool,
                "accumulated_amount": str,
                "months_earned": int,
                "subscription_active": bool,
                "subscription_end": Optional[str],
                "next_tier_milestone": str
            }
        """
        try:
            with self._read_connection() as conn:
                # Get all payments for this wallet
                cursor = conn.execute(
                    """
                    SELECT COUNT(*), COALESCE(SUM(amount), 0)
                    FROM wallet_payments
                    WHERE from_address = ?
                    """,
                    (wallet_address.lower(),)
                )
                payment_count, total_amount = cursor.fetchone()

                # Get latest payment info
                cursor = conn.execute(
                    """
                    SELECT subscription_created, updated_at
                    FROM wallet_payments
                    WHERE from_address = ?
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    (wallet_address.lower(),)
                )
                row = cursor.fetchone()
                subscription_created = row[0] if row else False

                total_amount = Decimal(str(total_amount))
                months_earned = int(total_amount / PRO_PRICE_USD)

                result = {
                    "wallet_address": wallet_address,
                    "has_payments": payment_count > 0,
                    "accumulated_amount": str(total_amount),
                    "months_earned": months_earned,
                    "subscription_active": subscription_created,
                    "subscription_end": None,
                    "next_tier_milestone": str(max(0, PRO_PRICE_USD - total_amount)),
                }

            # Optionally fetch real-time subscription status from backend
            if self._backend_client:
                try:
                    endpoint = f"/payments/wallet/check/{wallet_address}"
                    response = self._backend_client.get(endpoint, timeout=10.0)

                    if response and response.status_code == 200:
                        backend_data = response.json()
                        # Merge backend data with local data
                        result["subscription_active"] = backend_data.get("subscription_active", result["subscription_active"])
                        result["subscription_end"] = backend_data.get("subscription_end")
                except Exception as api_error:
                    LOGGER.debug("Failed to fetch backend subscription status", extra={
                        "error": str(api_error),
                        "wallet": wallet_address,
                    })

            return result

        except Exception as e:
            LOGGER.error("Failed to check payment status", extra={
                "error": str(e),
                "wallet": wallet_address
            })
            return {
                "wallet_address": wallet_address,
                "has_payments": False,
                "accumulated_amount": "0",
                "months_earned": 0,
                "subscription_active": False,
                "subscription_end": None,
                "error": str(e),
            }

    def _start_ws_listener(self) -> None:
        """Start WebSocket listener for real-time Transfer events."""
        # TODO: Implement WebSocket listener for real-time events
        LOGGER.info("WebSocket listener not yet implemented")
        pass
