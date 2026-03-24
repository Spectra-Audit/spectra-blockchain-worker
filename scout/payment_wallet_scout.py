"""PaymentWalletScout - Monitor USDT/USDC transfers for Pro subscriptions.

This scout monitors ERC-20 Transfer events for USDT/USDC tokens sent to a
configured wallet address. When payments are detected, it immediately
forwards them to the backend API for processing.

Key Features:
- Monitor ERC-20 Transfer() events for specific tokens
- Forward payment events to backend API immediately
- No local storage - backend handles accumulation and subscription creation
- On-demand mode only (no background polling)
"""

import logging
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Optional, Sequence, Dict, Any

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

    # Feature flags
    enable_polling: bool = False  # On-demand mode by default


class PaymentWalletScout:
    """Monitor USDT/USDC transfers to wallet for Pro subscriptions.

    This scout forwards payment events to the backend API immediately,
    without any local storage. The backend handles all payment tracking,
    accumulation, and subscription creation.
    """

    # Token contract addresses
    TOKEN_CONTRACTS: Dict[str, str] = {
        "USDT": USDT_CONTRACT,
        "USDC": USDC_CONTRACT,
    }

    def __init__(
        self,
        config: PaymentWalletConfig,
        *,
        backend_client=None,
        ws_provider_pool=None,
    ):
        self._config = config
        self._backend_client = backend_client
        self._ws_provider_pool = ws_provider_pool

        # State management
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._ws_thread: Optional[threading.Thread] = None

        # Web3 setup
        self._web3: Optional[Web3] = None
        self._contracts: Dict[str, Contract] = {}

        # Thread safety
        self._lock = threading.Lock()

        LOGGER.info("PaymentWalletScout initialized (API-only mode)", extra={
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
            poll_interval_sec=poll_interval,
            reorg_confirmations=reorg_conf,
            enable_polling=enable_polling,
        )

        return cls(config, **kwargs)

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

        Forwards the payment event to the backend API immediately.
        The backend handles storage, accumulation, and subscription creation.

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

            LOGGER.info("Payment detected - forwarding to backend", extra={
                "token": token_symbol,
                "from": from_address,
                "amount": str(amount_decimal),
                "usd_value": str(usd_value),
                "tx_hash": tx_hash,
            })

            # Forward ALL payments to backend - let it handle accumulation
            self._forward_to_backend(
                token_symbol,
                from_address,
                to_address,
                amount_decimal,
                usd_value,
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

    def _forward_to_backend(
        self,
        token_symbol: str,
        from_address: str,
        to_address: str,
        amount: Decimal,
        usd_value: Decimal,
        tx_hash: str,
        block_number: int,
        log_index: int
    ) -> None:
        """Forward payment event to backend API.

        The backend will:
        - Store the payment in wallet_payments table
        - Accumulate payments until $20 threshold
        - Create subscription when threshold reached

        Args:
            token_symbol: Token symbol
            from_address: Sender address
            to_address: Recipient address
            amount: Transfer amount
            usd_value: USD value
            tx_hash: Transaction hash
            block_number: Block number
            log_index: Log index
        """
        try:
            if not self._backend_client:
                LOGGER.warning("No backend client configured, cannot forward payment")
                return

            # Forward raw payment to backend - let it handle accumulation and subscription
            endpoint = "/payments/wallet/subscription"
            payload = {
                "wallet_address": from_address,
                "usd_amount": str(usd_value),
                "tx_hash": tx_hash,
                "token_address": self.TOKEN_CONTRACTS.get(token_symbol, ""),
            }

            response = self._backend_client.post(endpoint, json=payload, timeout=30.0)

            if response and response.status_code in (200, 201):
                LOGGER.info("Payment forwarded to backend", extra={
                    "wallet": from_address,
                    "usd_value": str(usd_value),
                    "tx_hash": tx_hash,
                    "status": response.status_code,
                })
            else:
                LOGGER.warning("Backend returned non-success status", extra={
                    "wallet": from_address,
                    "status": response.status_code if response else None,
                    "response": response.text if response else None,
                    "tx_hash": tx_hash,
                })

        except Exception as e:
            LOGGER.error("Failed to forward payment to backend", extra={
                "error": str(e),
                "tx_hash": tx_hash,
            })

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

    def _start_ws_listener(self) -> None:
        """Start WebSocket listener for real-time Transfer events."""
        # TODO: Implement WebSocket listener for real-time events
        LOGGER.info("WebSocket listener not yet implemented")
        pass
