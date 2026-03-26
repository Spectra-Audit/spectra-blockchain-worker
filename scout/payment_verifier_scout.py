"""Payment Verifier Scout - On-demand payment verification.

This scout handles immediate payment verification requests from the backend.
Unlike FeaturedScout which monitors events continuously, this scout
verifies specific transactions on-demand using the shared RPC Manager.

Key Features:
- On-demand transaction verification by tx_hash
- Decodes Paid() events from transaction receipts
- Callbacks to backend with verification results
- Async queue for handling multiple requests
- Uses shared RPC Manager for efficient connection use

Usage:
    scout = PaymentVerifierScout.from_env()
    scout.start()
    scout.verify_payment(tx_hash, submission_id, creator_address, expected_amount)
"""

import logging
import os
import queue
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any, Dict, Optional

import requests

try:
    from web3 import Web3
    HAS_WEB3 = True
except ImportError:
    HAS_WEB3 = False

from .shared_rpc_manager import get_rpc_manager

LOGGER = logging.getLogger(__name__)

# Paid event signature
PAID_EVENT_SIGNATURE = "0x" + Web3.keccak(
    text="Paid(address,address,bytes32,uint256,uint8,uint256,uint64)"
).hex() if HAS_WEB3 else "0x"

# VeritasPaymentsAndBids contract address
VERITAS_PAYMENTS_CONTRACT = "0xe6733635aF5Ce7a1E022fbD87670EADa95397558"

# Retry backoff intervals in seconds: 10s, 20s, 40s, 80s, 160s
RETRY_DELAYS = [10, 20, 40, 80, 160]


@dataclass
class PaymentVerificationRequest:
    """Request for payment verification."""
    tx_hash: str
    submission_id: str
    creator_address: str
    expected_amount: int  # in wei
    backend_url: str
    backend_token: str
    number_of_contracts: int = 0  # Expected number of contracts from Paid() event
    retry_attempt: int = 0  # Current retry attempt (0-4)
    requested_at: datetime = None

    def __post_init__(self):
        if self.requested_at is None:
            self.requested_at = datetime.now()

    @property
    def max_retries(self) -> int:
        """Maximum number of retry attempts."""
        return 5

    @property
    def should_retry(self) -> bool:
        """Check if this request should be retried."""
        return self.retry_attempt < self.max_retries

    @property
    def retry_delay_seconds(self) -> int:
        """Calculate retry delay using exponential backoff: 10s, 20s, 40s, 80s, 160s."""
        return 10 * (2 ** self.retry_attempt)


@dataclass
class PaymentVerificationResult:
    """Result of payment verification."""
    tx_hash: str
    submission_id: str
    verified: bool
    creator_address: str
    amount_paid: int
    expected_amount: int
    failure_reason: Optional[str] = None
    verified_at: datetime = None

    def __post_init__(self):
        if self.verified_at is None:
            self.verified_at = datetime.now()


class PaymentVerifierScout:
    """
    On-demand payment verification scout.

    Verifies payments by fetching transaction receipts and decoding
    Paid() events. Results are sent back to the backend via callback.

    Unlike FeaturedScout, this doesn't run continuously - it processes
    requests from a queue as they arrive.
    """

    def __init__(
        self,
        backend_url: str,
        backend_token: str,
        rpc_manager=None,
    ):
        """Initialize Payment Verifier Scout.

        Args:
            backend_url: Backend API base URL
            backend_token: Backend authentication token
            rpc_manager: Shared RPC Manager instance
        """
        self._backend_url = backend_url.rstrip("/")
        self._backend_token = backend_token
        self._rpc_manager = rpc_manager or get_rpc_manager()

        # Request queue
        self._request_queue: queue.Queue[PaymentVerificationRequest] = queue.Queue()
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

        LOGGER.info("Payment Verifier Scout initialized")

    @classmethod
    def from_env(cls, **kwargs) -> "PaymentVerifierScout":
        """Create Payment Verifier Scout from environment variables.

        Environment Variables:
            API_BASE_URL: Backend API base URL
            ADMIN_ACCESS_TOKEN: Backend authentication token

        Returns:
            Payment Verifier Scout instance
        """
        backend_url = os.environ.get("API_BASE_URL", "")
        if not backend_url:
            raise ValueError("API_BASE_URL environment variable is required")

        backend_token = os.environ.get("ADMIN_ACCESS_TOKEN", "")
        if not backend_token:
            raise ValueError("ADMIN_ACCESS_TOKEN environment variable is required")

        return cls(
            backend_url=backend_url,
            backend_token=backend_token,
            **kwargs,
        )

    def start(self) -> None:
        """Start the payment verifier scout."""
        if self._worker_thread and self._worker_thread.is_alive():
            raise RuntimeError("Payment Verifier Scout already running")

        self._stop_event.clear()
        self._worker_thread = threading.Thread(
            target=self._run_verification_loop,
            name="PaymentVerifierScout",
            daemon=True,
        )
        self._worker_thread.start()

        LOGGER.info("Payment Verifier Scout started")

    def stop(self, timeout: float = 10.0) -> None:
        """Stop the payment verifier scout."""
        self._stop_event.set()
        if self._worker_thread:
            self._worker_thread.join(timeout=timeout)
            self._worker_thread = None
        LOGGER.info("Payment Verifier Scout stopped")

    def verify_payment(
        self,
        tx_hash: str,
        submission_id: str,
        creator_address: str,
        expected_amount: int,
        number_of_contracts: int = 0,
    ) -> None:
        """
        Queue a payment verification request.

        Args:
            tx_hash: Transaction hash to verify
            submission_id: Pending submission ID
            creator_address: Expected creator address
            expected_amount: Expected payment amount in wei
            number_of_contracts: Expected number of contracts from Paid() event
        """
        request = PaymentVerificationRequest(
            tx_hash=tx_hash,
            submission_id=submission_id,
            creator_address=creator_address,
            expected_amount=expected_amount,
            number_of_contracts=number_of_contracts,
            backend_url=self._backend_url,
            backend_token=self._backend_token,
        )

        self._request_queue.put(request)
        LOGGER.info(f"Payment verification queued: {tx_hash}")

    def _run_verification_loop(self) -> None:
        """Main verification loop - processes requests from queue."""
        LOGGER.info("Payment verification loop started")

        while not self._stop_event.is_set():
            try:
                # Get request from queue with timeout
                try:
                    request = self._request_queue.get(timeout=1.0)
                except queue.Empty:
                    continue

                # Process the verification
                result = self._verify_transaction(request)

                # Check if we should retry (pending/insufficient confirmations)
                if result.verified:
                    # Payment verified - send success callback
                    self._send_callback(request, result)
                elif self._should_retry_verification(request, result):
                    # Requeue with delay for retry
                    request.retry_attempt += 1
                    delay = request.retry_delay_seconds
                    LOGGER.info(
                        f"Requeuing payment verification: {request.tx_hash[:10]}... "
                        f"(attempt {request.retry_attempt}/{request.max_retries}, "
                        f"delay {delay}s, reason: {result.failure_reason})"
                    )

                    # Schedule retry with delay
                    def requeue_with_delay(req, d):
                        time.sleep(d)
                        if not self._stop_event.is_set():
                            self._request_queue.put(req)

                    retry_thread = threading.Thread(
                        target=requeue_with_delay,
                        args=(request, delay),
                        daemon=True,
                    )
                    retry_thread.start()
                else:
                    # Final failure - send failure callback with timeout reason
                    LOGGER.warning(
                        f"Payment verification failed after {request.retry_attempt} attempts: "
                        f"{request.tx_hash[:10]}... - {result.failure_reason}"
                    )
                    # Update failure reason to verification_timeout if it was a retryable failure
                    if result.failure_reason and ("Transaction receipt not found" in result.failure_reason or
                                                   "Insufficient confirmations" in result.failure_reason):
                        result.failure_reason = "verification_timeout"
                    self._send_callback(request, result)

                # Mark task done
                self._request_queue.task_done()

            except Exception as e:
                LOGGER.error(f"Error in verification loop: {e}", exc_info=True)

        LOGGER.info("Payment verification loop stopped")

    def _should_retry_verification(
        self,
        request: PaymentVerificationRequest,
        result: PaymentVerificationResult,
    ) -> bool:
        """
        Determine if verification should be retried.

        Args:
            request: Verification request
            result: Verification result

        Returns:
            True if should retry, False otherwise
        """
        # Don't retry if already verified
        if result.verified:
            return False

        # Don't retry if max attempts reached
        if not request.should_retry:
            return False

        # Retry if transaction not mined yet
        if "Transaction receipt not found" in result.failure_reason:
            return True

        # Retry if insufficient confirmations
        if "Insufficient confirmations" in result.failure_reason:
            return True

        # Don't retry on permanent failures (wrong contract, wrong amount, etc.)
        return False

    def _get_current_block_number(self, provider) -> Optional[int]:
        """
        Get current block number.

        Args:
            provider: RPC provider

        Returns:
            Current block number or None
        """
        try:
            import asyncio
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            result = loop.run_until_complete(
                provider.make_request("eth_blockNumber", [])
            )
            if isinstance(result, str) and result.startswith("0x"):
                return int(result, 16)
            return result
        except Exception as e:
            LOGGER.error(f"Failed to get current block number: {e}")
            return None

    def _verify_transaction(
        self,
        request: PaymentVerificationRequest,
    ) -> PaymentVerificationResult:
        """
        Verify a transaction by fetching its receipt.

        Args:
            request: Verification request

        Returns:
            Verification result
        """
        tx_hash = request.tx_hash

        try:
            if not self._rpc_manager:
                raise ConnectionError("RPC Manager not available")

            # Get a provider for this transaction (block 0 = any block)
            provider = self._rpc_manager.get_provider_for_block(0, "eth_getTransactionReceipt")
            if not provider:
                raise ConnectionError("No healthy RPC providers available")

            # Fetch transaction receipt using async provider
            import asyncio
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            receipt = loop.run_until_complete(
                provider.make_request("eth_getTransactionReceipt", [tx_hash])
            )

            LOGGER.info(f"Fetched receipt for {tx_hash[:10]}...: receipt={'found' if receipt else 'None'}")

            # Check if receipt exists (transaction might not be mined yet)
            if receipt is None:
                LOGGER.warning(f"Transaction receipt not found for {tx_hash[:10]}... - transaction may not be mined yet")
                return PaymentVerificationResult(
                    tx_hash=tx_hash,
                    submission_id=request.submission_id,
                    verified=False,
                    creator_address=request.creator_address,
                    amount_paid=0,
                    expected_amount=request.expected_amount,
                    failure_reason="Transaction receipt not found - transaction may not be mined yet",
                )

            # Get current block number for confirmation check
            current_block = self._get_current_block_number(provider)
            tx_block = int(receipt.get("blockNumber", "0x0"), 16) if isinstance(receipt.get("blockNumber"), str) else receipt.get("blockNumber", 0)

            # Check confirmations (require at least 1)
            if current_block is not None:
                confirmations = current_block - tx_block
                if confirmations < 1:
                    LOGGER.info(
                        f"Transaction {tx_hash[:10]}... has {confirmations} confirmations "
                        f"(block {tx_block}, current {current_block}) - waiting for more"
                    )
                    return PaymentVerificationResult(
                        tx_hash=tx_hash,
                        submission_id=request.submission_id,
                        verified=False,
                        creator_address=request.creator_address,
                        amount_paid=0,
                        expected_amount=request.expected_amount,
                        failure_reason=f"Insufficient confirmations: {confirmations} < 1",
                    )

            # Check if transaction was successful
            if receipt.get("status") != 1:
                return PaymentVerificationResult(
                    tx_hash=tx_hash,
                    submission_id=request.submission_id,
                    verified=False,
                    creator_address=request.creator_address,
                    amount_paid=0,
                    expected_amount=request.expected_amount,
                    failure_reason="Transaction failed",
                )

            # Find Paid() event in logs (also verifies contract address)
            paid_event = self._find_paid_event(receipt)

            if not paid_event:
                return PaymentVerificationResult(
                    tx_hash=tx_hash,
                    submission_id=request.submission_id,
                    verified=False,
                    creator_address=request.creator_address,
                    amount_paid=0,
                    expected_amount=request.expected_amount,
                    failure_reason="No Paid() event found in transaction",
                )

            # Verify numberOfContracts matches (if provided)
            if request.number_of_contracts > 0:
                event_contracts = paid_event.get("number_of_contracts", 0)
                if event_contracts != request.number_of_contracts:
                    return PaymentVerificationResult(
                        tx_hash=tx_hash,
                        submission_id=request.submission_id,
                        verified=False,
                        creator_address=paid_event.get("creator", ""),
                        amount_paid=paid_event.get("amount_paid_fees", 0),
                        expected_amount=request.expected_amount,
                        failure_reason=f"Contract count mismatch: expected {request.number_of_contracts}, got {event_contracts}",
                    )

            # Verify creator address matches
            event_creator = paid_event.get("creator", "").lower()
            expected_creator = request.creator_address.lower()

            if event_creator != expected_creator:
                return PaymentVerificationResult(
                    tx_hash=tx_hash,
                    submission_id=request.submission_id,
                    verified=False,
                    creator_address=paid_event.get("creator", ""),
                    amount_paid=paid_event.get("amount_paid_fees", 0),
                    expected_amount=request.expected_amount,
                    failure_reason=f"Creator mismatch: expected {expected_creator}, got {event_creator}",
                )

            # Verify amount (with 5% tolerance)
            amount_paid = paid_event.get("amount_paid_fees", 0)
            min_acceptable = int(request.expected_amount * 0.95)

            if amount_paid < min_acceptable:
                return PaymentVerificationResult(
                    tx_hash=tx_hash,
                    submission_id=request.submission_id,
                    verified=False,
                    creator_address=paid_event.get("creator", ""),
                    amount_paid=amount_paid,
                    expected_amount=request.expected_amount,
                    failure_reason=f"Insufficient payment: {amount_paid} < {min_acceptable}",
                )

            # Payment verified!
            return PaymentVerificationResult(
                tx_hash=tx_hash,
                submission_id=request.submission_id,
                verified=True,
                creator_address=paid_event.get("creator", ""),
                amount_paid=amount_paid,
                expected_amount=request.expected_amount,
            )

        except Exception as e:
            LOGGER.error(f"Failed to verify transaction {tx_hash}: {e}")
            return PaymentVerificationResult(
                tx_hash=tx_hash,
                submission_id=request.submission_id,
                verified=False,
                creator_address=request.creator_address,
                amount_paid=0,
                expected_amount=request.expected_amount,
                failure_reason=f"Verification error: {str(e)}",
            )

    def _find_paid_event(self, receipt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Find and decode Paid() event from transaction receipt.

        Args:
            receipt: Transaction receipt

        Returns:
            Decoded event data or None
        """
        for log in receipt.get("logs", []):
            # First verify the contract address (log.address)
            log_address = log.get("address", "")
            if isinstance(log_address, bytes):
                log_address = "0x" + log_address.hex()
            elif isinstance(log_address, str):
                log_address = log_address.lower()

            expected_address = VERITAS_PAYMENTS_CONTRACT.lower()
            if log_address != expected_address:
                # This log is from a different contract, skip it
                continue

            # Check if log has Paid event signature
            topics = log.get("topics", [])
            if not topics:
                continue

            try:
                topic0 = topics[0]
                if isinstance(topic0, bytes):
                    topic0 = "0x" + topic0.hex()
                elif isinstance(topic0, str):
                    topic0 = topic0.lower()

                if topic0 != PAID_EVENT_SIGNATURE.lower():
                    continue

                # Decode the event
                # topics[1] = payer (indexed)
                # topics[2] = creator (indexed)
                # topics[3] = projectId (indexed, bytes32)
                # data contains: amountPaidFees, numberOfContracts, featuredBid, roundId

                data_hex = log.get("data", "")
                if isinstance(data_hex, bytes):
                    data_hex = "0x" + data_hex.hex()
                if data_hex.startswith("0x"):
                    data_hex = data_hex[2:]

                # Decode parameters (each is 32 bytes / 64 hex chars)
                amount_paid_fees = int(data_hex[0:64], 16) if len(data_hex) >= 64 else 0
                number_of_contracts = int(data_hex[64:128], 16) if len(data_hex) >= 128 else 0
                featured_bid = int(data_hex[128:192], 16) if len(data_hex) >= 192 else 0
                round_id = int(data_hex[192:256], 16) if len(data_hex) >= 256 else 0

                # Extract indexed parameters
                def bytes_to_address(data):
                    if isinstance(data, bytes):
                        return "0x" + data[-40:].hex()
                    elif isinstance(data, str):
                        return "0x" + data[-40:].rjust(40, "0")
                    return "0x0000000000000000000000000000000000000000"

                payer = bytes_to_address(topics[1]) if len(topics) > 1 else None
                creator = bytes_to_address(topics[2]) if len(topics) > 2 else None

                return {
                    "payer": payer,
                    "creator": creator,
                    "amount_paid_fees": amount_paid_fees,
                    "number_of_contracts": number_of_contracts,
                    "featured_bid": featured_bid,
                    "round_id": round_id,
                }

            except Exception as e:
                LOGGER.warning(f"Failed to decode Paid event: {e}")
                continue

        return None

    def _send_callback(
        self,
        request: PaymentVerificationRequest,
        result: PaymentVerificationResult,
    ) -> None:
        """
        Send verification result to backend via callback.

        Args:
            request: Original verification request
            result: Verification result
        """
        # backend_url already includes /v1 suffix, so don't add it again
        url = f"{request.backend_url}/pending/{request.submission_id}"

        LOGGER.info(f"Sending callback to: {url} (verified={result.verified})")

        payload = {
            "status": "verified" if result.verified else "failed",
            "tx_hash": result.tx_hash,
            "verified_at": result.verified_at.isoformat(),
        }

        if result.verified:
            payload["message"] = "Payment verified successfully!"
        else:
            payload["failure_reason"] = result.failure_reason or "Verification failed"
            payload["message"] = payload["failure_reason"]

        headers = {
            "Authorization": f"Bearer {request.backend_token}",
            "Content-Type": "application/json",
        }

        try:
            response = requests.put(url, json=payload, headers=headers, timeout=10.0)

            if response.status_code in (200, 202):
                LOGGER.info(
                    f"Callback sent successfully: {request.submission_id} -> {result.verified}"
                )
            else:
                LOGGER.warning(
                    f"Callback returned {response.status_code}: {response.text}"
                )

        except Exception as e:
            LOGGER.error(f"Failed to send callback: {e}")


# Global scout instance
_payment_verifier_scout: Optional[PaymentVerifierScout] = None


def get_payment_verifier_scout() -> Optional[PaymentVerifierScout]:
    """Get the global Payment Verifier Scout instance."""
    return _payment_verifier_scout


def set_payment_verifier_scout(scout: PaymentVerifierScout) -> None:
    """Set the global Payment Verifier Scout instance."""
    global _payment_verifier_scout
    _payment_verifier_scout = scout


__all__ = [
    "PaymentVerifierScout",
    "PaymentVerificationRequest",
    "PaymentVerificationResult",
    "get_payment_verifier_scout",
    "set_payment_verifier_scout",
]
