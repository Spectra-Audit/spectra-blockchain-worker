"""Unified audit API for Spectra Blockchain Worker.

Provides a single API for:
- Triggering audits for projects
- Querying audit results
- Contract update notifications
- Health and status monitoring
- Payment confirmation via WebSocket
- Featured projects management

Endpoints:
- POST /audit/trigger          - Trigger full or partial audit
- GET  /audit/{project_id}      - Get all audit data for project
- GET  /audit/{project_id}/history - Get historical snapshots
- POST /audit/contract-update  - Trigger code audit on contract change
- GET  /health                  - Health check
- GET  /stats                   - Service statistics
- GET  /admin/wallet            - Get admin wallet address
- POST /admin/payment/confirm   - Confirm payment via on-demand WebSocket
- GET  /admin/payment/{tx_hash} - Check payment status
- POST /admin/featured/sync     - Sync featured projects from contract
- GET  /admin/featured          - List current featured projects
"""
from __future__ import annotations

import logging
import os
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

try:
    from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, status
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field, validator
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    FastAPI = None
    BaseModel = None
    BackgroundTasks = None

from .audit_orchestrator import AuditOrchestrator

LOGGER = logging.getLogger(__name__)

# Global orchestrator instance - set by main app
orchestrator: Optional[AuditOrchestrator] = None

# Global FeaturedScout instance - set by main app for on-demand payment confirmation
featured_scout = None

# Payment event cache - stores recently received Paid events from WebSocket
# Format: {tx_hash: {creator_address, amount, block_number, round_id, received_at}}
_payment_cache: Dict[str, Dict[str, Any]] = {}
_payment_cache_lock = threading.RLock()
# Keep payment events for 1 hour
_PAYMENT_CACHE_TTL = timedelta(hours=1)


def set_orchestrator(orch: AuditOrchestrator) -> None:
    """Set the global orchestrator instance.

    Args:
        orch: AuditOrchestrator instance
    """
    global orchestrator
    orchestrator = orch
    LOGGER.info("Audit orchestrator registered with unified API server")


def get_orchestrator() -> Optional[AuditOrchestrator]:
    """Get the global orchestrator instance.

    Returns:
        AuditOrchestrator instance or None
    """
    return orchestrator


def set_featured_scout(scout) -> None:
    """Set the global FeaturedScout instance.

    Args:
        scout: FeaturedScout instance
    """
    global featured_scout
    featured_scout = scout
    LOGGER.info("FeaturedScout registered with unified API server")


def get_featured_scout():
    """Get the global FeaturedScout instance.

    Returns:
        FeaturedScout instance or None
    """
    return featured_scout


def add_payment_event(tx_hash: str, creator_address: str, amount: int,
                     block_number: int, round_id: int) -> None:
    """Add a payment event to the cache.

    Called by FeaturedScout when a Paid event is received via WebSocket.

    Args:
        tx_hash: Transaction hash
        creator_address: Creator wallet address
        amount: Amount paid in VERITAS (wei)
        block_number: Block number
        round_id: Round ID from the event
    """
    with _payment_cache_lock:
        _payment_cache[tx_hash.lower()] = {
            "creator_address": creator_address.lower(),
            "amount": amount,
            "block_number": block_number,
            "round_id": round_id,
            "received_at": datetime.utcnow(),
        }
        # Clean up old entries
        _cleanup_payment_cache()


def get_payment_event(tx_hash: str) -> Optional[Dict[str, Any]]:
    """Get a payment event from the cache.

    Args:
        tx_hash: Transaction hash to look up

    Returns:
        Payment event data or None if not found
    """
    with _payment_cache_lock:
        _cleanup_payment_cache()
        return _payment_cache.get(tx_hash.lower())


def _cleanup_payment_cache() -> None:
    """Remove expired entries from the payment cache."""
    now = datetime.utcnow()
    expired = [
        tx_hash for tx_hash, data in _payment_cache.items()
        if now - data.get("received_at", now) > _PAYMENT_CACHE_TTL
    ]
    for tx_hash in expired:
        del _payment_cache[tx_hash]


if HAS_FASTAPI:

    class AuditTriggerRequest(BaseModel):
        """Request to trigger an audit for a project."""

        project_id: str = Field(..., description="Project UUID")
        token_address: str = Field(..., description="Token contract address")
        chain_id: int = Field(default=1, description="Chain ID (default: Ethereum)")
        force_full: bool = Field(
            default=False,
            description="Force full audit including static data (contract audit)",
        )

        @validator("token_address")
        def validate_token_address(cls, v: str) -> str:
            """Validate token address format."""
            if not v.startswith("0x") or len(v) != 42:
                raise ValueError("Invalid token address format")
            return v.lower()

        @validator("project_id")
        def validate_project_id(cls, v: str) -> str:
            """Validate project ID is not empty."""
            if not v or not v.strip():
                raise ValueError("Project ID cannot be empty")
            return v

        class Config:
            """Pydantic config."""

            json_schema_extra = {
                "example": {
                    "project_id": "550e8400-e29b-41d4-a716-446655440000",
                    "token_address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                    "chain_id": 1,
                    "force_full": False,
                }
            }

    class ContractUpdateRequest(BaseModel):
        """Request to trigger contract audit on code update."""

        project_id: str = Field(..., description="Project UUID")
        token_address: str = Field(..., description="Token contract address")
        chain_id: int = Field(default=1, description="Chain ID")
        previous_code_hash: Optional[str] = Field(None, description="Previous contract code hash")
        new_code_hash: Optional[str] = Field(None, description="New contract code hash")

        @validator("token_address")
        def validate_token_address(cls, v: str) -> str:
            """Validate token address format."""
            if not v.startswith("0x") or len(v) != 42:
                raise ValueError("Invalid token address format")
            return v.lower()

        class Config:
            """Pydantic config."""

            json_schema_extra = {
                "example": {
                    "project_id": "550e8400-e29b-41d4-a716-446655440000",
                    "token_address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                    "chain_id": 1,
                }
            }

    class AuditDataResponse(BaseModel):
        """Response with all audit data for a project."""

        project_id: str
        token_address: str
        chain_id: int
        token_distribution: Optional[Dict[str, Any]] = None
        tokenomics: Optional[Dict[str, Any]] = None
        liquidity: Optional[Dict[str, Any]] = None
        contract_audit: Optional[Dict[str, Any]] = None
        collected_at: str
        updated_at: str

    class AuditStatusResponse(BaseModel):
        """Response for audit status queries."""

        project_id: str
        status: str
        has_data: bool = False
        error: Optional[str] = None
        started_at: Optional[str] = None
        completed_at: Optional[str] = None

    # Create FastAPI app
    app = FastAPI(
        title="Spectra Unified Audit API",
        description="Unified API for triggering audits and querying results",
        version="2.0.0",
    )

    @app.get("/health")
    async def health_check():
        """Health check endpoint.

        Returns:
            Health status with orchestrator ready flag
        """
        return {
            "status": "healthy",
            "service": "spectra-unified-audit-api",
            "orchestrator_ready": orchestrator is not None,
            "version": "2.0.0",
        }

    @app.get("/admin/wallet")
    async def get_admin_wallet():
        """Get the admin wallet address for this worker.

        Returns the admin wallet address that should be added to the backend's
        ADMIN_WALLETS environment variable for authentication.

        Returns:
            Admin wallet address or 404 if not configured
        """
        if not orchestrator:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Orchestrator not ready",
            )

        try:
            from .auth_wallet import ADMIN_WALLET_ADDRESS_META
            wallet_address = orchestrator.database.get_meta(ADMIN_WALLET_ADDRESS_META)
            if not wallet_address:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Admin wallet not found in database",
                )
            return {
                "address": wallet_address,
                "message": f"Add this address to backend ADMIN_WALLETS: {wallet_address}"
            }
        except Exception as e:
            LOGGER.error(f"Failed to get admin wallet: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to retrieve admin wallet: {str(e)}",
            )

    class PaymentConfirmationRequest(BaseModel):
        """Request to confirm a payment transaction via on-demand WebSocket."""

        tx_hash: str = Field(..., description="Transaction hash to confirm")
        timeout_seconds: int = Field(default=300, description="Timeout in seconds (default: 300, max: 600)")
        project_hex: Optional[str] = Field(None, description="Project hex ID (optional, for logging)")

        @validator("tx_hash")
        def validate_tx_hash(cls, v: str) -> str:
            """Validate transaction hash format."""
            if not v.startswith("0x") or len(v) not in (66, 70):  # 66 for 0x + 64 hex chars
                raise ValueError("Invalid transaction hash format")
            return v.lower()

        @validator("timeout_seconds")
        def validate_timeout(cls, v: int) -> int:
            """Validate timeout is reasonable."""
            if v < 10:
                raise ValueError("Timeout must be at least 10 seconds")
            if v > 600:  # Max 10 minutes
                raise ValueError("Timeout cannot exceed 600 seconds")
            return v

        class Config:
            """Pydantic config."""

            json_schema_extra = {
                "example": {
                    "tx_hash": "0x789468322a0cb8b056aa8ecbf2a06d2390be245b20329cb9495b1c3d068478e9",
                    "timeout_seconds": 300,
                    "project_hex": "0x3000000000000000000000000000000000000000000000000000000000000001",
                }
            }

    class PaymentConfirmationResponse(BaseModel):
        """Response for payment confirmation."""

        confirmed: bool
        tx_hash: str
        message: str
        creator_address: Optional[str] = None
        amount: Optional[int] = None
        block_number: Optional[int] = None
        round_id: Optional[int] = None
        found_in_cache: bool = False
        timeout: bool = False

    @app.post("/admin/payment/confirm", response_model=PaymentConfirmationResponse)
    async def confirm_payment_via_websocket(request: PaymentConfirmationRequest):
        """Confirm a payment transaction via on-demand WebSocket connection.

        Opens a WebSocket connection, waits for the payment to be confirmed,
        processes ALL pending payments while connected, then closes the connection.

        This is more efficient than keeping WebSocket open permanently.

        Args:
            request: Payment confirmation request with tx_hash and timeout

        Returns:
            Payment confirmation result
        """
        if not featured_scout:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="FeaturedScout not ready",
            )

        try:
            LOGGER.info(
                f"On-demand WebSocket confirmation requested for tx: {request.tx_hash[:10]}...",
                extra={"tx_hash": request.tx_hash, "timeout": request.timeout_seconds}
            )

            # Check if payment is already in cache
            cached_payment = get_payment_event(request.tx_hash)
            if cached_payment:
                LOGGER.info(
                    f"Payment found in cache: {request.tx_hash[:10]}...",
                    extra={"tx_hash": request.tx_hash}
                )
                return PaymentConfirmationResponse(
                    confirmed=True,
                    tx_hash=request.tx_hash,
                    message="Payment confirmed from cache",
                    creator_address=cached_payment.get("creator_address"),
                    amount=cached_payment.get("amount"),
                    block_number=cached_payment.get("block_number"),
                    round_id=cached_payment.get("round_id"),
                    found_in_cache=True,
                    timeout=False,
                )

            # Open on-demand WebSocket and wait for confirmation
            result = await featured_scout.confirm_payment_on_demand(
                tx_hash=request.tx_hash,
                timeout_seconds=request.timeout_seconds,
                project_hex=request.project_hex
            )

            LOGGER.info(
                f"On-demand WebSocket confirmation {'succeeded' if result['confirmed'] else 'timed out'}: {request.tx_hash[:10]}...",
                extra={"tx_hash": request.tx_hash, "confirmed": result['confirmed']}
            )

            return PaymentConfirmationResponse(**result)

        except Exception as e:
            LOGGER.error(f"Payment confirmation failed: {e}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Payment confirmation failed: {str(e)}",
            )

    @app.get("/admin/payment/{tx_hash}")
    async def check_payment_status(tx_hash: str):
        """Check if a payment transaction has been received via WebSocket subscription.

        The blockchain worker constantly subscribes to Paid events from the
        VeritasPaymentsAndBids contract. When a payment is detected, it's
        cached in memory for fast lookup.

        Args:
            tx_hash: Transaction hash to check (with or without 0x prefix)

        Returns:
            Payment event data if found, 404 if not found

            Response format when found:
            {
                "found": true,
                "tx_hash": "0x...",
                "creator_address": "0x...",
                "amount": 4600,
                "block_number": 12345,
                "round_id": 27,
                "received_at": "2024-01-01T00:00:00Z"
            }
        """
        # Ensure 0x prefix
        if not tx_hash.startswith("0x"):
            tx_hash = "0x" + tx_hash

        payment_data = get_payment_event(tx_hash)

        if not payment_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Payment transaction not found in cache",
            )

        return {
            "found": True,
            "tx_hash": tx_hash,
            "creator_address": payment_data["creator_address"],
            "amount": payment_data["amount"],
            "block_number": payment_data["block_number"],
            "round_id": payment_data["round_id"],
            "received_at": payment_data["received_at"].isoformat() + "Z",
        }

    class FeaturedSyncResponse(BaseModel):
        """Response for featured projects sync."""

        success: bool
        message: str
        featured_count: int = 0
        unfeatured_count: int = 0
        block_number: Optional[int] = None
        featured_projects: List[str] = []

    @app.post("/admin/featured/sync", response_model=FeaturedSyncResponse)
    async def sync_featured_projects():
        """Sync featured projects from the VeritasPaymentsAndBids contract.

        Calls the winningBids() view function to get the current round's winners
        and updates the backend accordingly.

        This endpoint:
        - Marks current winning bids as featured
        - Unfeatures projects that are no longer winning
        - Returns the list of featured projects

        The sync also runs automatically once a week (every 604800 seconds).

        Returns:
            Featured sync results with counts and project list

        Raises:
            HTTPException: If FeaturedScout is not ready or sync fails
        """
        if not featured_scout:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="FeaturedScout not ready",
            )

        try:
            LOGGER.info("Manual featured projects sync requested via admin API")

            # Call the sync method
            success = featured_scout._sync_featured_projects_from_contract()

            if not success:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to sync featured projects from contract",
                )

            # Get current featured projects for response
            featured_projects = featured_scout._list_all_featured_projects()
            web3 = featured_scout._get_web3_for_contract_calls()
            block_number = web3.eth.block_number if web3 else None

            LOGGER.info(
                f"Featured projects sync completed: {len(featured_projects)} featured",
                extra={"featured_count": len(featured_projects)}
            )

            return FeaturedSyncResponse(
                success=True,
                message="Featured projects synced successfully",
                featured_count=len(featured_projects),
                unfeatured_count=0,  # Not tracked separately in current implementation
                block_number=block_number,
                featured_projects=featured_projects,
            )

        except HTTPException:
            raise
        except Exception as e:
            LOGGER.error(f"Featured projects sync failed: {e}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Featured sync failed: {str(e)}",
            )

    @app.get("/admin/featured")
    async def list_featured_projects():
        """Get the current list of featured projects.

        Returns all projects currently marked as featured from the local database.

        Returns:
            List of featured project hex IDs

        Response format:
        {
            "featured_projects": ["0x3000...", "0x3001..."],
            "count": 2,
            "last_sync_block": 12345
        }
        """
        if not featured_scout:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="FeaturedScout not ready",
            )

        try:
            featured_projects = featured_scout._list_all_featured_projects()
            web3 = featured_scout._get_web3_for_contract_calls()
            block_number = web3.eth.block_number if web3 else None

            return {
                "featured_projects": featured_projects,
                "count": len(featured_projects),
                "last_sync_block": block_number,
            }

        except Exception as e:
            LOGGER.error(f"Failed to list featured projects: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to list featured projects: {str(e)}",
            )

    @app.post(
        "/audit/trigger",
        response_model=Dict[str, str],
        status_code=status.HTTP_202_ACCEPTED,
        responses={
            202: {"description": "Audit queued successfully"},
            503: {"description": "Audit service not ready"},
            400: {"description": "Invalid payload"},
        },
    )
    async def trigger_audit(
        request: AuditTriggerRequest,
        background_tasks: BackgroundTasks,
    ):
        """Trigger audit for a project.

        Runs all scouts in parallel:
        - TokenHolderScout (always)
        - TokenomicsAnalyzerScout (always)
        - LiquidityAnalyzerScout (always)
        - ContractAuditScout (if force_full=True or first time)

        Args:
            request: Audit trigger request
            background_tasks: FastAPI background tasks

        Returns:
            Confirmation response

        Raises:
            HTTPException: If orchestrator is not ready
        """
        # Optional webhook secret verification
        webhook_secret = os.environ.get("AUDIT_BACKEND_WEBHOOK_SECRET")
        if webhook_secret:
            # TODO: Implement secret verification from headers
            pass

        if not orchestrator:
            LOGGER.warning("Audit trigger requested but orchestrator not ready")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Audit service not ready",
            )

        # Queue audit in background
        background_tasks.add_task(
            _run_audit_task,
            request.project_id,
            request.token_address,
            request.chain_id,
            request.force_full,
        )

        LOGGER.info(
            f"Audit queued for project {request.project_id[:8]}... "
            f"(token={request.token_address[:10]}..., chain={request.chain_id}, "
            f"force_full={request.force_full})"
        )

        return {
            "status": "queued",
            "message": f"Audit queued for project {request.project_id}",
            "project_id": request.project_id,
        }

    @app.get(
        "/audit/{project_id}",
        response_model=AuditDataResponse,
        responses={
            200: {"description": "Audit data retrieved"},
            404: {"description": "Project not found"},
            503: {"description": "Service not ready"},
        },
    )
    async def get_audit_data(project_id: str):
        """Get all audit data for a project.

        Args:
            project_id: Project UUID

        Returns:
            All audit data from all scouts

        Raises:
            HTTPException: If orchestrator is not ready or database error
        """
        if not orchestrator:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Audit service not ready",
            )

        # Query database for all scout data
        try:
            data = orchestrator.database.get_unified_audit_data(project_id)

            if not data or not data.get("token_address"):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"No audit data found for project {project_id}",
                )

            return AuditDataResponse(**data)

        except Exception as e:
            LOGGER.error(f"Failed to get audit data for {project_id[:8]}...: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to retrieve audit data: {str(e)}",
            )

    @app.get(
        "/audit/{project_id}/history",
        responses={
            200: {"description": "History retrieved"},
            503: {"description": "Service not ready"},
        },
    )
    async def get_audit_history(project_id: str, limit: int = 10):
        """Get historical audit snapshots for a project.

        Args:
            project_id: Project UUID
            limit: Maximum number of snapshots (default: 10)

        Returns:
            List of historical snapshots
        """
        if not orchestrator:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Audit service not ready",
            )

        try:
            history = orchestrator.database.get_unified_audit_history(
                project_id=project_id,
                limit=limit,
            )

            return {
                "project_id": project_id,
                "snapshots": history,
                "count": len(history),
            }

        except Exception as e:
            LOGGER.error(f"Failed to get audit history for {project_id[:8]}...: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to retrieve history: {str(e)}",
            )

    @app.get(
        "/audit/{project_id}/status",
        response_model=AuditStatusResponse,
        responses={
            200: {"description": "Status retrieved"},
            404: {"description": "No audit running"},
        },
    )
    async def get_audit_status(project_id: str):
        """Get status of a running audit for a project.

        Args:
            project_id: Project UUID

        Returns:
            Audit status response

        Raises:
            HTTPException: If orchestrator is not ready
        """
        if not orchestrator:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Audit service not ready",
            )

        result = orchestrator.get_audit_status(project_id)

        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No audit found for project {project_id}",
            )

        return AuditStatusResponse(
            project_id=result.project_id,
            status=result.status,
            has_data=bool(result.data),
            error=result.error,
            started_at=result.started_at.isoformat() if result.started_at else None,
            completed_at=result.completed_at.isoformat() if result.completed_at else None,
        )

    @app.post(
        "/audit/contract-update",
        response_model=Dict[str, str],
        status_code=status.HTTP_202_ACCEPTED,
        responses={
            202: {"description": "Contract audit queued"},
            503: {"description": "Service not ready"},
        },
    )
    async def trigger_contract_audit(
        request: ContractUpdateRequest,
        background_tasks: BackgroundTasks,
    ):
        """Trigger code audit when contract is updated.

        Only runs ContractAuditScout to analyze new contract code.

        Args:
            request: Contract update request
            background_tasks: FastAPI background tasks

        Returns:
            Confirmation response

        Raises:
            HTTPException: If orchestrator is not ready
        """
        if not orchestrator:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Audit service not ready",
            )

        # Queue contract audit in background
        background_tasks.add_task(
            _run_contract_audit_task,
            request.project_id,
            request.token_address,
            request.chain_id,
        )

        LOGGER.info(
            f"Contract audit queued for project {request.project_id[:8]}... "
            f"(token={request.token_address[:10]}..., chain={request.chain_id})"
        )

        return {
            "status": "queued",
            "message": f"Contract audit queued for project {request.project_id}",
            "project_id": request.project_id,
        }

    @app.get("/stats")
    async def get_stats():
        """Get orchestrator statistics.

        Returns:
            Statistics dictionary
        """
        if not orchestrator:
            return {
                "error": "Orchestrator not ready",
                "running_audits": 0,
            }

        return orchestrator.get_stats()

    # Staking verification endpoints
    class StakingVerificationRequest(BaseModel):
        """Request to verify staking status for a wallet."""
        wallet_address: str = Field(..., description="Wallet address to verify")
        chain_id: int = Field(default=1, description="Chain ID (default: Ethereum)")

        @validator("wallet_address")
        def validate_wallet_address(cls, v: str) -> str:
            """Validate wallet address format."""
            if not v.startswith("0x") or len(v) != 42:
                raise ValueError("Invalid wallet address format")
            return v.lower()

        class Config:
            """Pydantic config."""
            json_schema_extra = {
                "example": {
                    "wallet_address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
                    "chain_id": 1,
                }
            }

    class StakingVerificationResponse(BaseModel):
        """Response with staking verification results."""
        wallet_address: str
        staked_amount: int
        staked_amount_formatted: str
        staking_tier: str
        staking_contract_address: Optional[str] = None
        is_verified: bool
        last_updated: str

    @app.post(
        "/staking/verify",
        response_model=StakingVerificationResponse,
        status_code=status.HTTP_200_OK,
        responses={
            200: {"description": "Staking verified successfully"},
            400: {"description": "Invalid wallet address"},
            503: {"description": "Service not ready"},
        },
    )
    async def verify_staking(request: StakingVerificationRequest):
        """Verify staking status for a wallet address.

        Queries the blockchain to check:
        - How many VERITAS LP tokens are staked
        - Current staking tier based on amount staked
        - Staking contract information

        Args:
            request: Staking verification request

        Returns:
            Staking verification results

        Raises:
            HTTPException: If service is not ready or verification fails
        """
        if not orchestrator or not orchestrator.w3:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Blockchain service not ready",
            )

        try:
            from eth_utils import to_checksum_address, from_wei
            from datetime import datetime

            checksum_address = to_checksum_address(request.wallet_address)
            w3 = orchestrator.w3

            # Get staking contract address from environment
            staking_contract_address = os.environ.get("VERITAS_STAKING_ADDRESS")
            veritas_lp_address = os.environ.get("VERITAS_LP_ADDRESS")

            # Query staked balance
            staked_amount = 0

            if staking_contract_address:
                try:
                    LOGGER.info(f"Querying staking contract {staking_contract_address} for wallet {checksum_address[:10]}...")

                    # Use web3 contract interface for proper ABI encoding/decoding
                    stake_of_abi = [{
                        "inputs": [{"internalType": "address", "name": "account", "type": "address"}],
                        "name": "stakeOf",
                        "outputs": [
                            {"components": [
                                {"internalType": "uint96", "name": "amount", "type": "uint96"},
                                {"internalType": "uint40", "name": "stakedAt", "type": "uint40"},
                                {"internalType": "uint40", "name": "activatesAt", "type": "uint40"},
                                {"internalType": "uint40", "name": "earliestUnstakeAt", "type": "uint40"},
                                {"internalType": "uint40", "name": "unstakeRequestedAt", "type": "uint40"},
                                {"internalType": "uint8", "name": "tier", "type": "uint8"},
                                {"internalType": "uint16", "name": "feeBpsApplied", "type": "uint16"}
                            ],
                            "internalType": "struct VeritaStaking.StakeInfo",
                            "name": "",
                            "type": "tuple"}
                        ],
                        "stateMutability": "view",
                        "type": "function"
                    }]

                    contract = w3.eth.contract(address=to_checksum_address(staking_contract_address), abi=stake_of_abi)
                    stake_info = contract.functions.stakeOf(checksum_address).call()

                    # stake_info is a tuple: (amount, stakedAt, activatesAt, earliestUnstakeAt, unstakeRequestedAt, tier, feeBpsApplied)
                    staked_amount = stake_info[0] if stake_info else 0
                    LOGGER.info(f"Stake info for {checksum_address[:10]}...: amount={staked_amount}, tier={stake_info[5] if stake_info else 'N/A'}, raw={stake_info}")
                except Exception as e:
                    LOGGER.warning(f"Failed to query staking contract: {e}")
                    staked_amount = 0

            elif veritas_lp_address:
                # Fallback: check LP token balance directly
                try:
                    # ERC20 balanceOf(address) function signature
                    balance_of_signature = "0x70a08231"
                    call_data = balance_of_signature + bytes.fromhex(checksum_address[2:]).rjust(32, b"\x00")

                    result = w3.eth.call({
                        "to": to_checksum_address(veritas_lp_address),
                        "data": "0x" + call_data.hex(),
                    })

                    staked_amount = int(result.hex(), 16)
                except Exception as e:
                    LOGGER.warning(f"Failed to query LP token balance: {e}")
                    staked_amount = 0
            else:
                LOGGER.warning("No staking contract or LP token configured")

            # Determine staking tier based on amount staked
            # Using same thresholds as backend StakingTierLimits
            LP_AMOUNTS = {
                "free": 0,
                "basic": 100,
                "basic_plus": 1000,
                "premium": 5000,
                "premium_plus": 10000,
                "pro": 100000,
            }

            staking_tier = "free"
            for tier, amount in sorted(LP_AMOUNTS.items(), key=lambda x: x[1], reverse=True):
                if staked_amount >= amount * (10 ** 18):
                    staking_tier = tier
                    break

            return StakingVerificationResponse(
                wallet_address=checksum_address,
                staked_amount=staked_amount,
                staked_amount_formatted=f"{from_wei(staked_amount, 'ether')} VERITAS LP",
                staking_tier=staking_tier,
                staking_contract_address=staking_contract_address,
                is_verified=True,
                last_updated=datetime.utcnow().isoformat(),
            )

        except Exception as e:
            LOGGER.error(f"Failed to verify staking for {request.wallet_address[:10]}...: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to verify staking: {str(e)}",
            )

    @app.get(
        "/staking/tiers",
        status_code=status.HTTP_200_OK,
    )
    async def get_staking_tiers():
        """Get staking tier information.

        Returns the tier thresholds and benefits.

        Returns:
            Dictionary with tier information
        """
        return {
            "tiers": [
                {
                    "name": "free",
                    "min_lp": 0,
                    "benefits": {
                        "max_audits_per_month": 0,
                        "detailed_analysis": False,
                        "project_reports": False,
                    },
                },
                {
                    "name": "basic",
                    "min_lp": 100,
                    "benefits": {
                        "max_audits_per_month": 0,
                        "detailed_analysis": False,
                        "project_reports": False,
                    },
                },
                {
                    "name": "basic_plus",
                    "min_lp": 1000,
                    "benefits": {
                        "max_audits_per_month": 1,
                        "detailed_analysis": True,
                        "project_reports": False,
                    },
                },
                {
                    "name": "premium",
                    "min_lp": 5000,
                    "benefits": {
                        "max_audits_per_month": 6,
                        "detailed_analysis": True,
                        "project_reports": False,
                    },
                },
                {
                    "name": "premium_plus",
                    "min_lp": 10000,
                    "benefits": {
                        "max_audits_per_month": 11,
                        "detailed_analysis": True,
                        "project_reports": False,
                    },
                },
                {
                    "name": "pro",
                    "min_lp": 100000,
                    "benefits": {
                        "max_audits_per_month": -1,  # Unlimited
                        "detailed_analysis": True,
                        "project_reports": True,
                    },
                },
            ]
        }

    async def _run_audit_task(
        project_id: str,
        token_address: str,
        chain_id: int,
        force_full: bool,
    ) -> None:
        """Run audit task in background.

        Args:
            project_id: Project UUID
            token_address: Token contract address
            chain_id: Chain ID
            force_full: Whether to force full audit including static data
        """
        try:
            LOGGER.info(
                f"Starting background audit for {project_id[:8]}... "
                f"(force_full={force_full})"
            )

            result = await orchestrator.run_full_audit(
                project_id=project_id,
                token_address=token_address,
                chain_id=chain_id,
            )

            LOGGER.info(
                f"Background audit completed: {result.status} for {project_id[:8]}..."
            )

        except Exception as e:
            LOGGER.error(f"Background audit failed for {project_id[:8]}...: {e}", exc_info=True)

    async def _run_contract_audit_task(
        project_id: str,
        token_address: str,
        chain_id: int,
    ) -> None:
        """Run contract audit task in background.

        Args:
            project_id: Project UUID
            token_address: Token contract address
            chain_id: Chain ID
        """
        try:
            LOGGER.info(f"Starting background contract audit for {project_id[:8]}...")

            # Check if orchestrator has contract audit scout
            if not hasattr(orchestrator, 'contract_audit_scout') or not orchestrator.contract_audit_scout:
                LOGGER.warning(f"ContractAuditScout not available for {project_id[:8]}...")
                return

            # Run contract audit only
            result = await orchestrator.contract_audit_scout.audit_contract(
                token_address=token_address,
                chain_id=chain_id,
                force=True,
            )

            LOGGER.info(
                f"Contract audit completed for {project_id[:8]}...: "
                f"score={result.overall_score:.1f}, risk={result.risk_level}"
            )

            # Store results to backend
            if orchestrator.backend_client:
                from datetime import datetime
                payload = {
                    "audit_data": {
                        "contract_audit": result.__dict__,
                    },
                    "completed_at": datetime.utcnow().isoformat(),
                }
                orchestrator.backend_client.store_audit_results(project_id, payload)

        except Exception as e:
            LOGGER.error(f"Contract audit failed for {project_id[:8]}...: {e}", exc_info=True)


def run_unified_api(
    host: Optional[str] = None,
    port: Optional[int] = None,
    log_level: str = "INFO",
) -> None:
    """Run the unified API server.

    Args:
        host: Host to bind to (default: from UNIFIED_API_HOST env or 0.0.0.0)
        port: Port to bind to (default: from UNIFIED_API_PORT env or 8080)
        log_level: Logging level (default: INFO)

    Raises:
        ImportError: If FastAPI is not installed
    """
    if not HAS_FASTAPI:
        raise ImportError(
            "FastAPI required for unified API server: pip install fastapi uvicorn"
        )

    import uvicorn

    host = host or os.environ.get("UNIFIED_API_HOST", "0.0.0.0")
    port = port or int(os.environ.get("UNIFIED_API_PORT", "8080"))

    logging.basicConfig(level=log_level)

    LOGGER.info(f"Starting unified API server on {host}:{port}")

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=log_level.lower(),
    )


# CLI entry point
if __name__ == "__main__":
    import sys

    log_level = sys.argv[1] if len(sys.argv) > 1 else "INFO"
    run_unified_api(log_level=log_level)
