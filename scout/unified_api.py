"""Unified audit API for Spectra Blockchain Worker.

Provides a single API for:
- Triggering audits for projects
- Querying audit results
- Contract update notifications
- Health and status monitoring

Endpoints:
- POST /audit/trigger          - Trigger full or partial audit
- GET  /audit/{project_id}      - Get all audit data for project
- GET  /audit/{project_id}/history - Get historical snapshots
- POST /audit/contract-update  - Trigger code audit on contract change
- GET  /health                  - Health check
- GET  /stats                   - Service statistics
"""
from __future__ import annotations

import logging
import os
from datetime import datetime
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
