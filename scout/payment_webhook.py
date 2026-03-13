"""Payment webhook handler for audit worker.

This module provides a FastAPI server that receives webhooks from the backend
when payments are verified, triggering full-spectrum audits.

Usage:
    python -m scout.payment_webhook

Environment Variables:
    AUDIT_WEBHOOK_PORT: Port for webhook server (default: 8080)
    AUDIT_WEBHOOK_HOST: Host for webhook server (default: 0.0.0.0)
    AUDIT_BACKEND_WEBHOOK_SECRET: Secret for webhook authentication (optional)
"""
from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

try:
    from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, status
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field, validator
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    FastAPI = None
    BaseModel = None

from .audit_orchestrator import AuditOrchestrator, AuditResult, create_audit_orchestrator

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
    LOGGER.info("Audit orchestrator registered with webhook server")


def get_orchestrator() -> Optional[AuditOrchestrator]:
    """Get the global orchestrator instance.

    Returns:
        AuditOrchestrator instance or None
    """
    return orchestrator


if HAS_FASTAPI:

    class PaymentVerifiedPayload(BaseModel):
        """Payload when payment is verified."""

        project_id: str = Field(..., description="Project UUID")
        token_address: str = Field(..., description="Token contract address")
        chain_id: int = Field(default=1, description="Chain ID (default: Ethereum)")
        payment_id: str = Field(..., description="Payment identifier")

        @validator("token_address")
        def validate_token_address(cls, v: str) -> str:
            """Validate token address format."""
            if not v.startswith("0x") or len(v) != 42:
                raise ValueError("Invalid token address format")
            return v.lower()

        @validator("project_id", "payment_id")
        def validate_not_empty(cls, v: str) -> str:
            """Validate field is not empty."""
            if not v or not v.strip():
                raise ValueError("Field cannot be empty")
            return v

        class Config:
            """Pydantic config."""

            schema_extra = {
                "example": {
                    "project_id": "550e8400-e29b-41d4-a716-446655440000",
                    "token_address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
                    "chain_id": 1,
                    "payment_id": "pay_1234567890",
                }
            }

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
        title="Spectra Audit Worker API",
        description="Webhook server for triggering audits upon payment verification",
        version="1.0.0",
    )

    @app.get("/health")
    async def health_check():
        """Health check endpoint.

        Returns:
            Health status with orchestrator ready flag
        """
        return {
            "status": "healthy",
            "service": "spectra-audit-worker",
            "orchestrator_ready": orchestrator is not None,
            "version": "1.0.0",
        }

    @app.post(
        "/webhook/payment-verified",
        response_model=Dict[str, str],
        status_code=status.HTTP_202_ACCEPTED,
        responses={
            202: {"description": "Audit queued successfully"},
            503: {"description": "Audit service not ready"},
            400: {"description": "Invalid payload"},
        },
    )
    async def payment_verified(
        payload: PaymentVerifiedPayload,
        background_tasks: BackgroundTasks,
        request: Request,
    ):
        """Webhook triggered when payment is verified.

        Queues a full audit as a background task.

        Args:
            payload: Payment verification payload
            background_tasks: FastAPI background tasks
            request: FastAPI request object

        Returns:
            Confirmation response

        Raises:
            HTTPException: If orchestrator is not ready
        """
        # Optional webhook secret verification
        webhook_secret = os.environ.get("AUDIT_BACKEND_WEBHOOK_SECRET")
        if webhook_secret:
            received_secret = request.headers.get("X-Webhook-Secret")
            if received_secret != webhook_secret:
                LOGGER.warning("Webhook secret verification failed")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid webhook secret",
                )

        if not orchestrator:
            LOGGER.warning("Payment verified but orchestrator not ready")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Audit service not ready",
            )

        # Queue audit in background
        background_tasks.add_task(
            _run_audit_task,
            payload.project_id,
            payload.token_address,
            payload.chain_id,
            payload.payment_id,
        )

        LOGGER.info(
            f"Audit queued for project {payload.project_id[:8]}... "
            f"(token={payload.token_address[:10]}..., chain={payload.chain_id})"
        )

        return {
            "status": "queued",
            "message": f"Audit queued for project {payload.project_id}",
            "project_id": payload.project_id,
        }

    @app.get(
        "/audit/{project_id}/status",
        response_model=AuditStatusResponse,
        responses={
            200: {"description": "Status retrieved"},
            404: {"description": "Project not found or no audit run"},
        },
    )
    async def get_audit_status(project_id: str):
        """Get status of an audit for a project.

        Args:
            project_id: Project UUID

        Returns:
            Audit status response

        Raises:
            HTTPException: If project not found
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
        payment_id: str,
    ) -> None:
        """Run audit task in background.

        Args:
            project_id: Project UUID
            token_address: Token contract address
            chain_id: Chain ID
            payment_id: Payment identifier
        """
        try:
            LOGGER.info(f"Starting background audit for {project_id[:8]}...")

            result = await orchestrator.run_full_audit(
                project_id=project_id,
                token_address=token_address,
                chain_id=chain_id,
                payment_id=payment_id,
            )

            LOGGER.info(
                f"Background audit completed: {result.status} for {project_id[:8]}..."
            )

        except Exception as e:
            LOGGER.error(f"Background audit failed for {project_id[:8]}...: {e}", exc_info=True)


def run_webhook_server(
    host: Optional[str] = None,
    port: Optional[int] = None,
    log_level: str = "INFO",
) -> None:
    """Run the webhook server.

    Args:
        host: Host to bind to (default: from AUDIT_WEBHOOK_HOST env or 0.0.0.0)
        port: Port to bind to (default: from AUDIT_WEBHOOK_PORT env or 8080)
        log_level: Logging level (default: INFO)

    Raises:
        ImportError: If FastAPI is not installed
    """
    if not HAS_FASTAPI:
        raise ImportError(
            "FastAPI required for webhook server: pip install fastapi uvicorn"
        )

    import uvicorn

    host = host or os.environ.get("AUDIT_WEBHOOK_HOST", "0.0.0.0")
    port = port or int(os.environ.get("AUDIT_WEBHOOK_PORT", "8080"))

    logging.basicConfig(level=log_level)

    LOGGER.info(f"Starting webhook server on {host}:{port}")

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
    run_webhook_server(log_level=log_level)
