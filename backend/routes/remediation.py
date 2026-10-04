"""API routes for AI-driven network remediation."""

import asyncio
from typing import Optional
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict
from backend.services.hardening_advice import get_advice_sync, rules_advice, build_input, TOTAL_TIMEOUT_SECONDS
from backend.remediation.remediation_engine import RemediationEngine
from backend.services.result_store import ResultStore
from backend.core.security import verify_api_auth, validate_job_id

router = APIRouter()
_engine = RemediationEngine()
_store = ResultStore()


@router.post("/api/v1/remediate/{job_id}")
async def generate_remediation(
    job_id: str,
    request: Request = None,
    local_subnet: Optional[str] = None,
    remote_subnet: Optional[str] = None,
    local_id: Optional[str] = None,
    remote_id: Optional[str] = None,
    replay_window: Optional[int] = None,
):
    """
    Generate hardened IPsec configuration based on audit findings.
    Requires a completed analysis job. Accepts real subnets/IDs via query params
    when missing from captured control-plane handshake.
    Uses asyncio.to_thread so LLM network calls do not block the event loop.
    """
    verify_api_auth(request)
    job_id = validate_job_id(job_id)
    try:
        result = _store.load(job_id)
    except (FileNotFoundError, ValueError):
        result = None

    if result is None:
        raise HTTPException(404, f"Job {job_id} not found.")

    findings = result.get("findings") or result.get("threat_matrix", [])
    control_plane = dict(result.get("control_plane") or {})

    # Apply real inputs from query parameters if provided
    if local_subnet and isinstance(local_subnet, str):
        control_plane["local_subnet"] = local_subnet
    if remote_subnet and isinstance(remote_subnet, str):
        control_plane["remote_subnet"] = remote_subnet
    if local_id and isinstance(local_id, str):
        control_plane["local_id"] = local_id
    if remote_id and isinstance(remote_id, str):
        control_plane["remote_id"] = remote_id
    if replay_window and isinstance(replay_window, (int, str)):
        control_plane["replay_window"] = int(replay_window)

    if not control_plane and not (local_subnet and remote_subnet):
        raise HTTPException(
            400,
            "No control-plane data available. "
            "Provide local_subnet and remote_subnet parameters or upload a capture with IKE negotiation.",
        )

    remediation = await asyncio.to_thread(
        _engine.generate_remediation,
        findings=findings,
        control_plane=control_plane,
    )

    return {
        "job_id": job_id,
        "remediation": remediation,
    }


class AdviceRequest(BaseModel):
    """Empty body; unknown fields are rejected."""
    model_config = ConfigDict(extra="forbid")


@router.post("/api/v1/remediate/{job_id}/advice")
async def hardening_advice(job_id: str, request: Request, body: Optional[AdviceRequest] = None):
    """Plain-language hardening advice (Gemini if enabled, else rules). Findings only."""
    verify_api_auth(request)
    job_id = validate_job_id(job_id)
    try:
        result = _store.load(job_id)
    except (FileNotFoundError, ValueError):
        raise HTTPException(404, f"Job {job_id} not found.")
    if result.get("status") != "completed":
        raise HTTPException(409, "Analysis not completed yet.")
    try:
        out = await asyncio.wait_for(asyncio.to_thread(get_advice_sync, result), TOTAL_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        out = {"source": "rules", "model": "rules-v1", "advice": rules_advice(build_input(result))}
    return {"job_id": job_id, "hardening_advice": out["advice"], "source": out["source"], "model": out["model"]}

@router.get("/api/v1/ai/status")
async def get_ai_status(request: Request = None):
    from backend.engine.llm_client.client import GeminiClient
    return GeminiClient.get_status()
