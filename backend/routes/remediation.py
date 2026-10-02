"""API routes for AI-driven network remediation."""

import asyncio
from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from backend.remediation.remediation_engine import RemediationEngine
from backend.services.result_store import ResultStore

router = APIRouter()
_engine = RemediationEngine()
_store = ResultStore()


@router.post("/api/v1/remediate/{job_id}")
async def generate_remediation(
    job_id: str,
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
    result = _store.load(job_id)
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
