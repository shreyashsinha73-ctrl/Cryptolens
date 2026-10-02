"""API routes for AI-driven network remediation."""

from fastapi import APIRouter, HTTPException
from backend.remediation.remediation_engine import RemediationEngine
from backend.services.result_store import ResultStore

router = APIRouter()
_engine = RemediationEngine()
_store = ResultStore()


@router.post("/api/v1/remediate/{job_id}")
async def generate_remediation(job_id: str):
    """
    Generate hardened IPsec configuration based on audit findings.
    Requires a completed analysis job.
    """
    result = _store.load(job_id)
    if result is None:
        raise HTTPException(404, f"Job {job_id} not found.")

    findings = result.get("findings") or result.get("threat_matrix", [])
    control_plane = result.get("control_plane", {})

    if not control_plane:
        raise HTTPException(
            400,
            "No control-plane data available. "
            "Cannot generate remediation without IKE handshake analysis.",
        )

    remediation = _engine.generate_remediation(
        findings=findings,
        control_plane=control_plane,
    )

    return {
        "job_id": job_id,
        "remediation": remediation,
    }
