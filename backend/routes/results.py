from fastapi.responses import JSONResponse
from fastapi import APIRouter, HTTPException, status
from backend.schemas.analysis import (
    AnalysisResultResponse,
    AnalysisFailureResponse,
    ErrorResponse,
)
from backend.services.result_store import ResultStore
from backend.core.security import validate_job_id


router = APIRouter()
result_store = ResultStore()


@router.get(
    "/results/{job_id}",
    response_model=AnalysisResultResponse | AnalysisFailureResponse,
    responses={404: {"model": ErrorResponse}}
)
async def get_results(job_id: str):
    job_id = validate_job_id(job_id)
    try:
        data = result_store.load(job_id)
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_code": "JOB_NOT_FOUND",
                "message": (
                    f"Job ID '{job_id}' does not exist "
                    "or is still processing."
                )
            }
        )

    if data.get("status") == "processing":
        return JSONResponse(status_code=200, content={"job_id": job_id, "status": "processing"})

    if data.get("status") == "failed":
        return AnalysisFailureResponse(**data)

    if data.get("status") == "completed" and not data.get("remediation"):
        try:
            import asyncio
            from backend.routes.analyze import _build_briefing
            findings = data.get("threat_matrix") or data.get("findings") or []
            cp = data.get("control_plane") or {}
            briefing = await asyncio.to_thread(_build_briefing, findings, cp)
            if briefing and (briefing.get("verbose_report") or briefing.get("executive_summary")):
                data["remediation"] = briefing
                result_store.save(job_id, data)
        except Exception:
            pass

    return AnalysisResultResponse(**data)