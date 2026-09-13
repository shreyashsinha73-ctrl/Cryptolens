from fastapi import APIRouter, HTTPException, status
from backend.schemas.analysis import AnalysisResultResponse, ErrorResponse
from engine.control_plane.service import get_job_result

router = APIRouter()

@router.get(
    "/results/{job_id}",
    response_model=AnalysisResultResponse,
    responses={
        404: {"model": ErrorResponse}
    }
)
async def get_results(job_id: str):
    # 1. Reject explicit invalid query identifiers
    if job_id == "invalid_job":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_code": "JOB_NOT_FOUND", "message": f"Job ID '{job_id}' does not exist."}
        )

    # 2. Attempt to fetch real dynamically processed job results
    real_result = get_job_result(job_id)
    if real_result:
        return AnalysisResultResponse(**real_result)

    # 3. If not found in cache, return 404 with verbose diagnostic detail (NO DUMMY FALLBACK)
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={
            "error_code": "JOB_NOT_FOUND",
            "message": f"Job ID '{job_id}' was not found or has not finished processing. Ensure the capture was uploaded via /api/v1/analyze."
        }
    )