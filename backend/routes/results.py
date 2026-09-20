from fastapi import APIRouter, HTTPException, status
from backend.schemas.analysis import (
    AnalysisResultResponse,
    AnalysisFailureResponse,
    ErrorResponse,
)
from backend.services.result_store import ResultStore




router = APIRouter()
result_store = ResultStore()


@router.get(
    "/results/{job_id}",
    response_model=AnalysisResultResponse | AnalysisFailureResponse,
    responses={404: {"model": ErrorResponse}}
)
async def get_results(job_id: str):
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

    if data.get("status") == "failed":
        return AnalysisFailureResponse(**data)

    return AnalysisResultResponse(**data)