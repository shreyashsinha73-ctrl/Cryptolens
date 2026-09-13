from fastapi import APIRouter, HTTPException, status

from backend.schemas.analysis import ErrorResponse
from backend.services.result_store import ResultStore


router = APIRouter()
result_store = ResultStore()


@router.get(
    "/report/{job_id}/pdf",
    responses={404: {"model": ErrorResponse}}
)
async def download_pdf(job_id: str, type: str = "executive"):
    try:
        result = result_store.load(job_id)

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

    # PDF generation will be added in the next step.
    return {
        "job_id": job_id,
        "status": result.get("status"),
        "report_type": type,
        "message": "Stored analysis loaded successfully."
    }