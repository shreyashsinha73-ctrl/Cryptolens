from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse

from backend.schemas.analysis import ErrorResponse
from backend.services.result_store import ResultStore
from backend.reporting.generate_pdf import generate_pdf


router = APIRouter()
result_store = ResultStore()


@router.get(
    "/report/{job_id}/pdf",
    responses={
        404: {"model": ErrorResponse},
        400: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    }
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

    if result.get("status") == "failed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error_code": "REPORT_UNAVAILABLE",
                "message": "A report cannot be generated for a failed analysis."
            }
        )

    try:
        pdf_path = generate_pdf(
            result=result,
            report_type=type
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error_code": "INVALID_REPORT_TYPE",
                "message": str(exc)
            }
        )

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error_code": "REPORT_GENERATION_FAILED",
                "message": "The security assessment report could not be generated."
            }
        )

    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=f"Security_Report_{job_id}_{type.lower()}.pdf",
    )