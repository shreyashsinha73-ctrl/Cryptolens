from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse

from backend.schemas.analysis import ErrorResponse
from backend.services.result_store import ResultStore
from backend.reporting.generate_pdf import generate_pdf
from backend.core.security import validate_job_id


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
    job_id = validate_job_id(job_id)
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
        try:
            from backend.services.neon_db import save_pdf_to_neon
            with open(pdf_path, "rb") as f:
                save_pdf_to_neon(job_id, type, f.read())
        except Exception:
            pass

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error_code": "INVALID_REPORT_TYPE",
                "message": str(exc)
            }
        )

    except Exception:
        try:
            from backend.services.neon_db import get_pdf_from_neon
            from fastapi.responses import Response
            cached_bytes = get_pdf_from_neon(job_id, type)
            if cached_bytes:
                return Response(
                    content=cached_bytes,
                    media_type="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename=Security_Report_{job_id}_{type.lower()}.pdf"}
                )
        except Exception:
            pass
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