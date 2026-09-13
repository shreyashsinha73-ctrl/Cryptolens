from fastapi import APIRouter, Response, HTTPException, status
from backend.schemas.analysis import ErrorResponse
from engine.control_plane.service import get_job_result
from backend.services.pdf_generator import generate_pdf_report

router = APIRouter()

@router.get(
    "/report/{job_id}/pdf",
    responses={
        400: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        500: {"model": ErrorResponse}
    }
)
async def download_pdf(job_id: str, type: str = "executive"):
    """
    Dynamically generates and downloads an Executive or Technical PDF assessment report
    based on the real parsed cryptographic and traffic results of job_id.
    """
    # 1. Fetch real processed job record
    job_data = get_job_result(job_id)
    if not job_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_code": "JOB_NOT_FOUND",
                "message": f"Job ID '{job_id}' does not exist or has not finished processing yet."
            }
        )

    # 2. Check if the job errored out
    if job_data.get("status") == "error":
        error_msg = job_data.get("error_message", "Unknown pipeline error.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error_code": "JOB_FAILED",
                "message": f"Cannot generate report for failed job: {error_msg}"
            }
        )

    # 3. Generate high-fidelity PDF report
    try:
        pdf_bytes = generate_pdf_report(job_data, report_type=type)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error_code": "PDF_GENERATION_FAILED",
                "message": f"Failed to render PDF report: {str(e)}"
            }
        )

    clean_type = "executive" if type.lower() == "executive" else "technical"
    filename = f"Security_Report_{job_id}_{clean_type}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
    )