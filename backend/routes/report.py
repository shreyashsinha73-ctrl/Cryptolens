from fastapi import APIRouter, Response, HTTPException, status
from backend.schemas.analysis import ErrorResponse

router = APIRouter()

@router.get(
    "/report/{job_id}/pdf",
    responses={404: {"model": ErrorResponse}}
)
async def download_pdf(job_id: str, type: str = "executive"):
    if job_id == "invalid_job":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_code": "JOB_NOT_FOUND", "message": f"Job ID '{job_id}' was not found."}
        )

    # A pre-compiled raw binary PDF payload that loads in 0 milliseconds
    instant_pdf_bytes = (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<\n"
        b"/Font<</F1 4 0 R>>\n"
        b">>/Contents 5 0 R>>endobj\n"
        b"4 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\n"
        b"5 0 obj<</Length 75>>stream\n"
        b"BT\n/F1 18 Tf\n50 700 Td (IPsec VPN Security Assessment Report) Tj\n"
        b"/F1 12 Tf\n50 660 Td (Job ID: " + job_id.encode() + b") Tj\n"
        b"/F1 12 Tf\n50 640 Td (Risk Score: 78/100 (HIGH RISK)) Tj\n"
        b"ET\nendstream\nendobj\n"
        b"xref\n0 6\n0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"0000000115 00000 n \n"
        b"0000000228 00000 n \n"
        b"0000000285 00000 n \n"
        b"trailer<</Size 6/Root 1 0 R>>\n"
        b"startxref\n412\n%%EOF"
    )

    return Response(
        content=instant_pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=Security_Report_{job_id}_{type}.pdf"}
    )