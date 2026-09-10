from fastapi import APIRouter, UploadFile, File, HTTPException, status
import uuid
from datetime import datetime, timezone
from backend.schemas.analysis import UploadResponse, ErrorResponse

router = APIRouter()

@router.post(
    "/analyze",
    response_model=UploadResponse,
    status_code=status.HTTP_202_ACCEPTED,
    responses={400: {"model": ErrorResponse}}
)
async def analyze_pcap(file: UploadFile = File(...)):
    if not (file.filename.endswith(".pcap") or file.filename.endswith(".pcapng")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error_code": "INVALID_FILE_FORMAT", "message": "Only .pcap and .pcapng files are supported."}
        )
    
    job_id = f"job_{uuid.uuid4().hex[:8]}"
    return UploadResponse(
        job_id=job_id,
        status="processing",
        filename=file.filename,
        uploaded_at=datetime.now(timezone.utc).isoformat()
    )