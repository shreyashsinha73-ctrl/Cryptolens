from datetime import datetime, timezone
from pathlib import Path
import uuid
import aiofiles
from backend.schemas.analysis import ErrorResponse, UploadResponse
from fastapi import APIRouter, File, HTTPException, UploadFile, status

router = APIRouter()

UPLOAD_DIR = Path("backend/uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


@router.post(
    "/analyze",
    response_model=UploadResponse,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        400: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
)
async def analyze_pcap(file: UploadFile = File(...)):
  # 1. Robust extension check
  file_ext = Path(file.filename).suffix.lower()
  if file_ext not in ALLOWED_EXTENSIONS:
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={
            "error_code": "INVALID_FILE_FORMAT",
            "message": "Only .pcap, .pcapng, and .cap files are supported.",
        },
    )

  # 2. Generate unique tracking ID
  job_id = f"job_{uuid.uuid4().hex[:8]}"
  safe_filename = f"{job_id}{file_ext}"
  file_path = UPLOAD_DIR / safe_filename

  try:
    # 3. Asynchronously stream and write the uploaded PCAP file to disk
    async with aiofiles.open(file_path, "wb") as buffer:
      while chunk := await file.read(1024 * 1024):  # 1MB chunks
        await buffer.write(chunk)
  except Exception as e:
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail={
            "error_code": "FILE_SAVE_FAILED",
            "message": f"Could not save uploaded file: {str(e)}",
        },
    )
  finally:
    await file.close()

  # 4. Trigger Control-Plane pipeline (Deterministic Demux + AST + Rules)
  try:
    from engine.control_plane.service import run_control_plane_pipeline
    run_control_plane_pipeline(str(file_path), job_id)
  except Exception as e:
    # Do not silently swallow pipeline failures: report verbose error
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail={
            "error_code": "PIPELINE_EXECUTION_FAILED",
            "message": f"Control-plane analysis pipeline failed on '{file.filename}': {str(e)}"
        }
    )


  # 5. Return matching Pydantic contract
  return UploadResponse(
      job_id=job_id,
      status="processing",
      filename=file.filename,
      uploaded_at=datetime.now(timezone.utc).isoformat(),
  )

