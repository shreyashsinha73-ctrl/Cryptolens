from datetime import datetime, timezone
from pathlib import Path
import uuid
import aiofiles
from fastapi import APIRouter, File, HTTPException, UploadFile, status, BackgroundTasks
from backend.schemas.analysis import ErrorResponse, UploadResponse
from backend.scoring.scoring_engine import ScoringEngine
from backend.services.result_store import ResultStore
from backend.services.analyzer_provider import get_analyzer_provider
from backend.scoring.compliance_engine import ComplianceEngine

router = APIRouter()

UPLOAD_DIR = Path("backend/uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

from backend.services.analyzer_provider import AnalyzerProvider

# 2. Instantiate the engines globally for the route
scorer = ScoringEngine()
provider = get_analyzer_provider()
compliance_engine = ComplianceEngine()
result_store = ResultStore()

async def process_pcap_pipeline(job_id: str, file_path: Path):
    try:
        # Part 2 is now integrated through AnalyzerProvider.
        # The provider calls IkeParser.parse(), unwraps control_plane,
        # and normalizes parser output for the backend contract.
        analysis_input = provider.get_analysis(str(file_path))

        # Part 5: authoritative security scoring
        evaluation = scorer.evaluate(analysis_input)

        # Part 5: standards alignment
        compliance_result = compliance_engine.evaluate(analysis_input)

        # Calculate processed packet count from the available data plane.
        # This remains compatible with the current placeholder Part 3.
        processed_packets = sum(
            item.get("packet_count", 0)
            for item in analysis_input.get("data_plane", {}).get(
                "detected_traffic", []
            )
        )

        result_payload = {
            "job_id": job_id,
            "status": "completed",
            "summary": {
                "overall_risk_score": 100 - evaluation["score"],
                "risk_level": evaluation["risk_level"],
                "ai_confidence_score": evaluation["ai_confidence_score"],
                "agreement_flag": evaluation["agreement_flag"],
                "processed_packets": processed_packets,
            },
            "control_plane": analysis_input.get("control_plane"),
            "data_plane": analysis_input.get("data_plane"),
            "score_breakdown": evaluation["score_breakdown"],
            "threat_matrix": evaluation["findings"],
            "compliance": compliance_result,
        }

        result_store.save(job_id, result_payload)

    except Exception as exc:
        error_payload = {
            "job_id": job_id,
            "status": "failed",
            "error": {
                "error_code": "ANALYSIS_FAILED",
                "message": str(exc),
            },
        }

        result_store.save(job_id, error_payload)
@router.post(
    "/analyze",
    response_model=UploadResponse,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        400: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
)
async def analyze_pcap(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error_code": "INVALID_FILE_FORMAT",
                "message": "Only .pcap, .pcapng, and .cap files are supported.",
            },
        )

    job_id = f"job_{uuid.uuid4().hex[:8]}"
    safe_filename = f"{job_id}{file_ext}"
    file_path = UPLOAD_DIR / safe_filename

    try:
        async with aiofiles.open(file_path, "wb") as buffer:
            while chunk := await file.read(1024 * 1024):
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

    # Trigger background task
    background_tasks.add_task(process_pcap_pipeline, job_id, file_path)

    return UploadResponse(
        job_id=job_id,
        status="processing",
        filename=file.filename,
        uploaded_at=datetime.now(timezone.utc).isoformat(),
    )
