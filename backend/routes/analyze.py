import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
import uuid
import aiofiles
from typing import Optional, Dict, Any
from fastapi import APIRouter, File, Form, HTTPException, UploadFile, status, BackgroundTasks
from backend.schemas.analysis import ErrorResponse, UploadResponse
from backend.schemas.sidecar import IPsecSidecarConfig
from backend.scoring.scoring_engine import ScoringEngine
from backend.services.result_store import ResultStore
from backend.services.analyzer_provider import get_analyzer_provider
from backend.scoring.compliance_engine import ComplianceEngine

router = APIRouter()
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
UPLOAD_DIR = PROJECT_ROOT / "backend" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

from backend.services.analyzer_provider import AnalyzerProvider

# 2. Instantiate the engines globally for the route
scorer = ScoringEngine()
provider = get_analyzer_provider()
compliance_engine = ComplianceEngine()
result_store = ResultStore()

def _build_briefing(findings, control_plane):
    from backend.remediation.remediation_engine import RemediationEngine
    rem = RemediationEngine().generate_remediation(findings=findings, control_plane=control_plane or {})
    return {k: rem.get(k) for k in (
        "executive_summary", "verbose_report", "findings_explanations",
        "engine_used", "cached_badge", "is_ai_generated",
    )}


async def _attach_briefing(job_id: str, payload: dict):
    briefing = None
    try:
        briefing = await asyncio.wait_for(
            asyncio.to_thread(_build_briefing, payload.get("threat_matrix") or [], payload.get("control_plane")),
            timeout=20.0,
        )
    except Exception as exc:
        logger.warning("Executive briefing failed for %s (%s); using rules fallback", job_id, type(exc).__name__)
    if not briefing or not (briefing.get("verbose_report") or briefing.get("executive_summary")):
        from backend.services.hardening_advice import build_input, rules_advice
        text = rules_advice(build_input(payload))["summary"]
        briefing = {"executive_summary": text, "verbose_report": text, "findings_explanations": [],
                    "engine_used": "Rules", "cached_badge": None, "is_ai_generated": False}
    try:
        stored = result_store.load(job_id)
        stored["remediation"] = briefing
        result_store.save(job_id, stored)
    except Exception as exc:
        logger.warning("Could not store briefing for %s: %s", job_id, exc)


async def process_pcap_pipeline(job_id: str, file_path: Path, sidecar_config: Optional[dict] = None):
    try:
        # Part 2 is integrated through AnalyzerProvider with optional operator sidecar.
        analysis_input = await asyncio.to_thread(provider.get_analysis, str(file_path), sidecar_config=sidecar_config)

        # Observed ESP sequence-number evidence (metadata only) grades replay protection.
        try:
            from backend.routes.xai import _extract_esp_records_from_pcap
            from backend.engine.xai.threat_localizer import detect_replay_attacks
            esp_records = await asyncio.to_thread(_extract_esp_records_from_pcap, file_path, 500)
            if esp_records:
                dp = analysis_input.setdefault("data_plane", {}) or {}
                analysis_input["data_plane"] = dp
                dp["esp_packet_count"] = len(esp_records)
                dp["replay_candidate_count"] = len(detect_replay_attacks(esp_records))
        except Exception as exc:
            logger.warning("Replay evidence extraction skipped: %s", type(exc).__name__)

        # Part 5: authoritative security scoring
        evaluation = scorer.evaluate(analysis_input)

        # Part 5: standards alignment
        compliance_result = compliance_engine.evaluate(analysis_input)

        # Calculate processed packet count from the available data plane.
        processed_packets = sum(
            item.get("packet_count", 0)
            for item in analysis_input.get("data_plane", {}).get(
                "detected_traffic", []
            )
        )

        security_score = evaluation["score"]

        if security_score is None:
            risk_level = "NOT_ASSESSED"
        else:
            risk_level = evaluation["risk_level"]

        result_payload = {
            "job_id": job_id,
            "status": "completed",
            "summary": {
                "overall_security_score": security_score,
                "risk_level": risk_level,
                "base_risk_level": evaluation.get("base_risk_level"),
                "risk_review": evaluation.get("risk_review"),
                "score_observed_only": evaluation.get("score_observed_only"),
                "score_if_unobserved_fail": evaluation.get("score_if_unobserved_fail"),
                "score_if_unobserved_pass": evaluation.get("score_if_unobserved_pass"),
                "score_headline": evaluation.get("score_headline"),
                "coverage": evaluation.get("coverage"),
                "coverage_ratio": evaluation.get("coverage_ratio"),
                "confidence_label": evaluation.get("confidence_label"),
                "ai_confidence_score": evaluation["ai_confidence_score"],
                "agreement_flag": evaluation["agreement_flag"],
                "processed_packets": processed_packets,
            },
            "control_plane": analysis_input.get("control_plane"),
            "data_plane": analysis_input.get("data_plane"),
            "score_breakdown": evaluation.get(
                "score_breakdown", {}
            ),
            "threat_matrix": evaluation.get(
                "findings", []
            ),
            "compliance": compliance_result,
            "pcap_file": str(Path(file_path).resolve()),
            "remediation": None,
        }

        # Core analysis persisted FIRST; Gemini steps (if any) must never fail the job.
        result_store.save(job_id, result_payload)

        # AI briefings are decoupled and only requested when operator visits AI Insights.

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
async def analyze_pcap(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    sidecar: Optional[UploadFile] = File(default=None),
    sidecar_json: Optional[str] = Form(default=None),
):
    import json
    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error_code": "INVALID_FILE_FORMAT",
                "message": "Only .pcap, .pcapng, and .cap files are supported.",
            },
        )

    # Parse and validate sidecar configuration if supplied
    sidecar_data = None
    if sidecar and sidecar.filename:
        try:
            content = await sidecar.read()
            if content:
                raw_sidecar = json.loads(content.decode("utf-8"))
                sidecar_data = IPsecSidecarConfig(**raw_sidecar).model_dump(exclude_unset=True)
        except json.JSONDecodeError as jde:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error_code": "INVALID_SIDECAR_JSON",
                    "message": f"Malformed sidecar JSON: {str(jde)}",
                },
            )
        except Exception as ve:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error_code": "INVALID_SIDECAR_SCHEMA",
                    "message": f"Sidecar schema validation failed: {str(ve)}",
                },
            )
    elif sidecar_json:
        try:
            raw_sidecar = json.loads(sidecar_json)
            sidecar_data = IPsecSidecarConfig(**raw_sidecar).model_dump(exclude_unset=True)
        except json.JSONDecodeError as jde:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error_code": "INVALID_SIDECAR_JSON",
                    "message": f"Malformed sidecar JSON string: {str(jde)}",
                },
            )
        except Exception as ve:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error_code": "INVALID_SIDECAR_SCHEMA",
                    "message": f"Sidecar schema validation failed: {str(ve)}",
                },
            )

    job_id = f"job_{uuid.uuid4().hex[:8]}"
    safe_filename = f"{job_id}{file_ext}"
    file_path = (UPLOAD_DIR / safe_filename).resolve()

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

    if not file_path.is_file() or file_path.stat().st_size == 0:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error_code": "FILE_SAVE_FAILED",
                "message": f"Uploaded PCAP was not written to {file_path}",
            },
        )

    # Register immediately so GET /results/{job_id} never 404s for a valid job
    result_store.save(job_id, {"job_id": job_id, "status": "processing"})

    # Trigger background task with sidecar configuration
    background_tasks.add_task(process_pcap_pipeline, job_id, file_path, sidecar_data)

    return UploadResponse(
        job_id=job_id,
        status="processing",
        filename=file.filename,
        uploaded_at=datetime.now(timezone.utc).isoformat(),
    )

