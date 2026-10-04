"""
capture.py — API routes for testbed capture auto-ingest

Provides endpoints for the frontend to:
  - List all testbed captures and their ingest status
  - Trigger batch ingestion of all captures from manifest.json
  - Ingest a single specific capture by config_id
  - Check auto-ingest status

These routes reuse the same analysis pipeline as manual uploads
(process_pcap_pipeline from routes/analyze.py), ensuring consistent
scoring, compliance, and reporting output.
"""

from pathlib import Path
from fastapi import APIRouter, HTTPException, status, BackgroundTasks

from backend.services.capture_watcher import CaptureWatcher
from backend.services.result_store import ResultStore
from backend.services.analyzer_provider import get_analyzer_provider
from backend.scoring.scoring_engine import ScoringEngine
from backend.scoring.compliance_engine import ComplianceEngine

router = APIRouter()

# Reuse the same engine instances as the main analyze route
scorer = ScoringEngine()
provider = get_analyzer_provider()
compliance_engine = ComplianceEngine()
result_store = ResultStore()

# Single watcher instance shared across requests
_watcher = CaptureWatcher()


def _run_pipeline_sync(job_id: str, file_path: Path):
    """
    Synchronous version of the analysis pipeline.
    Identical logic to process_pcap_pipeline in routes/analyze.py,
    but runs synchronously for batch ingest.
    """
    try:
        analysis_input = provider.get_analysis(str(file_path))

        evaluation = scorer.evaluate(analysis_input)

        compliance_result = compliance_engine.evaluate(analysis_input)

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

        remediation = None
        try:
            from backend.remediation.remediation_engine import RemediationEngine
            _rem_engine = RemediationEngine()
            remediation = _rem_engine.generate_remediation(
                findings=evaluation.get("findings", []),
                control_plane=analysis_input.get("control_plane") or {},
            )
        except Exception as r_err:
            pass

        result_payload = {
            "job_id": job_id,
            "status": "completed",
            "source": "testbed_auto_ingest",
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
            "score_breakdown": evaluation.get("score_breakdown", {}),
            "threat_matrix": evaluation.get("findings", []),
            "compliance": compliance_result,
            "pcap_file": str(Path(file_path).resolve()),
            "remediation": remediation,
        }

        result_store.save(job_id, result_payload)

    except Exception as exc:
        error_payload = {
            "job_id": job_id,
            "status": "failed",
            "source": "testbed_auto_ingest",
            "error": {
                "error_code": "INGEST_FAILED",
                "message": str(exc),
            },
        }
        result_store.save(job_id, error_payload)
        raise


# ──────────────────────────────────────────────────────────────────
# GET /api/v1/capture/testbed — List all available testbed captures
# ──────────────────────────────────────────────────────────────────

@router.get("/capture/testbed")
async def list_testbed_captures():
    """
    Returns all captures from the testbed manifest.json with their
    analysis ingest status (ingested / not yet ingested).
    """
    captures = _watcher.list_available_captures()
    untracked = _watcher.scan_untracked_pcaps()

    return {
        "captures": captures,
        "untracked_pcaps": untracked,
        "status": _watcher.get_ingest_status(),
    }


# ──────────────────────────────────────────────────────────────────
# POST /api/v1/capture/ingest — Batch ingest all testbed captures
# ──────────────────────────────────────────────────────────────────

@router.post("/capture/ingest", status_code=status.HTTP_200_OK)
async def ingest_all_captures(force: bool = False):
    """
    Batch-ingest all PCAP files from the testbed captures/ directory.
    Reads manifest.json and processes each capture through the full
    analysis pipeline (IKE parsing → scoring → compliance → storage).

    Query params:
      - force: if true, re-analyze captures even if already ingested
    """
    result = _watcher.ingest_all(_run_pipeline_sync, force=force)

    if result["status"] == "no_captures":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_code": "NO_CAPTURES",
                "message": result["message"],
            },
        )

    return result


# ──────────────────────────────────────────────────────────────────
# POST /api/v1/capture/ingest/{config_id} — Ingest a single capture
# ──────────────────────────────────────────────────────────────────

@router.post(
    "/capture/ingest/{config_id}",
    status_code=status.HTTP_200_OK,
)
async def ingest_single_capture(config_id: str, force: bool = False):
    """
    Ingest a single testbed capture by config ID.
    The config_id corresponds to a specific row in config_matrix.yaml.

    Example: POST /api/v1/capture/ingest/config_01_tunnel_aes256gcm_dh19_pfson
    """
    # Find the matching PCAP file from the manifest
    captures = _watcher.list_available_captures()
    matching = [
        c for c in captures
        if c["config_id"] == config_id
    ]

    if not matching:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_code": "CONFIG_NOT_FOUND",
                "message": (
                    f"No capture found for config_id '{config_id}'. "
                    "Check GET /api/v1/capture/testbed for available configs."
                ),
            },
        )

    entry = matching[0]
    pcap_file = entry["pcap_file"]

    result = _watcher.ingest_single(pcap_file, _run_pipeline_sync, force=force)

    if result["status"] == "file_not_found":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_code": "PCAP_NOT_FOUND",
                "message": result.get("error", "PCAP file missing from disk."),
            },
        )

    return result


# ──────────────────────────────────────────────────────────────────
# GET /api/v1/capture/status — Check overall ingest status
# ──────────────────────────────────────────────────────────────────

@router.get("/capture/status")
async def get_capture_status():
    """Returns the current auto-ingest status and registry."""
    return _watcher.get_ingest_status()
