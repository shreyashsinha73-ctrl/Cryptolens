from fastapi import APIRouter, HTTPException, status
from backend.schemas.analysis import AnalysisResultResponse, ErrorResponse

router = APIRouter()

@router.get(
    "/results/{job_id}",
    response_model=AnalysisResultResponse,
    responses={404: {"model": ErrorResponse}}
)
async def get_results(job_id: str):
    if job_id == "invalid_job":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_code": "JOB_NOT_FOUND", "message": f"Job ID '{job_id}' does not exist."}
        )

    return AnalysisResultResponse(
        job_id=job_id,
        status="completed",
        summary={
            "overall_risk_score": 78,
            "risk_level": "HIGH",
            "ai_confidence_score": 0.92,
            "agreement_flag": True
        },
        control_plane={
            "ike_version": "IKEv2",
            "operating_mode": "Tunnel",
            "encryption_algorithm": "AES-128-CBC",
            "integrity_algorithm": "HMAC-SHA2-256",
            "dh_group": 14,
            "pfs_enabled": False,
            "key_lifetime_seconds": 28800,
            "replay_protection_enabled": True
        },
        data_plane={
            "detected_traffic": [
                {"traffic_type": "VoIP", "percentage": 45.2, "packet_count": 1240, "avg_packet_size_bytes": 160},
                {"traffic_type": "Video Streaming", "percentage": 38.8, "packet_count": 890, "avg_packet_size_bytes": 1380},
                {"traffic_type": "WhatsApp/Messaging", "percentage": 16.0, "packet_count": 210, "avg_packet_size_bytes": 85}
            ],
            "heuristic_mode_prediction": "Tunnel",
            "llm_mode_prediction": "Tunnel"
        },
        threat_matrix=[
            {
                "id": "VULN-001",
                "severity": "HIGH",
                "category": "Forward Secrecy",
                "title": "Perfect Forward Secrecy (PFS) Disabled",
                "description": "If the private key is compromised, all recorded past traffic can be retroactively decrypted."
            },
            {
                "id": "VULN-002",
                "severity": "MEDIUM",
                "category": "Cipher Strength",
                "title": "Legacy Cipher Suite (AES-CBC without AEAD)",
                "description": "CBC mode without authenticated encryption leaves traffic vulnerable to padding attacks."
            }
        ]
    )