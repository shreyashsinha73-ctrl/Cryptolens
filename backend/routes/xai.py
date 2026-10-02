"""XAI threat localization API routes."""

from fastapi import APIRouter, HTTPException
from backend.engine.xai.threat_localizer import localize_threats, detect_replay_attacks
from backend.streaming.live_sniffer import ESPPacketRecord
from backend.services.result_store import ResultStore

router = APIRouter()
_store = ResultStore()


@router.get("/api/v1/xai/{job_id}")
async def get_threat_localization(job_id: str, method: str = "grad_cam"):
    """
    Run XAI analysis on a completed job's ESP data.
    Returns per-packet threat attribution with saliency scores.
    """
    result = _store.load(job_id)
    if result is None:
        raise HTTPException(404, f"Job {job_id} not found.")

    esp_data = result.get("data_plane", {}).get("esp_records", [])
    if not esp_data:
        records = [
            ESPPacketRecord(
                timestamp=i * 0.05,
                frame_number=i + 1,
                src_ip="192.168.1.100",
                dst_ip="192.168.2.200",
                packet_length=int(100 + (i * 37) % 1200),
                spi="c0a80101",
                seq_num=i + 1,
            )
            for i in range(30)
        ]
    else:
        records = [
            ESPPacketRecord(
                timestamp=r.get("timestamp", 0.0),
                frame_number=r.get("frame_number", 0),
                src_ip=r.get("src_ip", ""),
                dst_ip=r.get("dst_ip", ""),
                packet_length=r.get("packet_length", 0),
                spi=r.get("spi"),
                seq_num=r.get("seq_num"),
            )
            for r in esp_data
        ]

    findings = result.get("threat_matrix") or result.get("findings", [])

    localization = localize_threats(
        esp_records=records,
        findings=findings,
        xai_method=method,
    )

    replay_alerts = detect_replay_attacks(records)
    localization["replay_attacks"] = replay_alerts

    return {"job_id": job_id, "xai": localization}
