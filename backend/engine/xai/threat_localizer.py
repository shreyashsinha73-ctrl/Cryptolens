"""
Threat Localizer — maps XAI saliency back to individual packets,
producing granular threat attribution with frame numbers, SPIs,
sequence numbers, and timestamps.
"""

import numpy as np
import torch
import logging
from typing import Optional

from backend.engine.xai.saliency import grad_cam_1d, integrated_gradients_1d
from backend.streaming.live_sniffer import ESPPacketRecord

logger = logging.getLogger(__name__)

# Normalization constants (from metrics.json)
NORM_MEAN = np.array([362.43, 0.13], dtype=np.float32).reshape(1, 2, 1)
NORM_STD = np.array([450.83, 0.25], dtype=np.float32).reshape(1, 2, 1)


def localize_threats(
    esp_records: list[ESPPacketRecord],
    findings: list[dict],
    xai_method: str = "grad_cam",
) -> dict:
    """
    Combine XAI saliency with packet metadata to produce
    per-packet threat attribution.
    """
    if len(esp_records) < 5:
        return {
            "threat_packets": [],
            "xai_heatmap": [],
            "channel_importance": {},
            "summary": "Insufficient ESP packets for XAI analysis (minimum 5 required).",
        }

    seq_len = 30
    lengths = [r.packet_length for r in esp_records][:seq_len]
    iats = []
    for i in range(len(esp_records[:seq_len])):
        if i == 0:
            iats.append(0.0)
        else:
            iats.append(esp_records[i].timestamp - esp_records[i - 1].timestamp)

    while len(lengths) < seq_len:
        lengths.append(0.0)
    while len(iats) < seq_len:
        iats.append(0.0)

    raw = np.array([[lengths, iats]], dtype=np.float32)  # (1, 2, 30)
    normalized = (raw - NORM_MEAN) / (NORM_STD + 1e-8)
    input_tensor = torch.tensor(normalized, dtype=torch.float32)

    if xai_method == "integrated_gradients":
        xai_result = integrated_gradients_1d(input_tensor, target_head="mode")
        heatmap = np.abs(np.array(xai_result["attributions"])).sum(axis=0).tolist()
        channel_imp = {
            "packet_lengths": xai_result["channel_importance"][0],
            "inter_arrival_times": xai_result["channel_importance"][1],
        }
    else:
        xai_result = grad_cam_1d(input_tensor, target_head="mode")
        heatmap = xai_result["heatmap"]
        channel_imp = {"packet_lengths": 0.0, "inter_arrival_times": 0.0}

    threat_packets = []
    ranked_indices = np.argsort(heatmap)[::-1]

    for rank, idx in enumerate(ranked_indices):
        if idx >= len(esp_records):
            continue
        record = esp_records[idx]
        saliency = heatmap[idx] if idx < len(heatmap) else 0.0

        threat_type, threat_desc = _classify_packet_threat(
            record, findings, saliency
        )

        if saliency < 0.1 and threat_type == "normal":
            continue

        threat_packets.append({
            "frame_number": record.frame_number,
            "timestamp": record.timestamp,
            "src_ip": record.src_ip,
            "dst_ip": record.dst_ip,
            "packet_length": record.packet_length,
            "spi": record.spi or "unknown",
            "seq_num": record.seq_num if record.seq_num is not None else -1,
            "saliency_score": round(float(saliency), 4),
            "attribution_rank": rank + 1,
            "threat_type": threat_type,
            "threat_description": threat_desc,
        })

    high_saliency = [p for p in threat_packets if p["saliency_score"] > 0.5]
    summary = (
        f"XAI analysis identified {len(high_saliency)} high-influence packets "
        f"out of {len(esp_records)} total ESP packets. "
        f"Predicted class: {xai_result.get('predicted_class', 'unknown')}."
    )

    return {
        "threat_packets": threat_packets[:20],
        "xai_heatmap": heatmap,
        "channel_importance": channel_imp,
        "summary": summary,
    }


def _classify_packet_threat(
    record: ESPPacketRecord,
    findings: list[dict],
    saliency: float,
) -> tuple[str, str]:
    """Classify a packet's threat type based on metadata and findings."""
    if record.packet_length > 0 and record.packet_length % 8 == 0:
        for f in findings:
            if "3DES" in f.get("title", "") or "Sweet32" in f.get("description", ""):
                return (
                    "sweet32_block_size",
                    f"Packet length {record.packet_length}B aligned to 64-bit "
                    f"block boundary — 3DES Sweet32 vulnerability surface."
                )

    if record.packet_length < 100:
        for f in findings:
            if "Transport" in f.get("title", "") or "mode" in f.get("category", ""):
                return (
                    "transport_metadata_exposure",
                    f"Small packet ({record.packet_length}B) in Transport mode "
                    f"may expose inner protocol headers."
                )

    if saliency > 0.5:
        return (
            "high_influence",
            f"High CNN attention (saliency={saliency:.3f}) — this packet's "
            f"metadata significantly influenced the classification decision."
        )

    return ("normal", "No specific threat attributed to this packet.")


def detect_replay_attacks(
    esp_records: list[ESPPacketRecord],
) -> list[dict]:
    """
    Detect potential replay attacks by finding duplicate
    (SPI, Sequence Number) pairs within the ESP stream.
    """
    seen = {}
    duplicates = []

    for record in esp_records:
        if record.spi is None or record.seq_num is None:
            continue
        key = (record.spi, record.seq_num)
        if key in seen:
            original = seen[key]
            duplicates.append({
                "type": "replay_attack_candidate",
                "severity": "CRITICAL",
                "spi": record.spi,
                "seq_num": record.seq_num,
                "original_frame": original.frame_number,
                "original_timestamp": original.timestamp,
                "duplicate_frame": record.frame_number,
                "duplicate_timestamp": record.timestamp,
                "time_delta_ms": round(
                    (record.timestamp - original.timestamp) * 1000, 2
                ),
                "description": (
                    f"Duplicate ESP packet detected: SPI=0x{record.spi}, "
                    f"Seq={record.seq_num}. Original frame #{original.frame_number} "
                    f"at t={original.timestamp:.6f}, duplicate frame "
                    f"#{record.frame_number} at t={record.timestamp:.6f} "
                    f"(delta={record.timestamp - original.timestamp:.6f}s). "
                    f"Potential replay attack."
                ),
            })
        else:
            seen[key] = record

    return duplicates
