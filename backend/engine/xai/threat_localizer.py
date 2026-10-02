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
    target_head: str = "mode",
    max_seq_len: int = 100,
) -> dict:
    """
    Combine XAI saliency (Grad-CAM 1D or Integrated Gradients) with packet metadata
    to produce per-packet threat attribution. Supports variable sequence lengths
    (up to max_seq_len) and dual prediction targets ('mode' vs 'traffic').
    """
    if len(esp_records) < 5:
        return {
            "threat_packets": [],
            "xai_heatmap": [],
            "channel_importance": {},
            "target_head": target_head,
            "predicted_class": "unknown",
            "summary": "Insufficient packets for XAI analysis (minimum 5 wire packets required).",
        }

    # Dynamically scale sequence length to captured packets
    seq_len = max(5, min(len(esp_records), max_seq_len))
    lengths = [r.packet_length for r in esp_records][:seq_len]
    iats = []
    for i in range(seq_len):
        if i == 0:
            iats.append(0.0)
        else:
            iats.append(esp_records[i].timestamp - esp_records[i - 1].timestamp)

    while len(lengths) < seq_len:
        lengths.append(0.0)
    while len(iats) < seq_len:
        iats.append(0.0)

    raw = np.array([[lengths, iats]], dtype=np.float32)  # (1, 2, seq_len)
    normalized = (raw - NORM_MEAN) / (NORM_STD + 1e-8)
    input_tensor = torch.tensor(normalized, dtype=torch.float32)

    head_norm = target_head.lower() if target_head in ("mode", "traffic") else "mode"

    if xai_method == "integrated_gradients":
        xai_result = integrated_gradients_1d(input_tensor, target_head=head_norm)
        heatmap = np.abs(np.array(xai_result["attributions"])).sum(axis=0).tolist()
        channel_imp = {
            "packet_lengths": xai_result["channel_importance"][0],
            "inter_arrival_times": xai_result["channel_importance"][1],
        }
    else:
        xai_result = grad_cam_1d(input_tensor, target_head=head_norm)
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
            record, findings, saliency, head_norm
        )

        if saliency < 0.05 and threat_type == "normal":
            continue

        threat_packets.append({
            "frame_number": record.frame_number,
            "timestamp": record.timestamp,
            "src_ip": record.src_ip,
            "dst_ip": record.dst_ip,
            "protocol": getattr(record, "protocol", "ESP"),
            "packet_type": getattr(record, "packet_type", "ESP"),
            "packet_length": record.packet_length,
            "spi": record.spi or "unknown",
            "seq_num": record.seq_num if record.seq_num is not None else -1,
            "saliency_score": round(float(saliency), 4),
            "attribution_rank": rank + 1,
            "threat_type": threat_type,
            "threat_description": threat_desc,
        })

    high_saliency = [p for p in threat_packets if p["saliency_score"] > 0.5]
    pred_cls = xai_result.get("predicted_class", "unknown")
    pred_conf = xai_result.get("predicted_confidence", 0.95)
    target_label = "Tunnel vs Transport Mode" if head_norm == "mode" else "Inner Traffic Type (HTTPS/VoIP/ICMP)"

    summary = (
        f"XAI {xai_method.replace('_', ' ').title()} analyzed {seq_len} consecutive frames "
        f"for {target_label}. Predicted class: '{pred_cls.upper()}' "
        f"({pred_conf*100:.1f}% confidence). "
        f"Identified {len(high_saliency)} high-influence packets across the sequence."
    )

    return {
        "threat_packets": threat_packets[:25],
        "xai_heatmap": heatmap,
        "channel_importance": channel_imp,
        "target_head": head_norm,
        "predicted_class": pred_cls,
        "predicted_confidence": pred_conf,
        "sequence_length": seq_len,
        "summary": summary,
    }


def _classify_packet_threat(
    record: ESPPacketRecord,
    findings: list[dict],
    saliency: float,
    target_head: str = "mode",
) -> tuple[str, str]:
    """Classify a packet's threat type based on protocol, metadata, and CNN attention."""
    proto = getattr(record, "protocol", "ESP").upper()
    pkt_type = getattr(record, "packet_type", "ESP")

    # 1. Non-ESP unencrypted / control traffic visibility
    if proto == "ICMP" or "ICMP" in pkt_type:
        return (
            "unencrypted_icmp_exposure",
            f"Plaintext ICMP payload ({record.packet_length}B) exposed on wire without tunnel encapsulation."
        )

    if proto == "IKE" or "IKE" in pkt_type:
        return (
            "ike_control_handshake",
            f"IKE security association handshake frame ({record.packet_length}B) establishing crypto parameters."
        )

    # 2. Sweet32 64-bit block alignment
    if record.packet_length > 0 and record.packet_length % 8 == 0:
        for f in findings:
            if "3DES" in f.get("title", "") or "Sweet32" in f.get("description", ""):
                return (
                    "sweet32_block_size",
                    f"Packet length {record.packet_length}B aligned to 64-bit block boundary — 3DES Sweet32 collision risk."
                )

    # 3. Transport mode metadata leakage
    if record.packet_length < 100:
        for f in findings:
            if "Transport" in f.get("title", "") or "mode" in f.get("category", ""):
                return (
                    "transport_metadata_exposure",
                    f"Small frame ({record.packet_length}B) in Transport mode exposes inner protocol transport headers."
                )

    # 4. Neural Saliency Attribution
    if saliency > 0.5:
        target_name = "Tunnel Mode" if target_head == "mode" else "Inner Traffic Profile"
        return (
            "high_influence",
            f"High neural attention (saliency={saliency:.3f}) — packet features strongly influenced {target_name} prediction."
        )

    return ("normal", "Nominal wire packet; conforms to expected cryptographic traffic profile.")


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
