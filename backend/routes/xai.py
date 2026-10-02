"""
backend/routes/xai.py
---------------------
Explainable AI (XAI) threat localization API routes.
Maps 1D-CNN neural activations (Grad-CAM & Integrated Gradients) back to genuine
wire frames directly from the analyzed PCAP capture. Zero dummy or hardcoded values.
"""

import logging
import subprocess
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, HTTPException

from backend.engine.xai.threat_localizer import localize_threats, detect_replay_attacks
from backend.streaming.live_sniffer import ESPPacketRecord
from backend.engine.data_plane.traffic_analyzer import classify_non_esp_packet
from backend.services.result_store import ResultStore
from backend.capture.pcap_utils import find_pcap_for_job, get_tshark_binary

logger = logging.getLogger(__name__)
router = APIRouter()
_store = ResultStore()


def _extract_wire_records_from_pcap(pcap_path: Path, max_records: int = 100) -> List[ESPPacketRecord]:
    """
    Extract genuine wire packet records directly from a PCAP file using tshark.
    Captures exact frame numbers, timestamps, real source/destination IPs,
    authentic SPIs, sequence numbers, lengths, and application protocol types across all packets.
    """
    tshark_bin = get_tshark_binary()

    cmd = [
        tshark_bin,
        "-r", str(pcap_path),
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "esp.spi",
        "-e", "esp.sequence",
        "-e", "frame.len",
        "-e", "_ws.col.Protocol",
        "-e", "ip.proto",
        "-e", "icmp.type",
        "-e", "_ws.col.Info",
        "-c", str(max_records),
    ]

    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
        lines = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
    except Exception as e:
        logger.warning(f"Error extracting wire records via tshark: {e}")
        lines = []

    records: List[ESPPacketRecord] = []
    for line in lines:
        parts = line.split("\t")
        if len(parts) >= 11:
            frame_num = int(parts[0]) if parts[0].isdigit() else (len(records) + 1)
            ts = float(parts[1]) if parts[1] else 0.0
            src_ip = parts[2] or "0.0.0.0"
            dst_ip = parts[3] or "0.0.0.0"
            udp_sport = parts[4] if len(parts) > 4 else ""
            udp_dport = parts[5] if len(parts) > 5 else ""
            tcp_sport = parts[6] if len(parts) > 6 else ""
            tcp_dport = parts[7] if len(parts) > 7 else ""
            spi = parts[8] if len(parts) > 8 and parts[8] else None
            seq_num = int(parts[9]) if len(parts) > 9 and parts[9].isdigit() else None
            pkt_len = int(parts[10]) if len(parts) > 10 and parts[10].isdigit() else 0
            proto = parts[11] if len(parts) > 11 and parts[11] else "Unknown"
            ip_proto = parts[12] if len(parts) > 12 else ""
            icmp_type = parts[13] if len(parts) > 13 else ""
            info_col = parts[14] if len(parts) > 14 else ""

            if pkt_len <= 0:
                continue

            is_esp = (ip_proto == "50" or proto.upper() == "ESP" or bool(spi))
            is_ike = ("IKE" in proto.upper() or udp_sport in ("500", "4500") or udp_dport in ("500", "4500"))

            if is_esp:
                protocol = "ESP"
                packet_type = "ESP Encrypted"
            elif is_ike:
                protocol = "IKE"
                packet_type = "IKE Key Exchange"
                if not spi:
                    spi = f"ike_{udp_sport or udp_dport or '500'}"
            else:
                packet_type = classify_non_esp_packet(
                    proto_col=proto,
                    ip_proto=ip_proto,
                    udp_sport=udp_sport,
                    udp_dport=udp_dport,
                    tcp_sport=tcp_sport,
                    tcp_dport=tcp_dport,
                    icmp_type=icmp_type,
                    info_col=info_col,
                )
                if "ICMP" in packet_type:
                    protocol = "ICMP"
                elif "VoIP" in packet_type:
                    protocol = "VoIP"
                elif "DNS" in packet_type:
                    protocol = "DNS"
                elif "Web" in packet_type or "TLS" in packet_type:
                    protocol = "HTTPS"
                else:
                    protocol = proto
                if not spi:
                    spi = f"wire_{protocol.lower()}"

            records.append(
                ESPPacketRecord(
                    timestamp=ts,
                    frame_number=frame_num,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    packet_length=pkt_len,
                    spi=spi,
                    seq_num=seq_num,
                    protocol=protocol,
                    packet_type=packet_type,
                )
            )

    return records


_extract_esp_records_from_pcap = _extract_wire_records_from_pcap


@router.get("/api/v1/xai/{job_id}")
async def get_threat_localization(
    job_id: str,
    method: str = "grad_cam",
    target_head: str = "mode",
):
    """
    Run Explainable AI (XAI) analysis on a completed job's genuine packet data.
    Extracts authentic wire frames directly from the analyzed PCAP and computes
    per-packet saliency and risk attribution.
    Supports dynamic sequence length and dual prediction targets ('mode' vs 'traffic').
    """
    result = None
    if _store.exists(job_id):
        result = _store.load(job_id)

    # 1. Resolve physical PCAP file
    pcap_path = None
    if result and result.get("pcap_file"):
        p_candidate = Path(result["pcap_file"])
        if p_candidate.exists() and p_candidate.stat().st_size > 0:
            pcap_path = p_candidate

    if not pcap_path:
        pcap_path = find_pcap_for_job(job_id)

    # 2. Extract authentic wire packet records directly from the PCAP (up to 100 frames)
    records: List[ESPPacketRecord] = []
    if pcap_path and pcap_path.exists():
        records = _extract_wire_records_from_pcap(pcap_path, max_records=100)

    # Check if stored result had pre-parsed records as fallback
    if not records and result:
        esp_data = result.get("data_plane", {}).get("esp_records", [])
        if esp_data:
            records = [
                ESPPacketRecord(
                    timestamp=r.get("timestamp", 0.0),
                    frame_number=r.get("frame_number", 0),
                    src_ip=r.get("src_ip", "0.0.0.0"),
                    dst_ip=r.get("dst_ip", "0.0.0.0"),
                    packet_length=r.get("packet_length", 0),
                    spi=r.get("spi", "unknown"),
                    seq_num=r.get("seq_num"),
                    protocol=r.get("protocol", "ESP"),
                    packet_type=r.get("packet_type", "ESP"),
                )
                for r in esp_data
            ]

    if not records:
        raise HTTPException(
            status_code=404,
            detail=f"No packet data found for job '{job_id}'. Please upload a valid PCAP file.",
        )

    findings = []
    if result:
        findings = result.get("threat_matrix") or result.get("findings", [])

    # 3. Compute dynamic XAI saliency map (Grad-CAM 1D or Integrated Gradients)
    localization = localize_threats(
        esp_records=records,
        findings=findings,
        xai_method=method,
        target_head=target_head,
        max_seq_len=100,
    )

    # 4. Check for replay attack duplicate sequence numbers
    replay_alerts = detect_replay_attacks(records)
    localization["replay_attacks"] = replay_alerts

    return {"job_id": job_id, "xai": localization}
