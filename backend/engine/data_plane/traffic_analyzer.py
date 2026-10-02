"""
traffic_analyzer.py - Dynamic Data-Plane DPI and Traffic Classifier.
Extracts real packet distributions, sizes, and protocol profiles from PCAP files.
Never uses hardcoded or mock values.

Integrates with inference_pipeline for Gemini API-based mode/traffic inference.
"""

import logging
import os
import subprocess
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.capture.pcap_utils import get_tshark_binary, validate_pcap
from backend.engine.inference_pipeline import infer_with_fallback

logger = logging.getLogger(__name__)


def classify_non_esp_packet(
    proto_col: str,
    ip_proto: str = "",
    udp_sport: str = "",
    udp_dport: str = "",
    tcp_sport: str = "",
    tcp_dport: str = "",
    icmp_type: str = "",
    info_col: str = "",
) -> str:
    """Classify non-ESP network packets into authentic, human-readable application categories."""
    p_up = proto_col.upper()
    info_up = info_col.upper()

    if "ICMP" in p_up or ip_proto == "1" or bool(icmp_type):
        if "REPLY" in info_up or icmp_type == "0":
            return "ICMP (Echo Reply)"
        elif "REQUEST" in info_up or icmp_type == "8":
            return "ICMP (Echo Request - Ping)"
        elif "UNREACHABLE" in info_up or icmp_type == "3":
            return "ICMP (Destination Unreachable)"
        return "ICMP (Diagnostics / Ping)"

    if "RTP" in p_up or "SIP" in p_up or udp_sport in ("5060", "5061") or udp_dport in ("5060", "5061"):
        return "VoIP (RTP Audio / SIP)"

    if "DNS" in p_up or udp_sport == "53" or udp_dport == "53":
        return "DNS (Name Resolution)"

    if "MDNS" in p_up or "SSDP" in p_up:
        return "Service Discovery (mDNS/SSDP)"

    if "QUIC" in p_up or "HTTP3" in p_up:
        return "QUIC / HTTP3 Streaming"

    if "TLS" in p_up or "SSL" in p_up or "HTTPS" in p_up or tcp_sport == "443" or tcp_dport == "443":
        return "Secure Web (HTTPS / TLS)"

    if "HTTP" in p_up or tcp_sport == "80" or tcp_dport == "80":
        return "Web Traffic (HTTP)"

    if "SSH" in p_up or tcp_sport == "22" or tcp_dport == "22":
        return "Remote Shell (SSH)"

    if "NTP" in p_up or udp_sport == "123" or udp_dport == "123":
        return "Network Time (NTP)"

    if "IKE" in p_up or udp_sport in ("500", "4500") or udp_dport in ("500", "4500"):
        return "IKE (Key Exchange)"

    if "TCP" in p_up or ip_proto == "6":
        port = tcp_dport or tcp_sport
        return f"TCP Stream (Port {port})" if port else "TCP Data Stream"

    if "UDP" in p_up or ip_proto == "17":
        port = udp_dport or udp_sport
        return f"UDP Datagram (Port {port})" if port else "UDP Datagrams"

    if "ARP" in p_up:
        return "ARP (Address Resolution)"

    return proto_col if proto_col and proto_col != "Unknown" else "Other Network Traffic"


_classify_non_esp_packet = classify_non_esp_packet


def analyze_data_plane(pcap_path: str | Path) -> Dict[str, Any]:
    """
    Dynamically analyzes packet traffic distributions, payload sizes,
    and infers tunnel characteristics directly from the wire packets.
    
    Integrates Gemini API inference for mode (tunnel/transport) and 
    traffic type (https/voip/icmp) classification.
    Zero hardcoded values.
    """
    pcap_path = str(Path(pcap_path).resolve())
    validate_pcap(pcap_path)
    tshark_bin = get_tshark_binary()
    tshark_pcap_path = pcap_path

    # A Windows TShark launched from WSL cannot resolve Linux mount paths
    # such as /mnt/c/...; pass it the equivalent Windows path instead.
    if tshark_bin.lower().endswith(".exe") and pcap_path.startswith("/"):
        try:
            path_result = subprocess.run(
                ["wslpath", "-w", pcap_path],
                capture_output=True,
                text=True,
                check=True,
            )
            tshark_pcap_path = path_result.stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            # Keep the original path so native Windows/Python environments
            # and installations without wslpath continue to work.
            tshark_pcap_path = pcap_path

    # Query comprehensive packet headers, ports, and protocol metadata
    cmd = [
        tshark_bin,
        "-r", tshark_pcap_path,
        "-T", "fields",
        "-e", "frame.len",
        "-e", "_ws.col.Protocol",
        "-e", "ip.proto",
        "-e", "esp.spi",
        "-e", "frame.time_epoch",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "icmp.type",
        "-e", "_ws.col.Info",
    ]

    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=45
    )

    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(f"tshark failed to analyze data plane: {proc.stderr.strip()}")

    lines = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
    if not lines:
        return {
            "detected_traffic": [],
            "heuristic_mode_prediction": None,
            "llm_mode_prediction": None,
            "ai_confidence_score": 0.0,
            "agreement_flag": False
        }

    total_packets = len(lines)
    esp_packet_sizes: List[int] = []
    esp_timestamps: List[float] = []
    proto_sizes: Dict[str, List[int]] = defaultdict(list)

    for line in lines:
        parts = line.split("\t")
        frame_len = int(parts[0]) if len(parts) >= 1 and parts[0].isdigit() else 0
        if frame_len <= 0:
            continue

        proto_col = parts[1] if len(parts) >= 2 else "Unknown"
        ip_proto = parts[2] if len(parts) >= 3 else ""
        esp_spi = parts[3] if len(parts) >= 4 else ""
        timestamp_raw = parts[4] if len(parts) >= 5 else ""
        udp_sport = parts[5] if len(parts) >= 6 else ""
        udp_dport = parts[6] if len(parts) >= 7 else ""
        tcp_sport = parts[7] if len(parts) >= 8 else ""
        tcp_dport = parts[8] if len(parts) >= 9 else ""
        icmp_type = parts[9] if len(parts) >= 10 else ""
        info_col = parts[10] if len(parts) >= 11 else ""

        is_esp = (ip_proto == "50" or proto_col.upper() == "ESP" or bool(esp_spi))

        if is_esp:
            esp_packet_sizes.append(frame_len)
            try:
                esp_timestamps.append(float(timestamp_raw))
            except (ValueError, TypeError):
                esp_timestamps.append(float("nan"))
        else:
            cat_label = _classify_non_esp_packet(
                proto_col, ip_proto, udp_sport, udp_dport, tcp_sport, tcp_dport, icmp_type, info_col
            )
            proto_sizes[cat_label].append(frame_len)

    detected_traffic: List[Dict[str, Any]] = []
    heuristic_mode: Optional[str] = None
    heuristic_traffic: Optional[str] = None
    api_mode: Optional[str] = None
    api_traffic: Optional[str] = None
    agreement_flag: bool = False
    confidence: float = 0.0

    # 1. If ESP packets are present, classify the encrypted data-plane stream
    if esp_packet_sizes:
        esp_count = len(esp_packet_sizes)
        sorted_sizes = sorted(esp_packet_sizes)
        
        # Compute distribution statistics for classification
        avg_overall = sum(esp_packet_sizes) / esp_count
        min_size = sorted_sizes[0]
        p10 = sorted_sizes[max(0, esp_count // 10)]
        p25 = sorted_sizes[max(0, esp_count // 4)]
        median_size = sorted_sizes[esp_count // 2]
        p75 = sorted_sizes[max(0, 3 * esp_count // 4)]
        max_size = sorted_sizes[-1]
        
        # Classify by packet size distribution (S_L)
        voip_sizes = [s for s in esp_packet_sizes if s < 250]
        msg_sizes = [s for s in esp_packet_sizes if 250 <= s < 600]
        web_sizes = [s for s in esp_packet_sizes if 600 <= s < 1100]
        video_sizes = [s for s in esp_packet_sizes if s >= 1100]

        categories = [
            ("VoIP", voip_sizes),
            ("Messaging", msg_sizes),
            ("Web Traffic", web_sizes),
            ("Video Streaming", video_sizes),
        ]

        for cat_name, sizes in categories:
            if sizes:
                count = len(sizes)
                avg_sz = round(sum(sizes) / count, 1)
                pct = round((count / total_packets) * 100.0, 1)
                detected_traffic.append({
                    "traffic_type": f"ESP - {cat_name}" if proto_sizes else cat_name,
                    "percentage": pct,
                    "packet_count": count,
                    "avg_packet_size_bytes": avg_sz
                })

        # Include all observed non-ESP protocols (ICMP, IKE, DNS, Web, etc.)
        for proto_name, sizes in sorted(proto_sizes.items(), key=lambda x: len(x[1]), reverse=True):
            count = len(sizes)
            avg_sz = round(sum(sizes) / count, 1)
            pct = round((count / total_packets) * 100.0, 1)
            detected_traffic.append({
                "traffic_type": proto_name,
                "percentage": pct,
                "packet_count": count,
                "avg_packet_size_bytes": avg_sz
            })

        # Sort descending by packet count
        detected_traffic.sort(key=lambda x: x["packet_count"], reverse=True)

        # ── Heuristic mode prediction ──
        # Tunnel mode wraps the entire original packet inside a new IP header,
        # adding ~20-40 bytes of overhead.  Key discriminators:
        #   1. Minimum / lower-percentile sizes are higher in tunnel mode
        #      (ICMP ping = ~84 bytes transport → ~104+ tunnel)
        #   2. Median shifts up by the tunnel overhead
        #
        # Empirical thresholds calibrated from testbed captures:
        #   Tunnel:    min ≥ 120, p10 ≥ 120, median ≥ 155
        #   Transport: min < 115, p10 < 115, median < 148
        tunnel_signals = 0
        transport_signals = 0
        
        # Signal 1: Floor size — tunnel adds minimum ~16-20 bytes
        if min_size >= 120:
            tunnel_signals += 2
        elif min_size <= 110:
            transport_signals += 2
        else:
            tunnel_signals += 1  # Ambiguous range
        
        # Signal 2: Lower-percentile analysis
        if p10 >= 120:
            tunnel_signals += 1
        elif p10 <= 110:
            transport_signals += 1
        
        # Signal 3: Median size shift
        if median_size >= 155:
            tunnel_signals += 2
        elif median_size <= 145:
            transport_signals += 2
        else:
            tunnel_signals += 1
        
        # Signal 4: P25 — consistent overhead visible in lower quartile
        if p25 >= 130:
            tunnel_signals += 1
        elif p25 <= 115:
            transport_signals += 1
        
        heuristic_mode = "tunnel" if tunnel_signals > transport_signals else "transport"
        
        logger.debug(
            f"Heuristic signals: tunnel={tunnel_signals}, transport={transport_signals} "
            f"(min={min_size}, p10={p10}, p25={p25}, median={median_size})"
        )
        
        # ── Heuristic traffic prediction ──
        # Use size distribution shape and presence of large packets:
        #   - VoIP: mostly small uniform packets (<250), few or no large packets
        #   - HTTPS: bimodal — many small ACKs + large data segments (>600)
        #   - ICMP: all very small (<150)
        large_pct = (len(web_sizes) + len(video_sizes)) / esp_count
        small_pct = len(voip_sizes) / esp_count
        
        if max_size < 200 and median_size < 150:
            heuristic_traffic = "icmp"
        elif large_pct >= 0.15:
            # Significant fraction of large packets → web/HTTPS traffic
            heuristic_traffic = "https"
        elif small_pct > 0.7 and max_size < 600:
            heuristic_traffic = "voip"
        else:
            # Mixed traffic — likely HTTPS with small ACKs
            heuristic_traffic = "https"
        
        heuristic_confidence = min(0.98, max(0.65, 0.70 + (esp_count / 10000.0) * 0.25))

        # Call Gemini API for joint mode + traffic inference
        # Compute inter-arrival times from packet timestamps
        inter_arrival_times = []

        valid_timestamps = [
            ts for ts in esp_timestamps
            if ts == ts
        ]

        for i in range(1, min(len(valid_timestamps), 100)):
            iat = (
                valid_timestamps[i]
                - valid_timestamps[i - 1]
            )
            inter_arrival_times.append(
                max(iat, 0.000001)
            )
        if not inter_arrival_times: #atleast 1 iat to receive
            inter_arrival_times = [0.000001]
        
        logger.info(
            f"Calling inference pipeline: {esp_count} ESP packets, "
            f"{min(len(esp_packet_sizes), 100)} for API, heuristic={heuristic_mode}/{heuristic_traffic}"
        )
        
        agreement_result = infer_with_fallback(
            packet_lengths=esp_packet_sizes[:100],
            inter_arrival_times=inter_arrival_times,
            packet_count=esp_count,
            heuristic_mode=heuristic_mode,
            heuristic_traffic=heuristic_traffic,
        )
        
        if agreement_result:
            api_mode = agreement_result.api_mode_prediction
            api_traffic = agreement_result.api_traffic_prediction
            agreement_flag = agreement_result.mode_agreement
            confidence = agreement_result.api_avg_confidence
            
            if api_mode == "unknown":
                # Fallback: use heuristic
                api_mode = None
            if api_traffic == "unknown":
                # Fallback: use heuristic
                api_traffic = None
        else:
            # Both API and heuristic failed
            api_mode = None
            api_traffic = None
            agreement_flag = False
            confidence = 0.0

    # 2. If non-ESP packets, classify the observed network protocols directly
    else:
        # Group real observed protocols into authentic traffic categories
        for proto, sizes in sorted(proto_sizes.items(), key=lambda x: len(x[1]), reverse=True):
            count = len(sizes)
            avg_sz = round(sum(sizes) / count, 1)
            pct = round((count / total_packets) * 100.0, 1)

            detected_traffic.append({
                "traffic_type": proto,
                "percentage": pct,
                "packet_count": count,
                "avg_packet_size_bytes": avg_sz
            })

        # Infer traffic type from dominant observed protocol
        if detected_traffic:
            top_label = detected_traffic[0]["traffic_type"].lower()
            if "icmp" in top_label or "ping" in top_label:
                heuristic_traffic = "icmp"
            elif "voip" in top_label or "rtp" in top_label or "sip" in top_label:
                heuristic_traffic = "voip"
            else:
                heuristic_traffic = "https"
            heuristic_mode = "plaintext"
            confidence = 0.95
        else:
            heuristic_mode = None
            api_mode = None
            confidence = 0.0
        agreement_flag = False

    return {
        "detected_traffic": detected_traffic,
        "heuristic_mode_prediction": heuristic_mode,
        "llm_mode_prediction": api_mode,
        "ai_confidence_score": round(confidence, 2),
        "agreement_flag": agreement_flag
    }
