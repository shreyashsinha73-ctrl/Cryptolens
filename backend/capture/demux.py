"""
demux.py - Dynamic PCAP Demultiplexer for IPsec analysis.
Splits packet captures into Control-Plane (IKE/ISAKMP) vs Data-Plane (ESP).
"""

import argparse
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.capture.pcap_utils import (
    filter_and_save_pcap,
    get_pcap_metadata,
    get_tshark_binary,
    run_tshark_json,
    validate_pcap,
)


IKE_DISPLAY_FILTER = (
    "(ike || isakmp || udp.port == 500 || "
    "(udp.port == 4500 && (ike || isakmp || (data.data[0:4] == 00:00:00:00))))"
)

ESP_DISPLAY_FILTER = (
    "(esp || ip.proto == 50 || ipv6.nxt == 50 || "
    "(udp.port == 4500 && !ike && !isakmp && data.data[0:4] != 00:00:00:00))"
)


@dataclass
class DemuxResult:
    source_pcap: str
    total_packets: int
    ike_packet_count: int
    esp_packet_count: int
    other_packet_count: int
    ike_pcap_path: Optional[str] = None
    esp_pcap_path: Optional[str] = None
    other_pcap_path: Optional[str] = None
    endpoints: List[Dict[str, str]] = field(default_factory=list)
    has_ike: bool = False
    has_esp: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PcapDemuxer:
    """
    Modular, deterministic PCAP demuxer that separates control-plane IKE exchanges
    from data-plane ESP encrypted packets without hardcoded values.
    """

    def __init__(self, tshark_path: Optional[str] = None):
        self.tshark_path = tshark_path or get_tshark_binary()

    def demux(
        self,
        pcap_path: str | Path,
        output_dir: Optional[str | Path] = None,
        prefix: Optional[str] = None,
        extract_other: bool = False,
    ) -> DemuxResult:
        """
        Splits the given PCAP into separate IKE and ESP PCAP files.
        If output_dir is None, creates files in a directory alongside the source PCAP.
        """
        pcap_path = str(Path(pcap_path).resolve())
        validate_pcap(pcap_path)

        meta = get_pcap_metadata(pcap_path)
        total_packets = meta.packet_count

        stem = Path(pcap_path).stem
        ext = Path(pcap_path).suffix or ".pcap"
        file_prefix = f"{prefix}_" if prefix else f"{stem}_"

        if output_dir:
            out_dir_path = Path(output_dir).resolve()
        else:
            out_dir_path = Path(pcap_path).parent / f"{stem}_demux"

        out_dir_path.mkdir(parents=True, exist_ok=True)

        ike_out = out_dir_path / f"{file_prefix}ike{ext}"
        esp_out = out_dir_path / f"{file_prefix}esp{ext}"
        other_out = out_dir_path / f"{file_prefix}other{ext}" if extract_other else None

        # 1. Filter IKE packets
        ike_count = filter_and_save_pcap(
            filepath=pcap_path,
            display_filter=IKE_DISPLAY_FILTER,
            output_path=ike_out
        )

        # 2. Filter ESP packets
        esp_count = filter_and_save_pcap(
            filepath=pcap_path,
            display_filter=ESP_DISPLAY_FILTER,
            output_path=esp_out
        )

        # 3. Filter Other packets if requested
        other_count = 0
        other_path_str = None
        if extract_other and other_out:
            other_filter = f"!({IKE_DISPLAY_FILTER}) && !({ESP_DISPLAY_FILTER})"
            other_count = filter_and_save_pcap(
                filepath=pcap_path,
                display_filter=other_filter,
                output_path=other_out
            )
            other_path_str = str(other_out) if other_count > 0 else None
        else:
            other_count = max(0, total_packets - (ike_count + esp_count))

        # 4. Discover endpoints dynamically
        endpoints = self._extract_endpoints(pcap_path)

        return DemuxResult(
            source_pcap=pcap_path,
            total_packets=total_packets,
            ike_packet_count=ike_count,
            esp_packet_count=esp_count,
            other_packet_count=other_count,
            ike_pcap_path=str(ike_out) if ike_count > 0 else None,
            esp_pcap_path=str(esp_out) if esp_count > 0 else None,
            other_pcap_path=other_path_str,
            endpoints=endpoints,
            has_ike=(ike_count > 0),
            has_esp=(esp_count > 0),
        )

    def _extract_endpoints(self, pcap_path: str) -> List[Dict[str, str]]:
        """Dynamically identifies communicating IP endpoints across the capture."""
        try:
            cmd = [
                self.tshark_path,
                "-r", pcap_path,
                "-T", "fields",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "ipv6.src",
                "-e", "ipv6.dst"
            ]
            import subprocess
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
            pairs: Set[Tuple[str, str]] = set()
            for line in res.stdout.splitlines():
                parts = [p.strip() for p in line.split("\t") if p.strip()]
                if len(parts) >= 2:
                    src, dst = parts[0], parts[1]
                    # Standardize order for bidirectional pairs
                    pair = tuple(sorted([src, dst]))
                    pairs.add(pair)
            
            return [{"src": p[0], "dst": p[1]} for p in sorted(pairs)]
        except Exception:
            return []


def main():
    parser = argparse.ArgumentParser(
        description="CryptoLens PCAP Demuxer: Split captures into IKE (Control) and ESP (Data)."
    )
    parser.add_argument("pcap_path", help="Path to input .pcap or .pcapng file")
    parser.add_argument("-o", "--output-dir", help="Directory to save demuxed PCAP files", default=None)
    parser.add_argument("-p", "--prefix", help="Prefix for demuxed output filenames", default=None)
    parser.add_argument("--other", action="store_true", help="Also extract non-IPsec packets")
    args = parser.parse_args()

    demuxer = PcapDemuxer()
    result = demuxer.demux(
        pcap_path=args.pcap_path,
        output_dir=args.output_dir,
        prefix=args.prefix,
        extract_other=args.other
    )

    import json
    print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()

