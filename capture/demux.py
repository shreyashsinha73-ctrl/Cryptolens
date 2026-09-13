#!/usr/bin/env python3
"""
Traffic Demultiplexer (capture/demux.py)
Splits raw packet captures into:
  - Control-Plane: IKEv1/IKEv2 negotiation packets (UDP port 500 / 4500 with non-ESP marker)
  - Data-Plane: ESP encrypted data packets (Protocol 50 / UDP 4500 with SPI)
Provides stream metrics, byte counts, and isolated sub-PCAP generation.
"""

import argparse
import json
import os
import sys
from typing import Dict, Any, Optional

from capture.pcap_utils import PcapReader, PcapWriter, parse_packet_layers, DLT_EN10MB


def demux_pcap(
    input_pcap: str,
    output_dir: Optional[str] = None,
    save_splits: bool = True
) -> Dict[str, Any]:
    """
    Demultiplexes input capture into control and data planes.

    Args:
        input_pcap: Path to source capture file.
        output_dir: Optional directory to store split captures.
        save_splits: Whether to physically write split PCAP files to disk.

    Returns:
        Structured demux telemetry dictionary.
    """
    if not os.path.exists(input_pcap):
        raise FileNotFoundError(f"Input capture not found: {input_pcap}")

    reader = PcapReader(input_pcap)
    base_name = os.path.splitext(os.path.basename(input_pcap))[0]

    control_path = None
    data_path = None
    ctrl_writer: Optional[PcapWriter] = None
    data_writer: Optional[PcapWriter] = None

    if save_splits:
        out_folder = output_dir or os.path.join(os.path.dirname(input_pcap) or ".", "demux")
        os.makedirs(out_folder, exist_ok=True)
        control_path = os.path.join(out_folder, f"{base_name}_control.pcap")
        data_path = os.path.join(out_folder, f"{base_name}_data.pcap")

    total_packets = 0
    control_packets = 0
    data_packets = 0
    other_packets = 0

    control_bytes = 0
    data_bytes = 0
    other_bytes = 0

    control_frames = []

    try:
        for ts, orig_len, pkt_data, link_type in reader.iter_packets():
            total_packets += 1
            meta = parse_packet_layers(pkt_data, link_type)

            if meta["is_ike"]:
                control_packets += 1
                control_bytes += orig_len
                control_frames.append((ts, orig_len, pkt_data, link_type))
                if save_splits:
                    if ctrl_writer is None:
                        ctrl_writer = PcapWriter(control_path, link_type=link_type)
                    ctrl_writer.write_packet(ts, pkt_data, orig_len)

            elif meta["is_esp"]:
                data_packets += 1
                data_bytes += orig_len
                if save_splits:
                    if data_writer is None:
                        data_writer = PcapWriter(data_path, link_type=link_type)
                    data_writer.write_packet(ts, pkt_data, orig_len)

            else:
                other_packets += 1
                other_bytes += orig_len

    finally:
        if ctrl_writer:
            ctrl_writer.close()
        if data_writer:
            data_writer.close()

    return {
        "source_file": input_pcap,
        "total_packets": total_packets,
        "control_plane": {
            "packet_count": control_packets,
            "byte_count": control_bytes,
            "pcap_file": control_path if control_packets > 0 and save_splits else None,
            "active": control_packets > 0
        },
        "data_plane": {
            "packet_count": data_packets,
            "byte_count": data_bytes,
            "pcap_file": data_path if data_packets > 0 and save_splits else None,
            "active": data_packets > 0
        },
        "other_traffic": {
            "packet_count": other_packets,
            "byte_count": other_bytes
        },
        "summary": {
            "has_ike": control_packets > 0,
            "has_esp": data_packets > 0,
            "is_complete_ipsec_session": (control_packets > 0 and data_packets > 0)
        }
    }


def main():
    parser = argparse.ArgumentParser(description="Demultiplex PCAP into IKE Control Plane and ESP Data Plane.")
    parser.add_argument("input_pcap", help="Path to input .pcap / .pcapng file")
    parser.add_argument("-o", "--output-dir", default=None, help="Directory to save split capture files")
    parser.add_argument("--no-save", action="store_true", help="Only compute metrics without writing split PCAPs")
    parser.add_argument("--json", action="store_true", help="Output raw JSON results")

    args = parser.parse_args()

    try:
        res = demux_pcap(args.input_pcap, output_dir=args.output_dir, save_splits=not args.no_save)
    except Exception as e:
        print(f"Error demuxing capture: {e}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(res, indent=2))
        return

    print("=" * 60)
    print(" CRYPTOLENS CAPTURE DEMUX REPORT")
    print("=" * 60)
    print(f"Source Capture : {res['source_file']}")
    print(f"Total Packets  : {res['total_packets']}")
    print("-" * 60)
    print("Stream Allocation:")
    cp = res["control_plane"]
    dp = res["data_plane"]
    op = res["other_traffic"]
    print(f"  • Control Plane (IKE) : {cp['packet_count']:>5} packets ({cp['byte_count']:>8} bytes)")
    if cp["pcap_file"]:
        print(f"    Saved to: {cp['pcap_file']}")
    print(f"  • Data Plane (ESP)    : {dp['packet_count']:>5} packets ({dp['byte_count']:>8} bytes)")
    if dp["pcap_file"]:
        print(f"    Saved to: {dp['pcap_file']}")
    print(f"  • Other Non-IPsec     : {op['packet_count']:>5} packets ({op['byte_count']:>8} bytes)")
    print("-" * 60)
    print(f"Session Status : {'Complete IPsec Session (IKE + ESP)' if res['summary']['is_complete_ipsec_session'] else 'Partial / Single-Track Capture'}")
    print("=" * 60)


if __name__ == "__main__":
    main()

