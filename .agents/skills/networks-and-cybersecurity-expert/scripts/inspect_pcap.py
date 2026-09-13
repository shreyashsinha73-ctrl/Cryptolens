#!/usr/bin/env python3
"""
Lightweight, Zero-External-Dependency Packet Capture (PCAP) Inspector.
Parses raw PCAP/PCAPNG streams to extract:
  - Protocol distributions (IPv4, IPv6, TCP, UDP, ESP, ICMP)
  - Port allocations (IKE UDP 500, NAT-T UDP 4500, TLS 443, DNS 53)
  - Packet size distributions (Min, Max, Mean, Standard Deviation)
  - Encrypted ESP tunnel metadata and timing characteristics
"""

import argparse
import json
import math
import os
import struct
import sys
from typing import Dict, List, Any, Tuple, Optional


PCAP_MAGIC_MICROSECONDS = 0xa1b2c3d4
PCAP_MAGIC_NANOSECONDS  = 0xa1b23c4d
PCAPNG_MAGIC            = 0x0a0d0d0a


def parse_pcap_native(file_path: str, max_packets: Optional[int] = None) -> Dict[str, Any]:
    """Parses standard PCAP files using native Python struct unpackers."""
    with open(file_path, "rb") as f:
        global_header = f.read(24)
        if len(global_header) < 24:
            raise ValueError("File is too small to be a valid PCAP.")

        magic = struct.unpack("<I", global_header[:4])[0]
        if magic in (PCAP_MAGIC_MICROSECONDS, PCAP_MAGIC_NANOSECONDS):
            endian = "<"
            nanoseconds = (magic == PCAP_MAGIC_NANOSECONDS)
        else:
            magic_be = struct.unpack(">I", global_header[:4])[0]
            if magic_be in (PCAP_MAGIC_MICROSECONDS, PCAP_MAGIC_NANOSECONDS):
                endian = ">"
                nanoseconds = (magic_be == PCAP_MAGIC_NANOSECONDS)
            elif magic == PCAPNG_MAGIC or magic_be == PCAPNG_MAGIC:
                return parse_pcapng_basic(file_path, max_packets)
            else:
                raise ValueError(f"Unsupported PCAP magic number: {hex(magic)}")

        version_major, version_minor, thiszone, sigfigs, snaplen, network = struct.unpack(
            f"{endian}HHIIII", global_header[4:24]
        )

        packet_sizes = []
        timestamps = []
        protocols: Dict[str, int] = {}
        ports: Dict[str, int] = {}
        esp_packets = 0
        ike_packets = 0
        tls_packets = 0
        dns_packets = 0

        pkt_idx = 0
        while True:
            if max_packets and pkt_idx >= max_packets:
                break

            hdr = f.read(16)
            if len(hdr) < 16:
                break

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", hdr)
            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break

            pkt_idx += 1
            packet_sizes.append(orig_len)
            epoch = ts_sec + (ts_usec / 1e9 if nanoseconds else ts_usec / 1e6)
            timestamps.append(epoch)

            # Basic Ethernet / IP parsing
            ip_proto, src_port, dst_port = parse_ethernet_ip(pkt_data, network)
            if ip_proto:
                protocols[ip_proto] = protocols.get(ip_proto, 0) + 1

                if ip_proto == "ESP (50)":
                    esp_packets += 1
                elif ip_proto == "UDP":
                    if 500 in (src_port, dst_port):
                        ike_packets += 1
                        ports["IKE (UDP 500)"] = ports.get("IKE (UDP 500)", 0) + 1
                    elif 4500 in (src_port, dst_port):
                        # Port 4500 carries either NAT-T IKE or NAT-T ESP
                        ports["NAT-T (UDP 4500)"] = ports.get("NAT-T (UDP 4500)", 0) + 1
                        esp_packets += 1
                    elif 53 in (src_port, dst_port):
                        dns_packets += 1
                        ports["DNS (UDP 53)"] = ports.get("DNS (UDP 53)", 0) + 1
                    else:
                        port_key = f"UDP/{min(src_port, dst_port)}"
                        ports[port_key] = ports.get(port_key, 0) + 1
                elif ip_proto == "TCP":
                    if 443 in (src_port, dst_port):
                        tls_packets += 1
                        ports["HTTPS/TLS (TCP 443)"] = ports.get("HTTPS/TLS (TCP 443)", 0) + 1
                    elif 53 in (src_port, dst_port):
                        dns_packets += 1
                        ports["DNS (TCP 53)"] = ports.get("DNS (TCP 53)", 0) + 1
                    else:
                        port_key = f"TCP/{min(src_port, dst_port)}"
                        ports[port_key] = ports.get(port_key, 0) + 1

        stats = compute_statistics(packet_sizes, timestamps)

        return {
            "format": "PCAP",
            "total_packets": pkt_idx,
            "snaplen": snaplen,
            "link_type": network,
            "protocols": protocols,
            "notable_ports": ports,
            "security_traffic": {
                "esp_tunnel_packets": esp_packets,
                "ike_handshake_packets": ike_packets,
                "tls_packets": tls_packets,
                "dns_packets": dns_packets
            },
            "packet_size_stats": stats
        }


def parse_ethernet_ip(data: bytes, link_type: int) -> Tuple[Optional[str], int, int]:
    """Extracts IP protocol and transport layer ports."""
    proto_map = {1: "ICMP", 6: "TCP", 17: "UDP", 50: "ESP (50)", 51: "AH (51)", 58: "ICMPv6"}
    
    # Standard Ethernet = 1, Raw IP = 101, Linux Cooked = 113
    ip_offset = 0
    if link_type == 1:  # DLT_EN10MB (Ethernet)
        if len(data) < 14:
            return None, 0, 0
        eth_type = struct.unpack("!H", data[12:14])[0]
        if eth_type == 0x0800: # IPv4
            ip_offset = 14
        elif eth_type == 0x86DD: # IPv6
            ip_offset = 14
        else:
            return None, 0, 0
    elif link_type == 113: # Linux cooked capture
        if len(data) < 16:
            return None, 0, 0
        eth_type = struct.unpack("!H", data[14:16])[0]
        if eth_type == 0x0800 or eth_type == 0x86DD:
            ip_offset = 16
        else:
            return None, 0, 0

    if len(data) < ip_offset + 20:
        return None, 0, 0

    version = (data[ip_offset] >> 4) & 0x0F
    if version == 4:
        ihl = (data[ip_offset] & 0x0F) * 4
        protocol_num = data[ip_offset + 9]
        proto_name = proto_map.get(protocol_num, f"Proto-{protocol_num}")

        transport_offset = ip_offset + ihl
        src_port, dst_port = 0, 0
        if protocol_num in (6, 17) and len(data) >= transport_offset + 4:
            src_port, dst_port = struct.unpack("!HH", data[transport_offset:transport_offset + 4])

        return proto_name, src_port, dst_port

    elif version == 6:
        if len(data) < ip_offset + 40:
            return None, 0, 0
        next_header = data[ip_offset + 6]
        proto_name = proto_map.get(next_header, f"IPv6-Proto-{next_header}")
        transport_offset = ip_offset + 40
        src_port, dst_port = 0, 0
        if next_header in (6, 17) and len(data) >= transport_offset + 4:
            src_port, dst_port = struct.unpack("!HH", data[transport_offset:transport_offset + 4])
        return proto_name, src_port, dst_port

    return None, 0, 0


def parse_pcapng_basic(file_path: str, max_packets: Optional[int] = None) -> Dict[str, Any]:
    """Basic fallback block parser for PCAPNG format."""
    total_packets = 0
    packet_sizes = []
    
    with open(file_path, "rb") as f:
        while True:
            if max_packets and total_packets >= max_packets:
                break
            hdr = f.read(8)
            if len(hdr) < 8:
                break
            block_type, block_len = struct.unpack("<II", hdr)
            if block_len < 12:
                break
            body = f.read(block_len - 8)
            # Enhanced Packet Block (EPB) type = 0x00000006
            if block_type == 6 and len(body) >= 20:
                total_packets += 1
                orig_len = struct.unpack("<I", body[16:20])[0]
                packet_sizes.append(orig_len)

    stats = compute_statistics(packet_sizes, [])
    return {
        "format": "PCAPNG",
        "total_packets": total_packets,
        "packet_size_stats": stats,
        "note": "For granular L4-L7 parsing of PCAPNG, invoke tshark or convert to PCAP."
    }


def compute_statistics(sizes: List[int], timestamps: List[float]) -> Dict[str, Any]:
    if not sizes:
        return {"count": 0, "min": 0, "max": 0, "mean": 0, "stddev": 0}

    n = len(sizes)
    mean_val = sum(sizes) / n
    variance = sum((x - mean_val) ** 2 for x in sizes) / n
    stddev = math.sqrt(variance)

    duration = 0.0
    if len(timestamps) >= 2:
        duration = max(timestamps) - min(timestamps)

    return {
        "count": n,
        "min_bytes": min(sizes),
        "max_bytes": max(sizes),
        "mean_bytes": round(mean_val, 2),
        "stddev_bytes": round(stddev, 2),
        "total_megabytes": round(sum(sizes) / (1024 * 1024), 3),
        "duration_seconds": round(duration, 3)
    }


def main():
    parser = argparse.ArgumentParser(description="Inspect PCAP/PCAPNG network captures.")
    parser.add_argument("pcap_file", help="Path to .pcap or .pcapng capture file")
    parser.add_argument("-n", "--max-packets", type=int, default=None, help="Limit number of packets to process")
    parser.add_argument("--json", action="store_true", help="Print structured JSON output")

    args = parser.parse_args()

    if not os.path.exists(args.pcap_file):
        print(f"Error: File '{args.pcap_file}' not found.", file=sys.stderr)
        sys.exit(1)

    try:
        results = parse_pcap_native(args.pcap_file, args.max_packets)
    except Exception as e:
        print(f"Error parsing capture: {e}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(results, indent=2))
        return

    print("=" * 60)
    print(" NETWORK PACKET CAPTURE INSPECTION")
    print("=" * 60)
    print(f"File Path      : {args.pcap_file}")
    print(f"Format         : {results.get('format', 'PCAP')}")
    print(f"Total Packets  : {results['total_packets']}")
    
    stats = results["packet_size_stats"]
    print(f"Total Volume   : {stats.get('total_megabytes', 0)} MB")
    print(f"Duration       : {stats.get('duration_seconds', 0)} seconds")
    print(f"Packet Sizes   : Min {stats.get('min_bytes', 0)} B | Mean {stats.get('mean_bytes', 0)} B | Max {stats.get('max_bytes', 0)} B (σ = {stats.get('stddev_bytes', 0)})")
    print("-" * 60)

    if "protocols" in results:
        print("Layer 3 / 4 Protocol Breakdown:")
        for proto, count in sorted(results["protocols"].items(), key=lambda x: x[1], reverse=True):
            pct = (count / results["total_packets"]) * 100 if results["total_packets"] else 0
            print(f"  • {proto:<18} : {count:>6} packets ({pct:>5.1f}%)")
        print("-" * 60)

    if "security_traffic" in results:
        sec = results["security_traffic"]
        print("Security & Cryptographic Traffic Detection:")
        print(f"  • IPsec ESP Tunnels : {sec['esp_tunnel_packets']} packets")
        print(f"  • IKE Handshakes    : {sec['ike_handshake_packets']} packets")
        print(f"  • TLS Traffic       : {sec['tls_packets']} packets")
        print(f"  • DNS Queries/Resps : {sec['dns_packets']} packets")
        print("-" * 60)

    if "notable_ports" in results and results["notable_ports"]:
        print("Notable Port Allocations:")
        for port, count in sorted(results["notable_ports"].items(), key=lambda x: x[1], reverse=True):
            print(f"  • {port:<20} : {count:>6} packets")

    print("=" * 60)


if __name__ == "__main__":
    main()

