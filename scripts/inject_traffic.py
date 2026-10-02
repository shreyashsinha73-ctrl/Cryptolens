#!/usr/bin/env python3
"""
scripts/inject_traffic.py
-------------------------
CLI packet injector for testing CryptoLens live packet sniffing.
Usage:
  python3 scripts/inject_traffic.py --profile hardened
  python3 scripts/inject_traffic.py --profile vulnerable
  python3 scripts/inject_traffic.py --api http://localhost:8000
"""

import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.streaming.injector import (
    generate_hardened_packets,
    generate_vulnerable_packets,
    try_transmit_raw_udp,
)


def main():
    parser = argparse.ArgumentParser(description="CryptoLens IPsec Packet Injector")
    parser.add_argument(
        "--profile",
        choices=["hardened", "vulnerable"],
        default="hardened",
        help="Traffic profile: hardened (NIST/CNSA aligned) or vulnerable (Sweet32 3DES + Replay)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=30,
        help="Number of packets to inject (default: 30)",
    )
    parser.add_argument(
        "--api",
        type=str,
        default="",
        help="Backend base URL to inject via API (e.g. http://localhost:8000)",
    )
    args = parser.parse_args()

    print(f"[+] CryptoLens Traffic Injector — Profile: {args.profile.upper()}")

    if args.api:
        url = f"{args.api.rstrip('/')}/api/v1/live/inject/{args.profile}"
        print(f"[+] Triggering injection via API: POST {url}")
        req = urllib.request.Request(url, method="POST")
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode())
                print(f"[+] API Response: {data}")
        except Exception as e:
            print(f"[-] API injection failed: {e}")
            sys.exit(1)
        return

    # Direct socket transmission
    if args.profile == "hardened":
        packets = generate_hardened_packets(count=args.count)
    else:
        packets = generate_vulnerable_packets(count=args.count)

    print(f"[+] Generated {len(packets)} frames.")
    for p in packets[:5]:
        print(f"    - Frame #{p.get('frame_number')}: {p.get('packet_type')} | {p.get('src_ip')} -> {p.get('dst_ip')} | SPI={p.get('spi')} | Len={p.get('packet_length')}B")
    if len(packets) > 5:
        print(f"    ... and {len(packets) - 5} more frames")

    print("[+] Transmitting packets over localhost loopback...")
    try_transmit_raw_udp(packets)
    print("[+] Ingestion complete.")


if __name__ == "__main__":
    main()
