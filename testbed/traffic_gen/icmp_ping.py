#!/usr/bin/env python3
"""
CryptoLens Traffic Generator - ICMP Echo / Baseline Ping
Sends uniform ICMP echo requests across the IPsec tunnel.
Provides the deterministic baseline signature for data-plane classification.
"""

import argparse
import subprocess
import sys
import time

def run_ping(target_ip: str, count: int = 20, interval: float = 0.5, packet_size: int = 64) -> bool:
    print(f"[icmp_ping] Target: {target_ip} | Count: {count} | Interval: {interval}s | Size: {packet_size} bytes")
    cmd = [
        "ping",
        "-c", str(count),
        "-i", str(interval),
        "-s", str(packet_size),
        "-W", "2",
        target_ip
    ]
    try:
        start_time = time.time()
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        elapsed = time.time() - start_time
        print(f"[icmp_ping] Finished in {elapsed:.2f}s (Exit code: {result.returncode})")
        if result.returncode == 0:
            print("[icmp_ping] ICMP baseline traffic generated successfully.")
            return True
        else:
            print(f"[icmp_ping] Ping warning/failure:\n{result.stderr or result.stdout}")
            return False
    except Exception as e:
        print(f"[icmp_ping] Error executing ping: {e}", file=sys.stderr)
        return False

def main():
    parser = argparse.ArgumentParser(description="CryptoLens ICMP Traffic Generator")
    parser.add_argument("--target", "-t", default="192.168.2.1", help="Target IP address across tunnel")
    parser.add_argument("--count", "-c", type=int, default=20, help="Number of ICMP packets to send")
    parser.add_argument("--interval", "-i", type=float, default=0.2, help="Interval between packets in seconds")
    parser.add_argument("--size", "-s", type=int, default=64, help="Data payload size in bytes")
    args = parser.parse_args()

    success = run_ping(args.target, args.count, args.interval, args.size)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
