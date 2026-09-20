#!/usr/bin/env python3
"""
scripts/send_live_packets.py
Sends authentic IKEv2 and ESP packets over the loopback interface (lo).
Allows capturing live IPsec packets in Wireshark in real-time without an external VPN.
"""

import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import argparse
from scapy.all import sendp, get_if_list, wrpcap
from scripts.test_control_plane import build_ikev2_packet


def main():
    parser = argparse.ArgumentParser(description="CryptoLens Live Packet Injector for Wireshark Testing")
    parser.add_argument("-i", "--iface", default="lo", help="Network interface to transmit packets on (default: lo)")
    parser.add_argument("-y", "--yes", action="store_true", help="Non-interactive mode (do not prompt for Enter)")
    parser.add_argument("-o", "--output", default=None, help="Optional PCAP file path to write generated packets directly")
    args = parser.parse_args()

    print("=" * 65)
    print("CryptoLens Live Packet Injector for Wireshark Testing")
    print("=" * 65)

    iface = args.iface
    if iface not in get_if_list():
        print(f"Error: Interface '{iface}' not found.")
        sys.exit(1)

    if not args.yes:
        print(f"\n1. In Wireshark, select interface: '{iface}' (Loopback)")
        print("2. Set Wireshark display filter to:  ike || isakmp || esp")
        print("3. Click 'Start Capturing' in Wireshark.")
        input("\nPress [ENTER] here when Wireshark is ready and capturing...")

    print("\n[+] Generating Modern Secure IKEv2 packets (AES-256-GCM, DH 19)...")
    secure_pkts = build_ikev2_packet(encr_id=20, key_len=256, dh_group=19, pfs_enabled=True)

    print("[+] Generating Legacy Weak IKEv2 packets (AES-128-CBC, DH 2, Replay Attack)...")
    legacy_pkts = build_ikev2_packet(encr_id=12, key_len=128, integ_id=2, dh_group=2, pfs_enabled=False, is_replayed=True)

    all_pkts = secure_pkts + legacy_pkts

    if args.output:
        wrpcap(args.output, all_pkts)
        print(f"[✓] Saved {len(all_pkts)} packets directly to PCAP: {args.output}")

    print(f"\n[+] Transmitting packets over interface '{iface}'...")
    try:
        for pkt in secure_pkts:
            sendp(pkt, iface=iface, verbose=False)
            time.sleep(0.05)

        time.sleep(0.5)

        for pkt in legacy_pkts:
            sendp(pkt, iface=iface, verbose=False)
            time.sleep(0.05)

        print(f"\n[✓] Transmitted {len(all_pkts)} packets successfully over '{iface}'!")
        print("[✓] Switch to your Wireshark window to see the captured packets.")
    except PermissionError:
        print("\n[!] PermissionError: Sending raw Layer-2 packets requires root/CAP_NET_RAW privileges.")
        print("    Please run with sudo in your terminal:")
        print(f"    sudo {PROJECT_ROOT}/.venv/bin/python {PROJECT_ROOT}/scripts/send_live_packets.py")
        sys.exit(1)


if __name__ == "__main__":
    main()

