#!/usr/bin/env python3
"""
scripts/generate_sample_pcap.py
Utility to generate authentic, wire-accurate IPsec (IKEv2 + ESP) packet captures
that can be uploaded directly to the CryptoLens dashboard or tested with the CLI.
"""

import argparse
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scapy.all import wrpcap
from scripts.test_control_plane import build_ikev2_packet


def generate_pcaps(output_dir: str = "."):
    out_path = Path(output_dir).resolve()
    out_path.mkdir(parents=True, exist_ok=True)

    # 1. Compliant Modern IPsec Tunnel: AES-256-GCM, DH Group 19 (P-256), Tunnel mode, PFS enabled
    modern_pkts = build_ikev2_packet(
        encr_id=20,          # AES-GCM
        key_len=256,
        integ_id=0,          # AEAD
        dh_group=19,         # Group 19 (NIST P-256)
        pfs_enabled=True,    # PFS ON
        transport_mode=False,# Tunnel mode
        is_replayed=False    # Replay protection clean
    )
    pcap1 = out_path / "ipsec_secure_aes256gcm_group19.pcapng"
    wrpcap(str(pcap1), modern_pkts)
    print(f"[+] Generated Modern Secure IPsec Capture : {pcap1}")

    # 2. Legacy / Weak IPsec Tunnel: AES-128-CBC, DH Group 2 (1024-bit MODP), Transport mode, PFS disabled, Replay attack
    legacy_pkts = build_ikev2_packet(
        encr_id=12,          # AES-CBC
        key_len=128,
        integ_id=2,          # HMAC-SHA1
        dh_group=2,          # Group 2 (1024-bit MODP)
        pfs_enabled=False,   # PFS OFF
        transport_mode=True, # Transport mode
        is_replayed=True     # Replay attack injected
    )
    pcap2 = out_path / "ipsec_legacy_aes128cbc_group2.pcapng"
    wrpcap(str(pcap2), legacy_pkts)
    print(f"[+] Generated Legacy Weak IPsec Capture   : {pcap2}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate realistic IPsec PCAP captures.")
    parser.add_argument("-o", "--output-dir", default="backend/uploads", help="Target directory for output PCAPs")
    args = parser.parse_args()
    generate_pcaps(args.output_dir)

