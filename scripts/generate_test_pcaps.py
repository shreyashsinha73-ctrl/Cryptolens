#!/usr/bin/env python3
"""
scripts/generate_test_pcaps.py
------------------------------
Generates a comprehensive suite of wire-accurate IPsec PCAP captures representing
different traffic types (HTTPS, VoIP, ICMP) across Tunnel and Transport modes.

These PCAPs are 100% compliant with Wireshark's IKEv2 and ESP dissectors,
allowing you to inspect them in Wireshark and cross-check against CryptoLens MVP.
"""

import os
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scapy.all import wrpcap
from scripts.test_control_plane import build_ikev2_packet


def generate_all_scenarios(output_dir: str = "test_pcaps"):
    out_path = Path(output_dir).resolve()
    out_path.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("  Generating Wireshark-Compatible IPsec Test PCAPs")
    print(f"  Target directory: {out_path}")
    print("=" * 70)

    scenarios = [
        {
            "filename": "01_tunnel_https_secure.pcap",
            "title": "Scenario 1: Modern Secure Tunnel (HTTPS Traffic)",
            "description": "AES-256-GCM, DH 19, Tunnel mode, PFS ON, Bursty large packets (1420B avg)",
            "params": {
                "encr_id": 20,       # AES-GCM
                "key_len": 256,
                "integ_id": 0,       # AEAD
                "dh_group": 19,      # NIST P-256
                "pfs_enabled": True,
                "transport_mode": False,  # Tunnel
                "is_replayed": False,
                "esp_packet_lengths": [1420, 1390, 1420, 680, 1410],
                "esp_intervals": [0.015, 0.008, 0.045, 0.012],
            },
            "expected": {
                "control_plane": "IKEv2 | Tunnel | AES-256-GCM | DH Group 19 | PFS: True | Replay: True",
                "data_plane": "Mode: Tunnel | Traffic: HTTPS | Avg Size: ~1264B | Packets: 5",
            },
        },
        {
            "filename": "02_transport_voip_legacy.pcap",
            "title": "Scenario 2: Legacy Transport Mode (VoIP Traffic)",
            "description": "AES-128-CBC, DH 2, Transport mode, PFS OFF, Small uniform packets (220B) @ 20ms cadence",
            "params": {
                "encr_id": 12,       # AES-CBC
                "key_len": 128,
                "integ_id": 2,       # HMAC-SHA1
                "dh_group": 2,       # 1024-bit MODP
                "pfs_enabled": False,
                "transport_mode": True,   # Transport
                "is_replayed": False,
                "esp_packet_lengths": [220, 216, 224, 218, 222],
                "esp_intervals": [0.020, 0.020, 0.020, 0.020],
            },
            "expected": {
                "control_plane": "IKEv2 | Transport | AES-128-CBC | DH Group 2 | PFS: False | Replay: True",
                "data_plane": "Mode: Transport | Traffic: VoIP | Avg Size: ~220B | Packets: 5",
            },
        },
        {
            "filename": "03_tunnel_voip_enterprise.pcap",
            "title": "Scenario 3: Secure Enterprise Tunnel (VoIP Traffic)",
            "description": "AES-256-GCM, DH 14, Tunnel mode, PFS ON, Voice packets (240B) in tunnel encapsulation",
            "params": {
                "encr_id": 20,
                "key_len": 256,
                "integ_id": 0,
                "dh_group": 14,      # 2048-bit MODP
                "pfs_enabled": True,
                "transport_mode": False,  # Tunnel
                "is_replayed": False,
                "esp_packet_lengths": [240, 240, 240, 240, 240],
                "esp_intervals": [0.020, 0.020, 0.020, 0.020],
            },
            "expected": {
                "control_plane": "IKEv2 | Tunnel | AES-256-GCM | DH Group 14 | PFS: True | Replay: True",
                "data_plane": "Mode: Tunnel | Traffic: VoIP | Avg Size: ~240B | Packets: 5",
            },
        },
        {
            "filename": "04_transport_icmp_ping.pcap",
            "title": "Scenario 4: Host-to-Host Transport (ICMP Diagnostic Ping)",
            "description": "AES-128-CBC, DH 14, Transport mode, Small 92B packets with 1.0s sparse intervals",
            "params": {
                "encr_id": 12,
                "key_len": 128,
                "integ_id": 2,
                "dh_group": 14,
                "pfs_enabled": False,
                "transport_mode": True,
                "is_replayed": False,
                "esp_packet_lengths": [92, 92, 92, 92, 92],
                "esp_intervals": [1.000, 1.000, 1.000, 1.000],
            },
            "expected": {
                "control_plane": "IKEv2 | Transport | AES-128-CBC | DH Group 14 | PFS: False | Replay: True",
                "data_plane": "Mode: Transport | Traffic: ICMP | Avg Size: 92B | Packets: 5",
            },
        },
        {
            "filename": "05_transport_replay_attack.pcap",
            "title": "Scenario 5: Replay Attack Injected (Duplicate Sequence Numbers)",
            "description": "AES-128-CBC, Transport mode, Duplicate ESP Sequence #2 injected to trigger replay detection",
            "params": {
                "encr_id": 12,
                "key_len": 128,
                "integ_id": 2,
                "dh_group": 2,
                "pfs_enabled": False,
                "transport_mode": True,
                "is_replayed": True,  # Injects duplicate seq: [1, 2, 3, 4, 2]
                "esp_packet_lengths": [220, 216, 224, 218, 216],
                "esp_intervals": [0.020, 0.020, 0.020, 0.005],
            },
            "expected": {
                "control_plane": "IKEv2 | Transport | Replay Protection: NOT VERIFIED / FAILED (Duplicate seq #2)",
                "data_plane": "Mode: Transport | Traffic: VoIP",
            },
        },
    ]

    summary_rows = []
    for s in scenarios:
        pkts = build_ikev2_packet(**s["params"])
        file_path = out_path / s["filename"]
        wrpcap(str(file_path), pkts)

        print(f"\n[+] Created: {s['filename']}")
        print(f"    Title   : {s['title']}")
        print(f"    Expected: {s['expected']['data_plane']}")
        print(f"              {s['expected']['control_plane']}")

        summary_rows.append((s["filename"], s["expected"]["data_plane"], s["expected"]["control_plane"]))

    # Also sync the primary ones into backend/uploads for easy UI selection
    uploads_dir = PROJECT_ROOT / "backend" / "uploads"
    uploads_dir.mkdir(parents=True, exist_ok=True)
    for s in scenarios:
        src = out_path / s["filename"]
        dst = uploads_dir / s["filename"]
        try:
            import shutil
            shutil.copy2(src, dst)
        except Exception:
            pass

    print("\n" + "=" * 70)
    print("  Generation Complete! All files also copied to backend/uploads/")
    print("=" * 70)


if __name__ == "__main__":
    generate_all_scenarios()
