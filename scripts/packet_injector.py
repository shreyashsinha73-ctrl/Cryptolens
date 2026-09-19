#!/usr/bin/env python3
"""
scripts/packet_injector.py
--------------------------
Realistic IPsec Wire Packet Generator & Injector for Wireshark & CryptoLens MVP.

Generates wire-accurate IKEv2 + ESP packet streams matching real-world traffic:
  1. HTTPS Web Traffic over IPsec Tunnel (bursty ~1400B payloads + ACKs)
  2. VoIP Telephony over IPsec Transport (steady ~220B frames @ 20ms cadence)
  3. VoIP Telephony over IPsec Tunnel (steady ~240B frames @ 20ms cadence)
  4. ICMP Diagnostic Ping (steady ~92B frames @ 1.0s cadence)
  5. Replay Attack Injected (duplicate ESP sequence number to trigger anti-replay)

Usage:
  # Generate all test PCAPs for Wireshark & CryptoLens:
  python scripts/packet_injector.py --all

  # Generate a specific scenario:
  python scripts/packet_injector.py --scenario https -o test_https.pcap
  python scripts/packet_injector.py --scenario voip -o test_voip.pcap

  # Live injection onto a local network adapter while Wireshark is capturing:
  python scripts/packet_injector.py --scenario voip --live
"""

import argparse
import os
import random
import struct
import sys
import time
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scapy.all import Ether, IP, UDP, Raw, wrpcap, sendp, get_if_list


def build_ikev2_init_packet(
    src_ip: str,
    dst_ip: str,
    encr_id: int = 20,       # 20 = AES-GCM, 12 = AES-CBC
    key_len: int = 256,      # 128 or 256
    integ_id: int = 0,       # 0 = AEAD, 2 = HMAC-SHA1
    dh_group: int = 19,      # 19 = NIST P-256, 14 = 2048-bit MODP, 2 = 1024-bit MODP
    initiator_spi: bytes = b"\x11\x22\x33\x44\x55\x66\x77\x88",
) -> Ether:
    """Constructs a real, wire-accurate IKE_SA_INIT exchange packet."""
    transforms = b""
    t_count = 0

    # Transform 1: Encryption
    if encr_id == 20:
        attr = struct.pack("!HH", 0x800E, key_len)
        transforms += struct.pack("!BBHBBH", 3, 0, 12, 1, 0, encr_id) + attr
        t_count += 1
    else:
        attr = struct.pack("!HH", 0x800E, key_len) if key_len else b""
        t_len = 8 + len(attr)
        transforms += struct.pack("!BBHBBH", 3 if (integ_id or dh_group) else 0, 0, t_len, 1, 0, encr_id) + attr
        t_count += 1

    # Transform 2: Integrity (if not AEAD)
    if integ_id:
        transforms += struct.pack("!BBHBBH", 3 if dh_group else 0, 0, 8, 3, 0, integ_id)
        t_count += 1

    # Transform 3: Diffie-Hellman Group
    if dh_group:
        transforms += struct.pack("!BBHBBH", 0, 0, 8, 4, 0, dh_group)
        t_count += 1

    prop_header = struct.pack("!BBHBBBB", 0, 0, 8 + len(transforms), 1, 1, 0, t_count)
    sa_payload = struct.pack("!BBH", 34, 0, 4 + len(prop_header) + len(transforms)) + prop_header + transforms

    ke_len = 64 if dh_group == 19 else (256 if dh_group == 14 else 128)
    ke_data = b"\xAA" * ke_len
    ke_payload = struct.pack("!BBHHH", 40, 0, 8 + len(ke_data), dh_group, 0) + ke_data

    nonce_data = b"\x55" * 32
    nonce_payload = struct.pack("!BBH", 0, 0, 4 + len(nonce_data)) + nonce_data

    init_payloads = sa_payload + ke_payload + nonce_payload
    init_total_len = 28 + len(init_payloads)
    init_header = struct.pack("!8s8sBBBBII", initiator_spi, b"\x00" * 8, 33, 0x20, 34, 0x08, 0, init_total_len)

    return (
        Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee")
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=500, dport=500)
        / Raw(load=init_header + init_payloads)
    )


def build_ikev2_child_packet(
    src_ip: str,
    dst_ip: str,
    transport_mode: bool = False,
    pfs_enabled: bool = True,
    dh_group: int = 19,
    initiator_spi: bytes = b"\x11\x22\x33\x44\x55\x66\x77\x88",
    responder_spi: bytes = b"\x99" * 8,
) -> Ether:
    """Constructs a real CREATE_CHILD_SA exchange packet with mode/PFS flags."""
    child_payloads = b""
    next_payload = 0

    if transport_mode:
        next_after_notify = 34 if pfs_enabled else 0
        notify = struct.pack("!BBHBBH", next_after_notify, 0, 8, 3, 0, 16391)  # USE_TRANSPORT_MODE
        child_payloads += notify
        next_payload = 41

    if pfs_enabled:
        ke_len = 64 if dh_group == 19 else (256 if dh_group == 14 else 128)
        ke_data = b"\xBB" * ke_len
        child_ke = struct.pack("!BBHHH", 0, 0, 8 + len(ke_data), dh_group, 0) + ke_data
        if not transport_mode:
            next_payload = 34
        child_payloads += child_ke

    if not child_payloads:
        # Minimal dummy notify payload if neither
        child_payloads = struct.pack("!BBHBBH", 0, 0, 8, 3, 0, 16400)
        next_payload = 41

    child_header = struct.pack(
        "!8s8sBBBBII", initiator_spi, responder_spi, next_payload, 0x20, 36, 0x08, 1, 28 + len(child_payloads)
    )

    return (
        Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee")
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=500, dport=500)
        / Raw(load=child_header + child_payloads)
    )


def build_ikev1_init_packet(
    src_ip: str,
    dst_ip: str,
    encr_id: int = 3,         # 3 = 3DES, 12 = AES-CBC
    integ_id: int = 2,        # 2 = HMAC-SHA1
    dh_group: int = 2,        # Group 2 (1024-bit MODP)
    initiator_spi: bytes = b"\x11\x22\x33\x44\x55\x66\x77\x88",
) -> Ether:
    """Constructs a real IKEv1 (ISAKMP) Main Mode SA exchange packet (version 0x10)."""
    transforms = struct.pack("!BBHBBH", 3, 0, 8, 1, 0, encr_id)    # Encryption (3DES / AES)
    transforms += struct.pack("!BBHBBH", 3, 0, 8, 3, 0, integ_id)   # Integrity (HMAC-SHA1)
    transforms += struct.pack("!BBHBBH", 0, 0, 8, 4, 0, dh_group)   # DH Group 2

    prop_header = struct.pack("!BBHBBBB", 0, 0, 8 + len(transforms), 1, 1, 0, 3)
    sa_payload = struct.pack("!BBH", 0, 0, 4 + len(prop_header) + len(transforms)) + prop_header + transforms

    # IKEv1 header: Version = 0x10 (Major=1, Minor=0), Exchange = 2 (Identity Protection / Main Mode)
    init_total_len = 28 + len(sa_payload)
    init_header = struct.pack("!8s8sBBBBII", initiator_spi, b"\x00" * 8, 1, 0x10, 2, 0x00, 0, init_total_len)

    return (
        Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee")
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=500, dport=500)
        / Raw(load=init_header + sa_payload)
    )


def generate_scenario_packets(scenario: str) -> tuple[list, dict]:
    """
    Builds authentic packet sequences for a specified traffic scenario.
    Returns: (list_of_scapy_packets, metadata_dict)
    """
    src_ip = "192.168.10.1"
    dst_ip = "192.168.10.2"
    spi = 0xCAFEBABE

    packets = []
    base_time = time.time()

    if scenario == "https":
        # Realistic HTTPS over Tunnel Mode (AES-256-GCM, DH 19, PFS ON)
        # Sequence: IKE Init -> Child SA -> TLS Handshake burst -> Content Bursts + ACKs
        init_pkt = build_ikev2_init_packet(src_ip, dst_ip, encr_id=20, key_len=256, integ_id=0, dh_group=19)
        init_pkt.time = base_time
        packets.append(init_pkt)

        child_pkt = build_ikev2_child_packet(src_ip, dst_ip, transport_mode=False, pfs_enabled=True, dh_group=19)
        child_pkt.time = base_time + 0.015
        packets.append(child_pkt)

        # 25 Realistic HTTPS payload packets (mix of full 1420B TLS records & smaller ACKs/responses)
        packet_lengths = [
            512, 1420, 1420, 68, 1420, 1420, 1420, 68, 1380, 1420,
            68, 1420, 1420, 920, 68, 1420, 1420, 68, 1420, 1420,
            1420, 1420, 68, 850, 68
        ]
        # Bursty timings: tightly spaced in burst (2-8ms), pause between bursts (60-120ms)
        intervals = [
            0.005, 0.003, 0.002, 0.080, 0.004, 0.002, 0.003, 0.090, 0.005, 0.002,
            0.075, 0.003, 0.004, 0.002, 0.060, 0.003, 0.002, 0.080, 0.004, 0.002,
            0.003, 0.002, 0.070, 0.005
        ]

        curr_time = base_time + 0.030
        for i, (length, interval) in enumerate(zip(packet_lengths, [0.0] + intervals)):
            curr_time += interval
            seq = i + 1
            esp_header = struct.pack("!II", spi, seq)
            payload_len = max(0, length - 28)
            payload = esp_header + b"\xDE\xAD\xBE\xEF" * (payload_len // 4 + 1)
            payload = payload[:length - 20]

            pkt = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src=src_ip, dst=dst_ip, proto=50) / Raw(load=payload)
            pkt.time = curr_time
            packets.append(pkt)

        meta = {
            "name": "HTTPS Web Browsing over IPsec Tunnel",
            "traffic_type": "HTTPS",
            "mode": "Tunnel",
            "encryption": "AES-256-GCM (Group 19, PFS ON)",
            "esp_count": len(packet_lengths),
            "avg_size": round(sum(packet_lengths) / len(packet_lengths), 1),
        }

    elif scenario == "voip":
        # Realistic VoIP (RTP / G.711 voice) over Transport Mode (AES-128-CBC, DH 2, PFS OFF)
        # Consistent ~218-224 byte packets at strict 20ms cadence
        init_pkt = build_ikev2_init_packet(src_ip, dst_ip, encr_id=12, key_len=128, integ_id=2, dh_group=2)
        init_pkt.time = base_time
        packets.append(init_pkt)

        child_pkt = build_ikev2_child_packet(src_ip, dst_ip, transport_mode=True, pfs_enabled=False, dh_group=2)
        child_pkt.time = base_time + 0.015
        packets.append(child_pkt)

        # 30 Voice packets with micro-jitter (19.5ms - 20.5ms)
        curr_time = base_time + 0.030
        lengths = []
        for seq in range(1, 31):
            length = random.choice([216, 218, 220, 222, 224])
            lengths.append(length)
            jitter = random.uniform(-0.001, 0.001)
            curr_time += 0.020 + jitter

            esp_header = struct.pack("!II", spi, seq)
            payload = esp_header + (b"\x12\x34\x56\x78" * (length // 4))[:length - 28]

            pkt = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src=src_ip, dst=dst_ip, proto=50) / Raw(load=payload)
            pkt.time = curr_time
            packets.append(pkt)

        meta = {
            "name": "VoIP Phone Call over IPsec Transport",
            "traffic_type": "VoIP",
            "mode": "Transport",
            "encryption": "AES-128-CBC (Group 2, PFS OFF)",
            "esp_count": len(lengths),
            "avg_size": round(sum(lengths) / len(lengths), 1),
        }

    elif scenario == "icmp":
        # Realistic ICMP Echo (Ping) over Transport Mode
        # Exactly 92-byte packets at 1.0s interval
        init_pkt = build_ikev2_init_packet(src_ip, dst_ip, encr_id=12, key_len=128, integ_id=2, dh_group=14)
        init_pkt.time = base_time
        packets.append(init_pkt)

        child_pkt = build_ikev2_child_packet(src_ip, dst_ip, transport_mode=True, pfs_enabled=False, dh_group=14)
        child_pkt.time = base_time + 0.015
        packets.append(child_pkt)

        curr_time = base_time + 0.030
        lengths = [92] * 10
        for seq in range(1, 11):
            curr_time += 1.000  # 1 second interval
            esp_header = struct.pack("!II", spi, seq)
            payload = esp_header + (b"\xCA\xFE" * 32)[:92 - 28]

            pkt = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src=src_ip, dst=dst_ip, proto=50) / Raw(load=payload)
            pkt.time = curr_time
            packets.append(pkt)

        meta = {
            "name": "ICMP Diagnostic Ping Stream",
            "traffic_type": "ICMP",
            "mode": "Transport",
            "encryption": "AES-128-CBC (Group 14, PFS OFF)",
            "esp_count": len(lengths),
            "avg_size": 92.0,
        }

    elif scenario == "replay":
        # Replay Attack: Injects duplicate sequence numbers (seq #3 sent twice)
        init_pkt = build_ikev2_init_packet(src_ip, dst_ip, encr_id=12, key_len=128, integ_id=2, dh_group=2)
        init_pkt.time = base_time
        packets.append(init_pkt)

        child_pkt = build_ikev2_child_packet(src_ip, dst_ip, transport_mode=True, pfs_enabled=False, dh_group=2)
        child_pkt.time = base_time + 0.015
        packets.append(child_pkt)

        # Sequence contains an explicit duplicate: 1, 2, 3, 4, 3 (replayed packet!)
        seq_list = [1, 2, 3, 4, 3]
        curr_time = base_time + 0.030
        for seq in seq_list:
            curr_time += 0.020
            esp_header = struct.pack("!II", spi, seq)
            payload = esp_header + b"\xDE\xAD\xBE\xEF" * 48

            pkt = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src=src_ip, dst=dst_ip, proto=50) / Raw(load=payload)
            pkt.time = curr_time
            packets.append(pkt)

        meta = {
            "name": "Replay Attack Attack Injected (Duplicate Seq #3)",
            "traffic_type": "VoIP",
            "mode": "Transport",
            "encryption": "AES-128-CBC (Replay Protection Flagged)",
            "esp_count": len(seq_list),
            "avg_size": 220.0,
        }

    elif scenario == "tunnel_icmp_gcm":
        # Scenario: Modern IKEv2 Tunnel with Large ICMP Ping (AES-256-GCM, DH 19, PFS ON)
        # Average packet size = 628 bytes (>= 500 bytes -> Heuristic: Tunnel, LLM: ICMP)
        init_pkt = build_ikev2_init_packet(src_ip, dst_ip, encr_id=20, key_len=256, integ_id=0, dh_group=19)
        init_pkt.time = base_time
        packets.append(init_pkt)

        child_pkt = build_ikev2_child_packet(src_ip, dst_ip, transport_mode=False, pfs_enabled=True, dh_group=19)
        child_pkt.time = base_time + 0.015
        packets.append(child_pkt)

        curr_time = base_time + 0.030
        lengths = [628] * 10
        for seq in range(1, 11):
            curr_time += 1.000  # 1.0 second ICMP echo ping cadence
            esp_header = struct.pack("!II", spi, seq)
            payload = esp_header + (b"\xCA\xFE" * 320)[:628 - 28]

            pkt = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src=src_ip, dst=dst_ip, proto=50) / Raw(load=payload)
            pkt.time = curr_time
            packets.append(pkt)

        meta = {
            "name": "IKEv2 Tunnel MTU Diagnostic Ping (AES-256-GCM, DH 19, PFS ON)",
            "traffic_type": "ICMP",
            "mode": "Tunnel",
            "encryption": "AES-256-GCM (Group 19, PFS ON)",
            "esp_count": len(lengths),
            "avg_size": 628.0,
        }

    elif scenario == "tunnel_icmp_cbc":
        # Scenario: Legacy IKEv2 Tunnel with Large ICMP Ping (AES-128-CBC, DH 14, PFS OFF)
        # Average packet size = 628 bytes (>= 500 bytes -> Heuristic: Tunnel, LLM: ICMP)
        init_pkt = build_ikev2_init_packet(src_ip, dst_ip, encr_id=12, key_len=128, integ_id=2, dh_group=14)
        init_pkt.time = base_time
        packets.append(init_pkt)

        child_pkt = build_ikev2_child_packet(src_ip, dst_ip, transport_mode=False, pfs_enabled=False, dh_group=14)
        child_pkt.time = base_time + 0.015
        packets.append(child_pkt)

        curr_time = base_time + 0.030
        lengths = [628] * 10
        for seq in range(1, 11):
            curr_time += 1.000
            esp_header = struct.pack("!II", spi, seq)
            payload = esp_header + (b"\xCA\xFE" * 320)[:628 - 28]

            pkt = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src=src_ip, dst=dst_ip, proto=50) / Raw(load=payload)
            pkt.time = curr_time
            packets.append(pkt)

        meta = {
            "name": "IKEv2 Tunnel MTU Diagnostic Ping (AES-128-CBC, DH 14, PFS OFF)",
            "traffic_type": "ICMP",
            "mode": "Tunnel",
            "encryption": "AES-128-CBC (Group 14, PFS OFF)",
            "esp_count": len(lengths),
            "avg_size": 628.0,
        }

    elif scenario == "tunnel_icmp_ikev1":
        # Scenario: Legacy IKEv1 Tunnel with Large ICMP Ping (3DES, DH 2, PFS OFF)
        # Average packet size = 628 bytes (>= 500 bytes -> Heuristic: Tunnel, LLM: ICMP)
        init_pkt = build_ikev1_init_packet(src_ip, dst_ip, encr_id=3, integ_id=2, dh_group=2)
        init_pkt.time = base_time
        packets.append(init_pkt)

        curr_time = base_time + 0.030
        lengths = [628] * 10
        for seq in range(1, 11):
            curr_time += 1.000
            esp_header = struct.pack("!II", spi, seq)
            payload = esp_header + (b"\xCA\xFE" * 320)[:628 - 28]

            pkt = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src=src_ip, dst=dst_ip, proto=50) / Raw(load=payload)
            pkt.time = curr_time
            packets.append(pkt)

        meta = {
            "name": "IKEv1 Legacy Tunnel Diagnostic Ping (3DES, DH 2, PFS OFF)",
            "traffic_type": "ICMP",
            "mode": "Tunnel",
            "encryption": "3DES (Group 2, IKEv1)",
            "esp_count": len(lengths),
            "avg_size": 628.0,
        }

    else:
        raise ValueError(
            f"Unknown scenario: {scenario}. Choose from: https, voip, icmp, replay, "
            "tunnel_icmp_gcm, tunnel_icmp_cbc, tunnel_icmp_ikev1"
        )

    return packets, meta


def run_live_injection(packets: list, iface: str = None):
    """Injects generated packets live onto a network interface."""
    if not iface:
        interfaces = get_if_list()
        # Default to first valid adapter or loopback
        iface = interfaces[0] if interfaces else None

    print(f"\n[LIVE INJECTION] Transmitting {len(packets)} packets on interface: {iface}")
    print("Press CTRL+C to stop.\n")

    t_start = time.time()
    for i, pkt in enumerate(packets):
        if i > 0:
            delta = pkt.time - packets[i - 1].time
            if delta > 0:
                time.sleep(min(delta, 1.0))
        sendp(pkt, iface=iface, verbose=False)
        proto = "IKEv2" if pkt.haslayer(UDP) else "ESP"
        print(f"  [{proto}] Packet #{i+1:02d} -> length={len(pkt)} bytes sent")

    print(f"\n[OK] Live transmission finished in {time.time() - t_start:.2f}s!")


def main():
    parser = argparse.ArgumentParser(description="IPsec Packet Generator & Injector for Wireshark & CryptoLens MVP")
    parser.add_argument(
        "--scenario",
        choices=[
            "https",
            "voip",
            "icmp",
            "replay",
            "tunnel_icmp_gcm",
            "tunnel_icmp_cbc",
            "tunnel_icmp_ikev1",
        ],
        default="voip",
        help="Traffic scenario to generate (default: voip)",
    )
    parser.add_argument("-o", "--output", default=None, help="Output PCAP path")
    parser.add_argument("--all", action="store_true", help="Generate all standard test PCAPs into test_pcaps/")
    parser.add_argument("--live", action="store_true", help="Transmit packets live on network interface")
    parser.add_argument("--iface", default=None, help="Interface name for live transmission")

    args = parser.parse_args()

    if args.all:
        out_dir = Path("test_pcaps")
        out_dir.mkdir(parents=True, exist_ok=True)
        print("=" * 65)
        print("  Generating Comprehensive IPsec Test Suite")
        print("=" * 65)

        scenarios_to_run = [
            "https",
            "voip",
            "icmp",
            "replay",
            "tunnel_icmp_gcm",
            "tunnel_icmp_cbc",
            "tunnel_icmp_ikev1",
        ]
        for sc in scenarios_to_run:
            pkts, meta = generate_scenario_packets(sc)
            file_name = f"ipsec_test_{sc}.pcap"
            file_path = out_dir / file_name
            wrpcap(str(file_path), pkts)
            print(f"\n[+] Created: {file_path}")
            print(f"    Scenario    : {meta['name']}")
            print(f"    Mode/Traffic: {meta['mode']} Mode | {meta['traffic_type']}")
            print(f"    ESP Packets : {meta['esp_count']} packets (avg {meta['avg_size']}B)")

            # Also mirror to backend/uploads for easy UI testing
            upload_path = Path("backend/uploads") / file_name
            wrpcap(str(upload_path), pkts)

        print("\n" + "=" * 65)
        print("  [SUCCESS] All test PCAPs generated in test_pcaps/ and backend/uploads/")
        print("=" * 65)
        return

    # Single scenario mode
    pkts, meta = generate_scenario_packets(args.scenario)

    if args.live:
        run_live_injection(pkts, iface=args.iface)
    else:
        out_file = args.output or f"ipsec_test_{args.scenario}.pcap"
        wrpcap(out_file, pkts)
        print("\n" + "=" * 65)
        print(f"  [SUCCESS] Created: {out_file}")
        print(f"  Scenario    : {meta['name']}")
        print(f"  Mode/Traffic: {meta['mode']} Mode | {meta['traffic_type']}")
        print(f"  ESP Packets : {meta['esp_count']} packets (average {meta['avg_size']} bytes)")
        print(f"  Total Wire  : {len(pkts)} packets (including IKEv2 negotiation)")
        print("=" * 65)
        print(f"\nNext steps:")
        print(f"  1. Open '{out_file}' in Wireshark (Filter: 'esp || ikev2')")
        print(f"  2. Upload '{out_file}' to CryptoLens MVP dashboard to cross-check!")


if __name__ == "__main__":
    main()
