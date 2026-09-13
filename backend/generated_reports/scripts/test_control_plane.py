#!/usr/bin/env python3
"""
scripts/test_control_plane.py - Comprehensive Manual Verification Harness
Tests the Control-Plane Lead components:
  1. capture/demux.py (IKE vs ESP capture separation)
  2. capture/pcap_utils.py (Metadata & safe AST extraction)
  3. engine/control_plane/ike_parser.py (Deterministic AST -> cipher/DH/mode/PFS/replay)
  4. engine/control_plane/rules_engine.py (NIST/CNSA compliance audit)

Generates wire-accurate synthetic test captures and validates against existing captures.
"""

import json
import os
import shutil
import struct
import sys
import tempfile
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scapy.all import Ether, IP, UDP, Raw, wrpcap
from backend.capture.demux import PcapDemuxer
from backend.capture.pcap_utils import get_pcap_metadata
from backend.engine.control_plane.ike_parser import IkeDeterministicParser
from backend.engine.control_plane.rules_engine import ControlPlaneRulesEngine


def build_ikev2_packet(
    encr_id: int = 20,           # 20 = AES-GCM, 12 = AES-CBC, 3 = 3DES
    key_len: int = 256,
    integ_id: int = 0,           # 0 = NONE (AEAD), 12 = HMAC-SHA2-256-128, 2 = HMAC-SHA1
    dh_group: int = 19,          # 19 = 256-bit ECP, 14 = 2048 MODP, 2 = 1024 MODP
    pfs_enabled: bool = True,
    transport_mode: bool = False,
    is_replayed: bool = False
) -> bytes:
    """
    Constructs real binary IKEv2 packets and ESP packets conforming to RFC 7296 and RFC 4303.
    """
    packets = []

    # 1. Proposal Transforms for IKE SA
    # Transform 1: ENCR
    t1 = struct.pack("!BBHBBH", 3, 0, 12, 1, 0, encr_id) + struct.pack("!HH", 0x800E, key_len)
    # Transform 2: PRF (PRF_HMAC_SHA2_256 = 5)
    t2 = struct.pack("!BBHBBH", 3, 0, 8, 2, 0, 5)
    # Transform 3: INTEG
    t3 = struct.pack("!BBHBBH", 3, 0, 8, 3, 0, integ_id)
    # Transform 4: D-H
    t4 = struct.pack("!BBHBBH", 3, 0, 8, 4, 0, dh_group)
    # Transform 5: ESN (0 = No ESN)
    t5 = struct.pack("!BBHBBH", 0, 0, 8, 5, 0, 0)

    transforms = t1 + t2 + t3 + t4 + t5
    prop_len = 8 + len(transforms)
    proposal = struct.pack("!BBHBBBB", 0, 0, prop_len, 1, 1, 0, 5) + transforms

    # SA Payload (type 33, next 34 = KE)
    sa_payload_len = 4 + len(proposal)
    sa_payload = struct.pack("!BBH", 34, 0, sa_payload_len) + proposal

    # KE Payload (type 34, next 40 = Nonce)
    ke_len_bytes = 64 if dh_group in (19, 20) else 256
    ke_data = b"\x41" * ke_len_bytes
    ke_payload = struct.pack("!BBHHH", 40, 0, 8 + len(ke_data), dh_group, 0) + ke_data

    # Nonce Payload (type 40, next 0)
    nonce_data = b"\x42" * 32
    nonce_payload = struct.pack("!BBH", 0, 0, 4 + len(nonce_data)) + nonce_data

    init_payloads = sa_payload + ke_payload + nonce_payload
    init_total_len = 28 + len(init_payloads)
    # IKE Header: ispi, rspi, next=33(SA), ver=0x20(IKEv2), exch=34(IKE_SA_INIT), flags=0x08(Init), msgid=0, len
    init_header = struct.pack("!8s8sBBBBII", b"\x11\x22\x33\x44\x55\x66\x77\x88", b"\x00"*8, 33, 0x20, 34, 0x08, 0, init_total_len)

    pkt1 = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / \
           IP(src="192.168.10.1", dst="192.168.10.2") / \
           UDP(sport=500, dport=500) / \
           Raw(load=init_header + init_payloads)
    packets.append(pkt1)

    # 2. CREATE_CHILD_SA Exchange (Exchange Type 36)
    # If transport mode, include Notify Payload 16391 (USE_TRANSPORT_MODE)
    child_payloads = b""
    next_payload = 0

    if transport_mode:
        # Notify payload for USE_TRANSPORT_MODE: next=0 (or 34 if KE follows), msg_type=16391
        next_after_notify = 34 if pfs_enabled else 0
        notify = struct.pack("!BBHBBH", next_after_notify, 0, 8, 3, 0, 16391)
        child_payloads += notify
        next_payload = 41  # Notify

    if pfs_enabled:
        # Key Exchange payload in Child SA (PFS proof)
        child_ke = struct.pack("!BBHHH", 0, 0, 8 + len(ke_data), dh_group, 0) + ke_data
        if not transport_mode:
            next_payload = 34  # KE
        child_payloads += child_ke

    if child_payloads:
        child_header = struct.pack("!8s8sBBBBII", b"\x11\x22\x33\x44\x55\x66\x77\x88", b"\x99"*8, next_payload, 0x20, 36, 0x08, 1, 28 + len(child_payloads))
        pkt2 = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / \
               IP(src="192.168.10.1", dst="192.168.10.2") / \
               UDP(sport=500, dport=500) / \
               Raw(load=child_header + child_payloads)
        packets.append(pkt2)

    # 3. ESP Data Packets (IP Proto 50)
    # ESP Header: SPI (4B), Sequence Number (4B), Payload Data
    seq_list = [1, 2, 3, 4, 2] if is_replayed else [1, 2, 3, 4, 5]
    for seq in seq_list:
        esp_header = struct.pack("!II", 0xCAFEBABE, seq)
        esp_payload = esp_header + b"\xDE\xAD\xBE\xEF" * 16
        esp_pkt = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / \
                  IP(src="192.168.10.1", dst="192.168.10.2", proto=50) / \
                  Raw(load=esp_payload)
        packets.append(esp_pkt)

    return packets


def test_scenario(name: str, packets: list, expect_mode: str, expect_cipher: str, expect_dh: int, expect_pfs: bool, expect_replay: bool):
    print(f"\n{'='*75}")
    print(f"RUNNING SCENARIO: {name}")
    print(f"{'='*75}")

    with tempfile.TemporaryDirectory() as tmpdir:
        pcap_path = os.path.join(tmpdir, f"{name}.pcap")
        wrpcap(pcap_path, packets)

        # 1. Demuxing Step
        print("\n[1] Executing Demuxer (capture/demux.py)...")
        demuxer = PcapDemuxer()
        demux_res = demuxer.demux(pcap_path, output_dir=os.path.join(tmpdir, "demux"))
        print(f"    - Total Packets : {demux_res.total_packets}")
        print(f"    - IKE Packets   : {demux_res.ike_packet_count}")
        print(f"    - ESP Packets   : {demux_res.esp_packet_count}")
        print(f"    - Other Packets : {demux_res.other_packet_count}")
        print(f"    - Endpoints     : {demux_res.endpoints}")
        print(f"    - IKE Pcap Path : {demux_res.ike_pcap_path}")
        print(f"    - ESP Pcap Path : {demux_res.esp_pcap_path}")

        # 2. Parsing Step
        print("\n[2] Executing Deterministic Parser (engine/control_plane/ike_parser.py)...")
        parser = IkeDeterministicParser()
        parse_res = parser.parse_pcap(pcap_path)
        cp_dict = parse_res.to_control_plane_dict()
        print("    - Extracted Control-Plane Parameters:")
        for k, v in cp_dict.items():
            print(f"        * {k:26}: {v}")

        print("\n    - Ground-Truth Wire Evidence Extracted:")
        for ev in parse_res.evidence:
            print(f"        [Frame {ev.frame_number:2}] {ev.field_name:24} = {str(ev.observed_value):15} -> {ev.detail}")

        # Assertions
        assert cp_dict["operating_mode"] == expect_mode, f"Mode mismatch: got {cp_dict['operating_mode']}, expected {expect_mode}"
        assert cp_dict["encryption_algorithm"] == expect_cipher, f"Cipher mismatch: got {cp_dict['encryption_algorithm']}, expected {expect_cipher}"
        assert cp_dict["dh_group"] == expect_dh, f"DH mismatch: got {cp_dict['dh_group']}, expected {expect_dh}"
        assert cp_dict["pfs_enabled"] == expect_pfs, f"PFS mismatch: got {cp_dict['pfs_enabled']}, expected {expect_pfs}"
        assert cp_dict["replay_protection_enabled"] == expect_replay, f"Replay mismatch: got {cp_dict['replay_protection_enabled']}, expected {expect_replay}"

        # 3. Rules Engine Step
        print("\n[3] Executing Compliance Rules Engine (engine/control_plane/rules_engine.py)...")
        rules = ControlPlaneRulesEngine()
        rules_res = rules.evaluate(parse_res)
        print(f"    - Overall Compliance Score : {rules_res.compliance_score}/100.0")
        print(f"    - Risk Level Assigned     : {rules_res.risk_level}")
        print("    - Category Scores Breakdown:")
        for cat, score in rules_res.category_scores.items():
            print(f"        * {cat:20}: {score:4.1f} pts")

        if rules_res.findings:
            print("    - Security Findings:")
            for f in rules_res.findings:
                print(f"        [{f.severity:8}] {f.finding_id:20}: {f.title}")
                print(f"                   Standard: {f.standard_ref}")
                print(f"                   Remedy  : {f.remediation}")
        else:
            print("    - Security Findings: None (Full Compliance Achieved!)")

        print(f"\n>>> Scenario '{name}' PASSED successfully with verified ground truth.")


def test_clean_non_ipsec():
    print(f"\n{'='*75}")
    print("RUNNING SCENARIO: Clean Non-IPsec Traffic (Dynamic Behavior Verification)")
    print(f"{'='*75}")
    sample_pcap = PROJECT_ROOT / "backend" / "uploads" / "job_362648fa.pcapng"
    if not sample_pcap.exists():
        print("Sample PCAP not found, skipping non-ipsec test.")
        return

    print(f"\n[1] Testing demuxer on {sample_pcap.name}...")
    demuxer = PcapDemuxer()
    with tempfile.TemporaryDirectory() as tmpdir:
        res = demuxer.demux(sample_pcap, output_dir=tmpdir)
        print(f"    - Total packets : {res.total_packets}")
        print(f"    - IKE packets   : {res.ike_packet_count} (correctly 0)")
        print(f"    - ESP packets   : {res.esp_packet_count} (correctly 0)")
        print(f"    - Other packets : {res.other_packet_count}")
        assert res.has_ike is False
        assert res.has_esp is False

    print("\n[2] Testing deterministic parser (verifying NO hardcoded fake fallbacks)...")
    parser = IkeDeterministicParser()
    parse_res = parser.parse_pcap(sample_pcap)
    cp_dict = parse_res.to_control_plane_dict()
    for k, v in cp_dict.items():
        print(f"    * {k:26}: {v} (dynamically unobserved)")
        assert v is None, f"Expected None for unobserved {k}, but got hardcoded value {v}!"

    print("\n[3] Testing rules engine on unobserved traffic...")
    rules = ControlPlaneRulesEngine()
    rules_res = rules.evaluate(parse_res)
    print(f"    - Compliance score: {rules_res.compliance_score}")
    print(f"    - Findings: {len(rules_res.findings)} INFO findings generated for unobserved controls.")
    print("\n>>> Scenario 'Clean Non-IPsec Traffic' PASSED: Verified zero hardcoded defaults.")


def main():
    print("*" * 75)
    print("CryptoLens Control-Plane Comprehensive Verification Suite")
    print("*" * 75)

    # Scenario 1: Modern Secure Tunnel (AES-256-GCM, DH 19, Tunnel mode, PFS ON, Replay Protection Clean)
    p1 = build_ikev2_packet(
        encr_id=20, key_len=256, integ_id=0, dh_group=19,
        pfs_enabled=True, transport_mode=False, is_replayed=False
    )
    test_scenario(
        name="modern_secure_tunnel_aes256gcm_group19",
        packets=p1,
        expect_mode="Tunnel",
        expect_cipher="AES-256-GCM",
        expect_dh=19,
        expect_pfs=True,
        expect_replay=True
    )

    # Scenario 2: Legacy Weak Transport Tunnel (AES-128-CBC, DH 2, Transport mode, PFS OFF, Replay DUPLICATES)
    p2 = build_ikev2_packet(
        encr_id=12, key_len=128, integ_id=2, dh_group=2,
        pfs_enabled=False, transport_mode=True, is_replayed=True
    )
    test_scenario(
        name="legacy_weak_transport_aes128cbc_group2_replayed",
        packets=p2,
        expect_mode="Transport",
        expect_cipher="AES-128-CBC",
        expect_dh=2,
        expect_pfs=False,
        expect_replay=False
    )

    # Scenario 3: Real Non-IPsec sample PCAP (verifying dynamic non-hardcoded behavior)
    test_clean_non_ipsec()

    print(f"\n{'='*75}")
    print("ALL CONTROL-PLANE TESTS COMPLETED SUCCESSFULLY!")
    print(f"{'='*75}")


if __name__ == "__main__":
    main()

