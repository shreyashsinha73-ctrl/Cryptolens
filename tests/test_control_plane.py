#!/usr/bin/env python3
"""
Unit and Integration Test Suite for Part 2 — Control-Plane Lead.
Tests PCAP parsing, stream demuxing, IKE proposal AST extraction,
and cryptographic compliance rules evaluation.
"""

import os
import shutil
import struct
import tempfile
import unittest

from capture.pcap_utils import PcapReader, PcapWriter, parse_packet_layers, DLT_EN10MB
from capture.demux import demux_pcap
from engine.control_plane.ike_parser import IkeParser
from engine.control_plane.rules_engine import RulesEngine
from engine.control_plane.service import run_control_plane_pipeline, get_job_result


def build_synthetic_packet(
    proto: int,
    src_ip: str = "192.168.1.1",
    dst_ip: str = "192.168.1.2",
    src_port: int = 500,
    dst_port: int = 500,
    payload: bytes = b""
) -> bytes:
    """Builds an Ethernet + IPv4 packet with specified protocol and payload."""
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    src_bytes = bytes([int(x) for x in src_ip.split(".")])
    dst_bytes = bytes([int(x) for x in dst_ip.split(".")])

    if proto == 17:  # UDP
        udp_len = 8 + len(payload)
        udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
        l4_bytes = udp_hdr + payload
    else:
        l4_bytes = payload

    ip_total_len = 20 + len(l4_bytes)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_total_len, 0x1234, 0x4000, 64, proto, 0, src_bytes, dst_bytes
    )
    return eth + ip_hdr + l4_bytes


def build_ikev2_sa_init_payload(enc_id: int = 20, key_len: int = 256, dh_id: int = 19, prf_id: int = 5) -> bytes:
    """
    Constructs an IKEv2 header and SA payload proposing specified transforms.
    ENCR: 20 (AES-GCM), key_len=256
    DH: 19 (256-bit ECP)
    PRF: 5 (HMAC-SHA2-256)
    """
    # Build Transforms:
    # 1. ENCR Transform (Type 1, ID enc_id, Attribute Key Length 14 = key_len)
    enc_attr = struct.pack("!HH", 0x800E, key_len)
    enc_t = struct.pack("!BBHBBH", 3, 0, 8 + len(enc_attr), 1, 0, enc_id) + enc_attr

    # 2. PRF Transform (Type 2, ID prf_id)
    prf_t = struct.pack("!BBHBBH", 3, 0, 8, 2, 0, prf_id)

    # 3. DH Transform (Type 4, ID dh_id)
    dh_t = struct.pack("!BBHBBH", 0, 0, 8, 4, 0, dh_id)

    transforms = enc_t + prf_t + dh_t
    num_transforms = 3

    # Proposal: Last=0, Proposal Len = 8 + transforms len, Prop #=1, Proto=1 (IKE), SPI Size=0, Transforms=3
    prop_len = 8 + len(transforms)
    proposal = struct.pack("!BBHBBBB", 0, 0, prop_len, 1, 1, 0, num_transforms) + transforms

    # SA Payload: Next=0, Critical=0, Len = 4 + proposal len
    sa_len = 4 + len(proposal)
    sa_payload = struct.pack("!BBH", 0, 0, sa_len) + proposal

    # IKE Header: Initiator SPI, Responder SPI, Next=33 (SA), Ver=0x20 (IKEv2), Exch=34 (IKE_SA_INIT), Flags=0x08, MsgID=0, TotalLen
    ike_total_len = 28 + len(sa_payload)
    ike_hdr = struct.pack(
        "!8s8sBBBBII",
        b"\x01\x02\x03\x04\x05\x06\x07\x08",
        b"\x00\x00\x00\x00\x00\x00\x00\x00",
        33,   # Next Payload: SA (33)
        0x20, # Version: IKEv2
        34,   # Exchange: IKE_SA_INIT
        0x08, # Initiator flag
        0,    # Message ID
        ike_total_len
    )
    return ike_hdr + sa_payload


class TestControlPlane(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="cryptolens_test_")
        self.compliant_pcap = os.path.join(self.test_dir, "compliant_ikev2.pcap")
        self.vulnerable_pcap = os.path.join(self.test_dir, "vulnerable_ikev1.pcap")
        self.mixed_pcap = os.path.join(self.test_dir, "mixed_session.pcap")

        # 1. Create compliant IKEv2 capture (AES-256-GCM, DH 19, PRF SHA2-256)
        with PcapWriter(self.compliant_pcap) as w:
            ike_payload = build_ikev2_sa_init_payload(enc_id=20, key_len=256, dh_id=19, prf_id=5)
            pkt = build_synthetic_packet(proto=17, src_port=500, dst_port=500, payload=ike_payload)
            w.write_packet(1700000000.0, pkt)

        # 2. Create vulnerable IKEv1 capture
        with PcapWriter(self.vulnerable_pcap) as w:
            # IKEv1 Header: Ver=0x10, Exch=2 (Identity Protection), Next=1 (SA)
            ike1_hdr = struct.pack(
                "!8s8sBBBBII",
                b"\xaa" * 8, b"\x00" * 8, 1, 0x10, 2, 0, 0, 28
            )
            pkt = build_synthetic_packet(proto=17, src_port=500, dst_port=500, payload=ike1_hdr)
            w.write_packet(1700000001.0, pkt)

        # 3. Create mixed capture: 1 IKE, 2 ESP, 1 DNS
        with PcapWriter(self.mixed_pcap) as w:
            # IKE packet
            ike_payload = build_ikev2_sa_init_payload(enc_id=20, key_len=256, dh_id=19, prf_id=5)
            pkt_ike = build_synthetic_packet(proto=17, src_port=500, dst_port=500, payload=ike_payload)
            w.write_packet(1700000002.0, pkt_ike)

            # Native ESP packet (Proto 50)
            esp_payload = struct.pack("!II", 0x12345678, 1) + b"\xee" * 64
            pkt_esp1 = build_synthetic_packet(proto=50, payload=esp_payload)
            w.write_packet(1700000002.1, pkt_esp1)

            # NAT-T ESP packet (UDP 4500, non-zero SPI)
            pkt_esp2 = build_synthetic_packet(proto=17, src_port=4500, dst_port=4500, payload=esp_payload)
            w.write_packet(1700000002.2, pkt_esp2)

            # DNS packet (UDP 53)
            pkt_dns = build_synthetic_packet(proto=17, src_port=53535, dst_port=53, payload=b"\x00\x01\x02\x03")
            w.write_packet(1700000002.3, pkt_dns)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_pcap_utils_reader(self):
        """Verify PCAP reader correctly parses packets and timestamps."""
        reader = PcapReader(self.compliant_pcap)
        packets = list(reader.iter_packets())
        self.assertEqual(len(packets), 1)
        ts, wire_len, pkt_data, link_type = packets[0]
        self.assertEqual(link_type, DLT_EN10MB)
        self.assertAlmostEqual(ts, 1700000000.0, places=2)

        meta = parse_packet_layers(pkt_data, link_type)
        self.assertTrue(meta["is_ike"])
        self.assertEqual(meta["src_port"], 500)
        self.assertEqual(meta["dst_port"], 500)

    def test_traffic_demux(self):
        """Verify demux_pcap splits mixed capture into control and data planes."""
        demux_out_dir = os.path.join(self.test_dir, "demux_out")
        res = demux_pcap(self.mixed_pcap, output_dir=demux_out_dir, save_splits=True)

        self.assertEqual(res["total_packets"], 4)
        self.assertEqual(res["control_plane"]["packet_count"], 1)  # 1 IKE
        self.assertEqual(res["data_plane"]["packet_count"], 2)     # 2 ESP (native + NAT-T)
        self.assertEqual(res["other_traffic"]["packet_count"], 1)  # 1 DNS
        self.assertTrue(res["summary"]["is_complete_ipsec_session"])

        # Check split files exist
        self.assertTrue(os.path.exists(res["control_plane"]["pcap_file"]))
        self.assertTrue(os.path.exists(res["data_plane"]["pcap_file"]))

    def test_ike_parser_compliant(self):
        """Verify IKE parser extracts AES-256-GCM and DH 19 from SA payload."""
        parser = IkeParser(self.compliant_pcap)
        ast = parser.parse()
        self.assertTrue(ast["parsed_successfully"])
        cp = ast["control_plane"]
        self.assertEqual(cp["ike_version"], "IKEv2")
        self.assertEqual(cp["encryption_algorithm"], "AES-GCM-256")
        self.assertEqual(cp["dh_group"], 19)
        self.assertEqual(cp["prf_algorithm"], "PRF_HMAC_SHA2_256")
        self.assertEqual(cp["integrity_algorithm"], "NONE")

    def test_rules_engine_compliant(self):
        """Verify compliant IKEv2 suite scores LOW risk and zero findings."""
        cp = {
            "ike_version": "IKEv2",
            "operating_mode": "Tunnel",
            "encryption_algorithm": "AES-256-GCM",
            "integrity_algorithm": "NONE",
            "dh_group": 19,
            "pfs_enabled": True,
            "key_lifetime_seconds": 28800,
            "replay_protection_enabled": True
        }
        engine = RulesEngine(target_standard="nist")
        eval_res = engine.evaluate(cp)
        self.assertEqual(eval_res["summary"]["overall_risk_score"], 0)
        self.assertEqual(eval_res["summary"]["risk_level"], "LOW")
        self.assertEqual(len(eval_res["threat_matrix"]), 0)

    def test_rules_engine_vulnerable(self):
        """Verify weak crypto triggers multiple threat findings and CRITICAL risk."""
        cp = {
            "ike_version": "IKEv1",
            "operating_mode": "Tunnel",
            "encryption_algorithm": "3DES",
            "integrity_algorithm": "HMAC-MD5",
            "dh_group": 2,
            "pfs_enabled": False,
            "key_lifetime_seconds": 86400,
            "replay_protection_enabled": False
        }
        engine = RulesEngine(target_standard="nist")
        eval_res = engine.evaluate(cp)
        self.assertGreaterEqual(eval_res["summary"]["overall_risk_score"], 80)
        self.assertEqual(eval_res["summary"]["risk_level"], "CRITICAL")
        # Should flag IKEv1, 3DES, MD5, DH 2, PFS, Lifetime, Replay
        self.assertGreaterEqual(len(eval_res["threat_matrix"]), 5)

    def test_control_plane_pipeline_service(self):
        """Verify end-to-end service pipeline execution and job caching."""
        job_id = "job_test_cp_001"
        res = run_control_plane_pipeline(self.compliant_pcap, job_id=job_id)
        self.assertEqual(res["job_id"], job_id)
        self.assertEqual(res["status"], "completed")
        self.assertEqual(res["summary"]["risk_level"], "LOW")

        # Verify cached retrieval
        cached = get_job_result(job_id)
        self.assertIsNotNone(cached)
        self.assertEqual(cached["job_id"], job_id)
        self.assertEqual(cached["control_plane"]["encryption_algorithm"], "AES-GCM-256")


if __name__ == "__main__":
    unittest.main()

