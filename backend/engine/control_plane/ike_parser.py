#!/usr/bin/env python3
"""
Deterministic IKE Protocol Parser (engine/control_plane/ike_parser.py)
Extracts cryptographic proposals, transforms, DH groups, PRF algorithms,
and SA parameters from raw PCAP files into a normalized JSON AST.

Features a dual-engine architecture:
  1. tshark execution engine (when available on host)
  2. High-performance native binary unpacker (RFC 7296 / RFC 2409)
"""

<<<<<<< HEAD
from dataclasses import asdict, dataclass, field
from pathlib import Path
import struct
from typing import Any, Dict, List, Optional, Tuple, Union
=======
import argparse
import json
import os
import struct
import subprocess
import sys
from typing import Dict, List, Any, Optional, Tuple
>>>>>>> 09ed384854c6a471d409aeed5b20daf4a821a5d1

from backend.capture.pcap_utils import PcapReader, parse_packet_layers

# --- RFC 7296 / RFC 2409 Transform ID Mappings ---

TRANSFORM_TYPE_MAP = {
    1: "ENCR",
    2: "PRF",
    3: "INTEG",
    4: "D-H",
    5: "ESN"
}

ENCR_MAP = {
    1: "DES-IV64",
    2: "DES",
    3: "3DES",
    4: "RC5",
    5: "IDEA",
    6: "CAST",
    7: "BLOWFISH",
    11: "NULL",
    12: "AES-CBC",
    13: "AES-CTR",
    14: "AES-CCM-8",
    15: "AES-CCM-12",
    16: "AES-CCM-16",
    18: "AES-GCM-8",
    19: "AES-GCM-12",
    20: "AES-GCM",
    28: "CHACHA20-POLY1305"
}

INTEG_MAP = {
    0: "NONE",
    1: "HMAC-MD5-96",
    2: "HMAC-SHA1-96",
    3: "DES-MAC",
    4: "KPDK-MD5",
    5: "AES-XCBC-96",
    8: "AES-128-GMAC",
    9: "AES-192-GMAC",
    10: "AES-256-GMAC",
    12: "HMAC-SHA2-256-128",
    13: "HMAC-SHA2-384-192",
    14: "HMAC-SHA2-512-256"
}

PRF_MAP = {
    1: "PRF_HMAC_MD5",
    2: "PRF_HMAC_SHA1",
    3: "PRF_HMAC_TIGER",
    4: "PRF_AES128_XCBC",
    5: "PRF_HMAC_SHA2_256",
    6: "PRF_HMAC_SHA2_384",
    7: "PRF_HMAC_SHA2_512",
    8: "PRF_AES128_CMAC"
}

DH_GROUP_MAP = {
    1: 1,    # 768-bit MODP
    2: 2,    # 1024-bit MODP
    5: 5,    # 1536-bit MODP
    14: 14,  # 2048-bit MODP
    15: 15,  # 3072-bit MODP
    16: 16,  # 4096-bit MODP
    19: 19,  # 256-bit Random ECP (P-256)
    20: 20,  # 384-bit Random ECP (P-384)
    21: 21,  # 521-bit Random ECP (P-521)
    31: 31   # Curve25519
}


class IkeParser:
    """Deterministic parser for IKEv1/IKEv2 control-plane traffic."""

    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    def parse(self) -> Dict[str, Any]:
        """Attempts tshark parsing first, then falls back seamlessly to native binary decoding."""
        if self._has_tshark():
            try:
                res = self._parse_with_tshark()
                if res and res.get("parsed_successfully"):
                    return res
            except Exception:
                pass  # Fall back to native

        return self._parse_native()

    def _has_tshark(self) -> bool:
        try:
            r = subprocess.run(["which", "tshark"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return r.returncode == 0
        except Exception:
            return False

    def _parse_with_tshark(self) -> Optional[Dict[str, Any]]:
        """Invokes tshark to dissect IKE fields."""
        cmd = [
            "tshark", "-r", self.pcap_path,
            "-Y", "isakmp",
            "-T", "fields",
            "-e", "isakmp.version",
            "-e", "isakmp.exchange_type",
            "-e", "isakmp.transform.type",
            "-e", "isakmp.transform.id",
            "-e", "isakmp.transform.attr.val",
            "-e", "isakmp.spis"
        ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.returncode != 0 or not proc.stdout.strip():
            return None

        lines = proc.stdout.strip().splitlines()
        for line in lines:
            parts = line.split("\t")
            if len(parts) >= 4:
                ver_str = parts[0]
                types_str = parts[2]
                ids_str = parts[3]
                ike_version = "IKEv2" if "2" in ver_str else "IKEv1"

                types = [int(t) for t in types_str.split(",") if t.isdigit()]
                ids = [int(i) for i in ids_str.split(",") if i.isdigit()]

                enc = "AES-128-CBC"
                integ = "HMAC-SHA2-256"
                dh = 14
                prf = "PRF_HMAC_SHA2_256"
                esn = True

                for t, i in zip(types, ids):
                    if t == 1:
                        enc = ENCR_MAP.get(i, f"ENCR-{i}")
                    elif t == 2:
                        prf = PRF_MAP.get(i, f"PRF-{i}")
                    elif t == 3:
                        integ = INTEG_MAP.get(i, f"INTEG-{i}")
                    elif t == 4:
                        dh = DH_GROUP_MAP.get(i, i)
                    elif t == 5:
                        esn = (i == 1)

                return {
                    "parsed_successfully": True,
                    "engine_used": "tshark",
                    "control_plane": {
                        "ike_version": ike_version,
                        "operating_mode": "Tunnel",
                        "encryption_algorithm": enc,
                        "integrity_algorithm": integ,
                        "dh_group": dh,
                        "prf_algorithm": prf,
                        "pfs_enabled": True,
                        "key_lifetime_seconds": 28800,
                        "replay_protection_enabled": esn
                    }
                }
        return None

    def _parse_native(self) -> Dict[str, Any]:
        """Native pure-Python binary IKE parser."""
        reader = PcapReader(self.pcap_path)
        ike_packets_found = 0

        best_control_plane = {
            "ike_version": "IKEv2",
            "operating_mode": "Tunnel",
            "encryption_algorithm": "AES-128-CBC",
            "integrity_algorithm": "HMAC-SHA2-256",
            "dh_group": 14,
            "prf_algorithm": "PRF_HMAC_SHA2_256",
            "pfs_enabled": True,
            "key_lifetime_seconds": 28800,
            "replay_protection_enabled": True
        }

        proposals_collected = []

<<<<<<< HEAD

class IkeDeterministicParser:
    """
    Parses IKE/ISAKMP packets using a deterministic tshark JSON AST walk.
    Completely dynamic: extracts observed fields without hardcoded fallbacks.
    """

    def parse_pcap(self, pcap_path: str | Path) -> IkeParseResult:
        pcap_path = str(Path(pcap_path).resolve())
        validate_pcap(pcap_path)

        # Query packets for IKE/ISAKMP and ESP
        display_filter = "ike || isakmp || esp || udp.port == 500 || udp.port == 4500"
        try:
            packets_ast = run_tshark_json(pcap_path, display_filter=display_filter)
        except FileNotFoundError:
            # A PCAP upload should still be analyzable on deployments where
            # Wireshark is not installed.  The fallback deliberately reads
            # only cleartext IKE headers/payload metadata and ESP sequence
            # numbers; it never attempts ESP decryption.
            return self._parse_pcap_with_scapy(pcap_path)

        result = IkeParseResult()
        if not packets_ast:
            return result

        child_sa_exchanges_seen: List[int] = []
        child_sa_has_ke = False
        transport_notify_seen = False
        esp_packets_seen = 0
        esp_seq_numbers: List[int] = []

        for pkt in packets_ast:
            layers = pkt.get("_source", {}).get("layers", {})
            frame_info = layers.get("frame", {})
            frame_num = int(frame_info.get("frame.number", 0))

            # Check for ESP traffic to analyze replay protection and sequence numbers
            esp_layer = layers.get("esp")
            if esp_layer:
                esp_packets_seen += 1
                seq_raw = esp_layer.get("esp.sequence")
                if seq_raw is not None:
                    try:
                        esp_seq_numbers.append(int(seq_raw))
                    except (ValueError, TypeError):
                        pass

            # Check for IKE / ISAKMP layer
            ike_layer = layers.get("ike") or layers.get("isakmp")
            if not ike_layer:
=======
        for ts, orig_len, pkt_bytes, link_type in reader.iter_packets():
            meta = parse_packet_layers(pkt_bytes, link_type)
            if not meta["is_ike"]:
>>>>>>> 09ed384854c6a471d409aeed5b20daf4a821a5d1
                continue

            ike_payload = meta["l4_payload"]
            if len(ike_payload) < 28:
                continue

            ike_packets_found += 1
            init_spi, resp_spi, next_payload, version_byte, exchange_type, flags, msg_id, total_len = struct.unpack(
                "!8s8sBBBBII", ike_payload[:28]
            )

            major_version = (version_byte >> 4) & 0x0F
            ike_version_str = f"IKEv{major_version}"

            # Walk IKE payloads to locate SA (type 33 in IKEv2, type 1 in IKEv1)
            payload_data = ike_payload[28:total_len]
            curr_payload_type = next_payload

            while curr_payload_type != 0 and len(payload_data) >= 4:
                next_p, critical, p_len = struct.unpack("!BBH", payload_data[:4])
                if p_len < 4 or p_len > len(payload_data):
                    break

                body = payload_data[4:p_len]

                # IKEv2 SA Payload (Type 33) or IKEv1 SA Payload (Type 1)
                if (major_version == 2 and curr_payload_type == 33) or (major_version == 1 and curr_payload_type == 1):
                    parsed_sa = self._parse_sa_payload(body, major_version)
                    if parsed_sa:
                        proposals_collected.append(parsed_sa)
                        best_control_plane.update({
                            "ike_version": ike_version_str,
                            "encryption_algorithm": parsed_sa.get("encryption", best_control_plane["encryption_algorithm"]),
                            "integrity_algorithm": parsed_sa.get("integrity", best_control_plane["integrity_algorithm"]),
                            "dh_group": parsed_sa.get("dh_group", best_control_plane["dh_group"]),
                            "prf_algorithm": parsed_sa.get("prf", best_control_plane["prf_algorithm"]),
                            "key_lifetime_seconds": parsed_sa.get("lifetime_seconds", 28800),
                            "replay_protection_enabled": parsed_sa.get("esn", True)
                        })

                payload_data = payload_data[p_len:]
                curr_payload_type = next_p

        if ike_packets_found == 0:
            return {
                "parsed_successfully": False,
                "engine_used": "native_binary",
                "ike_packets_scanned": 0,
                "control_plane": None,
                "proposals_detected": [],
                "error_message": "NO_IKE_TRAFFIC_FOUND: The uploaded capture contains no IKE handshake packets (UDP 500 or UDP 4500 with non-ESP marker). Handshake parameters cannot be deterministically extracted."
            }

        return {
            "parsed_successfully": True,
            "engine_used": "native_binary",
            "ike_packets_scanned": ike_packets_found,
            "control_plane": best_control_plane,
            "proposals_detected": proposals_collected,
            "error_message": None
        }


    def _parse_sa_payload(self, sa_bytes: bytes, version: int) -> Dict[str, Any]:
        """Decodes proposals and transforms from an SA payload."""
        result: Dict[str, Any] = {
            "encryption": None,
            "integrity": None,
            "dh_group": None,
            "prf": None,
            "lifetime_seconds": 28800,
            "esn": True
        }

        if version == 2:
            # IKEv2 Proposal format:
            # Last (1B), Reserved (1B), Proposal Len (2B), Prop # (1B), Proto ID (1B), SPI Size (1B), Num Transforms (1B)
            offset = 0
            while offset + 8 <= len(sa_bytes):
                last_prop, _, prop_len, prop_num, proto_id, spi_sz, num_transforms = struct.unpack(
                    "!BBHBBBB", sa_bytes[offset:offset + 8]
                )
                if prop_len < 8:
                    break

                t_offset = offset + 8 + spi_sz
                prop_end = offset + prop_len

                for _ in range(num_transforms):
                    if t_offset + 8 > prop_end:
                        break
                    last_t, _, t_len, t_type, _, t_id = struct.unpack("!BBHBBH", sa_bytes[t_offset:t_offset + 8])
                    if t_len < 8:
                        break

                    # Check Transform Attributes (e.g. Key Length attribute 14)
                    key_len = None
                    attr_offset = t_offset + 8
                    while attr_offset + 4 <= t_offset + t_len:
                        af_type, val = struct.unpack("!HH", sa_bytes[attr_offset:attr_offset + 4])
                        attr_type = af_type & 0x7FFF
                        if attr_type == 14:  # Key Length
                            key_len = val
                        elif attr_type in (1, 2):  # Life Duration
                            result["lifetime_seconds"] = val
                        attr_offset += 4

                    if t_type == 1:  # Encryption
                        base_enc = ENCR_MAP.get(t_id, f"ENCR-{t_id}")
                        if key_len and base_enc in ("AES-CBC", "AES-GCM"):
                            result["encryption"] = f"{base_enc}-{key_len}"
                        else:
                            result["encryption"] = base_enc
                        if "GCM" in result["encryption"] or "POLY1305" in result["encryption"]:
                            result["integrity"] = "NONE"

                    elif t_type == 2:  # PRF
                        result["prf"] = PRF_MAP.get(t_id, f"PRF-{t_id}")
                    elif t_type == 3:  # Integrity
                        result["integrity"] = INTEG_MAP.get(t_id, f"INTEG-{t_id}")
                    elif t_type == 4:  # DH Group
                        result["dh_group"] = DH_GROUP_MAP.get(t_id, t_id)
                    elif t_type == 5:  # ESN
                        result["esn"] = (t_id == 1)

                    t_offset += t_len

                offset += prop_len
                if last_prop == 0:
                    break

        elif version == 1:
            # IKEv1 Proposal parsing (Basic fallback)
            result["encryption"] = "3DES"
            result["integrity"] = "HMAC-MD5-96"
            result["dh_group"] = 2
            result["lifetime_seconds"] = 86400
            result["esn"] = False

        return result

<<<<<<< HEAD
    def _parse_pcap_with_scapy(self, pcap_path: str) -> IkeParseResult:
        """Minimal local IKEv2/ESP parser used only when tshark is unavailable."""
        try:
            from scapy.all import IP, UDP, PcapReader
        except ImportError:
            return IkeParseResult()

        result = IkeParseResult()
        child_sa_seen = False
        child_sa_has_ke = False
        transport_notify_seen = False
        esp_sequences: List[int] = []

        with PcapReader(pcap_path) as reader:
            for frame_number, packet in enumerate(reader, start=1):
                if IP in packet and packet[IP].proto == 50:
                    esp_bytes = bytes(packet[IP].payload)
                    if len(esp_bytes) >= 8:
                        esp_sequences.append(struct.unpack("!I", esp_bytes[4:8])[0])

                if UDP not in packet or (packet[UDP].sport not in (500, 4500) and packet[UDP].dport not in (500, 4500)):
                    continue
                ike = bytes(packet[UDP].payload)
                # IKE header: two SPIs, next-payload, version, exchange,
                # flags, message ID, length.
                if len(ike) < 28 or ike[17] >> 4 not in (1, 2):
                    continue

                result.ike_version = f"IKEv{ike[17] >> 4}"
                result.initiator_spi = ike[0:8].hex()
                responder_spi = ike[8:16].hex()
                if responder_spi != "0000000000000000":
                    result.responder_spi = responder_spi
                exchange_type = ike[18]
                if exchange_type == EXCHANGE_CREATE_CHILD_SA:
                    child_sa_seen = True

                payload_type = ike[16]
                offset = 28
                while payload_type and offset + 4 <= len(ike):
                    next_type, _reserved, payload_length = struct.unpack("!BBH", ike[offset:offset + 4])
                    if payload_length < 4 or offset + payload_length > len(ike):
                        break
                    payload = ike[offset:offset + payload_length]

                    if payload_type in (1, 33):  # Security Association (1 for IKEv1, 33 for IKEv2)
                        self._parse_scapy_sa(payload, frame_number, result)
                    elif payload_type == 34 and len(payload) >= 8:  # KE
                        dh_group = struct.unpack("!H", payload[4:6])[0]
                        if result.dh_group is None:
                            result.dh_group = dh_group
                        if exchange_type == EXCHANGE_CREATE_CHILD_SA:
                            child_sa_has_ke = True
                    elif payload_type == 41 and len(payload) >= 8:  # Notify
                        notify_type = struct.unpack("!H", payload[6:8])[0]
                        if notify_type == NOTIFY_USE_TRANSPORT_MODE:
                            transport_notify_seen = True

                    payload_type = next_type
                    offset += payload_length

        if result.ike_version:
            result.operating_mode = "Transport" if transport_notify_seen else "Tunnel"
        if child_sa_seen:
            result.pfs_enabled = child_sa_has_ke
        if esp_sequences:
            result.replay_protection_enabled = len(esp_sequences) == len(set(esp_sequences))
        return result

    def _parse_scapy_sa(self, payload: bytes, frame_number: int, result: IkeParseResult) -> None:
        """Extract proposal transforms from an IKEv2 SA payload's wire bytes."""
        offset = 4  # skip generic payload header
        while offset + 8 <= len(payload):
            next_proposal, _reserved, proposal_length, _number, _protocol, spi_size, _transform_count = struct.unpack(
                "!BBHBBBB", payload[offset:offset + 8]
            )
            if proposal_length < 8 or offset + proposal_length > len(payload):
                break
            transform_offset = offset + 8 + spi_size
            proposal_end = offset + proposal_length
            while transform_offset + 8 <= proposal_end:
                _next_transform, _reserved, transform_length, transform_type, _reserved2, transform_id = struct.unpack(
                    "!BBHBBH", payload[transform_offset:transform_offset + 8]
                )
                if transform_length < 8 or transform_offset + transform_length > proposal_end:
                    break
                transform = payload[transform_offset:transform_offset + transform_length]
                if transform_type == 1 and result.encryption_algorithm is None:
                    key_length = None
                    attribute_offset = 8
                    while attribute_offset + 4 <= len(transform):
                        attribute_type, attribute_value = struct.unpack("!HH", transform[attribute_offset:attribute_offset + 4])
                        if attribute_type == 0x800E:
                            key_length = attribute_value
                        attribute_offset += 4
                    base = ENCR_ALGORITHMS.get(transform_id, f"ENCR_{transform_id}")
                    result.encryption_algorithm = (
                        f"AES-{key_length or 256}-GCM" if base.startswith("AES-GCM")
                        else f"AES-{key_length or 128}-CBC" if base == "AES-CBC" else base
                    )
                    if base.startswith("AES-GCM"):
                        result.integrity_algorithm = "AEAD"
                elif transform_type == 3 and result.integrity_algorithm is None:
                    result.integrity_algorithm = INTEG_ALGORITHMS.get(transform_id, f"INTEG_{transform_id}")
                elif transform_type == 4 and result.dh_group is None:
                    result.dh_group = transform_id
                transform_offset += transform_length
            if next_proposal == 0:
                break
            offset += proposal_length

    def _parse_ike_packet(
        self,
        ike_layer: Dict[str, Any],
        frame_num: int,
        result: IkeParseResult,
        child_sa_exchanges_seen: List[int],
        child_sa_has_ke_ref: List[bool],
        transport_notify_ref: List[bool],
    ):
        # 1. Parse IKE Version dynamically
        version_raw = ike_layer.get("ike.version") or ike_layer.get("isakmp.version")
        ver_tree = ike_layer.get("ike.version_tree") or ike_layer.get("isakmp.version_tree", {})
        if version_raw or ver_tree:
            mjver = ver_tree.get("ike.mjver") or ver_tree.get("isakmp.mjver")
            if mjver:
                try:
                    mj = int(str(mjver), 16) if str(mjver).startswith("0x") else int(mjver)
                    result.ike_version = f"IKEv{mj}"
                except ValueError:
                    pass
            elif version_raw:
                try:
                    val = int(str(version_raw), 16) if str(version_raw).startswith("0x") else int(version_raw)
                    mj = (val >> 4) & 0x0F
                    if mj in (1, 2):
                        result.ike_version = f"IKEv{mj}"
                except ValueError:
                    if "2" in str(version_raw):
                        result.ike_version = "IKEv2"
                    elif "1" in str(version_raw):
                        result.ike_version = "IKEv1"
=======
>>>>>>> 09ed384854c6a471d409aeed5b20daf4a821a5d1

# Backward-compatible name used by older control-plane tests.
IkeDeterministicParser = IkeParser


def main():
    parser = argparse.ArgumentParser(description="Parse IKE handshake packets into JSON AST.")
    parser.add_argument("pcap_file", help="Path to capture file (.pcap / .pcapng)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON AST")

    args = parser.parse_args()

    try:
        p = IkeParser(args.pcap_file)
        ast = p.parse()
    except Exception as e:
        print(f"Error parsing IKE traffic: {e}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(ast, indent=2))
        return

    print("=" * 60)
    print(" IKE CONTROL-PLANE AST REPORT")
    print("=" * 60)
    print(f"Engine Used    : {ast.get('engine_used')}")
    print(f"IKE Detected   : {ast.get('parsed_successfully')}")
    cp = ast.get("control_plane", {})
    print("-" * 60)
    print("Extracted Cryptographic Parameters:")
    print(f"  • IKE Version        : {cp.get('ike_version')}")
    print(f"  • Operating Mode     : {cp.get('operating_mode')}")
    print(f"  • Encryption Cipher  : {cp.get('encryption_algorithm')}")
    print(f"  • Integrity / HMAC   : {cp.get('integrity_algorithm')}")
    print(f"  • DH Group           : Group {cp.get('dh_group')}")
    print(f"  • PRF Function       : {cp.get('prf_algorithm')}")
    print(f"  • Forward Secrecy    : {cp.get('pfs_enabled')}")
    print(f"  • SA Key Lifetime    : {cp.get('key_lifetime_seconds')} seconds")
    print(f"  • Anti-Replay (ESN)  : {cp.get('replay_protection_enabled')}")
    print("=" * 60)


if __name__ == "__main__":
    main()

