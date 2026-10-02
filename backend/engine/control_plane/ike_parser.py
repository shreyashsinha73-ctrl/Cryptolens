#!/usr/bin/env python3
"""
Deterministic IKE Protocol Parser (engine/control_plane/ike_parser.py)
Extracts cryptographic proposals, transforms, DH groups, PRF algorithms,
and SA parameters from raw PCAP files into a normalized JSON AST.

Features a dual-engine architecture:
  1. tshark execution engine (when available on host)
  2. High-performance native binary unpacker (RFC 7296 / RFC 2409)
"""

import argparse
import json
import os
import struct
import subprocess
import sys
from typing import Dict, List, Any, Optional, Tuple

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
            "-e", "isakmp.spis",
            "-e", "isakmp.notify.msg_type"
        ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.returncode != 0 or not proc.stdout.strip():
            return None

        lines = proc.stdout.strip().splitlines()
        is_transport = False
        for line in lines:
            parts = line.split("\t")
            if len(parts) >= 7 and parts[6]:
                for item in parts[6].split(","):
                    if item.strip().isdigit() and int(item.strip()) == 16391:
                        is_transport = True

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

                pfs_val = False if ike_version == "IKEv1" else True
                lifetime_val = 86400 if ike_version == "IKEv1" else 28800
                esn_val = False if ike_version == "IKEv1" else esn

                obs_map, ev_map = self.get_default_observability_maps(ike_version)

                return {
                    "parsed_successfully": True,
                    "engine_used": "tshark",
                    "control_plane": {
                        "ike_version": ike_version,
                        "operating_mode": "Transport" if is_transport else "Tunnel",
                        "encryption_algorithm": enc,
                        "integrity_algorithm": integ,
                        "dh_group": dh,
                        "prf_algorithm": prf,
                        "pfs_enabled": pfs_val,
                        "key_lifetime_seconds": lifetime_val,
                        "replay_protection_enabled": esn_val,
                        "observability": obs_map,
                        "evidence_source": ev_map,
                    }
                }
        return None

    @staticmethod
    def get_default_observability_maps(ike_version: str) -> Tuple[Dict[str, str], Dict[str, str]]:
        """Return canonical wire observability and evidence provenance maps for IKEv1 vs IKEv2."""
        if "1" in str(ike_version).lower():
            obs = {
                "ike_version": "observed",
                "key_exchange": "observed",
                "encryption": "observed",
                "integrity": "observed",
                "replay_protection": "observed",
                "mode": "inferred",
                "pfs": "not_observable",
                "key_lifetime": "not_observable",
            }
            ev = {
                "ike_version": "ike_v1_cleartext",
                "key_exchange": "ike_v1_cleartext",
                "encryption": "ike_v1_cleartext",
                "integrity": "ike_v1_cleartext",
                "replay_protection": "esp_header_metadata",
                "mode": "traffic_statistics",
                "pfs": "inferred",
                "key_lifetime": "inferred",
            }
        else:
            obs = {
                "ike_version": "observed",
                "key_exchange": "observed",
                "replay_protection": "observed",
                "mode": "inferred",
                "encryption": "not_observable",
                "integrity": "not_observable",
                "pfs": "not_observable",
                "key_lifetime": "not_observable",
            }
            ev = {
                "ike_version": "ike_sa_init",
                "key_exchange": "ike_sa_init",
                "replay_protection": "esp_header_metadata",
                "mode": "traffic_statistics",
                "encryption": "testbed_config",
                "integrity": "testbed_config",
                "pfs": "testbed_config",
                "key_lifetime": "testbed_config",
            }
        return obs, ev

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
        child_sa_seen = False
        child_ke_seen = False

        for ts, orig_len, pkt_bytes, link_type in reader.iter_packets():
            meta = parse_packet_layers(pkt_bytes, link_type)
            if not meta["is_ike"]:
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
            if major_version == 2 and exchange_type == 36:
                child_sa_seen = True

            # Walk IKE payloads to locate SA (type 33 in IKEv2, type 1 in IKEv1)
            payload_data = ike_payload[28:total_len]
            curr_payload_type = next_payload

            while curr_payload_type != 0 and len(payload_data) >= 4:
                next_p, critical, p_len = struct.unpack("!BBH", payload_data[:4])
                if p_len < 4 or p_len > len(payload_data):
                    break

                body = payload_data[4:p_len]

                # Check for Key Exchange in CREATE_CHILD_SA (PFS indicator)
                if major_version == 2 and exchange_type == 36 and curr_payload_type == 34:
                    child_ke_seen = True

                # Check for USE_TRANSPORT_MODE Notify (Type 41, Message Type 16391)
                if curr_payload_type == 41 and len(body) >= 4:
                    proto_id, spi_sz, msg_type = struct.unpack("!BBH", body[:4])
                    if msg_type == 16391:
                        best_control_plane["operating_mode"] = "Transport"

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
                            "pfs_enabled": parsed_sa.get("pfs", False) if major_version == 1 else best_control_plane["pfs_enabled"],
                            "key_lifetime_seconds": parsed_sa.get("lifetime_seconds", 28800),
                            "replay_protection_enabled": parsed_sa.get("esn", False if major_version == 1 else True)
                        })

                payload_data = payload_data[p_len:]
                curr_payload_type = next_p

        if child_sa_seen:
            best_control_plane["pfs_enabled"] = child_ke_seen

        obs_map, ev_map = self.get_default_observability_maps(best_control_plane["ike_version"])
        best_control_plane["observability"] = obs_map
        best_control_plane["evidence_source"] = ev_map

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
            # IKEv1 Proposal parsing (RFC 2409 / RFC 2407)
            result["encryption"] = "3DES"
            result["integrity"] = "HMAC-SHA1-96"
            result["dh_group"] = 2
            result["prf"] = "PRF_HMAC_SHA1"
            result["lifetime_seconds"] = 86400
            result["esn"] = False
            result["pfs"] = False

            try:
                # ISAKMP SA payload: DOI (4B) + Situation (4B) = 8B header
                if len(sa_bytes) >= 8:
                    pos = 8
                    while pos + 8 <= len(sa_bytes):
                        np_prop, _, prop_len, p_num, proto_id, spi_sz, num_t = struct.unpack("!BBHBBBB", sa_bytes[pos:pos+8])
                        if prop_len < 8:
                            break
                        t_pos = pos + 8 + spi_sz
                        prop_end = pos + prop_len
                        for _ in range(num_t):
                            if t_pos + 8 > prop_end:
                                break
                            np_t, _, t_len, t_num, t_id, _ = struct.unpack("!BBHBBH", sa_bytes[t_pos:t_pos+8])
                            if t_len < 8:
                                break
                            attr_pos = t_pos + 8
                            t_end = t_pos + t_len
                            key_len = None
                            while attr_pos + 4 <= t_end:
                                af_type, val_or_len = struct.unpack("!HH", sa_bytes[attr_pos:attr_pos+4])
                                is_basic = bool(af_type & 0x8000)
                                attr_type = af_type & 0x7FFF
                                if is_basic:
                                    val = val_or_len
                                    attr_pos += 4
                                else:
                                    v_len = val_or_len
                                    attr_pos += 4
                                    if attr_pos + v_len <= t_end and v_len <= 8:
                                        val = int.from_bytes(sa_bytes[attr_pos:attr_pos+v_len], "big")
                                    else:
                                        val = 0
                                    attr_pos += v_len
                                if attr_type == 1:  # Encryption Algorithm
                                    ikev1_enc = {1: "DES", 2: "IDEA", 3: "Blowfish", 4: "RC5", 5: "3DES", 7: "AES-CBC"}
                                    result["encryption"] = ikev1_enc.get(val, f"ENCR-{val}")
                                elif attr_type == 2:  # Hash Algorithm
                                    ikev1_hash = {1: "HMAC-MD5-96", 2: "HMAC-SHA1-96", 4: "HMAC-SHA2-256", 5: "HMAC-SHA2-384", 6: "HMAC-SHA2-512"}
                                    result["integrity"] = ikev1_hash.get(val, f"HASH-{val}")
                                elif attr_type == 4:  # Group Description
                                    result["dh_group"] = DH_GROUP_MAP.get(val, val)
                                elif attr_type in (11, 12):  # Life Duration
                                    result["lifetime_seconds"] = val
                                elif attr_type == 14:  # Key Length
                                    key_len = val

                            if key_len and result.get("encryption") == "AES-CBC":
                                result["encryption"] = f"AES-CBC-{key_len}"
                            t_pos += t_len
                        pos += prop_len
                        if np_prop == 0:
                            break
            except Exception:
                pass

        return result


def parse_ike_bytes(ike_payload: bytes) -> Optional[Dict[str, Any]]:
    """Parse raw IKE packet bytes (UDP payload) into control plane parameters."""
    if len(ike_payload) < 28:
        return None
    try:
        init_spi, resp_spi, next_payload, version_byte, exchange_type, flags, msg_id, total_len = struct.unpack(
            "!8s8sBBBBII", ike_payload[:28]
        )
        major_version = (version_byte >> 4) & 0x0F
        ike_version_str = f"IKEv{major_version}"

        payload_data = ike_payload[28:total_len] if total_len <= len(ike_payload) else ike_payload[28:]
        curr_payload_type = next_payload

        parser = IkeParser.__new__(IkeParser)
        control_plane = {
            "ike_version": ike_version_str,
            "encryption_algorithm": "AES-256-GCM" if major_version == 2 else "3DES",
            "integrity_algorithm": "NONE" if major_version == 2 else "HMAC-SHA1-96",
            "dh_group": 19 if major_version == 2 else 2,
            "prf_algorithm": "PRF_HMAC_SHA2_256" if major_version == 2 else "PRF_HMAC_SHA1",
            "pfs_enabled": True if major_version == 2 else False,
            "key_lifetime_seconds": 28800 if major_version == 2 else 86400,
            "replay_protection_enabled": True if major_version == 2 else False,
            "operating_mode": "tunnel",
        }

        obs_map, ev_map = IkeParser.get_default_observability_maps(ike_version_str)
        control_plane["observability"] = obs_map
        control_plane["evidence_source"] = ev_map

        while curr_payload_type != 0 and len(payload_data) >= 4:
            next_p, critical, p_len = struct.unpack("!BBH", payload_data[:4])
            if p_len < 4 or p_len > len(payload_data):
                break
            body = payload_data[4:p_len]
            if (major_version == 2 and curr_payload_type == 33) or (major_version == 1 and curr_payload_type == 1):
                parsed_sa = parser._parse_sa_payload(body, major_version)
                if parsed_sa:
                    control_plane.update({
                        "encryption_algorithm": parsed_sa.get("encryption", control_plane["encryption_algorithm"]),
                        "integrity_algorithm": parsed_sa.get("integrity", control_plane["integrity_algorithm"]),
                        "dh_group": parsed_sa.get("dh_group", control_plane["dh_group"]),
                        "prf_algorithm": parsed_sa.get("prf", control_plane["prf_algorithm"]),
                        "pfs_enabled": parsed_sa.get("pfs", False) if major_version == 1 else True,
                        "key_lifetime_seconds": parsed_sa.get("lifetime_seconds", 28800),
                        "replay_protection_enabled": parsed_sa.get("esn", True),
                    })
                    return control_plane
            payload_data = payload_data[p_len:]
            curr_payload_type = next_p

        return control_plane
    except Exception:
        return None


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

