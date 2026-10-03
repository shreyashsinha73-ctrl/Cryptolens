"""
Sidecar Consistency Verifier (backend/scoring/sidecar_consistency.py)
Compares operator-supplied sidecar assertions against passively observed wire telemetry.

Checks:
  1. IKE Version and DH Group vs. IKE_SA_INIT cleartext payloads
  2. ESP Length Alignment vs. claimed cipher suite (block size and padding constraints)
  3. Rekey Cadence (distinct SPIs over time) vs. claimed lifetime

Asymmetry Doctrine:
  Passive checks can CONTRADICT an operator claim, but can never conclusively CONFIRM it
  (e.g., a CBC-AES flow can happen to satisfy GCM 4-byte alignment).
  A 'consistent' check result does NOT elevate observability above 'operator_supplied'.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from backend.capture.pcap_utils import PcapReader, parse_packet_layers
from backend.schemas.sidecar import IPsecSidecarConfig


class ConsistencyCheckResult(BaseModel):
    check_name: str
    target_field: str
    status: str = Field(..., description="consistent | contradicts | inconclusive")
    claimed_value: Any
    observed_evidence: Optional[str] = None
    details: str


class SidecarConsistencyReport(BaseModel):
    is_valid: bool
    overall_status: str = Field(..., description="consistent | contradicts | inconclusive")
    contradictions_count: int = 0
    checks: List[ConsistencyCheckResult] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)


def _get_cipher_parameters(encryption: Optional[str], integrity: Optional[str]) -> Tuple[int, int, int]:
    """
    Returns (iv_len, icv_len, block_size) for a given encryption + integrity suite.
    """
    enc = str(encryption or "").upper()
    integ = str(integrity or "").upper()

    # Determine ICV length
    if "GCM" in enc or "POLY1305" in enc or integ == "AEAD":
        icv_len = 16
    elif "SHA2-512" in integ:
        icv_len = 32
    elif "SHA2-384" in integ:
        icv_len = 24
    elif "SHA2-256" in integ or "SHA256" in integ:
        icv_len = 16
    elif "SHA1" in integ or "MD5" in integ or "96" in integ:
        icv_len = 12
    elif integ in ("NONE", ""):
        icv_len = 0
    else:
        icv_len = 16

    # Determine IV length and block size
    if "GCM" in enc:
        iv_len = 8   # 8-byte explicit IV in ESP header
        block_size = 4  # ESP 4-byte padding boundary
    elif "POLY1305" in enc:
        iv_len = 8
        block_size = 4
    elif "3DES" in enc or "DES" in enc:
        iv_len = 8
        block_size = 8  # 64-bit DES block size
    elif "AES" in enc or "CBC" in enc:
        iv_len = 16  # 128-bit AES block size IV
        block_size = 16
    else:
        iv_len = 8
        block_size = 4

    return iv_len, icv_len, block_size


def check_sidecar_consistency(
    pcap_path: str,
    control_plane: Optional[Dict[str, Any]],
    sidecar_config: Optional[Any],
) -> SidecarConsistencyReport:
    """
    Execute deterministic consistency checks comparing sidecar claims against wire facts.
    """
    if not sidecar_config:
        return SidecarConsistencyReport(
            is_valid=True,
            overall_status="inconclusive",
            contradictions_count=0,
            checks=[],
            findings=[],
        )

    if isinstance(sidecar_config, dict):
        try:
            sidecar = IPsecSidecarConfig(**sidecar_config)
        except Exception:
            sidecar = IPsecSidecarConfig.model_construct(**sidecar_config)
    else:
        sidecar = sidecar_config

    checks: List[ConsistencyCheckResult] = []
    findings: List[Dict[str, Any]] = []

    # -------------------------------------------------------------------------
    # Check 1: IKE Version & DH Group vs. Observed Handshake
    # -------------------------------------------------------------------------
    cp = control_plane or {}
    obs_ike = None
    obs_dh = None
    if pcap_path and os.path.exists(pcap_path):
        try:
            from backend.engine.control_plane.ike_parser import IkeParser
            wire_res = IkeParser(pcap_path).parse()
            wire_cp = wire_res.get("control_plane") or {}
            obs_ike = wire_cp.get("ike_version")
            obs_dh = wire_cp.get("dh_group")
        except Exception:
            pass

    if obs_ike is None:
        obs_ike = cp.get("ike_version")
    if obs_dh is None:
        obs_dh = cp.get("dh_group")

    if sidecar.ike_version and obs_ike:
        norm_sidecar_v = "IKEv2" if "2" in str(sidecar.ike_version) else "IKEv1"
        norm_obs_v = "IKEv2" if "2" in str(obs_ike) else "IKEv1"
        if norm_sidecar_v != norm_obs_v:
            checks.append(ConsistencyCheckResult(
                check_name="IKE Version Consistency",
                target_field="ike_version",
                status="contradicts",
                claimed_value=sidecar.ike_version,
                observed_evidence=obs_ike,
                details=f"Sidecar asserted {sidecar.ike_version}, but wire ISAKMP header observed {obs_ike}.",
            ))
            findings.append({
                "severity": "HIGH",
                "finding_id": "CONTRADICTED_IKE_VERSION",
                "category": "Operator Sidecar Consistency",
                "title": f"Sidecar Contradiction: IKE Version ({sidecar.ike_version} vs. {obs_ike})",
                "description": f"Operator asserted {sidecar.ike_version} in sidecar, but wire header shows {obs_ike}.",
                "evidence_source": "ike_sa_init",
                "observability": "contradicted",
            })
        else:
            checks.append(ConsistencyCheckResult(
                check_name="IKE Version Consistency",
                target_field="ike_version",
                status="consistent",
                claimed_value=sidecar.ike_version,
                observed_evidence=obs_ike,
                details=f"Claimed IKE version {sidecar.ike_version} matches observed wire handshake.",
            ))

    if sidecar.dh_group is not None and obs_dh is not None:
        if str(sidecar.dh_group) != str(obs_dh):
            checks.append(ConsistencyCheckResult(
                check_name="DH Group Consistency",
                target_field="dh_group",
                status="contradicts",
                claimed_value=sidecar.dh_group,
                observed_evidence=f"Group {obs_dh}",
                details=f"Sidecar claimed DH Group {sidecar.dh_group}, but cleartext IKE_SA_INIT negotiated Group {obs_dh}.",
            ))
            findings.append({
                "severity": "HIGH",
                "finding_id": "CONTRADICTED_DH_GROUP",
                "category": "Operator Sidecar Consistency",
                "title": f"Sidecar Contradiction: DH Group ({sidecar.dh_group} vs. Group {obs_dh})",
                "description": f"Operator asserted DH Group {sidecar.dh_group}, but cleartext handshake established Group {obs_dh}.",
                "evidence_source": "ike_sa_init",
                "observability": "contradicted",
            })
        else:
            checks.append(ConsistencyCheckResult(
                check_name="DH Group Consistency",
                target_field="dh_group",
                status="consistent",
                claimed_value=sidecar.dh_group,
                observed_evidence=f"Group {obs_dh}",
                details=f"Claimed DH Group {sidecar.dh_group} matches cleartext IKE_SA_INIT proposal.",
            ))

    # -------------------------------------------------------------------------
    # Check 2: ESP Payload Length Alignment vs. Claimed Cipher Suite
    # -------------------------------------------------------------------------
    if sidecar.encryption_algorithm and os.path.exists(pcap_path):
        iv_len, icv_len, block_size = _get_cipher_parameters(
            sidecar.encryption_algorithm,
            sidecar.integrity_algorithm
        )

        esp_packets_tested = 0
        alignment_violations = 0
        reader = PcapReader(pcap_path)

        for ts, orig_len, pkt_bytes, link_type in reader.iter_packets():
            meta = parse_packet_layers(pkt_bytes, link_type)
            if not meta.get("is_esp"):
                continue

            ip_len = meta.get("ip_len")
            ip_hdr_len = meta.get("ip_hdr_len", 20)
            is_natt = meta.get("is_natt", False)
            udp_len = 8 if is_natt else 0

            if not ip_len or ip_len <= (ip_hdr_len + udp_len + 8 + iv_len + icv_len):
                continue

            esp_packets_tested += 1
            # Inner ciphertext payload length
            ciphertext_len = ip_len - ip_hdr_len - udp_len - 8 - iv_len - icv_len

            if ciphertext_len % block_size != 0:
                alignment_violations += 1

        if esp_packets_tested < 20:
            checks.append(ConsistencyCheckResult(
                check_name="ESP Length Alignment",
                target_field="encryption_algorithm",
                status="inconclusive",
                claimed_value=sidecar.encryption_algorithm,
                observed_evidence=f"{esp_packets_tested} ESP packets",
                details=f"Insufficient ESP packet sample size ({esp_packets_tested} < 20 required) for block alignment verification.",
            ))
        else:
            violation_rate = alignment_violations / float(esp_packets_tested)
            if violation_rate > 0.02:  # > 2% violation tolerance
                checks.append(ConsistencyCheckResult(
                    check_name="ESP Length Alignment",
                    target_field="encryption_algorithm",
                    status="contradicts",
                    claimed_value=sidecar.encryption_algorithm,
                    observed_evidence=f"{alignment_violations}/{esp_packets_tested} misaligned ({violation_rate:.1%})",
                    details=(
                        f"Claimed cipher suite '{sidecar.encryption_algorithm}' requires {block_size}-byte block alignment. "
                        f"{alignment_violations} of {esp_packets_tested} ESP frames ({violation_rate:.1%}) violated block constraints."
                    ),
                ))
                findings.append({
                    "severity": "HIGH",
                    "finding_id": "CONTRADICTED_CIPHER_ALIGNMENT",
                    "category": "Operator Sidecar Consistency",
                    "title": f"Sidecar Contradiction: Cipher Alignment ({sidecar.encryption_algorithm})",
                    "description": (
                        f"Wire ESP frames fail mathematical block alignment for '{sidecar.encryption_algorithm}' "
                        f"({violation_rate:.1%} violations). The capture contains traffic under a different block size or AEAD structure."
                    ),
                    "evidence_source": "esp_header_metadata",
                    "observability": "contradicted",
                })
            else:
                checks.append(ConsistencyCheckResult(
                    check_name="ESP Length Alignment",
                    target_field="encryption_algorithm",
                    status="consistent",
                    claimed_value=sidecar.encryption_algorithm,
                    observed_evidence=f"{esp_packets_tested} ESP packets, 0% misaligned",
                    details=f"ESP packet lengths are mathematically consistent with {block_size}-byte {sidecar.encryption_algorithm} block alignment.",
                ))

    # -------------------------------------------------------------------------
    # Check 3: Rekey Cadence vs. Claimed Lifetime
    # -------------------------------------------------------------------------
    if sidecar.key_lifetime_seconds and os.path.exists(pcap_path):
        reader = PcapReader(pcap_path)
        timestamps = []
        spis = set()
        for ts, orig_len, pkt_bytes, link_type in reader.iter_packets():
            meta = parse_packet_layers(pkt_bytes, link_type)
            if meta.get("is_esp"):
                timestamps.append(ts)
                if meta.get("esp_spi"):
                    spis.add(meta["esp_spi"])

        if timestamps:
            duration = max(timestamps) - min(timestamps)
            if duration >= (2.0 * sidecar.key_lifetime_seconds) and len(spis) <= 1:
                checks.append(ConsistencyCheckResult(
                    check_name="Rekey Cadence",
                    target_field="key_lifetime_seconds",
                    status="contradicts",
                    claimed_value=f"{sidecar.key_lifetime_seconds}s",
                    observed_evidence=f"Duration {duration:.1f}s, SPI count={len(spis)}",
                    details=f"Capture elapsed {duration:.1f}s without SA rekey, violating claimed {sidecar.key_lifetime_seconds}s lifetime.",
                ))
                findings.append({
                    "severity": "HIGH",
                    "finding_id": "CONTRADICTED_REKEY_CADENCE",
                    "category": "Operator Sidecar Consistency",
                    "title": f"Sidecar Contradiction: Rekey Cadence ({sidecar.key_lifetime_seconds}s)",
                    "description": f"Observed single SPI over {duration:.1f}s without rekey, contradicting claimed {sidecar.key_lifetime_seconds}s lifetime.",
                    "evidence_source": "esp_header_metadata",
                    "observability": "contradicted",
                })
            else:
                checks.append(ConsistencyCheckResult(
                    check_name="Rekey Cadence",
                    target_field="key_lifetime_seconds",
                    status="inconclusive",
                    claimed_value=f"{sidecar.key_lifetime_seconds}s",
                    observed_evidence=f"Duration {duration:.1f}s",
                    details=f"Capture duration ({duration:.1f}s) is shorter than evaluation window for {sidecar.key_lifetime_seconds}s lifetime.",
                ))

    contradictions = [c for c in checks if c.status == "contradicts"]
    if contradictions:
        overall = "contradicts"
    elif any(c.status == "consistent" for c in checks):
        overall = "consistent"
    else:
        overall = "inconclusive"

    return SidecarConsistencyReport(
        is_valid=(len(contradictions) == 0),
        overall_status=overall,
        contradictions_count=len(contradictions),
        checks=checks,
        findings=findings,
    )
