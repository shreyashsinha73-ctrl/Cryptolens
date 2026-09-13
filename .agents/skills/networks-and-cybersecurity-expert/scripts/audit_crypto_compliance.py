#!/usr/bin/env python3
"""
Cryptographic Compliance Auditor for IPsec, VPN, and Network Protocols.
Evaluates cryptographic parameters against:
  - NIST SP 800-77 Rev 1 (Guide to IPsec VPNs)
  - NSA CNSA 1.0 & CNSA 2.0 (Commercial National Security Algorithm Suite)
  - NIST SP 800-52 Rev 2 (TLS)

Outputs deterministic risk scores, compliance tiers, itemized findings, and remediations.
"""

import argparse
import json
import sys
from typing import Dict, List, Any, Optional

# --- Reference Standards Database ---

ENCRYPTION_RULES = {
    # AEAD Modes (Approved, recommended)
    "AES-GCM-256": {"nist": "APPROVED", "cnsa1": "APPROVED", "cnsa2": "APPROVED", "risk_penalty": 0, "type": "AEAD"},
    "AES-256-GCM": {"nist": "APPROVED", "cnsa1": "APPROVED", "cnsa2": "APPROVED", "risk_penalty": 0, "type": "AEAD"},
    "AES-GCM-128": {"nist": "APPROVED", "cnsa1": "NON_COMPLIANT", "cnsa2": "NON_COMPLIANT", "risk_penalty": 5, "type": "AEAD"},
    "AES-128-GCM": {"nist": "APPROVED", "cnsa1": "NON_COMPLIANT", "cnsa2": "NON_COMPLIANT", "risk_penalty": 5, "type": "AEAD"},
    "CHACHA20-POLY1305": {"nist": "ACCEPTABLE", "cnsa1": "NON_COMPLIANT", "cnsa2": "NON_COMPLIANT", "risk_penalty": 5, "type": "AEAD"},
    
    # CBC Modes (Approved with separate HMAC, but legacy)
    "AES-CBC-256": {"nist": "APPROVED", "cnsa1": "APPROVED", "cnsa2": "NON_COMPLIANT", "risk_penalty": 10, "type": "CBC"},
    "AES-256-CBC": {"nist": "APPROVED", "cnsa1": "APPROVED", "cnsa2": "NON_COMPLIANT", "risk_penalty": 10, "type": "CBC"},
    "AES-CBC-128": {"nist": "ACCEPTABLE", "cnsa1": "NON_COMPLIANT", "cnsa2": "NON_COMPLIANT", "risk_penalty": 15, "type": "CBC"},
    "AES-128-CBC": {"nist": "ACCEPTABLE", "cnsa1": "NON_COMPLIANT", "cnsa2": "NON_COMPLIANT", "risk_penalty": 15, "type": "CBC"},
    
    # Vulnerable / Prohibited
    "3DES": {"nist": "PROHIBITED", "cnsa1": "PROHIBITED", "cnsa2": "PROHIBITED", "risk_penalty": 50, "type": "LEGACY_VULNERABLE", "vuln": "Sweet32 collision attack on 64-bit block size"},
    "3DES-CBC": {"nist": "PROHIBITED", "cnsa1": "PROHIBITED", "cnsa2": "PROHIBITED", "risk_penalty": 50, "type": "LEGACY_VULNERABLE", "vuln": "Sweet32 collision attack on 64-bit block size"},
    "DES": {"nist": "PROHIBITED", "cnsa1": "PROHIBITED", "cnsa2": "PROHIBITED", "risk_penalty": 60, "type": "BROKEN", "vuln": "56-bit key trivially brute-forced"},
    "RC4": {"nist": "PROHIBITED", "cnsa1": "PROHIBITED", "cnsa2": "PROHIBITED", "risk_penalty": 60, "type": "BROKEN", "vuln": "Severe statistical biases in keystream"},
    "NULL": {"nist": "PROHIBITED", "cnsa1": "PROHIBITED", "cnsa2": "PROHIBITED", "risk_penalty": 80, "type": "NONE", "vuln": "Zero confidentiality"}
}

INTEGRITY_RULES = {
    "HMAC-SHA2-512": {"nist": "APPROVED", "cnsa1": "APPROVED", "cnsa2": "APPROVED", "risk_penalty": 0},
    "SHA512": {"nist": "APPROVED", "cnsa1": "APPROVED", "cnsa2": "APPROVED", "risk_penalty": 0},
    "HMAC-SHA2-384": {"nist": "APPROVED", "cnsa1": "APPROVED", "cnsa2": "APPROVED", "risk_penalty": 0},
    "SHA384": {"nist": "APPROVED", "cnsa1": "APPROVED", "cnsa2": "APPROVED", "risk_penalty": 0},
    "HMAC-SHA2-256": {"nist": "APPROVED", "cnsa1": "ACCEPTABLE", "cnsa2": "NON_COMPLIANT", "risk_penalty": 0},
    "SHA256": {"nist": "APPROVED", "cnsa1": "ACCEPTABLE", "cnsa2": "NON_COMPLIANT", "risk_penalty": 0},
    "NONE": {"nist": "APPROVED_IF_AEAD", "cnsa1": "APPROVED_IF_AEAD", "cnsa2": "APPROVED_IF_AEAD", "risk_penalty": 0},
    
    # Deprecated / Broken
    "HMAC-SHA1": {"nist": "DEPRECATED", "cnsa1": "PROHIBITED", "cnsa2": "PROHIBITED", "risk_penalty": 30, "vuln": "Practical collision attacks demonstrated on SHA-1"},
    "SHA1": {"nist": "DEPRECATED", "cnsa1": "PROHIBITED", "cnsa2": "PROHIBITED", "risk_penalty": 30, "vuln": "Practical collision attacks demonstrated on SHA-1"},
    "HMAC-MD5": {"nist": "PROHIBITED", "cnsa1": "PROHIBITED", "cnsa2": "PROHIBITED", "risk_penalty": 45, "vuln": "MD5 collision resistance is completely broken"},
    "MD5": {"nist": "PROHIBITED", "cnsa1": "PROHIBITED", "cnsa2": "PROHIBITED", "risk_penalty": 45, "vuln": "MD5 collision resistance is completely broken"}
}

DH_GROUP_RULES = {
    # Post-Quantum / CNSA 2.0
    "ML-KEM-1024": {"nist": "APPROVED", "cnsa1": "APPROVED", "cnsa2": "APPROVED", "strength": 256, "risk_penalty": 0, "pqc": True},
    "KYBER-1024": {"nist": "APPROVED", "cnsa1": "APPROVED", "cnsa2": "APPROVED", "strength": 256, "risk_penalty": 0, "pqc": True},
    "20": {"nist": "APPROVED", "cnsa1": "APPROVED", "cnsa2": "TRANSITION_ONLY", "strength": 192, "name": "384-bit ECP (NIST P-384)", "risk_penalty": 0},
    "ECP384": {"nist": "APPROVED", "cnsa1": "APPROVED", "cnsa2": "TRANSITION_ONLY", "strength": 192, "name": "384-bit ECP (NIST P-384)", "risk_penalty": 0},
    "21": {"nist": "APPROVED", "cnsa1": "APPROVED", "cnsa2": "TRANSITION_ONLY", "strength": 256, "name": "521-bit ECP (NIST P-521)", "risk_penalty": 0},
    "19": {"nist": "APPROVED", "cnsa1": "NON_COMPLIANT", "cnsa2": "NON_COMPLIANT", "strength": 128, "name": "256-bit ECP (NIST P-256)", "risk_penalty": 5},
    "ECP256": {"nist": "APPROVED", "cnsa1": "NON_COMPLIANT", "cnsa2": "NON_COMPLIANT", "strength": 128, "name": "256-bit ECP (NIST P-256)", "risk_penalty": 5},
    "31": {"nist": "APPROVED", "cnsa1": "NON_COMPLIANT", "cnsa2": "NON_COMPLIANT", "strength": 128, "name": "Curve25519 (RFC 8031)", "risk_penalty": 5},
    "16": {"nist": "APPROVED", "cnsa1": "NON_COMPLIANT", "cnsa2": "NON_COMPLIANT", "strength": 128, "name": "4096-bit MODP", "risk_penalty": 5},
    "15": {"nist": "APPROVED", "cnsa1": "NON_COMPLIANT", "cnsa2": "NON_COMPLIANT", "strength": 128, "name": "3072-bit MODP", "risk_penalty": 5},
    "14": {"nist": "APPROVED", "cnsa1": "NON_COMPLIANT", "cnsa2": "NON_COMPLIANT", "strength": 112, "name": "2048-bit MODP (Minimum NIST acceptable)", "risk_penalty": 10},
    "MODP2048": {"nist": "APPROVED", "cnsa1": "NON_COMPLIANT", "cnsa2": "NON_COMPLIANT", "strength": 112, "name": "2048-bit MODP (Minimum NIST acceptable)", "risk_penalty": 10},
    
    # Broken / Prohibited MODP Groups
    "5": {"nist": "PROHIBITED", "cnsa1": "PROHIBITED", "cnsa2": "PROHIBITED", "strength": 80, "name": "1536-bit MODP", "risk_penalty": 35, "vuln": "Sub-112-bit security; vulnerable to Logjam precomputation"},
    "2": {"nist": "PROHIBITED", "cnsa1": "PROHIBITED", "cnsa2": "PROHIBITED", "strength": 80, "name": "1024-bit MODP", "risk_penalty": 40, "vuln": "Vulnerable to Logjam discrete logarithm precomputation"},
    "MODP1024": {"nist": "PROHIBITED", "cnsa1": "PROHIBITED", "cnsa2": "PROHIBITED", "strength": 80, "name": "1024-bit MODP", "risk_penalty": 40, "vuln": "Vulnerable to Logjam discrete logarithm precomputation"},
    "1": {"nist": "PROHIBITED", "cnsa1": "PROHIBITED", "cnsa2": "PROHIBITED", "strength": 64, "name": "768-bit MODP", "risk_penalty": 50, "vuln": "Trivially broken with modern compute"}
}


def normalize_token(token: Optional[str]) -> str:
    if not token:
        return "NONE"
    return token.strip().upper().replace("_", "-")


def audit_proposal(
    enc: str,
    integrity: Optional[str] = None,
    dh: Optional[str] = None,
    prf: Optional[str] = None,
    pfs: bool = True,
    ike_version: int = 2,
    target_standard: str = "nist"
) -> Dict[str, Any]:
    norm_enc = normalize_token(enc)
    norm_int = normalize_token(integrity)
    norm_dh = normalize_token(dh)
    norm_prf = normalize_token(prf)

    findings: List[Dict[str, str]] = []
    remediations: List[str] = []
    penalty_total = 0

    # 1. Evaluate IKE Version
    if ike_version < 2:
        penalty_total += 30
        findings.append({
            "severity": "HIGH",
            "component": "IKE_VERSION",
            "issue": f"IKEv{ike_version} is legacy and deprecated by NIST SP 800-77 Rev 1.",
            "detail": "Aggressive Mode exposes PSK hashes to offline cracking."
        })
        remediations.append("Enforce IKEv2 (RFC 7296) and disable IKEv1 support.")

    # 2. Evaluate Encryption
    enc_info = ENCRYPTION_RULES.get(norm_enc)
    if not enc_info:
        penalty_total += 20
        findings.append({
            "severity": "MEDIUM",
            "component": "ENCRYPTION",
            "issue": f"Unrecognized or unverified encryption algorithm '{enc}'.",
            "detail": "Ensure algorithm conforms to FIPS 140-3 validation."
        })
    else:
        penalty_total += enc_info.get("risk_penalty", 0)
        status = enc_info.get(target_standard, "NON_COMPLIANT")
        if status in ("PROHIBITED", "DEPRECATED"):
            findings.append({
                "severity": "CRITICAL" if status == "PROHIBITED" else "HIGH",
                "component": "ENCRYPTION",
                "issue": f"Encryption algorithm '{norm_enc}' is {status} under {target_standard.upper()}.",
                "detail": enc_info.get("vuln", "Algorithm does not meet security strength criteria.")
            })
            remediations.append("Upgrade encryption algorithm to AES-256-GCM or AES-128-GCM.")
        elif target_standard == "cnsa2" and status != "APPROVED":
            findings.append({
                "severity": "HIGH",
                "component": "ENCRYPTION",
                "issue": f"Encryption '{norm_enc}' does not satisfy CNSA 2.0 requirements.",
                "detail": "CNSA 2.0 strictly requires 256-bit AES."
            })
            remediations.append("Migrate to AES-256-GCM for CNSA 2.0 compliance.")

        # Check AEAD vs CBC integrity requirements
        is_aead = enc_info.get("type") == "AEAD"
        if not is_aead and norm_int in ("NONE", ""):
            penalty_total += 40
            findings.append({
                "severity": "CRITICAL",
                "component": "INTEGRITY",
                "issue": f"CBC mode cipher '{norm_enc}' is running without message integrity (HMAC).",
                "detail": "Unauthenticated CBC mode is vulnerable to bit-flipping and padding oracle attacks."
            })
            remediations.append("Configure HMAC-SHA2-256 or switch to an AEAD cipher (AES-GCM).")

    # 3. Evaluate Integrity / HMAC
    if norm_int and norm_int != "NONE":
        int_info = INTEGRITY_RULES.get(norm_int)
        if not int_info:
            penalty_total += 15
            findings.append({
                "severity": "MEDIUM",
                "component": "INTEGRITY",
                "issue": f"Unrecognized integrity algorithm '{integrity}'.",
                "detail": "Verify algorithm standard conformance."
            })
        else:
            penalty_total += int_info.get("risk_penalty", 0)
            status = int_info.get(target_standard, "NON_COMPLIANT")
            if status in ("PROHIBITED", "DEPRECATED"):
                findings.append({
                    "severity": "HIGH",
                    "component": "INTEGRITY",
                    "issue": f"Integrity algorithm '{norm_int}' is {status}.",
                    "detail": int_info.get("vuln", "Integrity algorithm lacks collision resistance.")
                })
                remediations.append("Replace hash algorithm with HMAC-SHA2-256, HMAC-SHA2-384, or HMAC-SHA2-512.")

    # 4. Evaluate Diffie-Hellman Group
    if norm_dh and norm_dh != "NONE":
        dh_info = DH_GROUP_RULES.get(norm_dh)
        if not dh_info:
            penalty_total += 15
            findings.append({
                "severity": "MEDIUM",
                "component": "KEY_EXCHANGE",
                "issue": f"Unrecognized Diffie-Hellman group '{dh}'.",
                "detail": "Ensure DH group ID complies with RFC 7296."
            })
        else:
            penalty_total += dh_info.get("risk_penalty", 0)
            status = dh_info.get(target_standard, "NON_COMPLIANT")
            if status == "PROHIBITED":
                findings.append({
                    "severity": "CRITICAL",
                    "component": "KEY_EXCHANGE",
                    "issue": f"Diffie-Hellman group {norm_dh} ({dh_info.get('name')}) is PROHIBITED.",
                    "detail": dh_info.get("vuln", "Insufficient bit strength.")
                })
                remediations.append("Upgrade DH group to at least Group 14 (MODP-2048), Group 19 (P-256), or Group 20 (P-384).")
            elif target_standard == "cnsa2" and not dh_info.get("pqc", False) and norm_dh not in ("20", "ECP384"):
                findings.append({
                    "severity": "HIGH",
                    "component": "KEY_EXCHANGE",
                    "issue": f"DH group {norm_dh} is not post-quantum resilient under CNSA 2.0.",
                    "detail": "CNSA 2.0 mandates transition to ML-KEM-1024 (FIPS 203) or transitionary 384-bit curves."
                })
                remediations.append("Plan transition to Post-Quantum Key Encapsulation (ML-KEM-1024 / Kyber).")

    # 5. Perfect Forward Secrecy
    if not pfs:
        penalty_total += 25
        findings.append({
            "severity": "HIGH",
            "component": "PFS",
            "issue": "Perfect Forward Secrecy (PFS) is disabled.",
            "detail": "Compromise of the initial keying material compromises all historical Child SAs."
        })
        remediations.append("Enable PFS on all Child SA rekeys (enforce ephemeral DH exchange).")

    # Calculate final risk score and compliance tier
    risk_score = min(100, penalty_total)
    if risk_score <= 15:
        tier = "EXCELLENT"
        compliance_status = "COMPLIANT"
    elif risk_score <= 35:
        tier = "ACCEPTABLE"
        compliance_status = "LEGACY_ACCEPTABLE"
    elif risk_score <= 65:
        tier = "ELEVATED_RISK"
        compliance_status = "NON_COMPLIANT"
    else:
        tier = "CRITICAL_RISK"
        compliance_status = "SEVERELY_VULNERABLE"

    return {
        "summary": {
            "risk_score": risk_score,
            "risk_tier": tier,
            "compliance_status": compliance_status,
            "target_standard": target_standard.upper(),
            "findings_count": len(findings)
        },
        "parameters_evaluated": {
            "encryption": norm_enc,
            "integrity": norm_int,
            "dh_group": norm_dh,
            "prf": norm_prf,
            "pfs_enabled": pfs,
            "ike_version": ike_version
        },
        "findings": findings,
        "remediations": list(dict.fromkeys(remediations))
    }


def main():
    parser = argparse.ArgumentParser(description="Audit cryptographic suite compliance for IPsec/VPNs.")
    parser.add_argument("-e", "--enc", required=True, help="Encryption algorithm (e.g. AES-256-GCM, AES-128-CBC, 3DES)")
    parser.add_argument("-i", "--int", default="NONE", help="Integrity algorithm (e.g. HMAC-SHA2-256, HMAC-MD5, NONE)")
    parser.add_argument("-d", "--dh", default="14", help="Diffie-Hellman group (e.g. 14, 19, 20, 2)")
    parser.add_argument("-p", "--prf", default="NONE", help="Pseudo-random function (e.g. HMAC-SHA2-256)")
    parser.add_argument("--no-pfs", action="store_true", help="Flag if PFS is disabled")
    parser.add_argument("--ike-version", type=int, default=2, choices=[1, 2], help="IKE Protocol Version (1 or 2)")
    parser.add_argument("--standard", default="nist", choices=["nist", "cnsa1", "cnsa2"], help="Evaluation Standard")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")

    args = parser.parse_args()

    result = audit_proposal(
        enc=args.enc,
        integrity=args.int,
        dh=args.dh,
        prf=args.prf,
        pfs=not args.no_pfs,
        ike_version=args.ike_version,
        target_standard=args.standard
    )

    if args.json:
        print(json.dumps(result, indent=2))
        return

    summary = result["summary"]
    print("=" * 60)
    print(" CRYPTOGRAPHIC COMPLIANCE AUDIT REPORT")
    print("=" * 60)
    print(f"Target Standard   : {summary['target_standard']}")
    print(f"Compliance Status : {summary['compliance_status']}")
    print(f"Overall Risk Score: {summary['risk_score']}/100 ({summary['risk_tier']})")
    print("-" * 60)
    print("Evaluated Suite:")
    params = result["parameters_evaluated"]
    print(f"  • Encryption  : {params['encryption']}")
    print(f"  • Integrity   : {params['integrity']}")
    print(f"  • DH Group    : {params['dh_group']}")
    print(f"  • PFS Active  : {params['pfs_enabled']}")
    print(f"  • IKE Version : v{params['ike_version']}")
    print("-" * 60)

    if result["findings"]:
        print(f"Findings ({len(result['findings'])}):")
        for idx, f in enumerate(result["findings"], 1):
            print(f"  [{idx}] [{f['severity']}] {f['issue']}")
            print(f"      Details: {f['detail']}")
    else:
        print("Findings: None! Cryptographic suite meets all evaluated criteria.")

    print("-" * 60)
    if result["remediations"]:
        print("Recommended Remediations:")
        for r in result["remediations"]:
            print(f"  ➜ {r}")
    else:
        print("No remediations required.")
    print("=" * 60)


if __name__ == "__main__":
    main()

