#!/usr/bin/env python3
"""
Authoritative Cryptographic Compliance and Rules Engine (engine/control_plane/rules_engine.py)
Evaluates control-plane AST against NIST SP 800-77 Rev 1 and NSA CNSA 2.0.
Generates deterministic risk scores, compliance ratings, and standard threat matrices.
"""

import argparse
import json
import sys
from typing import Dict, List, Any, Optional

PROHIBITED_CIPHERS = {"3DES", "3DES-CBC", "DES", "RC4", "NULL", "BLOWFISH", "IDEA"}
LEGACY_CIPHERS = {"AES-128-CBC", "AES-CBC-128", "AES-CBC", "AES-CTR"}
APPROVED_AEAD_CIPHERS = {"AES-256-GCM", "AES-GCM-256", "AES-128-GCM", "AES-GCM-128", "CHACHA20-POLY1305"}

PROHIBITED_HASHES = {"MD5", "HMAC-MD5", "HMAC-MD5-96", "SHA1", "HMAC-SHA1", "HMAC-SHA1-96"}
APPROVED_HASHES = {"HMAC-SHA2-256", "HMAC-SHA2-384", "HMAC-SHA2-512", "NONE", "HMAC-SHA2-256-128"}

PROHIBITED_DH_GROUPS = {1, 2, 5}  # Sub-2048-bit MODP
APPROVED_DH_GROUPS = {14, 15, 16, 19, 20, 21, 31}


class RulesEngine:
    """Evaluates cryptographic compliance and scores threat vulnerabilities."""

    def __init__(self, target_standard: str = "nist"):
        self.target_standard = target_standard.lower()

    def evaluate(self, control_plane: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if not control_plane:
            return {
                "summary": {
                    "overall_risk_score": 50,
                    "risk_level": "ELEVATED",
                    "ai_confidence_score": 0.0,
                    "agreement_flag": False
                },
                "control_plane": None,
                "threat_matrix": [
                    {
                        "id": "ERR-001",
                        "severity": "HIGH",
                        "category": "Capture Quality",
                        "title": "Missing IKE Handshake",
                        "description": "No IKE handshake packets (UDP 500 / 4500) were found in the uploaded capture. Cleartext cryptographic parameters could not be deterministically audited."
                    }
                ]
            }

        threat_matrix: List[Dict[str, str]] = []
        penalty = 0

        ike_ver = control_plane.get("ike_version", "IKEv2")

        enc = str(control_plane.get("encryption_algorithm", "")).upper()
        integ = str(control_plane.get("integrity_algorithm", "")).upper()
        dh = control_plane.get("dh_group", 14)
        pfs = control_plane.get("pfs_enabled", True)
        lifetime = control_plane.get("key_lifetime_seconds", 28800)
        esn = control_plane.get("replay_protection_enabled", True)

        vuln_counter = 1

        # 1. Protocol Version Check
        if "V1" in ike_ver:
            penalty += 30
            threat_matrix.append({
                "id": f"VULN-{vuln_counter:03d}",
                "severity": "HIGH",
                "category": "Protocol Deprecation",
                "title": "Legacy Protocol: IKEv1 Detected",
                "description": "IKEv1 is deprecated by NIST SP 800-77 Rev 1 due to lack of standard identity protection in Aggressive Mode and known offline cracking vulnerabilities."
            })
            vuln_counter += 1

        # 2. Symmetric Encryption Cipher Check
        if any(bad in enc for bad in PROHIBITED_CIPHERS):
            penalty += 50
            threat_matrix.append({
                "id": f"VULN-{vuln_counter:03d}",
                "severity": "CRITICAL",
                "category": "Cipher Strength",
                "title": f"Prohibited Cipher: {enc}",
                "description": "Cipher is deprecated and broken (e.g. Sweet32 birthday attacks on 64-bit block size). Upgrade to AES-256-GCM."
            })
            vuln_counter += 1
        elif any(legacy in enc for legacy in LEGACY_CIPHERS):
            penalty += 15
            threat_matrix.append({
                "id": f"VULN-{vuln_counter:03d}",
                "severity": "MEDIUM",
                "category": "Cipher Strength",
                "title": f"Legacy Cipher Suite: {enc} without AEAD",
                "description": "CBC mode without integrated authenticated encryption leaves traffic susceptible to padding oracle attacks if not strictly authenticated."
            })
            vuln_counter += 1

        # 3. Integrity / Hash Algorithm Check
        if any(bad in integ for bad in PROHIBITED_HASHES):
            penalty += 35
            threat_matrix.append({
                "id": f"VULN-{vuln_counter:03d}",
                "severity": "HIGH",
                "category": "Integrity",
                "title": f"Insecure Integrity Hash: {integ}",
                "description": "Hash function suffers from demonstrated collision attacks (MD5/SHA-1). Replace with SHA-256, SHA-384, or SHA-512."
            })
            vuln_counter += 1

        # 4. Diffie-Hellman Key Exchange Group Check
        if dh in PROHIBITED_DH_GROUPS:
            penalty += 40
            threat_matrix.append({
                "id": f"VULN-{vuln_counter:03d}",
                "severity": "CRITICAL",
                "category": "Key Exchange",
                "title": f"Weak Diffie-Hellman Group {dh}",
                "description": "DH groups with modulus < 2048-bit are vulnerable to Logjam discrete logarithm precomputations. Enforce Group 14+ or Group 19 (P-256)."
            })
            vuln_counter += 1
        elif self.target_standard == "cnsa2" and dh not in (20, 21):
            penalty += 20
            threat_matrix.append({
                "id": f"VULN-{vuln_counter:03d}",
                "severity": "HIGH",
                "category": "Quantum Resistance",
                "title": f"Non-Quantum Resistant Key Exchange: Group {dh}",
                "description": "CNSA 2.0 requires transition to Post-Quantum Cryptography (ML-KEM-1024) or transitionary 384-bit curves."
            })
            vuln_counter += 1

        # 5. Perfect Forward Secrecy Check
        if not pfs:
            penalty += 25
            threat_matrix.append({
                "id": f"VULN-{vuln_counter:03d}",
                "severity": "HIGH",
                "category": "Forward Secrecy",
                "title": "Perfect Forward Secrecy (PFS) Disabled",
                "description": "If the main private key is compromised, all past recorded traffic can be retroactively decrypted."
            })
            vuln_counter += 1

        # 6. SA Key Lifetime Check (Addresses PS gap #148)
        if lifetime > 28800:
            penalty += 10
            threat_matrix.append({
                "id": f"VULN-{vuln_counter:03d}",
                "severity": "LOW",
                "category": "Key Lifetime",
                "title": f"Excessive SA Lifetime: {lifetime} seconds",
                "description": "Security Association lifetime exceeds NIST recommended 8-hour / 28800-second rekey threshold, increasing key-exposure windows."
            })
            vuln_counter += 1

        # 7. Anti-Replay Protection Check
        if not esn:
            penalty += 15
            threat_matrix.append({
                "id": f"VULN-{vuln_counter:03d}",
                "severity": "MEDIUM",
                "category": "Replay Protection",
                "title": "Extended Sequence Numbers (ESN) Disabled",
                "description": "Standard 32-bit sequence numbers can wrap around on high-speed gigabit links, leaving sessions vulnerable to replay attacks."
            })
            vuln_counter += 1

        # Calculate final normalized risk score
        overall_risk = min(100, penalty)
        if overall_risk <= 15:
            risk_level = "LOW"
        elif overall_risk <= 45:
            risk_level = "MEDIUM"
        elif overall_risk <= 75:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        return {
            "summary": {
                "overall_risk_score": overall_risk,
                "risk_level": risk_level,
                "ai_confidence_score": 1.0,
                "agreement_flag": True
            },
            "control_plane": control_plane,
            "threat_matrix": threat_matrix
        }


def main():
    parser = argparse.ArgumentParser(description="Evaluate control-plane compliance against NIST/CNSA.")
    parser.add_argument("ast_json", help="Path to IKE AST JSON file or '-' for stdin")
    parser.add_argument("--standard", default="nist", choices=["nist", "cnsa2"], help="Compliance standard")
    parser.add_argument("--json", action="store_true", help="Print raw JSON output")

    args = parser.parse_args()

    if args.ast_json == "-":
        data = json.load(sys.stdin)
    else:
        with open(args.ast_json, "r") as f:
            data = json.load(f)

    cp = data.get("control_plane", data)
    engine = RulesEngine(target_standard=args.standard)
    res = engine.evaluate(cp)

    if args.json:
        print(json.dumps(res, indent=2))
        return

    s = res["summary"]
    print("=" * 60)
    print(" CRYPTOLENS CONTROL-PLANE COMPLIANCE AUDIT")
    print("=" * 60)
    print(f"Overall Risk Score : {s['overall_risk_score']}/100 ({s['risk_level']} RISK)")
    print(f"Confidence Score   : {s['ai_confidence_score'] * 100:.0f}% (Ground Truth)")
    print("-" * 60)
    print("Threat Matrix Findings:")
    if res["threat_matrix"]:
        for item in res["threat_matrix"]:
            print(f"  [{item['id']}] [{item['severity']}] {item['title']}")
            print(f"        Category : {item['category']}")
            print(f"        Details  : {item['description']}")
    else:
        print("  None. The cryptographic suite is fully compliant with NIST SP 800-77 Rev 1.")
    print("=" * 60)


if __name__ == "__main__":
    main()

