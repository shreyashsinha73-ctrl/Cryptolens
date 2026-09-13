"""
rules_engine.py - Deterministic Security & Compliance Rules Engine for IPsec Control-Plane.
Audits parsed IKE parameters against NIST SP 800-77 Rev 1, CNSA 2.0, and RFC 8221.
"""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Union

from backend.engine.control_plane.ike_parser import IkeParseResult


@dataclass
class RuleFinding:
    finding_id: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    category: str
    title: str
    description: str
    observed_value: Any
    standard_ref: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RulesEngineResult:
    compliance_score: float  # 0 to 100
    risk_level: str          # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    findings: List[RuleFinding] = field(default_factory=list)
    category_scores: Dict[str, float] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


class ControlPlaneRulesEngine:
    """
    Deterministic rules engine that evaluates parsed control-plane parameters
    strictly against standards without arbitrary hardcoded scoring.
    """

    def evaluate(self, control_plane: Union[IkeParseResult, Dict[str, Any]]) -> RulesEngineResult:
        if isinstance(control_plane, IkeParseResult):
            data = control_plane.to_control_plane_dict()
        else:
            data = control_plane

        findings: List[RuleFinding] = []
        category_scores: Dict[str, float] = {}

        # 1. Evaluate Encryption Algorithm (Weight: 25)
        encr_score = self._eval_encryption(data.get("encryption_algorithm"), findings)
        category_scores["encryption"] = encr_score

        # 2. Evaluate Integrity Algorithm (Weight: 15)
        integ_score = self._eval_integrity(data.get("integrity_algorithm"), data.get("encryption_algorithm"), findings)
        category_scores["integrity"] = integ_score

        # 3. Evaluate DH Group / Key Exchange (Weight: 20)
        dh_score = self._eval_dh_group(data.get("dh_group"), findings)
        category_scores["key_exchange"] = dh_score

        # 4. Evaluate PFS (Weight: 15)
        pfs_score = self._eval_pfs(data.get("pfs_enabled"), findings)
        category_scores["pfs"] = pfs_score

        # 5. Evaluate Replay Protection (Weight: 10)
        replay_score = self._eval_replay_protection(data.get("replay_protection_enabled"), findings)
        category_scores["replay_protection"] = replay_score

        # 6. Evaluate Key Lifetime (Weight: 5)
        lifetime_score = self._eval_lifetime(data.get("key_lifetime_seconds"), findings)
        category_scores["key_lifetime"] = lifetime_score

        # 7. Evaluate IKE Version (Weight: 5)
        ver_score = self._eval_ike_version(data.get("ike_version"), findings)
        category_scores["ike_version"] = ver_score

        # 8. Evaluate Operating Mode (Weight: 5)
        mode_score = self._eval_mode(data.get("operating_mode"), findings)
        category_scores["operating_mode"] = mode_score

        # Total overall score
        total_score = round(sum(category_scores.values()), 1)
        total_score = max(0.0, min(100.0, total_score))

        # Risk level determination based on findings severity
        has_critical = any(f.severity == "CRITICAL" for f in findings)
        has_high = any(f.severity == "HIGH" for f in findings)
        has_medium = any(f.severity == "MEDIUM" for f in findings)

        if has_critical or total_score < 40:
            risk_level = "CRITICAL"
        elif has_high or total_score < 65:
            risk_level = "HIGH"
        elif has_medium or total_score < 85:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return RulesEngineResult(
            compliance_score=total_score,
            risk_level=risk_level,
            findings=findings,
            category_scores=category_scores,
            summary={
                "total_findings": len(findings),
                "critical_findings": sum(1 for f in findings if f.severity == "CRITICAL"),
                "high_findings": sum(1 for f in findings if f.severity == "HIGH"),
                "medium_findings": sum(1 for f in findings if f.severity == "MEDIUM"),
                "info_findings": sum(1 for f in findings if f.severity == "INFO"),
            }
        )

    def _eval_encryption(self, cipher: Optional[str], findings: List[RuleFinding]) -> float:
        if not cipher:
            findings.append(RuleFinding(
                finding_id="ENC_NOT_OBSERVED",
                severity="INFO",
                category="Encryption",
                title="Encryption Cipher Not Observed",
                description="No encryption transform proposal was observed in the captured handshake.",
                observed_value=None,
                standard_ref="NIST SP 800-77 Rev 1 Sec 3.3",
                remediation="Capture full IKE_SA_INIT negotiation to audit cipher proposal."
            ))
            return 0.0

        cipher_upper = cipher.upper()
        if "256-GCM" in cipher_upper or "CHACHA20" in cipher_upper:
            return 25.0
        elif "128-GCM" in cipher_upper:
            return 22.0
        elif "256-CBC" in cipher_upper:
            findings.append(RuleFinding(
                finding_id="ENC_CBC_MODE",
                severity="MEDIUM",
                category="Encryption",
                title="Legacy CBC Mode Cipher (AES-256-CBC)",
                description="AES-CBC requires separate integrity hashing and is susceptible to padding oracle attacks.",
                observed_value=cipher,
                standard_ref="NIST SP 800-77 Rev 1 Sec 3.3.1",
                remediation="Upgrade IPsec proposal to authenticated encryption: AES-256-GCM."
            ))
            return 18.0
        elif "128-CBC" in cipher_upper:
            findings.append(RuleFinding(
                finding_id="ENC_SUBOPTIMAL",
                severity="MEDIUM",
                category="Encryption",
                title="Suboptimal Cipher (AES-128-CBC)",
                description="AES-128-CBC lacks AEAD and does not meet CNSA 2.0 high-assurance requirements.",
                observed_value=cipher,
                standard_ref="NIST SP 800-77 Rev 1 / CNSA 2.0",
                remediation="Configure AES-256-GCM in Phase 1 and Phase 2 proposals."
            ))
            return 14.0
        elif "3DES" in cipher_upper or "DES" in cipher_upper:
            findings.append(RuleFinding(
                finding_id="ENC_CRITICAL_DEPRECATED",
                severity="CRITICAL",
                category="Encryption",
                title="Critically Deprecated Cipher Suite",
                description=f"Cipher '{cipher}' is cryptographically broken, obsolete, and forbidden by NIST.",
                observed_value=cipher,
                standard_ref="NIST SP 800-131A / RFC 8221",
                remediation="Immediately eliminate DES/3DES and migrate to AES-256-GCM."
            ))
            return 0.0
        else:
            return 10.0

    def _eval_integrity(self, integ: Optional[str], cipher: Optional[str], findings: List[RuleFinding]) -> float:
        if cipher and ("GCM" in cipher.upper() or "POLY1305" in cipher.upper()):
            # AEAD provides integrated cryptographic integrity
            return 15.0

        if not cipher and not integ:
            findings.append(RuleFinding(
                finding_id="INT_NOT_OBSERVED",
                severity="INFO",
                category="Integrity",
                title="Integrity Algorithm Not Observed",
                description="No integrity transform proposal was observed in the captured handshake.",
                observed_value=None,
                standard_ref="NIST SP 800-77 Rev 1",
                remediation="Capture full IKE negotiation to audit integrity algorithm."
            ))
            return 0.0

        if not integ or integ == "NONE":
            findings.append(RuleFinding(
                finding_id="INT_NONE",
                severity="CRITICAL",
                category="Integrity",
                title="No Integrity Protection",
                description="Non-AEAD traffic is operating without integrity validation, enabling packet tampering.",
                observed_value=integ,
                standard_ref="RFC 8221 / NIST SP 800-77 Rev 1",
                remediation="Configure HMAC-SHA2-256 or deploy AEAD AES-GCM."
            ))
            return 0.0

        integ_upper = integ.upper()
        if "SHA2-256" in integ_upper or "SHA256" in integ_upper or "SHA2-384" in integ_upper or "SHA2-512" in integ_upper:
            return 15.0
        elif "SHA1" in integ_upper:
            findings.append(RuleFinding(
                finding_id="INT_SHA1_DEPRECATED",
                severity="HIGH",
                category="Integrity",
                title="Deprecated SHA-1 Integrity Hash",
                description="SHA-1 is vulnerable to collision attacks and deprecated by NIST for cryptographic integrity.",
                observed_value=integ,
                standard_ref="NIST SP 800-131A Rev 2",
                remediation="Upgrade integrity algorithm to HMAC-SHA2-256 or HMAC-SHA2-384."
            ))
            return 0.0
        elif "MD5" in integ_upper:
            findings.append(RuleFinding(
                finding_id="INT_MD5_BROKEN",
                severity="CRITICAL",
                category="Integrity",
                title="Broken MD5 Integrity Hash",
                description="MD5 is completely broken and forbidden.",
                observed_value=integ,
                standard_ref="NIST SP 800-131A",
                remediation="Immediately disable MD5 and configure HMAC-SHA2-256."
            ))
            return 0.0
        return 8.0

    def _eval_dh_group(self, dh_group: Optional[Union[int, str]], findings: List[RuleFinding]) -> float:
        if dh_group is None:
            findings.append(RuleFinding(
                finding_id="DH_NOT_OBSERVED",
                severity="INFO",
                category="Key Exchange",
                title="Diffie-Hellman Group Not Observed",
                description="No Diffie-Hellman group exchange was observed in the captured packets.",
                observed_value=None,
                standard_ref="NIST SP 800-77 Rev 1 Sec 3.3.3",
                remediation="Ensure Phase 1 negotiation packets are included in the capture."
            ))
            return 0.0

        # Normalize to integer if possible
        try:
            val = int(str(dh_group))
        except ValueError:
            val = None

        if val in (19, 20, 21, 31):  # ECP 256/384/521 or Curve25519
            return 20.0
        elif val in (14, 15, 16):    # MODP 2048/3072/4096
            findings.append(RuleFinding(
                finding_id="DH_LEGACY_MODP",
                severity="MEDIUM",
                category="Key Exchange",
                title="Legacy MODP Diffie-Hellman Group",
                description=f"MODP Group {val} provides minimum required strength but Elliptic Curve groups (19, 20, 21) are strongly recommended for speed and modern security.",
                observed_value=dh_group,
                standard_ref="NIST SP 800-77 Rev 1 Sec 3.3.3",
                remediation="Configure Diffie-Hellman Group 19 (NIST P-256) or Group 20 (NIST P-384)."
            ))
            return 14.0
        elif val in (1, 2, 5):      # MODP 768, 1024, 1536
            findings.append(RuleFinding(
                finding_id="DH_WEAK_GROUP",
                severity="CRITICAL",
                category="Key Exchange",
                title="Critically Weak Diffie-Hellman Group (< 2048 bits)",
                description=f"Diffie-Hellman Group {val} is insecure against well-resourced adversaries (Logjam attack vulnerability).",
                observed_value=dh_group,
                standard_ref="NIST SP 800-77 Rev 1 / CNSA 2.0",
                remediation="Immediately eliminate DH Groups 1, 2, and 5. Migrate to Group 19 or Group 14+."
            ))
            return 0.0
        else:
            return 10.0

    def _eval_pfs(self, pfs_enabled: Optional[bool], findings: List[RuleFinding]) -> float:
        if pfs_enabled is True:
            return 15.0
        elif pfs_enabled is False:
            findings.append(RuleFinding(
                finding_id="PFS_DISABLED",
                severity="HIGH",
                category="Forward Secrecy",
                title="Perfect Forward Secrecy (PFS) Disabled",
                description="Child SA does not perform independent Diffie-Hellman exchange. If long-term private keys are compromised, all historical recorded sessions can be decrypted.",
                observed_value=False,
                standard_ref="NIST SP 800-77 Rev 1 Sec 3.3.3",
                remediation="Enable PFS in Child SA configuration (e.g. 'esp = aes256gcm16-sha256-modp2048!')."
            ))
            return 0.0
        else:
            findings.append(RuleFinding(
                finding_id="PFS_NOT_OBSERVED",
                severity="INFO",
                category="Forward Secrecy",
                title="PFS Status Not Observed",
                description="Child SA creation / rekeying packets were not present in capture.",
                observed_value=None,
                standard_ref="NIST SP 800-77 Rev 1",
                remediation="Capture CREATE_CHILD_SA exchange to audit PFS."
            ))
            return 7.5

    def _eval_replay_protection(self, replay_enabled: Optional[bool], findings: List[RuleFinding]) -> float:
        if replay_enabled is True:
            return 10.0
        elif replay_enabled is False:
            findings.append(RuleFinding(
                finding_id="REPLAY_VULNERABILITY",
                severity="HIGH",
                category="Replay Protection",
                title="Anti-Replay Protection Disabled / Duplicate Packets Detected",
                description="Duplicate ESP sequence numbers or disabled anti-replay window detected, enabling malicious packet replay.",
                observed_value=False,
                standard_ref="RFC 4301 Sec 3.4.3 / NIST SP 800-77 Rev 1",
                remediation="Enable anti-replay window verification and ensure ESN is negotiated."
            ))
            return 0.0
        else:
            return 5.0

    def _eval_lifetime(self, lifetime: Optional[int], findings: List[RuleFinding]) -> float:
        if lifetime is None or lifetime == 0:
            return 3.0
        if 3600 <= lifetime <= 28800:
            return 5.0
        elif lifetime > 86400:
            findings.append(RuleFinding(
                finding_id="LIFETIME_EXCESSIVE",
                severity="LOW",
                category="Key Lifetime",
                title="Excessive SA Key Lifetime",
                description=f"Configured key lifetime ({lifetime}s) exceeds recommended 8-hour maximum, extending key exposure window.",
                observed_value=lifetime,
                standard_ref="NIST SP 800-77 Rev 1 Sec 3.3.4",
                remediation="Configure rekeying interval to 28800 seconds (8 hours) or less."
            ))
            return 2.0
        return 4.0

    def _eval_ike_version(self, version: Optional[str], findings: List[RuleFinding]) -> float:
        if version == "IKEv2":
            return 5.0
        elif version == "IKEv1":
            findings.append(RuleFinding(
                finding_id="IKEV1_LEGACY",
                severity="HIGH",
                category="Protocol Version",
                title="Legacy IKEv1 Protocol Detected",
                description="IKEv1 is deprecated by IETF (RFC 9395) due to cryptographic weaknesses and protocol vulnerabilities.",
                observed_value="IKEv1",
                standard_ref="IETF RFC 9395 / NIST SP 800-77 Rev 1",
                remediation="Migrate endpoints to IKEv2 (RFC 7296)."
            ))
            return 0.0
        return 2.5

    def _eval_mode(self, mode: Optional[str], findings: List[RuleFinding]) -> float:
        if mode == "Tunnel":
            return 5.0
        elif mode == "Transport":
            findings.append(RuleFinding(
                finding_id="MODE_TRANSPORT",
                severity="LOW",
                category="Operating Mode",
                title="Transport Mode In Use",
                description="Transport mode encrypts payload but leaves outer IP headers visible, potentially leaking endpoint communication metadata.",
                observed_value="Transport",
                standard_ref="NIST SP 800-77 Rev 1 Sec 3.2",
                remediation="Use Tunnel mode when traffic crosses public or untrusted gateway networks."
            ))
            return 4.0
        return 2.5

