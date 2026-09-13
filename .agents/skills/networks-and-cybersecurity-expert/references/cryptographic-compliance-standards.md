# Cryptographic Compliance Standards: NIST SP 800-77 Rev 1 & CNSA 2.0

This document serves as the authoritative compliance reference for auditing cryptographic suites across
IPsec VPNs, TLS endpoints, and network infrastructure.

---

## Table of Contents
1. [Standards Framework Overview](#standards-framework-overview)
2. [NIST SP 800-77 Rev 1: IPsec VPN Compliance](#nist-sp-800-77-rev-1-ipsec-vpn-compliance)
3. [CNSA 1.0 & CNSA 2.0 Post-Quantum Transition](#cnsa-10--cnsa-20-post-quantum-transition)
4. [NIST SP 800-52 Rev 2: TLS Guidelines](#nist-sp-800-52-rev-2-tls-guidelines)
5. [Deprecated & Vulnerable Algorithm Catalog](#deprecated--vulnerable-algorithm-catalog)
6. [Compliance Scoring & Risk Assessment Model](#compliance-scoring--risk-assessment-model)

---

## Standards Framework Overview

Cryptographic algorithms protecting network traffic are evaluated against formal federal and defense standards:
- **NIST SP 800-77 Rev 1**: *Guide to IPsec VPNs* (National Institute of Standards and Technology).
- **CNSA 1.0 & 2.0**: *Commercial National Security Algorithm Suite* (National Security Agency / Committee on National Security Systems).
- **FIPS 140-3**: *Security Requirements for Cryptographic Modules*.
- **RFC 8221 / RFC 8247**: Cryptographic Algorithm Implementation Requirements and Usage Guidance for ESP, AH, and IKEv2.

---

## NIST SP 800-77 Rev 1: IPsec VPN Compliance

NIST SP 800-77 Rev 1 categorizes cryptographic algorithms into three operational tiers:
1. **Approved**: Meets modern federal cryptographic standards (>= 112-bit or >= 128-bit security strength).
2. **Legacy / Acceptable**: Permitted only for backward compatibility with existing systems, but must not be used in new deployments.
3. **Deprecated / Prohibited**: Known cryptographic vulnerabilities; must be removed immediately.

### 1. Symmetric Encryption Algorithms (ESP & IKE)
| Algorithm | Key Size | Status | Notes |
| :--- | :--- | :--- | :--- |
| **AES-GCM (Authenticated)** | 128, 256 bits | **Approved (Recommended)** | Combined AEAD mode; eliminates need for separate HMAC. High throughput. |
| **AES-CBC** | 128, 192, 256 bits | **Approved** | Requires separate HMAC (e.g. HMAC-SHA-256). Vulnerable to padding oracle if misconfigured. |
| **AES-CTR** | 128, 192, 256 bits | **Approved** | Stream cipher mode; requires separate HMAC. |
| **ChaCha20-Poly1305** | 256 bits | **Acceptable (RFC 7634)** | Excellent software performance on CPUs without AES-NI. |
| **Triple-DES (3DES / 3DEA)** | 168 bits (112 effective) | **Deprecated / Prohibited** | Vulnerable to Sweet32 collision attacks (64-bit block size). Prohibited since 2023. |
| **DES / RC4 / Blowfish** | Variable / 56 bits | **Prohibited** | Cryptographically broken; trivial to crack. |

### 2. Integrity & Message Authentication (HMAC / ICV)
| Algorithm | Digest / ICV Size | Status | Notes |
| :--- | :--- | :--- | :--- |
| **HMAC-SHA2-256** | 256 bits (truncated to 128 for IPsec) | **Approved** | Industry standard baseline. |
| **HMAC-SHA2-384** | 384 bits (truncated to 192) | **Approved** | High security tier. |
| **HMAC-SHA2-512** | 512 bits (truncated to 256) | **Approved** | Maximum security strength. |
| **AES-GMAC** | 128 bits | **Approved** | Used when integrity only is requested without confidentiality. |
| **HMAC-SHA-1** | 160 bits (truncated to 96) | **Deprecated** | Collision attacks demonstrated; disallowed in new federal systems. |
| **HMAC-MD5** | 128 bits | **Prohibited** | Broken collision resistance. |

### 3. Diffie-Hellman / Key Exchange Groups
| Group ID | Name / Type | Key Size / Strength | NIST SP 800-77 Status |
| :--- | :--- | :--- | :--- |
| **Group 14** | 2048-bit MODP | 112-bit strength | **Approved (Minimum acceptable MODP)** |
| **Group 15** | 3072-bit MODP | 128-bit strength | **Approved** |
| **Group 16** | 4096-bit MODP | 128-bit+ strength | **Approved** |
| **Group 19** | 256-bit Random ECP (NIST P-256) | 128-bit strength | **Approved (Recommended for speed)** |
| **Group 20** | 384-bit Random ECP (NIST P-384) | 192-bit strength | **Approved (CNSA compliant)** |
| **Group 21** | 521-bit Random ECP (NIST P-521) | 256-bit strength | **Approved** |
| **Group 31** | Curve25519 (RFC 8031) | 128-bit strength | **Approved** |
| **Group 1, 2, 5** | 768-bit, 1024-bit, 1536-bit MODP | < 112-bit strength | **Prohibited (Vulnerable to Logjam / precomputation)** |

---

## CNSA 1.0 & CNSA 2.0 Post-Quantum Transition

The NSA's **Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)** mandates transition to quantum-resistant
cryptographic algorithms to protect National Security Systems against Cryptanalytically Relevant Quantum Computers (CRQCs).

### CNSA 2.0 Algorithm Requirements

| Security Function | CNSA 1.0 (Legacy Classical) | CNSA 2.0 (Quantum-Resistant) |
| :--- | :--- | :--- |
| **Symmetric Encryption** | AES-256 (GCM or CBC) | **AES-256** |
| **Hashing / Integrity** | SHA-384 | **SHA-384 or SHA-512** |
| **Key Establishment (KEM)** | ECDH over P-384 or RSA-3072 | **ML-KEM (FIPS 203 / CRYSTALS-Kyber-1024)** |
| **Digital Signatures** | ECDSA over P-384 or RSA-3072 | **ML-DSA (FIPS 204 / CRYSTALS-Dilithium)** or **LMS/XMSS** (RFC 8554 / RFC 8391) |

### Transition Timelines (CNSA 2.0):
- **Software & Firmware**: Transition began 2025; exclusive post-quantum enforcement by **2030**.
- **Network Equipment (VPNs, Routers, Firewalls)**: New acquisitions must support PQC by **2026**; complete deployment by **2030**.
- **Legacy Systems**: Full replacement deadline by **2033**.

---

## NIST SP 800-52 Rev 2: TLS Guidelines

For TLS endpoints (HTTPS, API gateways, VPN web portals):
1. **Mandatory Protocols**: TLS 1.3 is strongly recommended; TLS 1.2 is permitted only when configured with approved cipher suites.
2. **Strictly Prohibited**: SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1.
3. **PFS Required**: Ephemeral Diffie-Hellman (`ECDHE` or `DHE`) is required for all sessions. Static RSA key transport is prohibited.
4. **Approved Cipher Suites (TLS 1.3)**:
   - `TLS_AES_256_GCM_SHA384`
   - `TLS_AES_128_GCM_SHA256`
   - `TLS_CHACHA20_POLY1305_SHA256`
5. **Approved Cipher Suites (TLS 1.2)**:
   - `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
   - `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
   - `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
   - `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`

---

## Deprecated & Vulnerable Algorithm Catalog

When any of these algorithms are detected on the wire or in configuration files, raise an immediate vulnerability finding:

| Algorithm / Feature | Flaw / Attack Vector | Remediation |
| :--- | :--- | :--- |
| **3DES (Triple-DES)** | 64-bit block size enables Sweet32 birthday attacks after ~32GB of encrypted data. | Upgrade to AES-GCM-256 or AES-GCM-128. |
| **DES / Single DES** | 56-bit key can be brute-forced in hours with commodity FPGA hardware. | Replace immediately with AES. |
| **RC4** | Biases in keystream allow plaintext recovery from repeated sessions. | Eliminate RC4; disable TLS 1.0/1.1. |
| **MD5** | Practical collision attacks allow forged certificates and signatures. | Replace with SHA-256, SHA-384, or SHA-512. |
| **SHA-1** | Chosen-prefix collisions demonstrated (SHAttered, Shambles). | Replace with SHA-2 family. |
| **DH Groups 1, 2, 5** | Modulus sizes (<2048-bit) vulnerable to discrete log precomputation (Logjam attack). | Upgrade to Group 14 (MODP-2048), Group 19 (P-256), or Group 20 (P-384). |
| **Missing PFS** | Compromising long-term private key allows retrospective decryption of all past traffic. | Enable ephemeral Diffie-Hellman in Child SA negotiation. |

---

## Compliance Scoring & Risk Assessment Model

Used to calculate quantitative risk scores (e.g., in CryptoLens platform):

$$\text{Risk Score} = \min\left(100, \sum \text{Penalty Points}\right)$$

### Penalty Deductions:
- **Prohibited Cipher** (3DES, DES, RC4): $+50$ points (Critical Risk).
- **Prohibited Hash/HMAC** (MD5, SHA-1): $+35$ points (High Risk).
- **Weak DH Group** (Group 1, 2, 5): $+40$ points (High Risk).
- **Missing PFS**: $+25$ points (Medium-High Risk).
- **IKEv1 in Use**: $+30$ points (High Risk).
- **Legacy Cipher** (AES-128-CBC without AEAD): $+10$ points (Low-Medium Risk).
- **Non-CNSA 2.0 in Defense Context**: $+20$ points (Compliance Violation).

### Compliance Tier Classification:
- **0–15**: EXCELLENT / NIST & CNSA Compliant.
- **16–35**: ACCEPTABLE / Legacy NIST Compliant (Requires minor upgrades).
- **36–65**: ELEVATED RISK / Non-Compliant (Weak ciphers or missing PFS).
- **66–100**: CRITICAL RISK / Severely Vulnerable (Immediate breach exposure).

