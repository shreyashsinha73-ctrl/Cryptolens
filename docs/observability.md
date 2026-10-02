# CryptoLens v2 — Passive Wire Observability & Scoring Specification
**Core Doctrine:** *Zero Decryption, Zero Plaintext Access*  
**Audience:** Defense & NTRO Technical Evaluation Teams

---

## 1. Executive Summary & Core Doctrine

CryptoLens operates strictly as a **passive network security auditing system**. It evaluates IPsec tunnels by inspecting control-plane exchanges and data-plane ESP metadata directly from network wire captures (PCAPs) or live network interfaces without:
1. Possessing or requesting pre-shared keys (PSKs), RSA private keys, or certificates.
2. Deriving shared Diffie-Hellman secrets ($SKEYSEED$, $SK_e$, $SK_a$).
3. Decrypting any IKE encrypted payloads or ESP ciphertext payloads.

Under this doctrine, **unknown cryptographic attributes must never score as safe**. Where parameters cannot be mathematically or deterministically observed on the wire, the system explicitly marks them as `not_observable`, flags the overall tunnel posture as `UNVERIFIED`, and bounds the security rating as a worst-case to best-case range.

---

## 2. Protocol Observability Matrix (IKEv1 vs. IKEv2 vs. ESP)

The table below defines what a passive, non-decrypting observer can and cannot observe from network packets under RFC 2409 (IKEv1), RFC 7296 (IKEv2), and RFC 4303 (ESP).

| Security Parameter / Control | IKEv1 Wire Observability (RFC 2409) | IKEv2 Wire Observability (RFC 7296) | ESP Data-Plane Observability (RFC 4303) | Observability Status (No Sidecar) | Evidence Provenance |
|---|---|---|---|---|---|
| **IKE Version** | **Cleartext** in ISAKMP header byte `0x10` | **Cleartext** in IKE header byte `0x20` | Not Applicable | `observed` | `ike_v1_cleartext` / `ike_sa_init` |
| **IKE SA DH Group** | **Cleartext** in Phase 1 SA Proposal (Transform Attribute 4) | **Cleartext** in `IKE_SA_INIT` (Transform Type 4, Key Exchange Payload) | Not Applicable | `observed` | `ike_sa_init` |
| **IKE SA Cipher & Hash** | **Cleartext** in Phase 1 SA Proposal | **Cleartext** in `IKE_SA_INIT` Proposal (for protecting IKE_AUTH) | Not Applicable | `observed` (IKE SA only) | `ike_sa_init` |
| **Child SA (ESP) Encryption Cipher** | **Cleartext** in Quick Mode SA Proposal (unless Phase 1 encrypted QM) | **ENCRYPTED** inside `IKE_AUTH` or `CREATE_CHILD_SA` Encrypted Payload (`SK{...}`) | **Ciphertext** (Indistinguishable from pseudorandom noise) | `not_observable` | `testbed_config` (unverified) / `operator_supplied` |
| **Child SA (ESP) Integrity / AEAD** | **Cleartext** in Quick Mode SA Proposal | **ENCRYPTED** inside `IKE_AUTH` Encrypted Payload (`SK{...}`) | **Ciphertext** ICV (Truncated tag bytes, algorithm unidentifiable) | `not_observable` | `testbed_config` (unverified) / `operator_supplied` |
| **Child SA Perfect Forward Secrecy (PFS)** | **Cleartext** Key Exchange payload in Quick Mode (if requested) | **ENCRYPTED** in `CREATE_CHILD_SA` KE payload or IKE_AUTH | Not Applicable | `not_observable` | `testbed_config` (unverified) / `operator_supplied` |
| **SA Key Lifetime (Seconds/Kilobytes)** | **Cleartext** in Life Duration attributes in SA proposal | **ENCRYPTED** / Internal daemon state (not sent in `IKE_SA_INIT`) | Not Applicable | `not_observable` | `testbed_config` (unverified) / `operator_supplied` |
| **Anti-Replay / Sequence Monotonicity** | Not in handshake | Not in handshake | **Cleartext** 32-bit Sequence Number in ESP header | `observed` | `esp_header_metadata` |
| **Extended Sequence Numbers (ESN)** | Not supported in RFC 2409 | **ENCRYPTED** in Child SA Proposal (Transform Type 5) | Sequence rollover behavior observed over $2^{32}$ frames | `observed` (wire sequence tracking) | `esp_header_metadata` |
| **Operating Mode (Tunnel vs. Transport)** | Phase 2 Encapsulation Mode attribute (Cleartext) | **ENCRYPTED** in `USE_TRANSPORT_MODE` Notify inside `IKE_AUTH` | Outer IP vs. Inner IP headers (Tunnel has 2 IP headers) | `inferred` | `traffic_statistics` |
| **Peer Identity (IDi, IDr)** | Cleartext in Aggressive Mode; Encrypted in Main Mode | **ENCRYPTED** inside `IKE_AUTH` Encrypted Payload (`SK{IDi, IDr}`) | Not Applicable | `not_observable` | N/A |
| **Traffic Selectors (Protected Subnets)** | Cleartext Quick Mode Client Identifiers | **ENCRYPTED** inside `IKE_AUTH` (`SK{TSi, TSr}`) | Inferred from outer IP communication patterns | `not_observable` (inner CIDRs) | `operator_supplied` |

---

## 3. The Three-Value Scoring System

To eliminate false certainty from partial observations, CryptoLens computes three distinct score values for every evaluation:

### 3.1 Mathematical Definitions

Let $C = \{c_1, \dots, c_m\}$ be the set of evaluated security controls (weights $W_c$, $\sum_{c \in C} W_c = 100$).  
Each control is assigned an observability state $O_c \in \{\text{observed}, \text{operator\_supplied}, \text{inferred}, \text{not\_observable}\}$.

Let $V = \{c \in C \mid O_c \in \{\text{observed}, \text{operator\_supplied}\}\}$ represent the **verified control subset**.  
Let $U = \{c \in C \mid O_c \notin \{\text{observed}, \text{operator\_supplied}\}\}$ represent the **unobserved control subset**.

For each control $c$, let $A_c \in [0, W_c]$ be the awarded compliance score.

1. **Worst-Case Score (`score_if_unobserved_fail`):**
   $$\text{Score}_{\text{worst}} = \sum_{c \in V} A_c$$
   *All unobserved and unverified controls are assumed to have failed (awarded 0 points).* This is the primary headline metric.

2. **Best-Case Score (`score_if_unobserved_pass`):**
   $$\text{Score}_{\text{best}} = \sum_{c \in V} A_c + \sum_{u \in U} W_u$$
   *All unobserved controls are assumed to be fully compliant (awarded full weight points).*

3. **Observed-Only Score (`score_observed_only`):**
   $$\text{Score}_{\text{observed\_only}} = \begin{cases} \frac{\sum_{c \in V} A_c}{\sum_{c \in V} W_c} \times 100 & \text{if } \sum_{c \in V} W_c > 0 \\ 0.0 & \text{otherwise} \end{cases}$$
   *Normalized score evaluating strictly the controls that could be verified.*

### 3.2 Headline Score & Risk Label Policy

- **Headline Display:** The primary assessment score is presented as a range:
  $$\text{Headline} = \text{Score}_{\text{worst}}–\text{Score}_{\text{best}}, \text{ coverage } |V|/|C|$$
  *Example:* `35–100, coverage 3/8`
- **Strict Prohibition on Unqualified 100/100:**
  An unqualified "100/100" or single passing score is **strictly forbidden** when coverage $< 100\%$.
- **Mandatory `UNVERIFIED` Status:**
  Whenever coverage $< 100\%$ and unobserved controls exist (that have not been supplied by the operator with validated sidecar provenance), the overall risk rating is clamped to:
  $$\text{Risk Level} = \mathbf{UNVERIFIED}$$

---

## 4. Operator-Supplied Sidecar Configuration

When evaluating IKEv2 tunnels where Child SA transforms are encrypted on the wire, an administrator or auditor may supply authoritative configuration metadata via a **Sidecar Configuration** file (`.sidecar.json` or `.sidecar.yaml`).

### 4.1 Strict Schema (`IPsecSidecarConfig`)

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "IPsecSidecarConfig",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "ike_version": { "type": "string", "enum": ["IKEv1", "IKEv2"] },
    "encryption_algorithm": { "type": "string", "example": "AES-256-GCM" },
    "integrity_algorithm": { "type": "string", "example": "AEAD" },
    "dh_group": { "type": ["integer", "string"], "example": 19 },
    "pfs_enabled": { "type": "boolean", "example": true },
    "key_lifetime_seconds": { "type": "integer", "minimum": 60, "example": 28800 },
    "replay_protection_enabled": { "type": "boolean", "example": true },
    "operating_mode": { "type": "string", "enum": ["Tunnel", "Transport", "tunnel", "transport"] },
    "local_subnet": { "type": "string", "example": "172.16.1.0/24" },
    "remote_subnet": { "type": "string", "example": "172.16.2.0/24" }
  }
}
```

### 4.2 Provenance Tracking & Display
Any parameter ingested through a sidecar config is explicitly stamped:
- `observability`: `"operator_supplied"`
- `evidence_source`: `"operator_supplied"`
- `provenance`: `"operator_supplied (sidecar config)"`

Supplying valid sidecar configuration elevates coverage from partial ($3/8$) up to full ($8/8$), enabling deterministic risk categorization (`LOW` / `MODERATE` / `HIGH` / `CRITICAL`) while maintaining transparent audit provenance for technical evaluators.
