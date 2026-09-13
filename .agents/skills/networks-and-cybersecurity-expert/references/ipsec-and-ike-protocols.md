# IPsec and IKE Protocol Engineering & Security Auditing

This document provides in-depth technical specifications, protocol wire structures, exchange mechanisms,
and security auditing procedures for Internet Protocol Security (IPsec) and Internet Key Exchange (IKE).

---

## Table of Contents
1. [Architectural Overview & RFC Foundation](#architectural-overview--rfc-foundation)
2. [IKEv1 vs IKEv2 Protocol Mechanics](#ikev1-vs-ikev2-protocol-mechanics)
3. [IKEv2 Packet Exchanges & Payloads](#ikev2-packet-exchanges--payloads)
4. [ESP (Protocol 50) vs AH (Protocol 51)](#esp-protocol-50-vs-ah-protocol-51)
5. [Operating Modes: Tunnel vs Transport](#operating-modes-tunnel-vs-transport)
6. [NAT Traversal (NAT-T) Mechanics](#nat-traversal-nat-t-mechanics)
7. [Security Controls: PFS, DPD, & Anti-Replay](#security-controls-pfs-dpd--anti-replay)
8. [Configuration Blueprints (strongSwan swanctl.conf)](#configuration-blueprints-strongswan-swanctlconf)
9. [IPsec Security Audit Checklist](#ipsec-security-audit-checklist)

---

## Architectural Overview & RFC Foundation

IPsec is a suite of protocols defined by the IETF (primarily RFC 4301) providing security services at the IP layer:
- **Confidentiality**: Encrypting traffic (ESP).
- **Data Origin Authentication & Integrity**: Verifying sender identity and payload integrity (AH / ESP-ICV).
- **Anti-Replay**: Rejecting duplicated packets within a sliding sequence window.
- **Key Management**: Dynamic automated key negotiation and mutual authentication via IKEv2 (RFC 7296) or IKEv1 (RFC 2409).

### Architecture Components:
- **Security Policy Database (SPD)**: Decides whether traffic is discarded, bypassed (cleartext), or protected via IPsec based on selectors (source IP, destination IP, protocol, ports).
- **Security Association Database (SAD)**: Stores active Security Associations (SAs). Each SA represents a unidirectional security channel identified by the tuple: `(Destination IP, Security Parameter Index [SPI], Security Protocol [ESP/AH])`. Two SAs are required for bidirectional communication.
- **Key Negotiation Daemon**: StrongSwan, Libreswan, or racoon negotiating keys and installing SA/SP into the Linux kernel `xfrm` subsystem.

---

## IKEv1 vs IKEv2 Protocol Mechanics

| Feature | IKEv1 (RFC 2409 - Legacy/Insecure) | IKEv2 (RFC 7296 - Modern Standard) |
| :--- | :--- | :--- |
| **Round Trips for SA Setup** | 6 packets (Main Mode) or 3 packets (Aggressive Mode) + 3 packets (Quick Mode) | 4 packets (2 round trips: `IKE_SA_INIT` + `IKE_AUTH`) |
| **Identity Protection** | Broken in Aggressive Mode (hashes sent in cleartext, vulnerable to offline cracking) | Always protected; IDs transmitted under `IKE_SA` encryption in `IKE_AUTH` |
| **NAT Traversal** | Ad-hoc vendor extensions (RFC 3947) | Natively integrated into standard specification |
| **Dead Peer Detection (DPD)**| Optional vendor extension | Standardized via `INFORMATIONAL` exchange |
| **Mobility & Multihoming** | None | Supported via MOBIKE (RFC 4555) |
| **EAP Support** | Non-standard | Standardized for multi-factor/enterprise auth |
| **Recommendation** | **Strictly Prohibited** (NIST SP 800-77 Rev 1) | **Mandatory Standard** |

---

## IKEv2 Packet Exchanges & Payloads

An IKEv2 session establishes two distinct tiers of Security Associations:
1. **IKE SA (Control Plane)**: Encrypted, authenticated management channel used to negotiate and maintain IPsec SAs.
2. **Child SA (Data Plane)**: The actual IPsec ESP/AH SA carrying customer/workload traffic.

### 1. `IKE_SA_INIT` (Exchange Type 34)
Unencrypted initial negotiation between Initiator and Responder on UDP port 500:
- **Packet 1 (Initiator -> Responder)**:
  - `HDR`: Initiator SPI, Responder SPI = 0, Version 2.0, Message ID = 0.
  - `SAi1`: Cryptographic proposals for the IKE SA (Encryption, PRF, Integrity, DH Group).
  - `KEi`: Initiator Diffie-Hellman public key share.
  - `Ni`: Initiator Nonce (random entropy).
  - `N(NAT_DETECTION_SOURCE_IP)` & `N(NAT_DETECTION_DESTINATION_IP)`: Hashes of IP/port to detect NAT.
- **Packet 2 (Responder -> Initiator)**:
  - `HDR`: Initiator SPI, Responder SPI != 0.
  - `SAr1`: Responder's selected cryptographic proposal.
  - `KEr`: Responder Diffie-Hellman public key share.
  - `Nr`: Responder Nonce.
  - `CERTREQ` (optional): Certificate request for initiator verification.

*Both endpoints now independently compute the master secret (`SKEYSEED`) and derive `SK_d`, `SK_ai`, `SK_ar`, `SK_ei`, `SK_er`, `SK_pi`, `SK_pr`.*

### 2. `IKE_AUTH` (Exchange Type 35)
Encrypted and authenticated exchange establishing mutual identity and creating the first Child SA:
- **Packet 3 (Initiator -> Responder)** (Encrypted with `SK_ei`, authenticated with `SK_ai`):
  - `Encrypted Payload`:
    - `IDi`: Initiator Identity (FQDN, IPv4, RFC822 name, or DER-ASN1 DN).
    - `CERT` (optional): Initiator X.509 public key certificate.
    - `AUTH`: Digital signature (RSA/ECDSA/Ed25519) or Pre-Shared Key HMAC proving possession of private key/secret.
    - `SAi2`: Cryptographic proposal for the first Child SA (ESP transforms).
    - `TSi` / `TSr`: Traffic Selectors (source/destination subnets protected by this Child SA).
- **Packet 4 (Responder -> Initiator)** (Encrypted with `SK_er`, authenticated with `SK_ar`):
  - `Encrypted Payload`:
    - `IDr`: Responder Identity.
    - `CERT`: Responder certificate.
    - `AUTH`: Responder authentication proof.
    - `SAr2`: Accepted Child SA proposal.
    - `TSi` / `TSr`: Accepted traffic selector ranges.

### 3. `CREATE_CHILD_SA` (Exchange Type 36)
Used to rekey existing IKE SAs or Child SAs, or to create additional Child SAs.
- Includes new `KE` payload if **Perfect Forward Secrecy (PFS)** is enabled.

---

## ESP (Protocol 50) vs AH (Protocol 51)

### Encapsulating Security Payload (ESP - IP Protocol 50)
- **Provides**: Confidentiality, data integrity, anti-replay, and data origin authentication.
- **Packet Structure**:
  ```text
  ┌─────────────────┬───────────┬──────────────┬──────────────────┬───────────┬──────────────┐
  │ Outer IP Header │  ESP SPI  │ ESP Sequence │ Payload Data     │ ESP Pad & │   ESP ICV    │
  │ (cleartext)     │  (32-bit) │   (32-bit)   │ (encrypted IV +  │ Pad Len + │ (Integrity   │
  │                 │           │              │  ciphertext)     │ Next Hdr  │ Check Value) │
  └─────────────────┴───────────┴──────────────┴──────────────────┴───────────┴──────────────┘
  ```
- **NAT Compatibility**: Compatible with NAT-Traversal (UDP 4500 encapsulation).

### Authentication Header (AH - IP Protocol 51)
- **Provides**: Data integrity, data origin authentication, anti-replay. **Zero confidentiality** (plaintext payload).
- **Fatal Weakness**: AH authenticates immutable fields in the outer IP header (including IP addresses). When a packet crosses a NAT router, the IP header is modified, immediately causing AH integrity check verification failure.
- **NIST SP 800-77 Guidance**: AH is deprecated and discouraged. **Always use ESP with AEAD or combined encryption + HMAC.**

---

## Operating Modes: Tunnel vs Transport

```text
1. TRANSPORT MODE (Host-to-Host):
┌────────────────┬────────────┬──────────────────┬──────────────┐
│ Orig IP Header │ ESP Header │ Original Payload │ ESP Trlr/ICV │
└────────────────┴────────────┴──────────────────┴──────────────┘

2. TUNNEL MODE (Gateway-to-Gateway / Gateway-to-Host):
┌─────────────────┬────────────┬────────────────┬──────────────────┬──────────────┐
│ Outer IP Header │ ESP Header │ Orig IP Header │ Original Payload │ ESP Trlr/ICV │
└─────────────────┴────────────┴────────────────┴──────────────────┴──────────────┘
```

- **Transport Mode**: Protects Layer 4 payload (TCP/UDP). The original IP header remains exposed. Suitable only for end-to-end security between two known endpoint hosts.
- **Tunnel Mode**: Encapsulates the entire inner IP packet (header + payload) inside a new outer IP header. Essential for site-to-site VPNs, protecting internal network topology and routing metadata.

---

## NAT Traversal (NAT-T) Mechanics

Routers performing NAT modify source IP addresses and rewrite Layer 4 port numbers. Since ESP (Proto 50) does not have TCP/UDP port numbers, standard Port Address Translation (PAT/NAPT) drops ESP packets or fails to route return traffic.

### How NAT-T Works:
1. During `IKE_SA_INIT`, both peers send `NAT_DETECTION_SOURCE_IP` and `NAT_DETECTION_DESTINATION_IP` notify payloads (hashes of IP + port).
2. If either calculated hash does not match the received socket IP/port, a NAT device is detected in the path.
3. Both peers immediately switch communication from UDP port 500 to **UDP port 4500**.
4. Subsequent ESP packets are encapsulated inside UDP port 4500:
   - For IKE messages on port 4500: Preceded by 4 bytes of zeros (`0x00000000` Non-ESP Marker) so the receiver distinguishes IKE from ESP.
   - For ESP packets on port 4500: The 32-bit SPI immediately follows the UDP header (SPI is never `0x00000000`).
5. **Keepalive Packets**: NAT routers expire idle UDP translation tables after 30–60 seconds. The VPN client/gateway transmits 1-byte UDP keepalives (`0xFF`) every 20 seconds.

---

## Security Controls: PFS, DPD, & Anti-Replay

### 1. Perfect Forward Secrecy (PFS)
- Without PFS, Child SAs derive their session keys directly from the master `SKEYSEED` established during `IKE_SA_INIT`. If the long-term private key or initial exchange is compromised, all past Child SA sessions can be decrypted.
- **With PFS Enabled**: Every rekey and `CREATE_CHILD_SA` executes an ephemeral Diffie-Hellman exchange (`KEi` / `KEr`), generating independent, ephemeral entropy. Compromising past sessions provides zero ability to decrypt future or past traffic.
- **NIST SP 800-77 Rule**: PFS **MUST** be enforced on all Child SAs.

### 2. Dead Peer Detection (DPD)
- RFC 3706 / RFC 7296 `INFORMATIONAL` keepalives.
- Prevents "blackhole tunnels" when an ungracefully terminated peer leaves dangling SAs in the local kernel.
- Recommended configuration: `dpddelay = 30s`, `dpdtimeout = 120s`, action = `restart` or `clear`.

### 3. Anti-Replay Sliding Window
- Prevents attackers from recording valid encrypted packets and injecting them back onto the wire.
- ESP packets carry a monotonically increasing 32-bit or 64-bit Extended Sequence Number (ESN).
- Receiver maintains a sliding bitmap window (typically 64 or 128 packets wide). Packets behind the window or duplicates already marked in the window are dropped immediately.

---

## Configuration Blueprints (strongSwan swanctl.conf)

Modern strongSwan deployments use `/etc/swanctl/swanctl.conf`:

```ini
connections {
    gw-to-gw {
        version = 2
        local_addrs  = 198.51.100.1
        remote_addrs = 203.0.113.1
        proposals = aes256gcm16-prfsha384-ecp384,aes256-sha384-modp3072

        local {
            auth = pubkey
            certs = gatewayCert.pem
            id = vpn1.enterprise.net
        }
        remote {
            auth = pubkey
            id = vpn2.enterprise.net
        }

        children {
            net-to-net {
                local_ts  = 10.1.0.0/16
                remote_ts = 10.2.0.0/16
                esp_proposals = aes256gcm16-ecp384,aes256gcm16-modp3072
                rekey_time = 1h
                dpd_action = restart
                mode = tunnel
                # Enforce PFS
                esp_proposals = aes256gcm16-ecp384
            }
        }
    }
}
```

---

## IPsec Security Audit Checklist

When reviewing any active or planned IPsec implementation:

- [ ] **IKE Version**: Is IKEv2 strictly enforced? (IKEv1 disabled).
- [ ] **Cryptographic Suite**:
  - Encryption: AES-GCM (128 or 256) preferred; AES-CBC acceptable with HMAC-SHA2.
  - No deprecated algorithms: 3DES, DES, RC4, MD5, SHA-1 eliminated.
  - Diffie-Hellman: MODP >= 2048-bit (Group 14+) or ECP >= 256-bit (Group 19, 20).
- [ ] **PFS (Perfect Forward Secrecy)**: Explicitly enabled for Child SA rekeying.
- [ ] **Operating Mode**: Tunnel Mode used for site-to-site; Transport Mode only for host-to-host.
- [ ] **NAT Traversal**: Enabled and verified on port 4500 when traversing perimeter gateways.
- [ ] **Authentication**: X.509 certificates (ECDSA/RSA >= 3072-bit) preferred over shared pre-shared keys (PSK). If PSK is used, must have high entropy (> 20 characters).
- [ ] **Replay Protection**: ESN (Extended Sequence Numbers) enabled, replay window >= 64 packets.
- [ ] **DPD (Dead Peer Detection)**: Configured with active timeout and cleanup action.

