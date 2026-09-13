---
name: networks-and-cybersecurity-expert
description: >-
  Comprehensive guide and operational toolkit for network protocol analysis, cybersecurity auditing,
  cryptographic compliance, packet inspection, and infrastructure defense. Always activate this skill
  whenever the user asks about network protocols (IPsec, IKEv1/IKEv2, WireGuard, TLS, TCP/UDP, BGP, DNS),
  packet analysis or PCAP inspection (tshark, tcpdump, Wireshark, scapy), cryptographic standards
  (NIST SP 800-77, NIST SP 800-52, CNSA 1.0/2.0, post-quantum cryptography), network hardening
  (firewalls, nftables, iptables, Linux sysctl security parameters), VPN configuration, network incident
  response, threat modeling (MITRE ATT&CK), or network latency/MTU troubleshooting, even if the user
  only asks for basic command syntax or configuration advice.
---

# Networks & Cybersecurity Expert

This skill provides operational blueprints, standard operating procedures (SOPs), decision trees,
and deterministic tools for network architecture, packet analysis, cryptographic auditing, and
system defense.

---

## Operating Principles & Safety Boundaries

1. **Defensive & Auditing Posture**: All procedures focus on security assessment, compliance validation,
   hardening, monitoring, and authorized troubleshooting. Never supply exploit code or engage in
   unauthorized penetration testing.
2. **Metadata-First & Privacy Preservation**: When auditing encrypted traffic (e.g., ESP, TLS), prioritize
   metadata (packet sizes, directionality, timing, cleartext headers) over invasive payload inspection.
   Never transmit plaintexts, keys, or Personally Identifiable Information (PII).
3. **Progressive Disclosure**: Keep this primary directive lean. Detailed technical specifications,
   cipher matrices, and deep packet recipes are modularized in [references/](file:///home/yugpo/SIH/Cryptolens/.agents/skills/networks-and-cybersecurity-expert/references/).
   Deterministic verification tools are in [scripts/](file:///home/yugpo/SIH/Cryptolens/.agents/skills/networks-and-cybersecurity-expert/scripts/).

---

## Core Decision Trees & Operational Workflows

```
User Query / Task
│
├── "Analyze PCAP / packet capture / tshark / tcpdump"
│   └── Follow Workflow 1: Packet & Traffic Inspection
│       ├── Read: references/packet-analysis-and-tshark.md
│       └── Run: scripts/inspect_pcap.py
│
├── "Audit crypto / check IPsec / IKEv2 / cipher suite / NIST / CNSA"
│   └── Follow Workflow 2: Cryptographic Compliance Auditing
│       ├── Read: references/cryptographic-compliance-standards.md
│       ├── Read: references/ipsec-and-ike-protocols.md
│       └── Run: scripts/audit_crypto_compliance.py
│
├── "Harden network / configure firewall / sysctl / Zero Trust"
│   └── Follow Workflow 3: Network Defense & Hardening
│       └── Read: references/network-hardening-and-defense.md
│
└── "Troubleshoot connection / packet loss / MTU / slow VPN / handshake failure"
    └── Follow Workflow 4: Network Incident Triage & Troubleshooting
        └── Read: references/troubleshooting-and-incident-response.md
```

---

## Workflow 1: Packet & Traffic Inspection

When investigating captures or live network flows:

1. **Identify the Protocol & Layer**:
   - Transport: UDP (500 for IKE, 4500 for NAT-T, 51820 for WireGuard, 53 for DNS), TCP (443 for TLS, 22 for SSH).
   - Encapsulation: Protocol 50 (ESP), Protocol 51 (AH), Protocol 47 (GRE).
2. **Extract Cleartext Handshake Metadata**:
   - For IKEv2: Extract initiator/responder SPIs, Message ID, Security Association (SA) payloads,
     Transform attributes (Encryption, PRF, Integrity, DH Group).
   - For TLS: Extract Client Hello (SNI, cipher suites, supported elliptic curves, ALPN), Server Hello (chosen cipher suite, key share), Certificate chain.
3. **Analyze Encrypted Data Plane Without Decryption**:
   - Compute packet length distribution (mean, variance, mode).
   - Compute inter-arrival time (IAT) variance and burst profiles.
   - Detect tunnel operating mode: Tunnel Mode adds an outer IP header (20 bytes for IPv4, 40 bytes for IPv6) + ESP header (8 bytes) + IV + padding + ICV. Transport Mode keeps original IP header.
4. **Tool Execution**:
   - Use `tshark` for non-interactive extraction (see recipes below).
   - Use [scripts/inspect_pcap.py](file:///home/yugpo/SIH/Cryptolens/.agents/skills/networks-and-cybersecurity-expert/scripts/inspect_pcap.py) for automated summary statistics.
   - For complete filter syntax and protocol dissection recipes, consult [references/packet-analysis-and-tshark.md](file:///home/yugpo/SIH/Cryptolens/.agents/skills/networks-and-cybersecurity-expert/references/packet-analysis-and-tshark.md).

---

## Workflow 2: Cryptographic Compliance Auditing

When assessing cryptographic security (e.g., for IPsec tunnels, VPN gateways, or TLS servers):

1. **Collect the Cryptographic Suite Parameters**:
   - Encryption Algorithm (e.g., `AES-CBC-128`, `AES-GCM-256`, `ChaCha20-Poly1305`, `3DES`)
   - Integrity / HMAC Algorithm (e.g., `HMAC-SHA2-256`, `HMAC-SHA1`, `HMAC-MD5`)
   - Diffie-Hellman / Key Exchange Group (e.g., Group 14 [2048-bit MODP], Group 19 [256-bit ECP], Group 2 [1024-bit MODP])
   - Pseudo-Random Function (PRF) (e.g., `PRF_HMAC_SHA2_256`, `PRF_HMAC_MD5`)
2. **Evaluate Against Target Standard**:
   - **NIST SP 800-77 Rev 1 (Enterprise / Federal)**:
     - *Approved Encryption*: AES-GCM (128/256), AES-CBC (128/256), AES-CTR.
     - *Legacy / Acceptable*: 3DES is completely deprecated; AES-128 is minimum acceptable.
     - *Approved DH Groups*: Minimum 2048-bit MODP (Group 14) or 256-bit ECDH (Group 19). Groups 1, 2, 5 (< 2048-bit) are strictly non-compliant.
     - *Integrity*: SHA-2 family (SHA-256, SHA-384, SHA-512). MD5 and SHA-1 are prohibited.
   - **CNSA 2.0 (Commercial National Security Algorithm Suite - Quantum Resistant)**:
     - Requires transition to post-quantum algorithms: AES-256 (symmetric), SHA-384/SHA-512 (hashing), ML-KEM/Kyber or stateful hash-based signatures (LMS/XMSS), or minimum 384-bit curves (Group 20).
3. **Automated Verification**:
   - Run: `python3 scripts/audit_crypto_compliance.py --enc <ALGO> --int <ALGO> --dh <GROUP> --prf <PRF>`
   - Review comprehensive compliance matrix in [references/cryptographic-compliance-standards.md](file:///home/yugpo/SIH/Cryptolens/.agents/skills/networks-and-cybersecurity-expert/references/cryptographic-compliance-standards.md).

---

## Workflow 3: Network Defense & Infrastructure Hardening

When designing or securing network perimeter and host stacks:

1. **Host-Level Kernel Network Hardening**:
   - Apply `sysctl` hardening to drop spoofed packets (Reverse Path Filtering), disable ICMP redirects,
     enable SYN cookies against SYN floods, and log Martian packets.
   - See [references/network-hardening-and-defense.md](file:///home/yugpo/SIH/Cryptolens/.agents/skills/networks-and-cybersecurity-expert/references/network-hardening-and-defense.md#linux-kernel-network-hardening) for production `/etc/sysctl.d/99-security.conf`.
2. **Firewall Policy (nftables / iptables)**:
   - Default DROP on `input` and `forward` chains.
   - Strict stateful connection tracking: accept `ct state { established, related }`, drop `ct state invalid`.
   - Explicit ingress allowlists; clamp MSS on VPN interfaces to prevent fragmentation.
3. **Zero Trust Network Architecture (ZTNA)**:
   - Assume perimeter breach. Enforce micro-segmentation, continuous mutual authentication (mTLS / 802.1X),
     and least-privilege egress filtering.
   - Reference: [references/network-hardening-and-defense.md](file:///home/yugpo/SIH/Cryptolens/.agents/skills/networks-and-cybersecurity-expert/references/network-hardening-and-defense.md#zero-trust-architecture).

---

## Workflow 4: Network Incident Triage & Troubleshooting

When diagnosing connectivity, latency, packet loss, or VPN stability issues:

1. **Determine the Failure Layer**:
   - Layer 1/2: Physical link, carrier loss, ARP resolution (`ip neigh`, `arping`).
   - Layer 3: Routing table, default gateway, Path MTU blackholes (`ip route`, `traceroute -T`, `ping -M do -s <size>`).
   - Layer 4: Port availability, connection states, firewall drops (`ss -tunap`, `nc -zv`, `conntrack -L`).
   - Layer 7 / Security: Handshake stalls (IKE proposal mismatch, TLS certificate expiration, cipher incompatibility).
2. **Execute MTU / PMTUD Diagnosis**:
   - If large packets fail but `ping` works: Path MTU Discovery is broken because ICMP type 3 code 4 (Fragmentation Needed)
     is dropped by upstream firewalls.
   - Remediation: Apply TCP MSS Clamping on the firewall/gateway (`tcp flags syn tcp option maxseg size set rt mtu`).
3. **Follow the Troubleshooting Playbook**:
   - Check [references/troubleshooting-and-incident-response.md](file:///home/yugpo/SIH/Cryptolens/.agents/skills/networks-and-cybersecurity-expert/references/troubleshooting-and-incident-response.md)
     for step-by-step diagnostic flowcharts and incident escalation guides.

---

## Essential CLI Tooling Quick Reference

### 1. `tshark` Command Recipes

```bash
# Summarize protocols in capture
tshark -r capture.pcap -q -z io,phs

# Extract IKEv2 SA handshake proposals
tshark -r capture.pcap -Y "isakmp.version == 2" \
  -T fields -e frame.number -e ip.src -e ip.dst -e isakmp.exchange_type \
  -e isakmp.spis -e isakmp.transform.type -e isakmp.transform.id

# Extract TLS Server Hello cipher suites & versions
tshark -r capture.pcap -Y "tls.handshake.type == 2" \
  -T fields -e frame.time -e ip.src -e ip.dst -e tls.handshake.ciphersuite -e tls.handshake.version

# Isolate ESP encrypted traffic and compute packet sizes
tshark -r capture.pcap -Y "esp" -T fields -e frame.len -e esp.spi
```

### 2. `tcpdump` Capture Recipes

```bash
# Capture IKE and NAT-T traffic with full packet payloads
tcpdump -nn -i any "udp port 500 or udp port 4500" -w ike_traffic.pcap

# Capture ESP traffic without DNS resolution
tcpdump -nn -i any "proto 50" -c 1000 -w esp_traffic.pcap

# Capture TCP SYN/RST packets to identify rejected connections
tcpdump -nn -i any "tcp[tcpflags] & (tcp-syn|tcp-rst) != 0"
```

### 3. Linux Network Inspection (`ip`, `ss`, `nft`)

```bash
# Inspect all listening and established sockets with PID/process
ss -tunap

# Inspect active IPsec Security Associations and Policies (XFRM)
ip xfrm state
ip xfrm policy

# Monitor live packet drops via nftables trace
nft monitor trace
```

---

## Reference Library Directory

Consult the following bundled references for specialized domains:

| Reference File | Domain / Contents |
| :--- | :--- |
| [references/ipsec-and-ike-protocols.md](file:///home/yugpo/SIH/Cryptolens/.agents/skills/networks-and-cybersecurity-expert/references/ipsec-and-ike-protocols.md) | IKEv1/IKEv2 handshakes, ESP/AH mechanics, strongSwan configs, NAT-T, DPD, PFS |
| [references/packet-analysis-and-tshark.md](file:///home/yugpo/SIH/Cryptolens/.agents/skills/networks-and-cybersecurity-expert/references/packet-analysis-and-tshark.md) | tshark/tcpdump filters, field extraction, encrypted traffic metadata profiling |
| [references/cryptographic-compliance-standards.md](file:///home/yugpo/SIH/Cryptolens/.agents/skills/networks-and-cybersecurity-expert/references/cryptographic-compliance-standards.md) | NIST SP 800-77 Rev 1, CNSA 2.0 PQC migration, approved/deprecated cipher suites |
| [references/network-hardening-and-defense.md](file:///home/yugpo/SIH/Cryptolens/.agents/skills/networks-and-cybersecurity-expert/references/network-hardening-and-defense.md) | Linux kernel network hardening (`sysctl`), `nftables` templates, Zero Trust architecture |
| [references/troubleshooting-and-incident-response.md](file:///home/yugpo/SIH/Cryptolens/.agents/skills/networks-and-cybersecurity-expert/references/troubleshooting-and-incident-response.md) | Systematic triage playbooks, MTU blackholes, routing loops, MITRE ATT&CK mapping |

## Bundled Helper Scripts

| Script | Purpose |
| :--- | :--- |
| [scripts/audit_crypto_compliance.py](file:///home/yugpo/SIH/Cryptolens/.agents/skills/networks-and-cybersecurity-expert/scripts/audit_crypto_compliance.py) | Deterministic NIST SP 800-77 & CNSA 2.0 compliance evaluation for cipher suites |
| [scripts/inspect_pcap.py](file:///home/yugpo/SIH/Cryptolens/.agents/skills/networks-and-cybersecurity-expert/scripts/inspect_pcap.py) | Standalone PCAP protocol summary, flow metrics, and metadata extraction |
