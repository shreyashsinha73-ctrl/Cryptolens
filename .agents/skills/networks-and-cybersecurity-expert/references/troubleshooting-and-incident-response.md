# Network Incident Response, Triage, and Forensic Troubleshooting

This document provides systematic diagnostics, root-cause analysis procedures, and incident response
workflows for network engineers and cybersecurity responders.

---

## Table of Contents
1. [Systematic Triage Methodology](#systematic-triage-methodology)
2. [Diagnosing PMTUD Blackholes & Fragmentation Issues](#diagnosing-pmtud-blackholes--fragmentation-issues)
3. [Asymmetric Routing & Stateful Drops](#asymmetric-routing--stateful-drops)
4. [IKEv2 & TLS Handshake Failure Diagnostic Matrix](#ikev2--tls-handshake-failure-diagnostic-matrix)
5. [MITRE ATT&CK Network Threat Mapping](#mitre-attck-network-threat-mapping)
6. [Forensic Evidence Acquisition & Preservation (RFC 3227)](#forensic-evidence-acquisition--preservation-rfc-3227)

---

## Systematic Triage Methodology

When a network anomaly, degradation, or outage is reported, apply the **Divide-and-Conquer** approach
across the network stack:

```
[Layer 7: Application] ── HTTP 502/504? TLS Alert? App log inspection
         │
[Layer 4: Transport]   ── SYN without SYN-ACK? RST received? ss -tunap / conntrack
         │
[Layer 3: Network]     ── Ping ok? MTU blackhole? Traceroute TTL expired? ip route
         │
[Layer 2: Data Link]   ── ARP resolved? Duplex mismatch? ip neigh / ethtool
         │
[Layer 1: Physical]    ── Carrier detected? Link flapping? RX/TX CRC errors?
```

### Layer-by-Layer Verification Commands

| Layer | Diagnostic Question | Command |
| :--- | :--- | :--- |
| **L1/L2** | Is the interface up and transmitting? | `ip -s link show eth0`<br>`ethtool eth0` |
| **L2** | Is the gateway MAC resolved in ARP cache? | `ip neigh show` |
| **L3** | Is there a valid routing table entry? | `ip route get <destination_ip>` |
| **L3** | Where in the path do packets drop? | `traceroute -I -N <destination_ip>` |
| **L4** | Is the service listening and backlog healthy? | `ss -tlpn` |
| **L4** | Is state tracking dropping invalid packets? | `conntrack -S` (check drop counter) |
| **L7** | Is the cryptographic handshake completing? | `openssl s_client -connect <host>:443` |

---

## Diagnosing PMTUD Blackholes & Fragmentation Issues

### Symptom:
A user can ping a remote host and complete a TCP 3-way handshake, but large data transfers (e.g. downloading a file, loading an enterprise web application, or running `git pull`) hang indefinitely.

### Root Cause:
The path has a reduced MTU (e.g., due to an IPsec tunnel or PPPoE). The sender sets the DF (Don't Fragment) bit. An intermediate router drops the oversized packet and generates an ICMP `Destination Unreachable / Fragmentation Needed` (Type 3, Code 4). If an intermediate firewall silently blocks all ICMP packets, the sender never receives the notification and repeatedly retransmits the dropped packet until timeout.

### Diagnostic Procedure:
1. Determine the maximum unfragmented packet size using `ping` with DF bit enabled:
   ```bash
   # Linux syntax (-M do sets DF bit; -s sets payload size excluding 28 bytes IP+ICMP header)
   ping -M do -s 1472 203.0.113.1
   ```
2. If `1472` fails with `message too long, mtu=...` or packet loss, decrement `-s` until packets pass:
   ```bash
   ping -M do -s 1400 203.0.113.1
   ping -M do -s 1380 203.0.113.1
   ```
3. Calculate actual Path MTU: $\text{PMTU} = \text{Successful Payload Size} + 28 \text{ bytes}$.
4. Remediation:
   - Allow ICMP Type 3 Code 4 through all network firewalls.
   - Clamp TCP MSS on the VPN gateway:
     ```bash
     nft add rule inet filter forward tcp flags syn tcp option maxseg size set rt mtu
     ```

---

## Asymmetric Routing & Stateful Drops

### Symptom:
Outbound traffic routes via ISP-A, but return traffic arrives on ISP-B. The firewall on ISP-B drops the traffic with `ct state invalid` because it never observed the initial TCP SYN packet.

### Diagnostic Check:
```bash
# Check if Reverse Path Filtering is dropping packets on an interface
cat /proc/sys/net/ipv4/conf/eth1/rp_filter

# Check conntrack drop counters
cat /proc/net/stat/nf_conntrack
```
### Remediation:
- Align routing policies using policy-based routing (`ip rule`, `ip route`).
- If asymmetric routing is unavoidable in a multi-homed topology, adjust `rp_filter` from `1` (strict) to `2` (loose) on the multi-homed interfaces, and ensure connection tracking is synchronized (e.g. via `conntrackd`).

---

## IKEv2 & TLS Handshake Failure Diagnostic Matrix

### IKEv2 Failure Codes

| Error / Notify Type | Wire Hex / Code | Root Cause | Remediation |
| :--- | :--- | :--- | :--- |
| `NO_PROPOSAL_CHOSEN` | 14 | Initiator and Responder have zero overlapping crypto algorithms in `SA` payload. | Verify encryption, integrity, PRF, and DH group proposals match in gateway configs. |
| `AUTHENTICATION_FAILED` | 24 | Pre-Shared Key mismatch, invalid certificate chain, or untrusted CA. | Check PSK strings for whitespace; check certificate validity (`openssl x509 -noout -dates -in cert.pem`). |
| `TS_UNACCEPTABLE` | 38 | Traffic Selectors (subnets) do not match or are not permitted by policy. | Align `local_ts` and `remote_ts` subnet masks on both peers. |
| `INVALID_SYNTAX` | 7 | Packet parsing error or corrupted payload. | Verify IPsec software versions and patch levels. |
| `COOKIE` (Response) | 16418 | Responder under DDoS load requesting stateless cookie verification. | Normal behavior under high load; ensure initiator sends back cookie. |

### TLS Alert Codes

| TLS Alert | Description | Investigation Steps |
| :--- | :--- | :--- |
| `handshake_failure (40)` | No common cipher suites or supported protocol version. | Run `nmap --script ssl-enum-ciphers -p 443 <host>` to inspect server ciphers. |
| `bad_certificate (42)` | Certificate is corrupted, signature failed, or key usage disallowed. | Check certificate extensions (`KeyUsage`, `ExtendedKeyUsage`). |
| `certificate_expired (45)` | Current timestamp is outside `notBefore` / `notAfter`. | Verify host system clock (`date`) and certificate expiration date. |
| `unknown_ca (48)` | Issuer CA is not present in local trust store. | Install root/intermediate CA in `/etc/ssl/certs/` or bundle into server chain. |

---

## MITRE ATT&CK Network Threat Mapping

Use this mapping during network incident response to classify adversary behavior:

| ATT&CK ID | Tactic / Technique | Observable Wire Artifacts | Defensive Countermeasures |
| :--- | :--- | :--- | :--- |
| **T1046** | Network Service Discovery | SYN scans, sweeping port connect attempts, sequential port probes. | Rate limiting (`nftables limit`), Suricata scan rules, honeypots. |
| **T1071.001** | Application Layer Protocol: Web (C2) | High-frequency periodic HTTP/HTTPS POSTs, jittered beaconing intervals. | TLS metadata profiling, domain reputation, JA4/JA3 fingerprinting. |
| **T1071.004** | Application Layer Protocol: DNS (C2/Exfil) | Abnormally long subdomain strings, high entropy TXT record queries. | DNS query length limits, response rate limiting (RRL), DNS sinkholing. |
| **T1572** | Protocol Tunneling | SSH, RDP, or HTTP payloads transported over non-standard ports (e.g. 53, 443). | Deep packet inspection (Zeek protocol detection), strict layer-7 application proxies. |
| **T1048.003** | Exfiltration Over Alternative Protocol | Outbound ICMP payloads with non-standard bytes, large ESP egress bursts. | Block ICMP payloads > 64 bytes; enforce strict egress filtering. |

---

## Forensic Evidence Acquisition & Preservation (RFC 3227)

When capturing traffic during an active cybersecurity incident:

1. **Order of Volatility (RFC 3227)**:
   - CPU caches, registers -> Routing tables, ARP cache, kernel memory -> Network connections -> Disk.
2. **Preservation Command Sequence**:
   ```bash
   TIMESTAMP=$(date +%Y%m%d_%H%M%S)
   mkdir -p /var/log/forensics_${TIMESTAMP}
   
   # 1. Capture active sockets & connections
   ss -tunapo > /var/log/forensics_${TIMESTAMP}/sockets.txt
   
   # 2. Capture routing and neighbors
   ip route show table all > /var/log/forensics_${TIMESTAMP}/routes.txt
   ip neigh show > /var/log/forensics_${TIMESTAMP}/arp.txt
   
   # 3. Capture firewall state
   nft list ruleset > /var/log/forensics_${TIMESTAMP}/nftables.txt
   
   # 4. Stream raw packets to disk with ring-buffer
   tcpdump -i any -s 0 -W 5 -C 100 -w /var/log/forensics_${TIMESTAMP}/traffic.pcap
   ```
3. **Evidence Integrity**: Immediately calculate and log cryptographic hashes (SHA-256) for all generated PCAP and log files:
   ```bash
   sha256sum /var/log/forensics_${TIMESTAMP}/* > /var/log/forensics_${TIMESTAMP}/checksums.sha256
   ```

