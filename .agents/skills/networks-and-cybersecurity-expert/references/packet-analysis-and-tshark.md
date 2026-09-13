# Packet Analysis, Deep Packet Inspection (DPI), and `tshark` Engineering

This reference provides command recipes, display filters, protocol dissections, and privacy-preserving
traffic profiling techniques using `tshark`, `tcpdump`, and Python.

---

## Table of Contents
1. [BPF Capture Filters vs Wireshark Display Filters](#bpf-capture-filters-vs-wireshark-display-filters)
2. [`tshark` Architecture & Key CLI Flags](#tshark-architecture--key-cli-flags)
3. [IKEv1 / IKEv2 Dissection & Proposal Extraction](#ikev1--ikev2-dissection--proposal-extraction)
4. [ESP (Proto 50) & NAT-T (UDP 4500) Dissection](#esp-proto-50--nat-t-udp-4500-dissection)
5. [TLS 1.2 / 1.3 Handshake & Cipher Suite Inspection](#tls-12--13-handshake--cipher-suite-inspection)
6. [DNS & DoH/DoT Inspection](#dns--dohdot-inspection)
7. [Zero-Decryption Encrypted Traffic Metadata Profiling](#zero-decryption-encrypted-traffic-metadata-profiling)
8. [Python & Scapy Automation Recipes](#python--scapy-automation-recipes)

---

## BPF Capture Filters vs Wireshark Display Filters

Understanding the distinction is vital for performance and accuracy:

| Aspect | Capture Filters (BPF / libpcap) | Display Filters (Wireshark / tshark) |
| :--- | :--- | :--- |
| **Execution Point** | In-kernel before packets reach user space | In user space during protocol tree dissection |
| **Performance** | Extremely fast, minimal CPU overhead | Higher CPU overhead, evaluates full protocol tree |
| **Capability** | Limited to byte offsets, ports, IP addresses, protocols | Full protocol-aware fields (e.g., `isakmp.transform.id == 14`) |
| **CLI Argument** | `-f "expression"` (in `tcpdump` / `tshark`) | `-Y "expression"` (read filter) or `-R` (two-pass) |

### Common BPF Capture Filters
```bash
# Capture IKE (500), NAT-T (4500), or native ESP (Proto 50)
"udp port 500 or udp port 4500 or proto 50"

# Capture DNS (UDP/TCP 53) and DoT (TCP 853)
"port 53 or port 853"

# Capture TCP SYN, FIN, and RST packets only
"tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) != 0"

# Exclude noisy SSH session while capturing all other traffic
"not port 22"
```

---

## `tshark` Architecture & Key CLI Flags

Essential flags for automated auditing:

| Flag | Purpose |
| :--- | :--- |
| `-r <file>` | Read packet capture from PCAP / PCAPNG file |
| `-i <interface>` | Live capture from network interface (`eth0`, `any`, `wg0`) |
| `-Y <filter>` | Apply display filter (evaluates dissected fields) |
| `-T fields` | Output text formatted as delimited fields (tab-separated by default) |
| `-e <field>` | Specific protocol field to print (can specify multiple times) |
| `-E separator=,` | Set delimiter character (e.g., `,` for CSV or `\t` for TSV) |
| `-E header=y` | Print header line with field names |
| `-q -z io,phs` | Quiet mode + Protocol Hierarchy Statistics |
| `-q -z conv,ip` | IP conversations summary (bytes, packets, bandwidth) |

---

## IKEv1 / IKEv2 Dissection & Proposal Extraction

### 1. Identify IKE Protocol Versions & Exchange Types
```bash
# Display all IKE/ISAKMP packets with exchange type and version
tshark -r capture.pcap -Y "isakmp" \
  -T fields -e frame.number -e ip.src -e ip.dst \
  -e isakmp.version -e isakmp.exchange_type
```
*Exchange Types in IKEv2*:
- `34`: `IKE_SA_INIT`
- `35`: `IKE_AUTH`
- `36`: `CREATE_CHILD_SA`
- `37`: `INFORMATIONAL`

### 2. Extract Cryptographic Transform Proposals (`IKE_SA_INIT`)
In IKEv2, the initiator proposes security parameters inside the `SA` payload.
```bash
tshark -r capture.pcap -Y "isakmp.exchange_type == 34" \
  -T fields -e frame.number -e ip.src -e ip.dst \
  -e isakmp.spis \
  -e isakmp.transform.type \
  -e isakmp.transform.id \
  -e isakmp.transform.attr.type \
  -e isakmp.transform.attr.val
```

*Transform Types (`isakmp.transform.type`)*:
- `1`: Encryption Algorithm (ENCR)
- `2`: Pseudo-random Function (PRF)
- `3`: Integrity Algorithm (INTEG)
- `4`: Diffie-Hellman Group (D-H)
- `5`: Extended Sequence Numbers (ESN)

### 3. Detect NAT-Traversal Notification Payloads
```bash
tshark -r capture.pcap -Y "isakmp.notify.type == 16388 || isakmp.notify.type == 16389" \
  -T fields -e frame.number -e ip.src -e ip.dst -e isakmp.notify.type -e isakmp.notify.data
```
- `16388`: `NAT_DETECTION_SOURCE_IP`
- `16389`: `NAT_DETECTION_DESTINATION_IP`

---

## ESP (Proto 50) & NAT-T (UDP 4500) Dissection

### 1. Native ESP Traffic Inspection
```bash
# Extract frame length, IP endpoints, SPI, and sequence numbers
tshark -r capture.pcap -Y "esp" \
  -T fields -e frame.number -e ip.src -e ip.dst -e esp.spi -e esp.sequence
```

### 2. NAT-T Encapsulated ESP (UDP 4500)
When NAT-T is active, packets are transported inside UDP port 4500:
- Non-ESP Marker: First 4 bytes are `0x00000000` for IKE control messages.
- ESP Packets: First 4 bytes contain the 32-bit SPI (never `0x00000000`).
```bash
# Filter UDP 4500 packets containing ESP payload
tshark -r capture.pcap -Y "udp.port == 4500 && !isakmp" \
  -T fields -e frame.number -e ip.src -e ip.dst -e frame.len
```

---

## TLS 1.2 / 1.3 Handshake & Cipher Suite Inspection

### 1. Extract Client Hello (SNI, Supported Ciphers & Curves)
```bash
tshark -r capture.pcap -Y "tls.handshake.type == 1" \
  -T fields -e frame.number -e ip.src -e ip.dst \
  -e tls.handshake.extensions_server_name \
  -e tls.handshake.ciphersuite \
  -e tls.handshake.extensions_supported_group \
  -e tls.handshake.extensions_alpn_str
```

### 2. Extract Server Hello (Selected Cipher Suite & TLS Version)
```bash
tshark -r capture.pcap -Y "tls.handshake.type == 2" \
  -T fields -e frame.number -e ip.src -e ip.dst \
  -e tls.handshake.version \
  -e tls.handshake.ciphersuite \
  -e tls.handshake.extensions_supported_group
```

*Key Cipher Values*:
- `0x1301`: `TLS_AES_128_GCM_SHA256` (TLS 1.3)
- `0x1302`: `TLS_AES_256_GCM_SHA384` (TLS 1.3)
- `0x1303`: `TLS_CHACHA20_POLY1305_SHA256` (TLS 1.3)
- `0xc02f`: `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (TLS 1.2)

---

## DNS & DoH/DoT Inspection

```bash
# Extract DNS queries and responses with response time
tshark -r capture.pcap -Y "dns" \
  -T fields -e frame.number -e ip.src -e ip.dst \
  -e dns.qry.name -e dns.qry.type -e dns.a -e dns.time

# Detect DNS Tunneling / Exfiltration (Look for long query lengths)
tshark -r capture.pcap -Y "dns.flags.response == 0" \
  -T fields -e dns.qry.name | awk '{ print length($0), $0 }' | sort -nr | head -n 20
```

---

## Zero-Decryption Encrypted Traffic Metadata Profiling

In compliance with enterprise privacy constraints and ethical auditing, encrypted tunnels
(such as IPsec ESP) can be fingerprinted and profiled **without decrypting payloads**:

### 1. Packet Size Histogram & Inner Payload Inference
- Small packets (~80–120 bytes): Voice over IP (VoIP / RTP) with G.711/G.729 codecs, TCP ACKs, or keepalives.
- Medium packets (~200–600 bytes): SSH keystrokes, DNS responses, interactive terminal traffic.
- Maximum Transmission Unit (MTU) packets (~1350–1500 bytes): Bulk file transfers (HTTPS, SFTP, video streaming).

### 2. Extract Packet Size & Timestamp Arrays for AI / Statistical Analysis
```bash
# Export chronological (epoch_time, frame_len, direction_src_ip)
tshark -r capture.pcap -Y "esp" \
  -T fields -e frame.time_epoch -e frame.len -e ip.src \
  -E separator=, > /tmp/esp_metadata.csv
```

### 3. Tunnel vs Transport Mode Fingerprinting
- **Tunnel Mode**: ESP packet size = Outer IP (20) + ESP Header (8) + IV (8 or 16) + Inner IP (20) + Inner Transport (TCP 20 / UDP 8) + Inner Payload + Pad (0-15) + PadLen (1) + NextHdr (1) + ICV (16).
- **Transport Mode**: Omits the 20-byte inner IP header.
- For known application packet payloads (e.g. ICMP ping request with 32-byte payload = 84 byte original IP packet), compare expected packet wire sizes:
  - Transport Mode wire size: `84 + 8(ESP) + 16(IV) + 8(Pad/Trailer) + 16(ICV) = 132 bytes`.
  - Tunnel Mode wire size: `84 + 20(Outer IP) + 8(ESP) + 16(IV) + 8(Pad/Trailer) + 16(ICV) = 152 bytes`.

---

## Python & Scapy Automation Recipes

### Parsing PCAP Packets with Scapy
```python
from scapy.all import rdpcap, IP, UDP, ESP

def analyze_capture(pcap_file: str):
    packets = rdpcap(pcap_file)
    print(f"Total packets parsed: {len(packets)}")
    
    proto_counts = {}
    esp_sizes = []
    
    for pkt in packets:
        if IP in pkt:
            proto = pkt[IP].proto
            proto_counts[proto] = proto_counts.get(proto, 0) + 1
            
            # Protocol 50 is ESP
            if proto == 50:
                esp_sizes.append(len(pkt))
            elif proto == 17: # UDP
                if pkt[UDP].dport == 4500 or pkt[UDP].sport == 4500:
                    esp_sizes.append(len(pkt))

    print(f"Protocol distribution (IP proto): {proto_counts}")
    if esp_sizes:
        avg_size = sum(esp_sizes) / len(esp_sizes)
        print(f"ESP Packets: {len(esp_sizes)}, Mean Size: {avg_size:.2f} bytes")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        analyze_capture(sys.argv[1])
```

