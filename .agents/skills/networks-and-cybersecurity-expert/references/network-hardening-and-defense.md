# Network Infrastructure Hardening & Defense-in-Depth

This document provides production configuration templates, kernel parameters, firewall rulesets,
and architecture patterns for hardening network nodes, gateways, and Linux hosts.

---

## Table of Contents
1. [Defense-in-Depth Architecture](#defense-in-depth-architecture)
2. [Linux Kernel Network Hardening (`sysctl`)](#linux-kernel-network-hardening-sysctl)
3. [Modern `nftables` Stateful Firewall Ruleset](#modern-nftables-stateful-firewall-ruleset)
4. [Zero Trust Network Architecture (ZTNA)](#zero-trust-network-architecture-ztna)
5. [TCP MSS Clamping for VPN Gateways](#tcp-mss-clamping-for-vpn-gateways)
6. [Intrusion Detection & Prevention (Suricata / Zeek)](#intrusion-detection--prevention-suricata--zeek)

---

## Defense-in-Depth Architecture

Securing network assets requires layering controls across multiple operational boundaries:
```text
┌────────────────────────────────────────────────────────┐
│ Edge / Perimeter: DDoS Mitigation, BGP RPKI, CDN/WAF   │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│ Gateway / Router: Stateful Firewall (nftables), IPsec  │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│ Segment / VLAN: Micro-segmentation, 802.1X, Private VLAN│
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│ Host: Kernel sysctl tuning, local firewall, IDS/IPS    │
└────────────────────────────────────────────────────────┘
```

---

## Linux Kernel Network Hardening (`sysctl`)

Save the following configuration to `/etc/sysctl.d/99-network-security.conf` and apply with `sysctl --system`:

```ini
# ====================================================================
# Linux Kernel Network Hardening - Production Profile
# ====================================================================

# 1. IP Spoofing Protection (Strict Reverse Path Filtering)
# Drops incoming packets whose source IP does not match the reverse route
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# 2. SYN Flood Protection via SYN Cookies
# Generates cryptographic cookie when SYN backlog overflows
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_synack_retries = 2

# 3. Prevent IP Source Routing
# Rejects packets with user-specified routing paths (prevents perimeter evasion)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# 4. Reject ICMP Redirects (Prevents MITM Routing Attacks)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Do not send ICMP redirects to other nodes
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# 5. Ignore Broadcast / Multicast ICMP Echo Requests (Prevents Smurf Attacks)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# 6. Ignore Bogus ICMP Error Responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# 7. Log "Martian" Packets (Packets with Impossible Source Addresses)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# 8. TCP Time-Wait & Resource Protection
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_rfc1337 = 1

# 9. TCP Window Scaling & SACK (Performance + Robustness)
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_sack = 1

# 10. Disable IPv6 Router Advertisements (if statically configured)
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
```

---

## Modern `nftables` Stateful Firewall Ruleset

`nftables` is the modern Linux successor to `iptables`. Place in `/etc/nftables.conf`:

```text
flush ruleset

table inet filter {
    # Set of allowed management IPs (e.g., Jump Host / Admin VPN)
    set admin_v4 {
        type ipv4_addr
        elements = { 10.0.0.50, 192.168.1.10 }
    }

    chain input {
        type filter hook input priority filter; policy drop;

        # 1. Accept localhost loopback traffic
        iifname "lo" accept

        # 2. State tracking: Accept established/related flows, drop invalid
        ct state established,related accept
        ct state invalid drop

        # 3. Rate-limited ICMP (Echo Request & Path MTU discovery)
        ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 5/second accept
        ip6 nexthdr icmpv6 icmpv6 type { echo-request, destination-unreachable, packet-too-big, time-exceeded } limit rate 5/second accept

        # 4. Ingress IPsec / VPN Handshake Ports
        udp dport 500 accept comment "IKEv2 Key Exchange"
        udp dport 4500 accept comment "IPsec NAT-Traversal"
        ip protocol esp accept comment "Encapsulating Security Payload (ESP)"

        # 5. SSH Access (restricted to admin set, rate-limited)
        ip saddr @admin_v4 tcp dport 22 ct state new limit rate 3/minute accept

        # 6. Public Web Services (HTTPS)
        tcp dport 443 accept
    }

    chain forward {
        type filter hook forward priority filter; policy drop;

        # Allow established forward traffic
        ct state established,related accept

        # Forward IPsec tunnel subnets
        ip saddr 10.10.0.0/16 ip daddr 10.20.0.0/16 accept
        ip saddr 10.20.0.0/16 ip daddr 10.10.0.0/16 accept
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}
```

---

## Zero Trust Network Architecture (ZTNA)

Per NIST SP 800-207, perimeter-only defenses are obsolete. Core implementation pillars:

1. **Verify Explicitly**:
   - Every request is authenticated and authorized using all available data points (identity, device health, location, workload).
   - Use mutual TLS (mTLS) with short-lived certificates for inter-service communication.
2. **Least Privilege Access**:
   - Limit access using Just-In-Time (JIT) and Just-Enough-Access (JEA) policies.
   - Restrict east-west network traffic between pods, containers, and VMs via micro-segmentation.
3. **Assume Breach**:
   - Segment networks into micro-zones.
   - Encrypt all traffic in transit (IPsec or WireGuard for overlay networks; TLS 1.3 for application tier).
   - Collect and analyze end-to-end telemetry (flow logs, handshake audit logs).

---

## TCP MSS Clamping for VPN Gateways

When packets traverse an IPsec tunnel, the addition of the outer IP header (20B), ESP header (8B), IV (16B),
padding (0–15B), and ICV (16B) reduces the effective Path MTU (typically from 1500 bytes to ~1420 bytes).

If the client sets the "Don't Fragment" (DF) bit and an intermediate router cannot forward the packet,
it sends an ICMP `Packet Too Big / Fragmentation Needed` (Type 3, Code 4). If firewalls block this ICMP packet,
a **Path MTU blackhole** occurs: small packets (`ping`, HTTP handshake) succeed, but large responses hang indefinitely.

### Solution: Clamp TCP MSS in `nftables`
```text
table inet filter {
    chain forward {
        type filter hook forward priority filter;
        # Automatically clamp MSS to interface MTU minus headers
        tcp flags syn tcp option maxseg size set rt mtu
    }
}
```

Or via `iptables`:
```bash
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```

---

## Intrusion Detection & Prevention (Suricata / Zeek)

### Suricata Signature Example: Detecting Insecure IKEv1 Aggressive Mode
```text
alert udp any 500 -> any 500 (msg:"SECURITY-ATTACK IKEv1 Aggressive Mode Attempt (Vulnerable to Offline PSK Cracking)"; \
  content:"|01 10 04|"; offset:16; depth:3; \
  classtype:attempted-recon; sid:1000001; rev:1;)
```

### Zeek Script Example: Detecting Weak SSL/TLS Ciphers
```zeek
event ssl_server_hello(c: connection, version: count, record_version: count,
                       possible_ts: time, server_random: string,
                       session_id: string, cipher: count, comp_method: count)
    {
    # 0x000a = TLS_RSA_WITH_3DES_EDE_CBC_SHA
    if ( cipher == 0x000a )
        {
        NOTICE([$note=Notice::Action,
                $msg=fmt("Weak 3DES Cipher negotiated by %s to %s", c$id$orig_h, c$id$resp_h),
                $conn=c]);
        }
    }
```

