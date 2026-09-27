# CryptoLens: An AI-Driven IPsec Protocol Analysis & Security Assessment Platform
### SIH 2026 — Team Solution Document (v3)

---

## 1. Problem We're Solving

IPsec secures the backbone of enterprise, government, military, and cloud networks — but its actual security depends entirely on *how* it's configured: cipher choice, DH group strength, PFS, operating mode, replay protection, and metadata exposure. A misconfigured "secure" tunnel looks identical to a hardened one on the wire.

Today, verifying that posture means a security engineer manually reading Wireshark traces — interpreting multi-phase IKE handshakes by hand, and once ESP encryption kicks in, losing all visibility into the inner traffic entirely. There is no tool that **automatically infers configuration quality from traffic and scores it against real compliance baselines**, without needing the private keys.

**CryptoLens does three things no existing tool does together:**
1. Parses IKE handshakes explicitly where visible (deterministic, ground-truth accurate).
2. **Infers** tunnel mode, transport mode, and inner application type from *encrypted* ESP traffic alone, using an external AI inference API (analyzing metadata, not payloads) — no decryption, no keys.
3. Converts that inference into a quantified, standards-referenced security score with actionable remediation — not just a Wireshark dump.

---

## 2. What We're Actually Building for the Hackathon (MVP)

We are explicitly scoping this into a **demoable MVP** and a **post-hackathon roadmap**. 

| Component | MVP (built, demoed live) | Roadmap (designed, future work) |
|---|---|---|
| Testbed | strongSwan in Docker + Linux netns, **6 core configs** (Tunnel/Transport × AES-GCM/AES-CBC+SHA1/3DES, 2 DH groups, PFS on/off), plus a scripted **active replay-injection test**. | Full config matrix incl. IPv6 dual-stack, all 6 DH groups, RFC 9370 PQC hybrid exchange |
| Traffic gen | curl (HTTPS), Scapy (SIP/VoIP), ping (ICMP) — 3 traffic types | Full set: WhatsApp-pattern media, SMTP/IMAP, video streaming (DASH) |
| Control-plane engine | tshark + custom parser → JSON AST → deterministic rule engine | Full IKEv1 Aggressive Mode edge cases, malformed-packet resilience |
| Data-plane engine | Feature extraction (packet length + inter-arrival times) → **JSON Batch Payload** → **Cloud AI API** → Tunnel vs Transport + 3-class inner traffic | Implement local edge models to completely eliminate API latency |
| Scoring engine | Full weighted formula (below), all 5 sub-scores live | Configurable weight profiles per compliance regime (NIST vs CNSA vs ISO 27001) |
| Reporting | Single-page PDF (risk score, threat table, top 3 remediations) via lightweight HTML→PDF pipeline | Full Executive + Technical dual-report suite, WeasyPrint templating |
| Dashboard | React SPA: live score dial, per-tunnel breakdown, confidence bar | Real-time WebSocket streaming, historical trend graphs, multi-tunnel fleet view |
| Deployment | `docker-compose up` — single command | Kubernetes, DPDK zero-copy ingestion for line-rate live capture |

---

## 3. System Architecture

```text
┌─────────────────────────────────────────────────────────────────────┐
│  STAGE 1 — Testbed: strongSwan in Docker/netns, Jinja2-templated    │
│  swanctl.conf, traffic injectors (curl/Scapy/ping),                 │
│  active replay-injection harness                                    │
└───────────────────────────────┬─────────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STAGE 2 — Capture & Demux: tshark ingestion, split by port         │
│  UDP 500/4500 (IKE control) vs IP proto 50 (ESP data)               │
└───────────────────────────────┬─────────────────────────────────────┘
                                ▼
┌───────────────────────┬───────────────────────────────────────────┐
│  Control Track        │  Data Track                               │
│  Parse SA/KE/Nonce/   │  Feature engineer: packet-length sequence │
│  Transform payloads   │  (S_L), inter-arrival times (S_IAT)       │
│  → explicit cipher,   │  → JSON Batch Formatting                  │
│  DH group, PRF (AST), │  → Async call to AI API                   │
│  identity exposure    │  → Inference: Mode + Inner traffic class  │
└───────────┬───────────┴──────────────────┬────────────────────────┘
            └──────────────┬───────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STAGE 3 — Security Scoring Engine                                  │
│  Deterministic weighted formula → S_sec (0–100) + Threat Matrix     │
│  mapped to NIST SP 800-77 Rev 1 / NSA CNSA 2.0                      │
└───────────────────────────────┬─────────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STAGE 4 — Dashboard (React) + PDF Report Generator                 │
└─────────────────────────────────────────────────────────────────────┘
```

**Precision note:** The AI fallback path is triggered when the control-plane capture is *missing, truncated, or begins mid-session* (e.g., capture starts after `IKE_SA_INIT`). When explicit IKEv2 negotiation is available, the deterministic control track takes precedence to save API calls and ensure 100% accuracy.

---

## 4. AI Engine Detail (API-Driven Inference)

Instead of training a local model, we utilize an external AI API to analyze structural network metadata. 

| Task | Methodology | Input | Why this approach |
|---|---|---|---|
| IKE version, cipher, DH group | Rules engine | Parsed handshake AST (JSON) | Explicit data is available — deterministic parsing is faster, completely accurate, and requires zero API calls. |
| Tunnel vs. Transport mode | API Prompt Engineering | First 30 packet lengths ($S_L$) formatted as JSON | Tunnel mode adds a consistent structural size offset (ΔS ≈ 20–40 bytes). An AI can easily classify this offset from numerical sequences via prompt instructions. |
| Inner traffic type (HTTPS/VoIP/ICMP) | API Prompt Engineering | $S_L$, $S_{IAT}$ grouped in time-windows | Length+timing rhythms differ sharply by app type. We structure this telemetry into a token-efficient text prompt for the API to classify. |

**API Optimization & Constraints:**
- **Asynchronous Batching:** To avoid rate limits and latency bottlenecks, packet sequences are buffered and sent to the API in asynchronous batches. 
- **Context Window Management:** We only send the first $N$ packets of a session (e.g., $N=30$) to establish the baseline signature, ensuring minimal token usage and fast API response times.
- **Honesty about limits:** Classifier accuracy assumes no active traffic-shaping or padding countermeasures by the endpoint. We state this explicitly in the technical report.

---

## 5. Security Scoring Algorithm

```text
S_sec = 100 × (0.30·C_score + 0.25·K_score + 0.15·M_score + 0.15·E_score + 0.15·PQC_score)
S_risk = 100 − S_sec
```

| Sub-score | Weight | Logic |
|---|---|---|
| **C_score** — Cipher strength | 0.30 | AES-256-GCM = 1.0, AES-128-GCM = 0.85, AES-256-CBC+SHA256 = 0.75, AES-CBC+SHA1 = 0.40, 3DES/MD5 = 0.0 |
| **K_score** — Key exchange | 0.25 | DH ≥ Group 14 (2048-bit+) = 1.0, Group 5 (1536-bit) = 0.5, Group 2 (1024-bit) = 0.0 |
| **M_score** — Mode & PFS | 0.15 | Baseline 1.0; −0.40 if PFS disabled; −0.20 if Transport mode used on a WAN-facing link |
| **E_score** — Metadata exposure | 0.15 | Baseline 1.0; −0.30 if Transport mode exposes inner IP headers; −0.30 if IKE identity payload sent in cleartext; −0.20 if SPI values are sequential; −0.20 if no NAT-T |
| **PQC_score** — Quantum readiness | 0.15 | RFC 9370 hybrid (classical+ML-KEM) = 1.0, RFC 8784 PSK-PQ = 0.6, classical-only = 0.2 |

**Replay protection** is reported separately as an **active test module** (scripted duplicate-packet injection against our own lab tunnels) rather than guessed passively.

---

## 6. Tech Stack 

| Layer | Choice | Why (not just "modern") |
|---|---|---|
| Testbed | strongSwan + Docker/netns | Only mature open-source IPsec daemon with full IKEv1/v2 + RFC 9370 support |
| Capture | tshark / PyPcapKit | Battle-tested dissection, no need to reinvent packet parsing |
| AI Inference | Cloud AI API + `asyncio` | Offloads complex pattern recognition; async handling prevents pipeline blocking during network calls |
| Backend | FastAPI | Async I/O for concurrent capture-analysis jobs and API requests |
| Frontend | React + Recharts | Fast to build a convincing live dashboard |
| Reporting | Jinja2 → HTML → PDF | Templated, avoids building a PDF layout engine from scratch |

---

## 7. Live Demo Script 

1. **Baseline good tunnel:** Spin up strongSwan tunnel live with AES-256-GCM, DH Group 19, PFS on. Run HTTPS + VoIP traffic through it.
2. **Capture & analyze:** Feed the live capture into CryptoLens. Dashboard populates in real time — score ≈ 90+/100.
3. **Bad tunnel, live comparison:** Reconfigure with 3DES + DH Group 2 + PFS off + Aggressive Mode. Re-run traffic.
4. **Score collapse:** Dashboard shows score drop sharply, threat matrix lights up CRITICAL on cipher/key exchange, PDF report auto-generates with exact remediation.
5. **Encrypted-only inference:** Show a third capture withholding the IKE handshake. CryptoLens packages the sequence metadata, queries the API, and correctly infers Tunnel Mode + VoIP traffic from ESP alone.
6. **Active replay test:** Trigger the scripted duplicate-packet injection and show the "Replay protection: confirmed" flag populate.

---

## 8. Differentiators

- **Not another Wireshark wrapper** — we score, not just parse.
- **Works without decryption keys** — inference-based mode/traffic classification via API payload analysis.
- **Standards-anchored, not arbitrary** — every score component maps to a named NIST/NSA clause.
- **Post-quantum aware** — CNSA 2.0 and RFC 9370 readiness scoring.
- **Metadata-exposure aware** — we score identity/topology leakage separately from cipher strength.

---

## 9. Ethical Scoping & Data Privacy

- **Authorized Audit Scope:** CryptoLens is strictly a self-assessment tool intended for an organization to evaluate its own authorized IPsec deployments. It is not built for third-party interception.
- **Zero-Payload API Privacy:** To protect sensitive network data, we do **not** send actual packet payloads or IP addresses to the external AI API. The AI engine receives strictly structural metadata (packet lengths represented as integers and inter-arrival times as floats). No plaintext data ever leaves the local environment.

---

## 10. Deliverables

1. Working Dockerized prototype (`docker-compose up`) — testbed + inference middleware + dashboard.
2. API integration middleware (prompt templates, batching logic, and response parsers).
3. React dashboard with live risk scoring and threat matrix.
4. Auto-generated PDF security report (sample: 1-page executive + appendix technical detail).
5. Demo video.
6. Technical documentation: architecture, API spec, limits, and validation methodology.
7. Labeled PCAP dataset used for testing the API prompts.

---

## 11. Risk & Mitigation 

| Risk | Mitigation |
|---|---|
| API rate limits or network latency during the live demo | Implement asynchronous batching for API requests; utilize a local cache (e.g., storing known sequence signatures) to bypass the API for identical traffic patterns. |
| Docker/netns environment fails live at venue | Pre-recorded fallback capture + cached API inference results as a backup path. |
| Judges probe "isn't this a privacy risk to use an API?" | Section 9 is prepared as a direct answer: we only send integers (sizes/times), completely stripping IPs, headers, and payloads before the API call. |
