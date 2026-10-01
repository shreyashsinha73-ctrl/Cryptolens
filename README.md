# CryptoLens

> **AI-Driven IPsec Protocol Analysis and Automated Security Assessment Platform**

![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)
![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)
![ONNX Runtime](https://img.shields.io/badge/ONNX_Runtime-005CED?style=for-the-badge&logo=onnx&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Python](https://img.shields.io/badge/Python_3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PyTorch](https://img.shields.io/badge/PyTorch-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)

---

## Table of Contents

- [Executive Overview](#executive-overview)
- [Demo Video](#demo-video)
- [Architecture Pipeline](#architecture-pipeline)
- [Analysis Lifecycle](#analysis-lifecycle)
- [Control-Plane Parser](#control-plane-parser)
- [Data-Plane AI Classifier](#data-plane-ai-classifier)
- [Dual-Track Agreement Logic](#dual-track-agreement-logic)
- [Security Scoring Engine](#security-scoring-engine)
- [Standards Compliance Engine](#standards-compliance-engine)
- [SOC Dashboard](#soc-dashboard)
- [Ground-Truth Testbed Matrix](#ground-truth-testbed-matrix)
- [Quick Start](#quick-start)
- [Running Verification and Tests](#running-verification-and-tests)
- [API Reference](#api-reference)
- [PCAP Demultiplexer](#pcap-demultiplexer)
- [Ethical Scoping and Privacy Guarantees](#ethical-scoping-and-privacy-guarantees)
- [Project Team and SIH 2026 Domains](#project-team-and-sih-2026-domains)

---

## Executive Overview

**The Problem:** Misconfigured IPsec tunnels often appear fully secure on the wire (encrypted ESP packets with valid sequence numbers) while silently employing deprecated cryptographic algorithms (e.g., 3DES, MD5, SHA-1), vulnerable Diffie-Hellman groups (<2048-bit modulus), or operating without Perfect Forward Secrecy (PFS). Auditing these tunnels passively, without access to private endpoint keys or credentials, has traditionally been impossible.

**The CryptoLens Solution:** CryptoLens is a dual-track security auditing and compliance evaluation platform for IPsec networks that operates with zero decryption. It combines three core subsystems:

1. **Deterministic Control-Plane Parser** -- Dissects cleartext IKEv1/IKEv2 handshakes (RFC 7296 / RFC 2409) using a dual-engine architecture (`tshark` dissector + pure-Python binary unpacker) to reconstruct cryptographic proposals with mathematical precision.
2. **Encrypted Data-Plane AI Classifier** -- When the handshake is unavailable or captured mid-session, a local 1D Convolutional Neural Network (CNN) analyzes numerical flow metadata (packet lengths and inter-arrival times) to classify operating mode and inner traffic type with calibrated confidence.
3. **Automated Compliance and Risk Engine** -- Grades the tunnel against NIST SP 800-77 Rev. 1 and NSA CNSA 2.0, generating a normalized 0-100 security score, risk level, threat matrix, and executive/technical PDF audit reports.

---

## Demo Video

> A full end-to-end walkthrough of CryptoLens covering all pipeline stages, dashboard interactions, and PDF report generation:
>
> **[Watch the CryptoLens Demo Video](https://drive.google.com/file/d/1svhQIZ8qLR4R4qhd-rPO23bJiGCA-W1a/view?usp=drive_link)**

---

## Architecture Pipeline

The complete analysis pipeline from PCAP ingestion through to dashboard rendering and PDF export:

```mermaid
flowchart TD
    A["PCAP / PCAPNG Upload"] --> B["PcapDemuxer Engine"]
    B -->|"IKE Packets\n(UDP 500/4500 + Non-ESP Marker)"| C["Control-Plane Parser"]
    B -->|"ESP Packets\n(IP Protocol 50)"| D["Data-Plane AI Classifier"]

    C --> E{"IKE Handshake\nFound?"}
    E -->|"Yes"| F["Extract Crypto Proposals\n(Cipher, DH, PFS, PRF, ESN, Rekey)"]
    E -->|"No"| G["Return NOT_ASSESSED\n(Mid-Session Capture)"]

    D --> H["Extract ESP Metadata\n(Packet Lengths + IATs)"]
    H --> I["1D-CNN Inference\n(ONNX Runtime)"]
    I --> J{"CNN\nSucceeded?"}
    J -->|"Yes"| K["Mode + Traffic Classification\nwith Calibrated Confidence"]
    J -->|"No"| L["Gemini LLM\nFallback Classifier"]
    L --> K

    F --> M["Dual-Track Agreement\nValidation"]
    K --> M
    G --> M

    M --> N["Scoring Engine\n(8 Weighted Dimensions)"]
    N --> O["Compliance Engine\n(NIST SP 800-77 / CNSA 2.0)"]

    O --> P["React SOC Dashboard"]
    O --> Q["PDF Report Engine\n(Executive + Technical)"]

    style A fill:#1a73e8,stroke:#1a73e8,color:#fff
    style B fill:#2c5f8a,stroke:#2c5f8a,color:#fff
    style C fill:#009688,stroke:#009688,color:#fff
    style D fill:#e03333,stroke:#e03333,color:#fff
    style F fill:#009688,stroke:#009688,color:#fff
    style K fill:#e03333,stroke:#e03333,color:#fff
    style N fill:#ff9800,stroke:#ff9800,color:#fff
    style O fill:#ff9800,stroke:#ff9800,color:#fff
    style P fill:#4caf50,stroke:#4caf50,color:#fff
    style Q fill:#4caf50,stroke:#4caf50,color:#fff
```

---

## Analysis Lifecycle

The full lifecycle of a PCAP analysis request through the system, from user upload to result delivery:

```mermaid
stateDiagram-v2
    [*] --> Uploaded: User uploads PCAP via Dashboard or API
    Uploaded --> Demuxing: job_id generated
    Demuxing --> ControlPlane: IKE packets extracted
    Demuxing --> DataPlane: ESP packets extracted
    ControlPlane --> Merging: Crypto proposals parsed
    DataPlane --> Merging: Mode + traffic classified
    Merging --> Scoring: Dual-track agreement validated
    Scoring --> Compliance: 8-dimension weighted score computed
    Compliance --> Completed: NIST / CNSA evaluation finalized
    Completed --> Dashboard: Results rendered in SOC UI
    Completed --> PDFReport: Audit report generated on demand
    Dashboard --> [*]
    PDFReport --> [*]
```

### Lifecycle Notes

| Stage | Detail |
|---|---|
| **Demuxing** | NAT-Traversal disambiguation: UDP 4500 with Non-ESP Marker (0x00000000) routes to IKE; without marker routes to ESP |
| **Control Plane** | Dual-engine fallback: Engine 1 uses tshark CLI; Engine 2 falls back to native Python binary unpacker |
| **Data Plane** | Dual-model fallback: Primary 1D-CNN via ONNX Runtime; fallback Gemini LLM API |
| **Scoring** | Missing control plane (mid-session capture) returns `NOT_ASSESSED` with INFO-level findings |

---

## Control-Plane Parser

**Location:** `backend/engine/control_plane/ike_parser.py`

The control-plane parser reconstructs cleartext cryptographic proposals from IKE handshakes without relying on endpoint access or private keys. It implements a fallback-tolerant dual-engine architecture:

```mermaid
flowchart TD
    A["Input PCAP File"] --> B{"tshark\nInstalled?"}
    B -->|"Yes"| C["Engine 1: tshark CLI\nExtract IKE fields via display filters"]
    B -->|"No"| D["Engine 2: Native Python\nBinary unpacker via struct.unpack"]
    C --> E{"Parse\nSuccessful?"}
    E -->|"No"| D
    E -->|"Yes"| F["Detect IKE Version"]
    D --> F

    F --> G{"IKEv2\n(RFC 7296)?"}
    F --> H{"IKEv1\n(RFC 2409)?"}

    G -->|"Yes"| I["Scan SA Payload Type 33\nIterate Proposals and Transforms"]
    H -->|"Yes"| J["Scan ISAKMP SA Payload Type 1\nDecode DOI + Situation + Transforms"]

    I --> K["Decode Transform Types"]
    J --> K

    K --> K1["Type 1: Encryption\n(AES-GCM, AES-CBC, 3DES, ChaCha20)"]
    K --> K2["Type 2: PRF\n(HMAC-SHA2-256/384/512, AES-XCBC)"]
    K --> K3["Type 3: Integrity\n(HMAC-SHA2, HMAC-SHA1, GMAC)"]
    K --> K4["Type 4: DH Group\n(Groups 1-31, ECP/MODP)"]
    K --> K5["Type 5: ESN\n(Anti-Replay Protection)"]
    K --> K6["Attributes: Key Length\n(128 / 256 bits)"]

    K1 --> L["Construct AST Output"]
    K2 --> L
    K3 --> L
    K4 --> L
    K5 --> L
    K6 --> L

    L --> M["AEAD Autodetection:\nGCM / Poly1305 sets Integrity = NONE"]

    style A fill:#1a73e8,stroke:#1a73e8,color:#fff
    style C fill:#009688,stroke:#009688,color:#fff
    style D fill:#ff9800,stroke:#ff9800,color:#fff
    style I fill:#2c5f8a,stroke:#2c5f8a,color:#fff
    style J fill:#2c5f8a,stroke:#2c5f8a,color:#fff
    style M fill:#4caf50,stroke:#4caf50,color:#fff
```

### Extracted AST Fields

| Field | Description | Example Values |
|---|---|---|
| `ike_version` | Detected IKE protocol version | `IKEv2`, `IKEv1` |
| `encryption_algorithm` | Negotiated cipher suite with key length | `AES-256-GCM`, `AES-128-CBC-128`, `3DES` |
| `integrity_algorithm` | HMAC or AEAD integrity mode | `HMAC-SHA2-256`, `NONE` (AEAD), `HMAC-SHA1-96` |
| `dh_group` | Diffie-Hellman group number | `19` (P-256 ECP), `14` (MODP 2048), `2` (MODP 1024) |
| `prf_algorithm` | Pseudo-Random Function | `PRF_HMAC_SHA2_256`, `PRF_HMAC_SHA1` |
| `pfs_enabled` | Perfect Forward Secrecy active | `true`, `false` |
| `key_lifetime_seconds` | SA rekey interval | `3600`, `28800`, `86400` |
| `replay_protection_enabled` | Extended Sequence Numbers | `true`, `false` |

---

## Data-Plane AI Classifier

**Location:** `backend/engine/data_plane/cnn_model.py`, `backend/engine/data_plane/classifier.py`

### 1D-CNN Architecture

The classifier operates on encrypted ESP traffic metadata without any decryption. It processes only numerical flow statistics:

```mermaid
flowchart TD
    A["ESP Packet Stream"] --> B["Feature Extraction"]
    B --> C["S_L: First 30 packet lengths in bytes\nS_IAT: First 30 inter-arrival times in seconds"]
    C --> D["Zero-pad / Truncate to length 30"]
    D --> E["Normalize: X_norm = X - mu / sigma + 1e-8"]
    E --> F["Input Tensor: shape 1 x 2 x 30"]

    F --> G["Conv1D Layer 1\n2 to 64 channels, kernel=3"]
    G --> H["BatchNorm1D + ReLU"]
    H --> I["Conv1D Layer 2\n64 to 64 channels, kernel=3"]
    I --> J["BatchNorm1D + ReLU"]
    J --> K["AdaptiveAvgPool1D to 64 x 1"]

    K --> L["Mode Head\nLinear 64-32 then ReLU then Dropout 0.2\nthen Linear 32-2"]
    K --> M["Traffic Head\nLinear 64-32 then ReLU then Dropout 0.2\nthen Linear 32-3"]

    L --> N["Softmax: Mode Prediction\ntunnel or transport"]
    M --> O["Softmax: Traffic Prediction\nhttps or voip or icmp"]

    N --> P["F1-Score Confidence Calibration\nConf = min of Softmax_Conf and Class_F1"]
    O --> P

    style A fill:#e03333,stroke:#e03333,color:#fff
    style F fill:#1a73e8,stroke:#1a73e8,color:#fff
    style G fill:#2c5f8a,stroke:#2c5f8a,color:#fff
    style I fill:#2c5f8a,stroke:#2c5f8a,color:#fff
    style K fill:#ff9800,stroke:#ff9800,color:#fff
    style L fill:#009688,stroke:#009688,color:#fff
    style M fill:#009688,stroke:#009688,color:#fff
    style P fill:#4caf50,stroke:#4caf50,color:#fff
```

### Inference Flow

| Step | Process | Detail |
|---|---|---|
| 1 | Session Init | Lazy-load ONNX weights from `weights/cnn_mode_traffic.onnx` |
| 2 | Normalization | Apply mu/sigma from `weights/metrics.json` |
| 3 | Inference | ONNX Runtime CPU-only execution |
| 4 | Softmax | Numerically stable with max-subtraction |
| 5 | Calibration | Cap confidence using per-class F1-scores from validation set |

### LLM Fallback Classifier

When the CNN is unavailable or fails, CryptoLens falls back to the Gemini LLM API (`gemini-3.8-flash`, temperature 0.1) with domain-grounded heuristic prompting:

| Traffic Type | Heuristic Signature |
|---|---|
| **HTTPS** | Bursty, variable packet sizes (500-1500 bytes) |
| **VoIP** | Small, constant sizes (150-300 bytes), regular 20ms cadence |
| **ICMP** | Small payloads (<100 bytes), sparse 0.5-1.0s intervals |
| **Tunnel vs Transport** | Outer IP encapsulation adds 20-40 bytes overhead |

---

## Dual-Track Agreement Logic

**Location:** `backend/engine/inference_pipeline.py`

The inference pipeline cross-validates AI predictions against statistical heuristics to flag low-confidence inferences:

```mermaid
flowchart TD
    A["ESP Packet Stream"] --> B["Statistical Heuristic Analysis\nPercentile-based flow statistics"]
    A --> C["AI Model Inference\n1D-CNN or LLM Fallback"]

    B --> D["Heuristic Mode Prediction\nPacket size percentiles:\nmin, p10, p25, median, max"]
    B --> E["Heuristic Traffic Prediction\nLarge vs small packet ratio"]

    C --> F["AI Mode Prediction\n+ Confidence Score"]
    C --> G["AI Traffic Prediction\n+ Confidence Score"]

    D --> H{"Mode\nAgrees?"}
    F --> H
    E --> I{"Traffic\nAgrees?"}
    G --> I

    H -->|"heuristic_mode == ai_mode"| J["mode_agree = True"]
    H -->|"Mismatch"| K["mode_agree = False"]
    I -->|"heuristic_traffic == ai_traffic"| L["traffic_agree = True"]
    I -->|"Mismatch"| M["traffic_agree = False"]

    J --> N["Overall Agreement Check"]
    K --> N
    L --> N
    M --> N

    N --> O["AgreementCheckResult:\noverall_agree, avg_confidence,\nmode_agree, traffic_agree"]

    style A fill:#1a73e8,stroke:#1a73e8,color:#fff
    style B fill:#ff9800,stroke:#ff9800,color:#fff
    style C fill:#e03333,stroke:#e03333,color:#fff
    style J fill:#4caf50,stroke:#4caf50,color:#fff
    style K fill:#e03333,stroke:#e03333,color:#fff
    style L fill:#4caf50,stroke:#4caf50,color:#fff
    style M fill:#e03333,stroke:#e03333,color:#fff
    style O fill:#2c5f8a,stroke:#2c5f8a,color:#fff
```

### Heuristic Discrimination Signals

| Signal | Threshold | Weight |
|---|---|---|
| Minimum packet size >= 120 bytes | Tunnel indicator | +2 |
| p10 >= 120 bytes | Tunnel indicator | +1 |
| Median >= 155 bytes | Tunnel indicator | +2 |
| p25 >= 130 bytes | Tunnel indicator | +1 |
| Large packets (>= 600B) ratio | HTTPS vs VoIP/ICMP | Variable |

---

## Security Scoring Engine

**Location:** `backend/scoring/scoring_engine.py`

### Scoring Computation Flow

```mermaid
flowchart TD
    A["Parsed IKE AST\n+ AI Classification Results"] --> B["Load Category Weights\nfrom weights_config.yaml"]
    B --> C["Evaluate 8 Scoring Dimensions"]

    C --> D["Encryption 25 percent\nCipher strength and block mode"]
    C --> E["Integrity 15 percent\nHMAC algorithm or AEAD"]
    C --> F["Key Exchange 15 percent\nDH / EC group security level"]
    C --> G["PFS 10 percent\nEphemeral key exchange active"]
    C --> H["Replay Protection 10 percent\nESN verification"]
    C --> I["Key Lifetime 10 percent\nRekey interval threshold"]
    C --> J["IKE Version 10 percent\nIKEv2 vs deprecated IKEv1"]
    C --> K["Operating Mode 5 percent\nTunnel vs Transport"]

    D --> L["Per-Category Score\n= awarded / max_points x weight"]
    E --> L
    F --> L
    G --> L
    H --> L
    I --> L
    J --> L
    K --> L

    L --> M["Overall Score = clamp sum 0 to 100"]
    M --> N{"Risk Level\nClassification"}

    N -->|"Score >= 90"| O["LOW"]
    N -->|"Score 75-89"| P["MODERATE"]
    N -->|"Score 50-74"| Q["HIGH"]
    N -->|"Score < 50"| R["CRITICAL"]

    style A fill:#1a73e8,stroke:#1a73e8,color:#fff
    style D fill:#4caf50,stroke:#4caf50,color:#fff
    style E fill:#4caf50,stroke:#4caf50,color:#fff
    style F fill:#4caf50,stroke:#4caf50,color:#fff
    style G fill:#009688,stroke:#009688,color:#fff
    style H fill:#009688,stroke:#009688,color:#fff
    style I fill:#009688,stroke:#009688,color:#fff
    style J fill:#009688,stroke:#009688,color:#fff
    style K fill:#009688,stroke:#009688,color:#fff
    style M fill:#ff9800,stroke:#ff9800,color:#fff
    style O fill:#4caf50,stroke:#4caf50,color:#fff
    style P fill:#ff9800,stroke:#ff9800,color:#fff
    style Q fill:#e03333,stroke:#e03333,color:#fff
    style R fill:#b71c1c,stroke:#b71c1c,color:#fff
```

### Scoring Formula

For each category `c` across all 8 dimensions:

```
Score_c = (raw_awarded_points_c / max_rule_points_c) * category_weight_c

Overall Security Score = round(clamp(sum(Score_c for all c), 0.0, 100.0), 2)
```

### Edge Cases and Robustness Rules

| Scenario | Behavior |
|---|---|
| **Missing Control Plane** (mid-session PCAP) | Returns `score: null`, `risk_level: NOT_ASSESSED`, INFO-level findings |
| **AEAD Cipher Detected** (AES-GCM, ChaCha20-Poly1305) | Integrity mapped to `AEAD`, full 15 points awarded |
| **Rekey Lifetime < 60s** | Flagged as corrupted/adversarial input (`INVALID_KEY_LIFETIME`, Severity MEDIUM, 0 points) |
| **Rekey Lifetime > 86,400s** | Exceeds 24-hour standard maximum |

---

## Standards Compliance Engine

**Location:** `backend/scoring/compliance_engine.py`, `compliance_standards.yaml`

```mermaid
flowchart LR
    A["Scored IPsec Parameters"] --> B["NIST SP 800-77 Rev. 1\nGuidance Alignment"]
    A --> C["NSA CNSA 2.0\nPackage-Scoped / Quantum-Ready"]

    B --> D["Per-Control Evaluation"]
    C --> D

    D --> E{"Control\nStatus"}
    E --> F["ALIGNED\nMeets standard"]
    E --> G["REVIEW\nPartial compliance"]
    E --> H["FAIL\nNon-compliant"]
    E --> I["NOT_ASSESSED\nInsufficient data"]

    F --> J["Aggregate by Priority:\nFAIL then REVIEW then ALIGNED then NOT_ASSESSED"]
    G --> J
    H --> J
    I --> J

    J --> K["Overall Compliance Status\nper Standard"]

    style A fill:#1a73e8,stroke:#1a73e8,color:#fff
    style B fill:#009688,stroke:#009688,color:#fff
    style C fill:#ff9800,stroke:#ff9800,color:#fff
    style F fill:#4caf50,stroke:#4caf50,color:#fff
    style G fill:#ff9800,stroke:#ff9800,color:#fff
    style H fill:#e03333,stroke:#e03333,color:#fff
```

### Standards Criteria

| Criterion | NIST SP 800-77 Rev. 1 | NSA CNSA 2.0 |
|---|---|---|
| **IKE Version** | IKEv2 required | IKEv2 mandated |
| **Encryption** | AEAD (AES-256-GCM) or AES-CBC with SHA-2 | AES-256-GCM mandated |
| **Integrity** | SHA-2 HMACs (SHA-256/384/512) | HMAC-SHA-384 / HMAC-SHA-512 |
| **DH Group** | Groups >= 14 (Groups 19/20 preferred) | Group 20 (384-bit ECP) mandated |
| **PFS** | Enabled | Enabled |
| **Replay Protection** | Enabled | Enabled |
| **Deprecated Suites** | 3DES, SHA-1, DH Group 2 flagged | Explicit FAIL for 3DES, SHA-1, DH-2, IKEv1 |

---

## SOC Dashboard

**Location:** `src/App.jsx`, `src/components/`

Built with React 19, Vite 8, Tailwind CSS v4, and Recharts. Supports dark mode and light mode themes.

### Dashboard Component Architecture

```mermaid
flowchart TD
    A["App Root + ThemeProvider"] --> B["SocSidebar\nNavigation"]
    A --> C["SocHeader\nUpload / Ingest / Export"]

    B --> D["Dashboard View"]
    B --> E["Alerts View"]
    B --> F["Reports View"]
    B --> G["Settings View"]

    D --> H["EmptyState\nNo analysis yet"]
    D --> I["AnalysingState\nSpinner + job_id"]
    D --> J["Results View"]

    J --> K["Live IPsec Status Bar\nCipher, DH, PFS, Mode"]
    J --> L["SocMetricCards\nTotal / Critical / Medium / Low alerts"]
    J --> M["ScoreDial\n0-100 SVG gauge + risk level"]
    J --> N["AnalysisDimensions\n8-dimension progress bars"]
    J --> O["ComplianceRadar\nSpider chart: Cipher, Key Exchange,\nMode/PFS, Metadata, PQC Readiness"]
    J --> P["AiTelemetryCard\nConfidence, Agreement, Mode, Anti-Replay"]
    J --> Q["SocAlertVolumeTrend\n+ SocSeverityDistribution"]
    J --> R["TrafficDistribution\nVoIP, Web, ICMP percentages"]
    J --> S["PerTunnelBreakdown\nPer-tunnel audit table"]

    C --> T["Amber Fallback Banner\nMid-session: AI Inference Engaged"]

    style A fill:#1a73e8,stroke:#1a73e8,color:#fff
    style D fill:#2c5f8a,stroke:#2c5f8a,color:#fff
    style M fill:#ff9800,stroke:#ff9800,color:#fff
    style O fill:#009688,stroke:#009688,color:#fff
```

### Dashboard Features

| Component | Description |
|---|---|
| **ScoreDial** | Circular SVG gauge (0-100), animated score transitions, risk status badge |
| **ComplianceRadar** | Recharts spider radar comparing 5 compliance axes |
| **AiTelemetryCard** | AI confidence, heuristic agreement flag, predicted mode, anti-replay |
| **TrafficDistribution** | Inner traffic profiling with percentage bars and packet counts |
| **PerTunnelBreakdown** | Per-tunnel table: encryption, DH group, PFS, mode, traffic type |
| **Amber Banner** | Triggered when control-plane handshake is unavailable |
| **Telemetry Polling** | 1.5-second polling loop on `/api/v1/results/{job_id}` |

---

## Ground-Truth Testbed Matrix

CryptoLens ships with 7 reference configurations verified against NIST SP 800-77 and NSA CNSA 2.0:

| ID | Name | Cipher | Hash | DH Group | PFS | Score | Risk |
|---|---|---|---|---|---|---|---|
| `config_01` | Hardened Tunnel | AES-256-GCM | AEAD | Group 19 (P-256) | ON | **100.0** | LOW |
| `config_02` | Standard Secure | AES-128-GCM | AEAD | Group 14 (MODP 2048) | ON | **95.0** | LOW |
| `config_03` | CBC Legacy Auth | AES-256-CBC | SHA2-256 | Group 14 (MODP 2048) | ON | **90.0** | MODERATE |
| `config_04` | Weak Integrity | AES-128-CBC | SHA-1 | Group 5 (MODP 1536) | OFF | **60.0** | HIGH |
| `config_05` | Deprecated Transport | 3DES | SHA-1 | Group 2 (MODP 1024) | OFF | **45.0** | CRITICAL |
| `config_06` | Insecure Tunnel | 3DES | SHA-1 | Group 2 (MODP 1024) | OFF | **45.0** | CRITICAL |
| `config_07` | Legacy IKEv1 Tunnel | 3DES | SHA-1 | Group 2 (MODP 1024) | OFF | **45.0** | CRITICAL |

### Testbed Infrastructure

```mermaid
flowchart LR
    A["peer_a Moon\n192.168.1.0/24"] <-->|"veth_a to veth_b\nIPsec Tunnel"| B["peer_b Sun\n192.168.2.0/24"]

    A --> C["strongSwan charon\nIsolated mount namespace"]
    B --> D["strongSwan charon\nIsolated mount namespace"]

    C --> E["Traffic Generators"]
    E --> F["icmp_ping.py\nBaseline ICMP"]
    E --> G["https_client.py\nBursty TLS/HTTPS"]
    E --> H["voip_sim.py\nRTP G.711 at 20ms"]

    D --> I["tcpdump Capture\n.pcap output"]
    I --> J["captures/manifest.json\nGround-truth labels"]

    style A fill:#2c5f8a,stroke:#2c5f8a,color:#fff
    style B fill:#2c5f8a,stroke:#2c5f8a,color:#fff
    style C fill:#009688,stroke:#009688,color:#fff
    style D fill:#009688,stroke:#009688,color:#fff
```

---

## Quick Start

### Option 1: Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/shreyashsinha73-ctrl/Cryptolens.git
cd Cryptolens

# Configure environment variables
cp .env.example .env

# Launch the entire stack
docker-compose up --build -d
```

| Service | URL |
|---|---|
| SOC React Dashboard | [http://localhost:5173](http://localhost:5173) |
| FastAPI Documentation | [http://localhost:8000/docs](http://localhost:8000/docs) |
| Backend Health Check | [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health) |

### Option 2: Local Development Setup

#### 1. System Prerequisites

- **OS:** Linux (Ubuntu 22.04+ / Debian 12 recommended)
- **Python:** 3.10 or higher
- **Node.js:** v18+ with npm
- **Wireshark CLI:** tshark (version 3.6.2+)

```bash
sudo apt-get update
sudo apt-get install -y tshark python3-venv python3-pip
```

#### 2. Backend and Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

#### 3. Frontend (React + Vite)

In a separate terminal:

```bash
npm install
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

---

## Running Verification and Tests

### Full Pipeline Automated Regression

```bash
source .venv/bin/activate
python3 scripts/test_end_to_end.py
```

Expected output:

```
======================================================================
 CryptoLens End-to-End Integration Test
======================================================================

[Stage 1: Testbed Output Verification]
[+] Found 6 PCAP files in captures/
[+] Ground-truth manifest contains 6 labeled configurations
[+] Using test capture: config_01_tunnel_aes256gcm_dh19_pfson_all.pcap

[Stage 2: Capture and Demux Verification]
[+] Demux Result: Total=590, IKE=4, ESP=248

[Stage 3: Control-Plane AST Parser Verification]
[+] Parsed IKE Version:  IKEv2
[+] Encryption Cipher:  AES-GCM-256
[+] Integrity Algo:     NONE
[+] Diffie-Hellman:     Group 19
[+] PFS Enabled:        True
[+] Replay Protection:  True

[Stage 3: Data-Plane AI Traffic Analyzer Verification]
[+] Heuristic Mode:     tunnel
[+] AI Mode Prediction: tunnel
[+] AI Confidence:      0.93
[+] Agreement Flag:     True
[+] Detected Traffic:   4 classes identified

[Stage 3: Security Scoring and Compliance Engine Verification]
[+] Security Score:     100.0 / 100
[+] Risk Level:         LOW
[+] Threat Findings:    0 vulnerabilities cataloged
[+] NIST SP 800-77:     ALIGNED
[+] NSA CNSA 2.0:       REVIEW

======================================================================
 ALL PIPELINE STAGES INTEGRATED AND VERIFIED SUCCESSFULLY!
======================================================================
```

### Individual Pipeline Commands

| Stage | Command |
|---|---|
| **Demux PCAP** | `python3 -m backend.capture.demux captures/config_01_tunnel_aes256gcm_dh19_pfson_all.pcap -o /tmp/demux_out` |
| **Parse IKE AST** | `python3 -m backend.engine.control_plane.ike_parser captures/config_01_tunnel_aes256gcm_dh19_pfson_all.pcap --json` |
| **Generate PDF Report** | `curl -X POST http://localhost:8000/api/v1/report/generate -H 'Content-Type: application/json' -d '{"job_id":"demo","report_type":"technical"}' -o report.pdf` |
| **Retrain CNN** | `python3 backend/engine/data_plane/verify.py --skip-venv --epochs 50 --configs 6 --runs-per-combo 20` |

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/analyze` | Upload PCAP for analysis. Returns `job_id` with HTTP 202. |
| `GET` | `/api/v1/results/{job_id}` | Poll analysis results (summary, control/data plane, scores, compliance). |
| `GET` | `/api/v1/report/{job_id}/pdf?type=executive` | Generate and stream PDF audit report. |
| `GET` | `/api/v1/capture/testbed` | List available testbed captures from manifest. |
| `POST` | `/api/v1/capture/ingest?force=false` | Batch auto-ingest all testbed PCAPs. |
| `POST` | `/api/v1/capture/ingest/{config_id}?force=false` | Ingest and score a single capture by config ID. |
| `GET` | `/api/v1/capture/status` | Check auto-ingest registry status. |

---

## PCAP Demultiplexer

**Location:** `backend/capture/demux.py`

The demultiplexer separates control-plane and data-plane traffic from mixed PCAP captures:

```mermaid
flowchart TD
    A["Raw PCAP Input"] --> B["PcapDemuxer"]
    B --> C{"Packet\nClassification"}

    C -->|"UDP 500\nStandard IKE"| D["IKE Control Plane"]
    C -->|"UDP 4500 +\nNon-ESP Marker\n0x00000000"| D
    C -->|"IP Protocol 50\nNative ESP"| E["ESP Data Plane"]
    C -->|"UDP 4500 without\nNon-ESP Marker\nNAT-T ESP"| E

    D --> F["Control-Plane Parser\nIKE Handshake Analysis"]
    E --> G["Data-Plane Classifier\nESP Metadata Analysis"]

    B --> H["Dynamic Endpoint\nExtraction\ntshark ip.src/ip.dst"]

    style A fill:#1a73e8,stroke:#1a73e8,color:#fff
    style D fill:#009688,stroke:#009688,color:#fff
    style E fill:#e03333,stroke:#e03333,color:#fff
    style B fill:#2c5f8a,stroke:#2c5f8a,color:#fff
```

---

## Ethical Scoping and Privacy Guarantees

> **Dual-Use and Privacy Notice:**
> CryptoLens is designed strictly for internal enterprise self-assessment, network auditing, and defense compliance.

| Guarantee | Description |
|---|---|
| **Zero Decryption** | CryptoLens never attempts to break, crack, or decrypt encrypted ESP payloads. |
| **Zero Plaintext Inspection** | Only RFC-standard cleartext handshake headers (IKE SA proposals) and ESP metadata (frame lengths, timing) are analyzed. |
| **Privacy Preservation** | All IP addresses, MAC addresses, and localized identifiers are sanitized before any inference processing. |

---

## Project Team and SIH 2026 Domains

| Domain | Scope |
|---|---|
| **Testbed Engineering** | Containerized strongSwan topologies and reproducible traffic matrix generation |
| **Control-Plane Parser** | Deterministic IKEv1/IKEv2 binary unpacker and proposal extraction |
| **Data-Plane Inference** | 1D-CNN neural flow classifier, ONNX runtime integration, and confidence calibration |
| **Scoring and Compliance** | Mathematical security scoring against NIST SP 800-77 Rev. 1 and NSA CNSA 2.0 |
| **SOC Dashboard** | React, Tailwind CSS, Vite high-contrast SOC analytics portal |
| **Reporting Engine** | Automated PDF generation with executive summaries and technical remediation blueprints |

---

## License

This project is licensed under the MIT License.
