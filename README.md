# CryptoLens
> **AI-Driven IPsec Protocol Analysis & Security Assessment Platform**

![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)
![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)

## The Problem & Our Solution

**The Problem:** Misconfigured IPsec tunnels can look secure on the wire while leaking critical metadata, employing deprecated cryptographic suites, or operating without Perfect Forward Secrecy (PFS). Auditing these active tunnels dynamically—without access to the endpoint keys—is a non-trivial challenge for network administrators.

**The Solution:** **CryptoLens** automates compliance scoring against **NIST SP 800-77 Rev 1** and **CNSA 2.0** standards. Our dual-track engine uses deterministic parsing to extract cleartext IKE handshake parameters and leverages an external AI API to infer tunnel operating modes (Transport/Tunnel) and inner traffic profiles (e.g., VoIP, HTTPS, ICMP) entirely from encrypted ESP metadata.

## Architecture Pipeline

CryptoLens operates via a stateless, passive analysis pipeline:

```text
┌──────────────────┐      ┌───────────────┐
│  Docker Testbed  │ ───▶ │ tshark Capture│
│  (strongSwan)    │      │   (PCAP/Live) │
└──────────────────┘      └───────┬───────┘
                                  │
                  ┌───────────────┴───────────────┐
                  ▼                               ▼
        ┌───────────────────┐           ┌───────────────────┐
        │   Control Track   │           │    Data Track     │
        │(Deterministic IKE)│           │  (AI API & ESP)   │
        └─────────┬─────────┘           └─────────┬─────────┘
                  │                               │
                  └───────────────┬───────────────┘
                                  ▼
                        ┌──────────────────┐
                        │  Scoring Engine  │
                        │ (NIST/CNSA Evals)│
                        └─────────┬─────────┘
                                  ▼
                        ┌──────────────────┐
                        │ React Dashboard  │
                        │ (Posture & Tele) │
                        └──────────────────┘
```

## Quick Start (Running the MVP)

To deploy the CryptoLens MVP locally, follow these steps:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-org/cryptolens.git
   cd cryptolens
   ```

2. **Configure the environment:**
   Create a `.env` file in the root directory and add your AI API key for the Data Track inference:
   ```env
   AI_API_KEY=your_secure_api_key_here
   ```

3. **Deploy the stack:**
   Boot up the strongSwan testbed, the FastAPI backend, and the React frontend simultaneously:
   ```bash
   docker-compose up --build -d
   ```
   *The React dashboard will be accessible at `http://localhost:5173`.*

## Tech Stack

- **Traffic Generation & Capture:** strongSwan (IPsec Testbed), tshark (Network Protocol Analyzer)
- **Backend & Data Processing:** Python 3.11, FastAPI
- **Frontend / Dashboard:** React.js, Tailwind CSS v4, Vite
- **Inference:** Cloud-based AI API (LLM/Statistical Inference)
- **Infrastructure:** Docker, Docker Compose

## Ethical Scoping & Dual-Use (CRITICAL)

> **⚠️ Privacy & Ethical Use Disclaimer**
> CryptoLens is strictly designed as an **internal security self-assessment and compliance validation tool**. 

**Privacy-Preserving Architecture:**
The Data Track inference engine operates *exclusively* on **numerical metadata** (e.g., encrypted ESP packet sizes, directionality, and inter-arrival timing matrices). 
- **Zero Decryption:** We do not attempt to decrypt payloads.
- **Zero Plaintext:** No cleartext payload data is ever processed or captured from the ESP track.
- **Zero PII Transmission:** Source and destination IP addresses, MAC addresses, and localized routing information are stripped before inference. The external AI API only receives sanitized numeric arrays, ensuring absolute data privacy and adhering to strict enterprise data-sharing constraints.

## Division of Labor

The development of CryptoLens for the Smart India Hackathon 2026 was distributed across 6 specialized functional domains:

1. **Testbed Engineering:** Construction of the containerized strongSwan IPsec topologies and traffic generators.
2. **Control-Plane Parser:** Development of the deterministic `tshark` PCAP parsing logic for IKEv2 handshakes.
3. **Data-Plane & API Integration:** Sanitization of ESP metadata and integration with the external AI API for behavioral classification.
4. **Scoring Engine (Backend):** Implementation of the FastAPI server and NIST/CNSA compliance algorithms.
5. **Frontend / Dashboard:** Design and development of the React + Tailwind high-contrast security analytics UI.
6. **Shared Documentation:** System architecture diagrams, ethical scoping reviews, and deployment documentation.
