# Standard Operating Procedure (SOP): Control-Plane Protocol Auditing & Demux

## Goal
Ingest raw packet capture files (`.pcap`, `.pcapng`), demultiplex the capture stream into Control-Plane (IKE handshakes) and Data-Plane (ESP payloads), parse cleartext IKE transform proposals into a normalized JSON AST, and deterministically evaluate cryptographic compliance against NIST SP 800-77 Rev 1 and CNSA 2.0 standards.

---

## Inputs
- `pcap_path`: Absolute path to a valid `.pcap` or `.pcapng` file.
- `output_dir` (optional): Directory where demuxed artifacts and JSON ASTs should be stored. Defaults to `.tmp/jobs/{job_id}/`.

---

## Deterministic Tools (Layer 3)
1. **`capture/demux.py`**:
   - Reads raw capture frames using `capture/pcap_utils.py`.
   - Filters packets:
     - **Control Plane**: UDP port 500 (standard IKE) or UDP port 4500 containing the Non-ESP Marker (`0x00000000`).
     - **Data Plane**: IP protocol 50 (native ESP) or UDP port 4500 with non-zero SPI (NAT-T ESP).
   - Emits stream metrics: packet counts, byte ratios, and separate control/data PCAP artifacts.
2. **`engine/control_plane/ike_parser.py`**:
   - Parses IKE handshake packets.
   - Decodes Exchange Types (`IKE_SA_INIT`, `IKE_AUTH`, `CREATE_CHILD_SA`).
   - Extracts transforms: Encryption algorithm, Integrity/HMAC, Diffie-Hellman Group ID, PRF algorithm, Key Lifetime, and Anti-Replay (ESN).
   - Generates normalized JSON AST.
3. **`engine/control_plane/rules_engine.py`**:
   - Evaluates the JSON AST against NIST SP 800-77 Rev 1 and CNSA 2.0 rulesets.
   - Computes overall risk score (0–100) and risk level.
   - Generates itemized `threat_matrix` findings (`id`, `severity`, `category`, `title`, `description`).

---

## Outputs & Contract
The output must conform strictly to `backend/schemas/analysis.py`:
```json
{
  "control_plane": {
    "ike_version": "IKEv2",
    "operating_mode": "Tunnel",
    "encryption_algorithm": "AES-256-GCM",
    "integrity_algorithm": "NONE",
    "dh_group": 19,
    "pfs_enabled": true,
    "key_lifetime_seconds": 28800,
    "replay_protection_enabled": true
  },
  "summary": {
    "overall_risk_score": 0,
    "risk_level": "LOW",
    "ai_confidence_score": 1.0,
    "agreement_flag": true
  },
  "threat_matrix": []
}
```

---

## Security & Privacy Rules
1. **Zero Payload Decryption**: Under no circumstances should payload data be decrypted or stored.
2. **Path Sanitization**: Validate all file paths to prevent directory traversal (`../`).
3. **Deterministic Fallback**: If `tshark` is unavailable, execute the native binary unpacker in `ike_parser.py` to prevent pipeline failures.

---

## Edge Cases & Handling
- **No IKE packets present (ESP-only capture)**: Flag `handshake_missing: true`. Return baseline control-plane defaults and signal Data-Plane inference to predict mode and suites.
- **Malformed or truncated packets**: Safely drop truncated frames and log warnings without crashing the execution loop.
- **Multiple proposals**: Capture both the initiator proposals and the responder selected proposal, prioritizing the selected proposal for compliance scoring.

