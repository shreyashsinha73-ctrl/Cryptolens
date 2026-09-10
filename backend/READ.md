# IPsec Protocol Analysis Platform — API Specification (v1)

Base URL: `http://localhost:8000/api/v1`

---

## 1. Upload PCAP for Analysis

Initiates asynchronous analysis on an uploaded packet capture file.

- **URL:** `/analyze`
- **Method:** `POST`
- **Content-Type:** `multipart/form-data`

### Request Body
- `file`: Binary file (Must be `.pcap` or `.pcapng`)

### Response (`202 Accepted`)
```json
{
  "job_id": "job_9f8b2c1a-3d4e",
  "status": "processing",
  "filename": "sample_traffic.pcap",
  "uploaded_at": "2026-04-12T10:30:00Z"
}
```

### Error Response (`400 Bad Request`)
```json
{
  "error_code": "INVALID_FILE_FORMAT",
  "message": "Only .pcap and .pcapng files are supported."
}
```

---

## 2. Get Analysis Results

Retrieves complete security analysis, control-plane specs, data-plane traffic predictions, and risk scores.

- **URL:** `/results/{job_id}`
- **Method:** `GET`

### Response (`200 OK` — Processing Completed)
```json
{
  "job_id": "job_9f8b2c1a-3d4e",
  "status": "completed",
  "summary": {
    "overall_risk_score": 78,
    "risk_level": "HIGH",
    "ai_confidence_score": 0.92,
    "agreement_flag": true
  },
  "control_plane": {
    "ike_version": "IKEv2",
    "operating_mode": "Tunnel",
    "encryption_algorithm": "AES-128-CBC",
    "integrity_algorithm": "HMAC-SHA2-256",
    "dh_group": 14,
    "pfs_enabled": false,
    "key_lifetime_seconds": 28800,
    "replay_protection_enabled": true
  },
  "data_plane": {
    "detected_traffic": [
      {
        "traffic_type": "VoIP",
        "percentage": 45.2,
        "packet_count": 1240,
        "avg_packet_size_bytes": 160
      },
      {
        "traffic_type": "Video Streaming",
        "percentage": 38.8,
        "packet_count": 890,
        "avg_packet_size_bytes": 1380
      },
      {
        "traffic_type": "WhatsApp/Messaging",
        "percentage": 16.0,
        "packet_count": 210,
        "avg_packet_size_bytes": 85
      }
    ],
    "heuristic_mode_prediction": "Tunnel",
    "llm_mode_prediction": "Tunnel"
  },
  "threat_matrix": [
    {
      "id": "VULN-001",
      "severity": "HIGH",
      "category": "Forward Secrecy",
      "title": "Perfect Forward Secrecy (PFS) Disabled",
      "description": "If the main private key is compromised, all past recorded traffic can be retroactively decrypted."
    },
    {
      "id": "VULN-002",
      "severity": "MEDIUM",
      "category": "Cipher Strength",
      "title": "Legacy Cipher Suite (AES-CBC without AEAD)",
      "description": "CBC mode without integrated authenticated encryption leaves traffic susceptible to padding oracle attacks."
    }
  ]
}
```

### Response (`200 OK` — Still Processing)
```json
{
  "job_id": "job_9f8b2c1a-3d4e",
  "status": "processing",
  "progress_percentage": 45
}
```

---

## 3. Download Security Assessment PDF

Generates and downloads the executive/technical PDF report.

- **URL:** `/report/{job_id}/pdf`
- **Method:** `GET`
- **Query Parameters:**
  - `type`: `executive` | `technical` (Default: `executive`)

### Response (`200 OK`)
- **Content-Type:** `application/pdf`
- **Content-Disposition:** `attachment; filename="Security_Report_job_9f8b2c1a.pdf"`