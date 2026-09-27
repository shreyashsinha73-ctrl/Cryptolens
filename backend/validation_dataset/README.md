# Validation Dataset for CryptoLens Inference Pipeline

## Purpose

This directory contains labeled PCAP files used to measure API inference accuracy offline.

Each PCAP is a real capture from the strongSwan testbed with **ground-truth labels** encoded in the filename:

```
{mode}__{traffic_type}__{config_id}__{run_idx}.pcap
```

Example:
```
tunnel__https__cfg001__001.pcap
transport__voip__cfg002__002.pcap
```

## Filename Format

- **mode**: `tunnel` or `transport` (Ground truth from IKE handshake)
- **traffic_type**: `https`, `voip`, or `icmp` (Ground truth from traffic generation script)
- **config_id**: Unique identifier for the strongSwan configuration (e.g., `cfg001`)
- **run_idx**: Run number/iteration (e.g., `001`, `002`)

## Labels

| Label | Values |
|-------|--------|
| mode | `tunnel`, `transport` |
| traffic_type | `https`, `voip`, `icmp` |
| config_id | String, e.g., `cfg001`, `cfg_aes256gcm_dh19` |
| run_idx | 3-digit zero-padded, e.g., `001`, `010` |

## Collection Process

1. Configure strongSwan with known parameters (encryption, DH group, mode, PFS)
2. Generate traffic (curl, scapy, ping)
3. Capture ESP packets via tshark
4. Save with filename = ground truth

Example script:
```bash
#!/bin/bash
# Generate one labeled capture
config_id="cfg001"
mode="tunnel"
traffic_type="https"
run_idx="001"

# Set up strongSwan, generate traffic, capture
tshark -i any -Y "esp" -w "${mode}__${traffic_type}__${config_id}__${run_idx}.pcap" &
sleep 2
curl https://example.com
kill %1
```

## Validation Metrics

After running `backend/scripts/validate_inference.py`, the following metrics are computed:

- **API-vs-Ground-Truth Accuracy**: Does API prediction match the filename label?
  - Per-class: accuracy for tunnel/transport (mode_accuracy), https/voip/icmp (traffic_accuracy)
  - Matrix: confusion matrix showing misclassifications
  
- **Heuristic-vs-API Agreement**: Do heuristic and API predictions match each other?
  - Reported separately (independent of ground truth)
  
- **Confidence Score Distribution**: How confident is the API?
  - Mean/min/max confidence per class

## Stored Results

Results are saved to:
```
backend/validation_dataset/metrics_report.json
```

Format:
```json
{
  "metadata": {
    "total_pcaps": 30,
    "api_calls_successful": 28,
    "timestamp": "2026-09-16T10:30:00Z"
  },
  "api_vs_ground_truth": {
    "mode": {
      "accuracy": 0.87,
      "confusion_matrix": { "tunnel": {"tunnel": 13, "transport": 2}, ... },
      "f1_macro": 0.85
    },
    "traffic": {
      "accuracy": 0.83,
      "confusion_matrix": { ... },
      "f1_macro": 0.82
    }
  },
  "heuristic_vs_api": {
    "mode_agreement_rate": 0.93,
    "traffic_agreement_rate": 0.80,
    "overall_agreement_rate": 0.76
  },
  "confidence_stats": {
    "mode": {
      "mean": 0.78,
      "min": 0.51,
      "max": 0.99
    },
    "traffic": {
      "mean": 0.72,
      "min": 0.48,
      "max": 0.95
    }
  }
}
```

## Running Validation

```bash
python backend/scripts/validate_inference.py \
    --dataset-dir backend/validation_dataset \
    --output backend/validation_dataset/metrics_report.json \
    --verbose
```
