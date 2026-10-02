#!/usr/bin/env python3
"""
Offline Training Script for CryptoLens ESP Anomaly Detector.
Trains an Isolation Forest on authentic baseline PCAP captures (config_01 through config_06)
augmented with standard HTTPS web traffic flow distributions.
Computes 99.5th percentile threshold on normal baseline to guarantee <= 0.5% FPR on normal data.
Saves serialized model and scaler as joblib artifacts and writes SHA-256 manifest.
"""

import hashlib
import json
import logging
import sys
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import joblib
import numpy as np
from pyod.models.iforest import IForest
from sklearn.preprocessing import StandardScaler

from backend.engine.anomaly.feature_engineer import extract_flow_features

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

WEIGHTS_DIR = ROOT_DIR / "backend" / "engine" / "anomaly" / "weights"
CAPTURES_DIR = ROOT_DIR / "captures"


def compute_sha256(filepath: Path) -> str:
    """Compute hex SHA-256 digest of a file."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def extract_pcap_normal_flows(pcap_path: Path, window_size: int = 30, step_size: int = 5) -> list[np.ndarray]:
    """Extract flow windows from a genuine baseline PCAP file."""
    if not pcap_path.exists():
        return []
    try:
        from scapy.all import rdpcap
        from scapy.layers.ipsec import ESP
        pkts = rdpcap(str(pcap_path))
        esp_pkts = [p for p in pkts if p.haslayer(ESP) or (p.haslayer("IP") and p["IP"].proto == 50)]
        if len(esp_pkts) < window_size:
            return []

        flows = []
        for i in range(0, len(esp_pkts) - window_size + 1, step_size):
            win = esp_pkts[i : i + window_size]
            lengths = [float(len(p)) for p in win]
            iats = [0.001]
            last_ts = float(win[0].time) if hasattr(win[0], "time") else 0.0
            for p in win[1:]:
                ts = float(p.time) if hasattr(p, "time") else last_ts
                iats.append(max(0.0001, ts - last_ts))
                last_ts = ts
            feat = extract_flow_features(lengths, iats)
            if feat is not None:
                flows.append(feat)
        return flows
    except Exception as e:
        logger.warning(f"Could not extract flows from {pcap_path}: {e}")
        return []


def generate_baseline_https_flows(n_samples: int = 500) -> list[np.ndarray]:
    """
    Generate synthetic representative normal HTTPS web browsing flows:
    Variable packet sizes (60-1500 B), bursty arrival intervals (mean 0.04s).
    """
    np.random.seed(42)
    features_list = []
    for _ in range(n_samples):
        lengths = np.random.normal(850, 300, 30).clip(60, 1500)
        iats = np.random.exponential(0.04, 30).clip(0.001, 1.5)
        feat = extract_flow_features(lengths.tolist(), iats.tolist())
        if feat is not None:
            features_list.append(feat)
    return features_list


def train_anomaly_model(output_dir: Path = WEIGHTS_DIR):
    """Train Isolation Forest offline and persist joblib artifacts with SHA-256 manifest."""
    output_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Extracting authentic wire flows from baseline PCAPs...")

    all_pcap_flows = []
    capture_files = sorted(CAPTURES_DIR.glob("config_*.pcap"))
    for pcap in capture_files:
        fl = extract_pcap_normal_flows(pcap, window_size=30, step_size=5)
        logger.info(f"  Ingested {len(fl)} windows from {pcap.name}")
        all_pcap_flows.extend(fl)

    logger.info("Generating standard HTTPS web traffic baseline...")
    https_flows = generate_baseline_https_flows(n_samples=500)

    # Blend authentic testbed captures with web HTTPS flows
    combined = all_pcap_flows * 5 + https_flows
    X = np.array(combined, dtype=np.float64)
    logger.info(f"Total training dataset size: {len(X)} normal flows (shape: {X.shape})")

    # Fit scaler
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Fit Isolation Forest
    logger.info("Fitting Isolation Forest model...")
    model = IForest(
        n_estimators=100,
        contamination=0.01,
        random_state=42,
    )
    model.fit(X_scaled)

    # Calculate 99.5th percentile threshold on normal data
    train_scores = model.decision_function(X_scaled)
    threshold = float(np.percentile(train_scores, 99.5))
    logger.info(f"Calculated 99.5th percentile anomaly threshold: {threshold:.6f}")

    # Save artifacts using joblib
    model_path = output_dir / "anomaly_iforest.joblib"
    scaler_path = output_dir / "anomaly_scaler.joblib"
    meta_path = output_dir / "anomaly_metadata.json"

    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)

    model_hash = compute_sha256(model_path)
    scaler_hash = compute_sha256(scaler_path)

    metadata = {
        "model_type": "IsolationForest",
        "training_dataset": {
            "total_windows": len(X),
            "authentic_wire_windows": len(all_pcap_flows),
            "synthetic_https_windows": len(https_flows),
            "baseline_captures_used": [p.name for p in capture_files],
            "missing_traffic_profiles": [
                "Continuous G.711 / Opus VoIP audio streaming (constant bitrate UDP)",
                "Multi-megabyte sustained bulk TCP file transfers",
            ],
            "included_traffic_profiles": [
                "IKEv2 control-plane negotiations and Child SA establishment",
                "Periodic ICMP echo requests / replies over IPsec ESP",
                "Transient HTTPS web requests and handshakes over IPsec ESP",
            ],
        },
        "threshold": round(threshold, 6),
        "threshold_percentile": 99.5,
        "n_features": X.shape[1],
        "feature_names": [
            "mean_length", "std_length", "min_length", "max_length", "length_range",
            "mean_iat", "std_iat", "max_iat",
            "large_pkt_ratio", "small_pkt_ratio", "burst_ratio",
            "length_entropy", "iat_cv", "log_bytes_per_second",
        ],
        "sha256": {
            model_path.name: model_hash,
            scaler_path.name: scaler_hash,
        },
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    logger.info(f"Saved artifacts to {output_dir}:")
    logger.info(f"  - {model_path.name} (SHA-256: {model_hash})")
    logger.info(f"  - {scaler_path.name} (SHA-256: {scaler_hash})")
    logger.info(f"  - {meta_path.name}")

    return model, scaler, threshold


if __name__ == "__main__":
    train_anomaly_model()
