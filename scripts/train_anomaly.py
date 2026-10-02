"""
Offline Training Script for CryptoLens ESP Anomaly Detector.
Trains an Isolation Forest on baseline normal traffic flows (HTTPS, VoIP, Bulk Transfer, ICMP, and testbed capture baselines).
Keeps capture file 'config_02_tunnel_aes128gcm_dh14_pfson_all.pcap' strictly held out for independent out-of-sample evaluation.
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


def extract_pcap_normal_flows(pcap_path: Path, window_size: int = 30, step_size: int = 15) -> list[np.ndarray]:
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


def generate_baseline_normal_flows(n_samples: int = 500) -> list[np.ndarray]:
    """
    Generate synthetic representative normal IPsec ESP flows:
      - Web / HTTPS: variable packet sizes (60-1500 B), bursty intervals (mean 0.04s)
      - VoIP (RTP/SRTP): small uniform packets (160-240 B), fixed regular timing (~20ms)
      - Bulk transfer: MTU-sized packets (1400-1500 B), continuous low IAT (~5ms)
      - Network keepalive / ICMP: sparse small packets (60-170 B), regular interval (0.1-1.0s)
    """
    np.random.seed(42)
    features_list = []

    # 1. Web / HTTPS flows (~40%)
    n_https = int(n_samples * 0.40)
    for _ in range(n_https):
        lengths = np.random.normal(850, 320, 30).clip(60, 1500)
        iats = np.random.exponential(0.04, 30).clip(0.001, 1.5)
        feat = extract_flow_features(lengths.tolist(), iats.tolist())
        if feat is not None:
            features_list.append(feat)

    # 2. VoIP flows (~30%) - Constant bitrate audio
    n_voip = int(n_samples * 0.30)
    for _ in range(n_voip):
        lengths = np.random.normal(200, 15, 30).clip(150, 260)
        iats = np.random.normal(0.020, 0.002, 30).clip(0.015, 0.025)
        feat = extract_flow_features(lengths.tolist(), iats.tolist())
        if feat is not None:
            features_list.append(feat)

    # 3. Bulk transfer flows (~20%) - Large contiguous packets
    n_bulk = int(n_samples * 0.20)
    for _ in range(n_bulk):
        lengths = np.random.normal(1460, 40, 30).clip(1350, 1500)
        iats = np.random.exponential(0.005, 30).clip(0.0005, 0.03)
        feat = extract_flow_features(lengths.tolist(), iats.tolist())
        if feat is not None:
            features_list.append(feat)

    # 4. Network keepalive / ICMP (~10%)
    n_icmp = int(n_samples * 0.10)
    for _ in range(n_icmp):
        lengths = [162.0] * 30  # Standard ESP ICMP echo payload size
        iats = np.random.normal(0.5, 0.05, 30).clip(0.1, 1.0)
        feat = extract_flow_features(lengths, iats.tolist())
        if feat is not None:
            features_list.append(feat)

    return features_list


def train_anomaly_model(output_dir: Path = WEIGHTS_DIR):
    """Train Isolation Forest offline and persist joblib artifacts with SHA-256 manifest."""
    output_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Generating baseline normal traffic flows...")

    # Collect PCAP flows from baseline captures, strictly holding out config_02 for evaluation
    train_pcap_flows = []
    pcap_stems = ["config_01", "config_03", "config_04", "config_05", "config_06"]
    for stem in pcap_stems:
        matched = list(CAPTURES_DIR.glob(f"{stem}*.pcap"))
        if matched:
            fl = extract_pcap_normal_flows(matched[0], window_size=30, step_size=15)
            logger.info(f"Ingested {len(fl)} flows from {matched[0].name}")
            train_pcap_flows.extend(fl)

    synth_flows = generate_baseline_normal_flows(n_samples=500)
    # Balanced blend: authentic wire flows over multiple configurations + synthetic distributions
    all_flows = train_pcap_flows * 10 + synth_flows
    X = np.array(all_flows, dtype=np.float64)
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
    logger.info(f"Calculated 99.5th percentile anomaly threshold: {threshold:.4f} (max={train_scores.max():.4f}, mean={train_scores.mean():.4f})")

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
        "n_samples": len(X),
        "threshold": round(threshold, 6),
        "threshold_percentile": 99.5,
        "n_features": X.shape[1],
        "feature_names": [
            "mean_length", "std_length", "min_length", "max_length", "length_range",
            "mean_iat", "std_iat", "max_iat",
            "large_pkt_ratio", "small_pkt_ratio", "burst_ratio",
            "length_entropy", "iat_cv", "log_bytes_per_second",
        ],
        "held_out_evaluation_capture": "config_02_tunnel_aes128gcm_dh14_pfson_all.pcap",
        "sha256": {
            model_path.name: model_hash,
            scaler_path.name: scaler_hash,
        },
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    logger.info(f"Saved artifacts to {output_dir}:")
    logger.info(f"  - {model_path.name} (SHA-256: {model_hash[:16]}...)")
    logger.info(f"  - {scaler_path.name} (SHA-256: {scaler_hash[:16]}...)")
    logger.info(f"  - {meta_path.name}")


if __name__ == "__main__":
    train_anomaly_model()
