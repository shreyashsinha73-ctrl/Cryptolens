"""
Offline Training Script for CryptoLens ESP Anomaly Detector.
Trains an Isolation Forest on baseline normal traffic flows (HTTPS, VoIP, Bulk Transfer, ICMP).
Computes 99.5th percentile threshold on normal baseline to guarantee <= 0.5% FPR on normal data.
Saves serialized model and scaler as joblib artifacts.
"""

import json
import logging
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import joblib
import numpy as np
from pyod.models.iforest import IForest
from sklearn.preprocessing import StandardScaler

from backend.engine.anomaly.feature_engineer import extract_flow_features

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

WEIGHTS_DIR = Path(__file__).resolve().parent.parent / "backend" / "engine" / "anomaly" / "weights"


def generate_baseline_normal_flows(n_samples: int = 1200) -> list[np.ndarray]:
    """
    Generate synthetic representative normal IPsec ESP flows:
      - Web / HTTPS: variable packet sizes (60-1500 B), bursty intervals (mean 0.04s)
      - VoIP (RTP/SRTP): small uniform packets (160-240 B), fixed regular timing (~20ms)
      - Bulk transfer: MTU-sized packets (1400-1500 B), continuous low IAT (~5ms)
      - Network keepalive / ICMP: sparse small packets (60-120 B), regular interval (0.5-2.0s)
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
        lengths = np.random.normal(90, 10, 30).clip(64, 128)
        iats = np.random.normal(1.0, 0.1, 30).clip(0.5, 2.0)
        feat = extract_flow_features(lengths.tolist(), iats.tolist())
        if feat is not None:
            features_list.append(feat)

    return features_list


def train_anomaly_model(output_dir: Path = WEIGHTS_DIR):
    """Train Isolation Forest offline and persist joblib artifacts."""
    output_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Generating baseline normal traffic flows...")
    raw_features = generate_baseline_normal_flows(n_samples=1500)
    X = np.array(raw_features, dtype=np.float64)
    logger.info(f"Extracted features for {len(X)} normal flows (shape: {X.shape})")

    # Fit scaler
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Fit Isolation Forest
    logger.info("Fitting Isolation Forest model...")
    # Using low contamination placeholder during fit; true decision boundary set via 99.5th percentile
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
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    logger.info(f"Saved artifacts to {output_dir}:")
    logger.info(f"  - {model_path.name}")
    logger.info(f"  - {scaler_path.name}")
    logger.info(f"  - {meta_path.name}")


if __name__ == "__main__":
    train_anomaly_model()
