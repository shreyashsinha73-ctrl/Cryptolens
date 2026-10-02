"""
Unsupervised anomaly detection for ESP traffic flows.
Identifies covert channels, data exfiltration, and encrypted DDoS
using Isolation Forest (PyOD) trained on baseline normal traffic.

Free/Open-Source: PyOD (BSD-2), scikit-learn (BSD-3)
"""

import json
import logging
import numpy as np
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

WEIGHTS_DIR = Path(__file__).resolve().parent / "weights"

# Feature names for interpretability
FEATURE_NAMES = [
    "mean_length", "std_length", "min_length", "max_length", "length_range",
    "mean_iat", "std_iat", "max_iat",
    "large_pkt_ratio", "small_pkt_ratio", "burst_ratio",
    "length_entropy", "iat_cv", "bytes_per_second",
]


class AnomalyDetector:
    """
    Isolation Forest-based anomaly detector for ESP flow metadata.

    Training protocol:
        1. Collect feature vectors from all 6 baseline normal configs
        2. Fit Isolation Forest with contamination=0.05
        3. Serialize model to weights/anomaly_iforest.pkl
    """

    def __init__(self):
        self._model = None
        self._scaler = None
        self._threshold = -0.1  # Default anomaly threshold

    def _ensure_loaded(self):
        """Lazy-load or fit the model."""
        if self._model is not None:
            return

        model_path = WEIGHTS_DIR / "anomaly_iforest.pkl"
        scaler_path = WEIGHTS_DIR / "anomaly_scaler.pkl"

        if model_path.exists() and scaler_path.exists():
            import pickle
            with open(model_path, "rb") as f:
                self._model = pickle.load(f)
            with open(scaler_path, "rb") as f:
                self._scaler = pickle.load(f)
            logger.info("Loaded pre-trained anomaly detection model.")
        else:
            logger.info("No pre-trained model found. Training on synthetic baseline.")
            self._train_on_baseline()

    def _train_on_baseline(self):
        """
        Train Isolation Forest on synthetic normal traffic features.
        Uses the 6 testbed configurations as baseline normal distribution.
        """
        try:
            from pyod.models.iforest import IForest
            from sklearn.preprocessing import StandardScaler
        except ImportError:
            logger.error(
                "PyOD not installed. Run: pip install pyod"
            )
            return

        from backend.engine.anomaly.feature_engineer import extract_flow_features

        # Generate synthetic normal features from known-good distributions
        np.random.seed(42)
        normal_features = []

        # Tunnel mode HTTPS (large, bursty)
        for _ in range(100):
            lengths = np.random.normal(800, 300, 30).clip(60, 1500)
            iats = np.random.exponential(0.05, 30).clip(0.001, 2.0)
            feat = extract_flow_features(lengths.tolist(), iats.tolist())
            if feat is not None:
                normal_features.append(feat)

        # Tunnel mode VoIP (small, regular)
        for _ in range(100):
            lengths = np.random.normal(200, 30, 30).clip(100, 350)
            iats = np.random.normal(0.02, 0.003, 30).clip(0.005, 0.05)
            feat = extract_flow_features(lengths.tolist(), iats.tolist())
            if feat is not None:
                normal_features.append(feat)

        # Tunnel mode ICMP (small, sparse)
        for _ in range(50):
            lengths = np.random.normal(100, 20, 30).clip(60, 200)
            iats = np.random.normal(1.0, 0.2, 30).clip(0.3, 3.0)
            feat = extract_flow_features(lengths.tolist(), iats.tolist())
            if feat is not None:
                normal_features.append(feat)

        X = np.array(normal_features)

        # Fit scaler
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)

        # Fit Isolation Forest
        self._model = IForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42,
        )
        self._model.fit(X_scaled)

        # Save model
        import pickle
        WEIGHTS_DIR.mkdir(parents=True, exist_ok=True)
        with open(WEIGHTS_DIR / "anomaly_iforest.pkl", "wb") as f:
            pickle.dump(self._model, f)
        with open(WEIGHTS_DIR / "anomaly_scaler.pkl", "wb") as f:
            pickle.dump(self._scaler, f)

        logger.info(
            f"Trained anomaly detector on {len(normal_features)} baseline samples."
        )

    def detect(
        self,
        packet_lengths: list[float],
        inter_arrival_times: list[float],
    ) -> dict:
        """
        Detect anomalies in an ESP flow window.

        Returns:
            {
                "is_anomaly": bool,
                "anomaly_score": float,       # Higher = more anomalous
                "anomaly_label": str,         # "normal" | "covert_channel" |
                                              #   "data_exfiltration" | "ddos"
                "feature_contributions": dict, # Per-feature deviation from normal
                "description": str,
            }
        """
        self._ensure_loaded()

        if self._model is None:
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "anomaly_label": "model_unavailable",
                "feature_contributions": {},
                "description": "Anomaly detection model not available.",
            }

        from backend.engine.anomaly.feature_engineer import extract_flow_features

        features = extract_flow_features(packet_lengths, inter_arrival_times)
        if features is None:
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "anomaly_label": "insufficient_data",
                "feature_contributions": {},
                "description": "Insufficient ESP packets for anomaly analysis.",
            }

        X = features.reshape(1, -1)
        X_scaled = self._scaler.transform(X)

        # Predict
        anomaly_score = float(self._model.decision_function(X_scaled)[0])
        is_anomaly = bool(self._model.predict(X_scaled)[0] == 1)

        # Feature contribution analysis
        contributions = {}
        for i, name in enumerate(FEATURE_NAMES):
            z_score = float(X_scaled[0, i])
            contributions[name] = round(z_score, 3)

        # Classify anomaly type
        label = "normal"
        description = "Traffic flow appears normal."

        if is_anomaly:
            label, description = self._classify_anomaly_type(features, contributions)

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": round(anomaly_score, 4),
            "anomaly_label": label,
            "feature_contributions": contributions,
            "description": description,
        }

    def _classify_anomaly_type(
        self, features: np.ndarray, contributions: dict
    ) -> tuple[str, str]:
        """Classify the type of anomaly based on feature deviations."""
        mean_len = features[0]
        std_len = features[1]
        burst_ratio = features[10]
        bytes_per_sec = features[13]
        small_ratio = features[9]

        # Data exfiltration: unusually high throughput with large packets
        if bytes_per_sec > 50000 and mean_len > 1000:
            return (
                "data_exfiltration",
                f"Abnormally high throughput ({bytes_per_sec:.0f} B/s) with "
                f"large average packet size ({mean_len:.0f}B). "
                f"Possible data exfiltration over IPsec tunnel."
            )

        # Covert channel: very uniform packet sizes (low std)
        if std_len < 5 and mean_len < 200:
            return (
                "covert_channel",
                f"Suspiciously uniform packet lengths (std={std_len:.1f}B, "
                f"mean={mean_len:.0f}B). Possible covert channel using "
                f"fixed-size steganographic encoding."
            )

        # DDoS: very high packet rate with small packets
        if small_ratio > 0.8 and burst_ratio > 10:
            return (
                "ddos_packet_flooding",
                f"High ratio of small packets ({small_ratio:.0%}) with "
                f"extreme burst ratio ({burst_ratio:.1f}). "
                f"Possible encrypted DDoS / packet flooding over VPN."
            )

        return (
            "unknown_anomaly",
            f"Statistical anomaly detected but pattern does not match "
            f"known threat signatures. Manual investigation recommended."
        )
