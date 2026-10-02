"""
Unsupervised anomaly detection for ESP traffic flows.
Identifies anomalous flow patterns using an offline-trained Isolation Forest (PyOD)
calibrated at a 99.5th percentile threshold on baseline normal traffic.

Free/Open-Source: PyOD (BSD-2), scikit-learn (BSD-3)
"""

import json
import logging
from collections import deque
from pathlib import Path
from typing import Optional, Tuple

import joblib
import numpy as np

from backend.engine.anomaly.feature_engineer import extract_flow_features

logger = logging.getLogger(__name__)

WEIGHTS_DIR = Path(__file__).resolve().parent / "weights"

# Feature names for interpretability (14 dimensions)
FEATURE_NAMES = [
    "mean_length", "std_length", "min_length", "max_length", "length_range",
    "mean_iat", "std_iat", "max_iat",
    "large_pkt_ratio", "small_pkt_ratio", "burst_ratio",
    "length_entropy", "iat_cv", "log_bytes_per_second",
]


class AnomalyDetector:
    """
    Isolation Forest-based anomaly detector for ESP flow metadata.
    Enforces offline pre-trained models and k-of-n window temporal persistence.
    """

    def __init__(self, k_windows: int = 3, n_windows: int = 5):
        self._model = None
        self._scaler = None
        self._threshold = 0.0081  # Default 99.5th percentile threshold
        self.k_windows = k_windows
        self.n_windows = n_windows
        self._window_history = deque(maxlen=n_windows)

    def reset_history(self):
        """Reset consecutive window evaluation history."""
        self._window_history.clear()

    def _ensure_loaded(self):
        """Load pre-trained model and scaler from joblib files. No in-request training."""
        if self._model is not None and self._scaler is not None:
            return

        model_path = WEIGHTS_DIR / "anomaly_iforest.joblib"
        scaler_path = WEIGHTS_DIR / "anomaly_scaler.joblib"
        meta_path = WEIGHTS_DIR / "anomaly_metadata.json"

        if not model_path.exists() or not scaler_path.exists():
            # Check legacy pkl fallback if available
            legacy_model = WEIGHTS_DIR / "anomaly_iforest.pkl"
            legacy_scaler = WEIGHTS_DIR / "anomaly_scaler.pkl"
            if legacy_model.exists() and legacy_scaler.exists():
                import pickle
                with open(legacy_model, "rb") as f:
                    self._model = pickle.load(f)
                with open(legacy_scaler, "rb") as f:
                    self._scaler = pickle.load(f)
                logger.info("Loaded legacy anomaly detection model.")
                return

            raise FileNotFoundError(
                f"Pre-trained anomaly detector weights not found in {WEIGHTS_DIR}. "
                f"Run 'python scripts/train_anomaly.py' to generate offline weights."
            )

        self._model = joblib.load(model_path)
        self._scaler = joblib.load(scaler_path)

        if meta_path.exists():
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                self._threshold = float(meta.get("threshold", self._threshold))
                manifest_hashes = meta.get("sha256", {})
                if manifest_hashes:
                    import hashlib

                    def get_file_sha256(p: Path) -> str:
                        h = hashlib.sha256()
                        with open(p, "rb") as f:
                            while chunk := f.read(65536):
                                h.update(chunk)
                        return h.hexdigest()

                    expected_model = manifest_hashes.get(model_path.name)
                    if expected_model and get_file_sha256(model_path) != expected_model:
                        raise ValueError(f"Integrity check failed: {model_path.name} SHA-256 mismatch")

                    expected_scaler = manifest_hashes.get(scaler_path.name)
                    if expected_scaler and get_file_sha256(scaler_path) != expected_scaler:
                        raise ValueError(f"Integrity check failed: {scaler_path.name} SHA-256 mismatch")
            except ValueError:
                raise
            except Exception as e:
                logger.warning(f"Could not load metadata from {meta_path}: {e}")

        logger.info(f"Loaded pre-trained Isolation Forest (threshold={self._threshold:.4f}).")

    def detect(
        self,
        packet_lengths: list[float],
        inter_arrival_times: list[float],
        force_single_window: bool = False,
    ) -> dict:
        """
        Detect anomalies in an ESP flow window.

        Args:
            packet_lengths: Window packet lengths (bytes)
            inter_arrival_times: Window inter-arrival times (seconds)
            force_single_window: If True, bypass k-of-n requirement for unit testing.

        Returns:
            Dict containing:
                - is_anomaly: bool (True only if k-of-n consecutive windows violate threshold)
                - anomaly_score: float (decision function score)
                - anomaly_label: str
                - feature_zscores: dict of per-feature z-scores
                - feature_contributions: backwards-compatible alias
                - description: str
        """
        self._ensure_loaded()

        features = extract_flow_features(packet_lengths, inter_arrival_times)
        if features is None:
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "anomaly_label": "insufficient_data",
                "feature_zscores": {},
                "feature_contributions": {},
                "description": "Insufficient ESP packets for anomaly analysis (minimum 5 required).",
            }

        X = features.reshape(1, -1)
        X_scaled = self._scaler.transform(X)

        # PyOD Isolation Forest decision function: higher = more anomalous
        raw_score = float(self._model.decision_function(X_scaled)[0])
        window_anomalous = bool(raw_score > self._threshold)

        # Record into history
        self._window_history.append(window_anomalous)
        anomalous_in_window = sum(self._window_history)

        if force_single_window:
            is_anomaly = window_anomalous
        else:
            is_anomaly = bool(anomalous_in_window >= self.k_windows)

        # Feature z-scores
        zscores = {}
        for i, name in enumerate(FEATURE_NAMES):
            zscores[name] = round(float(X_scaled[0, i]), 3)

        label = "normal"
        description = "Traffic flow statistical profile matches normal baseline."

        if is_anomaly or window_anomalous:
            label, description = self._classify_anomaly_profile(features, zscores, is_anomaly)

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": round(raw_score, 4),
            "anomaly_label": label,
            "threshold": round(self._threshold, 4),
            "k_of_n_count": f"{anomalous_in_window}/{len(self._window_history)}",
            "feature_zscores": zscores,
            "feature_contributions": zscores,  # Backwards compatibility alias
            "description": description,
        }

    def _classify_anomaly_profile(
        self,
        features: np.ndarray,
        zscores: dict,
        persisted: bool,
    ) -> Tuple[str, str]:
        """
        Relabel heuristics honestly based on observable traffic statistics.
        Refrains from claiming covert channels or data exfiltration without tunnel baselines.
        """
        mean_len = features[0]
        std_len = features[1]
        mean_iat = features[5]
        burst_ratio = features[10]
        small_ratio = features[9]
        log_bps = features[13]

        # Normal profile guards:
        # Constant-bitrate VoIP: small packets (< 300B) with low jitter (< 0.05s)
        if 100 <= mean_len <= 350 and std_len < 40 and 0.010 <= mean_iat <= 0.050:
            return (
                "normal",
                "Traffic matches standard constant-bitrate VoIP audio session."
            )

        # Bulk transfer: large packets (> 1300B) with high throughput
        if mean_len >= 1300 and log_bps > 10.0 and small_ratio < 0.15:
            return (
                "normal",
                "Traffic matches standard high-throughput bulk IPsec data transfer."
            )

        persistence_note = " (persisted across rolling windows)" if persisted else " (transient deviation)"

        # High burst small packets
        if small_ratio > 0.85 and burst_ratio > 8.0:
            return (
                "anomalous_flow (high_volume_burst)",
                f"Abnormally high ratio of small packets ({small_ratio:.0%}) with "
                f"burst ratio {burst_ratio:.1f}{persistence_note}."
            )

        # Extreme uniform packet size deviation
        if std_len < 2.0 and mean_len < 150:
            return (
                "anomalous_flow (resembles uniform small packets)",
                f"Unusually uniform packet lengths (std={std_len:.2f}B, "
                f"mean={mean_len:.1f}B){persistence_note}."
            )

        return (
            "anomalous_flow (statistical deviation)",
            f"Statistical deviation from baseline distribution (score above 99.5th percentile)"
            f"{persistence_note}. Review feature z-scores."
        )
