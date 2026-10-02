import numpy as np
import pytest

from backend.engine.anomaly.detector import AnomalyDetector
from backend.engine.anomaly.feature_engineer import extract_flow_features


def test_offline_loading_and_threshold():
    """Verify anomaly detector loads offline-trained joblib weights with 99.5th percentile threshold."""
    detector = AnomalyDetector()
    detector._ensure_loaded()
    assert detector._model is not None
    assert detector._scaler is not None
    # 99.5th percentile threshold should be close to 0.008
    assert detector._threshold > -0.05
    assert detector._threshold < 0.05


def test_low_fpr_on_normal_traffic():
    """Verify that false positive rate on baseline normal traffic is <= 2% (far below 5%)."""
    detector = AnomalyDetector()
    detector._ensure_loaded()
    np.random.seed(99)

    normal_samples = 100
    anomalies_detected = 0

    for _ in range(normal_samples):
        # Generate normal HTTPS flow
        lengths = np.random.normal(850, 300, 30).clip(60, 1500).tolist()
        iats = np.random.exponential(0.04, 30).clip(0.001, 1.5).tolist()
        res = detector.detect(lengths, iats, force_single_window=True)
        if res["is_anomaly"]:
            anomalies_detected += 1

    fpr = anomalies_detected / normal_samples
    assert fpr <= 0.02, f"FPR on normal traffic was too high: {fpr:.2%}"


def test_k_of_n_consecutive_windows():
    """Verify that k-of-n window filter requires 3 of 5 windows before raising an alert."""
    detector = AnomalyDetector(k_windows=3, n_windows=5)
    detector.reset_history()

    # Extreme anomalous traffic (e.g. huge burst flooding)
    bad_lengths = [70.0] * 30
    bad_iats = [0.0001] * 29 + [10.0]  # extreme burst

    # Window 1: anomalous, but only 1/1 -> is_anomaly should be False
    res1 = detector.detect(bad_lengths, bad_iats)
    assert res1["is_anomaly"] is False
    assert res1["k_of_n_count"] == "1/1"

    # Window 2: anomalous, 2/2 -> is_anomaly should be False
    res2 = detector.detect(bad_lengths, bad_iats)
    assert res2["is_anomaly"] is False
    assert res2["k_of_n_count"] == "2/2"

    # Window 3: anomalous, 3/3 -> is_anomaly becomes True! (k=3 reached)
    res3 = detector.detect(bad_lengths, bad_iats)
    assert res3["is_anomaly"] is True
    assert res3["k_of_n_count"] == "3/3"


def test_voip_regression_not_flagged_as_covert_channel():
    """Verify that constant-bitrate VoIP audio is NOT flagged as covert channel."""
    detector = AnomalyDetector()
    detector.reset_history()
    np.random.seed(123)

    # 30 packets of standard G.711 / Opus VoIP: ~200B at 20ms intervals
    voip_lengths = np.random.normal(200, 10, 30).clip(160, 240).tolist()
    voip_iats = np.random.normal(0.020, 0.001, 30).clip(0.018, 0.022).tolist()

    res = detector.detect(voip_lengths, voip_iats)
    # Must NOT claim covert_channel
    assert "covert_channel" not in res["anomaly_label"]
    assert res["anomaly_label"] == "normal"


def test_bulk_transfer_regression_not_flagged_as_exfiltration():
    """Verify that high-throughput bulk transfer is NOT flagged as data exfiltration."""
    detector = AnomalyDetector()
    detector.reset_history()
    np.random.seed(456)

    # 30 packets of full MTU bulk transfer
    bulk_lengths = np.random.normal(1460, 20, 30).clip(1400, 1500).tolist()
    bulk_iats = np.random.exponential(0.004, 30).clip(0.0005, 0.015).tolist()

    res = detector.detect(bulk_lengths, bulk_iats)
    # Must NOT claim data_exfiltration
    assert "data_exfiltration" not in res["anomaly_label"]
    assert res["anomaly_label"] == "normal"


def test_honest_label_and_feature_zscores():
    """Verify honest labeling and presence of feature_zscores dictionary."""
    detector = AnomalyDetector()
    detector.reset_history()

    # Extreme uniform small packet pattern
    lengths = [80.0] * 30
    iats = [0.001] * 29 + [5.0]

    res = detector.detect(lengths, iats, force_single_window=True)
    assert "feature_zscores" in res
    assert "feature_contributions" in res  # Backwards compatibility
    assert "log_bytes_per_second" in res["feature_zscores"]

    # If anomalous, label must use honest description
    if res["is_anomaly"]:
        assert "anomalous_flow" in res["anomaly_label"]
        assert "covert_channel" not in res["anomaly_label"]
        assert "data_exfiltration" not in res["anomaly_label"]
