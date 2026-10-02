"""
ESP flow feature engineering for unsupervised anomaly detection.
Extracts statistical features from ESP packet metadata sequences.
"""

import numpy as np
from typing import Optional


def extract_flow_features(
    packet_lengths: list[float],
    inter_arrival_times: list[float],
    window_size: int = 30,
) -> Optional[np.ndarray]:
    """
    Extract a feature vector from an ESP flow window.

    Feature Vector (14 dimensions):
        [0]  mean_length          - Mean packet length
        [1]  std_length           - Std deviation of packet lengths
        [2]  min_length           - Minimum packet length
        [3]  max_length           - Maximum packet length
        [4]  length_range         - max - min packet length
        [5]  mean_iat             - Mean inter-arrival time
        [6]  std_iat              - Std deviation of IATs
        [7]  max_iat              - Maximum IAT (burst gap)
        [8]  large_pkt_ratio      - Fraction of packets >= 600 bytes
        [9]  small_pkt_ratio      - Fraction of packets < 100 bytes
        [10] burst_ratio          - Ratio of max_iat to mean_iat
        [11] length_entropy       - Shannon entropy of length distribution
        [12] iat_cv               - Coefficient of variation of IATs
        [13] bytes_per_second     - Total bytes / total time
    """
    if len(packet_lengths) < 5:
        return None

    lengths = np.array(packet_lengths[:window_size], dtype=np.float64)
    iats = np.array(inter_arrival_times[:window_size], dtype=np.float64)

    # Length statistics
    mean_len = np.mean(lengths)
    std_len = np.std(lengths) + 1e-8
    min_len = np.min(lengths)
    max_len = np.max(lengths)
    length_range = max_len - min_len

    # IAT statistics
    positive_iats = iats[iats > 0]
    mean_iat = np.mean(positive_iats) if len(positive_iats) > 0 else 0.0
    std_iat = np.std(positive_iats) if len(positive_iats) > 0 else 0.0
    max_iat = np.max(positive_iats) if len(positive_iats) > 0 else 0.0

    # Ratios
    large_pkt_ratio = np.sum(lengths >= 600) / len(lengths)
    small_pkt_ratio = np.sum(lengths < 100) / len(lengths)
    burst_ratio = (max_iat / mean_iat) if mean_iat > 0 else 0.0

    # Shannon entropy of length distribution
    length_bins = np.histogram(lengths, bins=10)[0].astype(np.float64)
    length_bins = length_bins[length_bins > 0]
    length_probs = length_bins / length_bins.sum()
    length_entropy = -np.sum(length_probs * np.log2(length_probs + 1e-12))

    # Coefficient of variation for IATs
    iat_cv = (std_iat / mean_iat) if mean_iat > 0 else 0.0

    # Throughput (log-transformed for variance stability across orders of magnitude)
    total_time = np.sum(positive_iats) if len(positive_iats) > 0 else 1.0
    bytes_per_second = np.sum(lengths) / max(total_time, 0.001)
    log_bytes_per_second = float(np.log1p(bytes_per_second))

    return np.array([
        mean_len, std_len, min_len, max_len, length_range,
        mean_iat, std_iat, max_iat,
        large_pkt_ratio, small_pkt_ratio, burst_ratio,
        length_entropy, iat_cv, log_bytes_per_second,
    ], dtype=np.float64)
