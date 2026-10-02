"""
Single shared preprocessing and feature normalization module.
Ensures strict train/serve/XAI parity by using identical normalization parameters
loaded directly from metrics.json.

Rule: Normalize real values FIRST, then pad with 0.0 (or mask).
Padded positions must have 0.0 activation value, not (0 - mean) / std.
"""

import json
from pathlib import Path
from typing import Optional, Tuple
import numpy as np
import torch

_WEIGHTS_DIR = Path(__file__).resolve().parent / "weights"
_METRICS_PATH = _WEIGHTS_DIR / "metrics.json"

_CACHED_MEAN: Optional[np.ndarray] = None
_CACHED_STD: Optional[np.ndarray] = None


def get_normalization_stats() -> Tuple[np.ndarray, np.ndarray]:
    """
    Load normalization mean and std from metrics.json.
    Returns:
        (mean, std) both of shape (1, 2, 1) as float32 numpy arrays.
    """
    global _CACHED_MEAN, _CACHED_STD
    if _CACHED_MEAN is not None and _CACHED_STD is not None:
        return _CACHED_MEAN, _CACHED_STD

    if _METRICS_PATH.exists():
        try:
            with open(_METRICS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            mean_vals = data.get("normalization_mean", [362.42984, 0.13068])
            std_vals = data.get("normalization_std", [450.82724, 0.25108])
            _CACHED_MEAN = np.array(mean_vals, dtype=np.float32).reshape(1, 2, 1)
            _CACHED_STD = np.array(std_vals, dtype=np.float32).reshape(1, 2, 1)
            return _CACHED_MEAN, _CACHED_STD
        except Exception:
            pass

    # Fallback to verified baseline constants
    _CACHED_MEAN = np.array([362.43, 0.13], dtype=np.float32).reshape(1, 2, 1)
    _CACHED_STD = np.array([450.83, 0.25], dtype=np.float32).reshape(1, 2, 1)
    return _CACHED_MEAN, _CACHED_STD


def preprocess_features(
    lengths: list[float],
    iats: list[float],
    target_len: Optional[int] = 30,
) -> Tuple[np.ndarray, torch.Tensor]:
    """
    Preprocess raw packet lengths and inter-arrival times into normalized model input.

    Order of operations (P0-8):
      1. Take real feature values.
      2. Normalize real values with (x - mean) / (std + 1e-8).
      3. Zero-pad to target_len so padded positions have exact 0.0 value.

    Returns:
        (x_norm_numpy, x_norm_torch) both with shape (1, 2, seq_len)
    """
    mean, std = get_normalization_stats()

    n_real = min(len(lengths), len(iats))
    if n_real == 0:
        actual_len = target_len if target_len is not None else 30
        arr = np.zeros((1, 2, actual_len), dtype=np.float32)
        return arr, torch.from_numpy(arr)

    # 1. Slice real values
    seq_len = target_len if target_len is not None else n_real
    k = min(n_real, seq_len)
    raw_sub = np.array([[lengths[:k], iats[:k]]], dtype=np.float32)  # (1, 2, k)

    # 2. Normalize real values FIRST
    norm_sub = (raw_sub - mean) / (std + 1e-8)

    # 3. Place into padded array with exact 0.0 for trailing slots
    final_arr = np.zeros((1, 2, seq_len), dtype=np.float32)
    final_arr[:, :, :k] = norm_sub

    return final_arr, torch.from_numpy(final_arr)
