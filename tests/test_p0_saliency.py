import pytest
import torch
import numpy as np
from unittest.mock import patch

from backend.engine.xai.saliency import grad_cam_1d, integrated_gradients_1d, _load_pytorch_model
from backend.engine.data_plane.preprocessing import preprocess_features, get_normalization_stats


def test_gradcam_output_shape():
    """Verify Grad-CAM output heatmap matches input sequence length."""
    # Standard sequence length 30
    x30 = torch.randn(1, 2, 30)
    res30 = grad_cam_1d(x30, target_head="mode")
    assert len(res30["heatmap"]) == 30

    # Non-standard sequence length 45
    x45 = torch.randn(1, 2, 45)
    res45 = grad_cam_1d(x45, target_head="traffic")
    assert len(res45["heatmap"]) == 45


def test_gradcam_non_negative():
    """Verify Grad-CAM values are non-negative due to ReLU."""
    x = torch.randn(1, 2, 30)
    res = grad_cam_1d(x, target_head="mode")
    heatmap = res["heatmap"]
    assert len(heatmap) == 30
    for val in heatmap:
        assert val >= 0.0, f"Grad-CAM value {val} is negative"
        assert val <= 1.0 + 1e-6, f"Normalized Grad-CAM value {val} exceeds 1.0"


def test_hook_cleanup_on_error():
    """Verify forward hook is removed from target_layer even when error occurs."""
    model = _load_pytorch_model()
    target_layer = model.last_conv
    initial_hook_count = len(target_layer._forward_hooks)

    x = torch.randn(1, 2, 30)

    # Intentionally trigger an error during execution
    with patch("torch.Tensor.backward", side_effect=RuntimeError("Simulated backward failure")):
        with pytest.raises(RuntimeError, match="Simulated backward failure"):
            grad_cam_1d(x, target_head="mode")

    # Assert hook was properly removed in the finally block
    assert len(target_layer._forward_hooks) == initial_hook_count, "Lingering hook detected after failure"


def test_ig_completeness():
    """Verify Integrated Gradients completeness axiom: sum(attributions) ≈ f(x) - f(baseline)."""
    x = torch.randn(1, 2, 30)
    res = integrated_gradients_1d(x, target_head="mode", n_steps=60)

    assert "completeness_delta" in res
    delta = res["completeness_delta"]
    # For a 60-step Riemann sum approximation on a smooth CNN, delta should be small (< 0.25)
    assert delta < 0.25, f"Completeness delta too high: {delta}"
    assert len(res["attributions"]) == 2
    assert len(res["attributions"][0]) == 30


def test_preprocessing_parity_and_zero_padding():
    """Verify that padding values remain exact 0.0 and are not normalized to negative numbers."""
    lengths = [100.0, 200.0, 300.0]
    iats = [0.01, 0.02, 0.03]

    x_np, x_torch = preprocess_features(lengths, iats, target_len=30)

    assert x_np.shape == (1, 2, 30)
    assert x_torch.shape == (1, 2, 30)

    # Real positions (indices 0..2) should be non-zero
    for i in range(3):
        assert x_np[0, 0, i] != 0.0
        assert x_np[0, 1, i] != 0.0

    # Padded positions (indices 3..29) MUST be exact 0.0, NOT (0 - mean) / std ≈ -0.8
    for i in range(3, 30):
        assert x_np[0, 0, i] == 0.0, f"Padded index {i} length is {x_np[0, 0, i]}, expected 0.0"
        assert x_np[0, 1, i] == 0.0, f"Padded index {i} IAT is {x_np[0, 1, i]}, expected 0.0"
