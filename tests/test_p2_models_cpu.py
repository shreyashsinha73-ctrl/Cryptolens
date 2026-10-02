import pytest
import torch
import numpy as np
from pathlib import Path

from backend.engine.data_plane.cnn_model import DataPlaneCNN
from backend.engine.data_plane.classifier import _get_onnx_session
from backend.engine.anomaly.detector import AnomalyDetector


def test_pytorch_model_loads_and_runs_cpu_forward_pass():
    """Verify DataPlaneCNN PyTorch model checkpoint loads and executes forward pass on CPU."""
    weights_path = (
        Path(__file__).resolve().parent.parent
        / "backend"
        / "engine"
        / "data_plane"
        / "weights"
        / "cnn_mode_traffic.pt"
    )
    assert weights_path.exists(), f"PyTorch weights not found at {weights_path}"

    model = DataPlaneCNN(seq_len=30, n_mode_classes=2, n_traffic_classes=3)
    state_dict = torch.load(weights_path, map_location="cpu", weights_only=True)
    model.load_state_dict(state_dict)
    model.eval()

    # Synthetic batch of shape (batch_size=4, channels=2, sequence_length=30)
    dummy_input = torch.randn(4, 2, 30, dtype=torch.float32)
    with torch.no_grad():
        mode_logits, traffic_logits = model(dummy_input)

    assert mode_logits.shape == (4, 2), f"Unexpected mode_logits shape: {mode_logits.shape}"
    assert traffic_logits.shape == (4, 3), f"Unexpected traffic_logits shape: {traffic_logits.shape}"
    assert not torch.isnan(mode_logits).any()
    assert not torch.isnan(traffic_logits).any()


def test_onnx_session_runs_cpu_inference():
    """Verify ONNX runtime session executes on CPU."""
    session, mode_classes, traffic_classes = _get_onnx_session()
    dummy_input = np.random.randn(1, 2, 30).astype(np.float32)

    input_name = session.get_inputs()[0].name
    outputs = session.run(None, {input_name: dummy_input})

    assert len(outputs) == 2
    mode_out, traffic_out = outputs
    assert mode_out.shape == (1, 2)
    assert traffic_out.shape == (1, 3)


def test_anomaly_detector_cpu_inference():
    """Verify AnomalyDetector loads trained IsolationForest model and scores synthetic input."""
    detector = AnomalyDetector()
    lengths = [1420.0] * 20
    iats = [0.02] * 20

    res = detector.detect(lengths, iats)
    assert "is_anomaly" in res
    assert "anomaly_score" in res
    assert "anomaly_label" in res
    assert "feature_zscores" in res
