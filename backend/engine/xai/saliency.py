import functools
import logging
from pathlib import Path
from typing import Optional

import numpy as np
import torch
import torch.nn.functional as F

from backend.engine.data_plane.cnn_model import DataPlaneCNN

logger = logging.getLogger(__name__)
WEIGHTS_DIR = Path(__file__).resolve().parent.parent / "data_plane" / "weights"


@functools.lru_cache(maxsize=1)
def _load_pytorch_model() -> DataPlaneCNN:
    """Load and cache PyTorch model for gradient-based XAI (not ONNX)."""
    model = DataPlaneCNN(seq_len=30, n_mode_classes=2, n_traffic_classes=3)
    ckpt_path = WEIGHTS_DIR / "cnn_mode_traffic.pt"
    if ckpt_path.exists():
        model.load_state_dict(torch.load(ckpt_path, map_location="cpu", weights_only=True))
    else:
        raise FileNotFoundError(
            f"PyTorch checkpoint not found at {ckpt_path}. "
            "PyTorch checkpoint required to enable XAI backpropagation."
        )
    model.eval()
    return model


def grad_cam_1d(
    input_tensor: torch.Tensor,
    target_head: str = "mode",
    target_class: int | None = None,
) -> dict:
    """
    Compute Grad-CAM heatmap for the 1D-CNN.
    Uses tensor hooks for robust gradient capture under in-place ReLU,
    model caching, and interpolation to guarantee len(heatmap) == input_len.
    """
    model = _load_pytorch_model()
    target_layer = model.last_conv

    activations = {}
    gradients = {}

    def forward_hook(module, inp, out):
        activations["value"] = out
        # Tensor hook on layer output (immune to in-place ReLU)
        out.register_hook(lambda grad: gradients.__setitem__("value", grad))

    fh = target_layer.register_forward_hook(forward_hook)
    try:
        input_len = input_tensor.shape[-1]
        input_clone = input_tensor.clone().detach().requires_grad_(True)
        mode_logits, traffic_logits = model(input_clone)

        if target_head == "mode":
            logits = mode_logits
            class_names = ["transport", "tunnel"]
        else:
            logits = traffic_logits
            class_names = ["https", "voip", "icmp"]

        probs = F.softmax(logits, dim=1)

        if target_class is None:
            target_class = logits.argmax(dim=1).item()

        # Backward pass for the target class
        model.zero_grad()
        score = logits[0, target_class]
        score.backward()

        # Compute Grad-CAM
        grads = gradients["value"]             # (1, 64, L_conv)
        acts = activations["value"]            # (1, 64, L_conv)
        weights = grads.mean(dim=2, keepdim=True)  # Global avg pool of gradients
        cam = (weights * acts).sum(dim=1, keepdim=True)  # (1, 1, L_conv)
        cam = F.relu(cam)                       # Non-negative influence

        # Interpolate heatmap to input length if pooling or stride differed
        if cam.shape[-1] != input_len:
            cam = F.interpolate(cam, size=input_len, mode="linear", align_corners=False)

        cam_np = cam.squeeze(0).squeeze(0).detach().cpu().numpy()

        raw_max = float(cam_np.max())
        if raw_max > 0:
            cam_np = cam_np / raw_max

        assert len(cam_np) == input_len, f"Heatmap length {len(cam_np)} != input length {input_len}"

        top_indices = np.argsort(cam_np)[::-1][:5].tolist()

        return {
            "heatmap": [float(v) for v in cam_np],
            "raw_max_attribution": raw_max,
            "predicted_class": class_names[target_class],
            "predicted_confidence": float(probs[0, target_class].item()),
            "top_indices": top_indices,
        }
    finally:
        fh.remove()


def integrated_gradients_1d(
    input_tensor: torch.Tensor,
    target_head: str = "mode",
    target_class: int | None = None,
    n_steps: int = 50,
) -> dict:
    """
    Compute Integrated Gradients attribution for the 1D-CNN with completeness check.
    Completeness: sum(attributions) ≈ f(x) - f(baseline).
    """
    model = _load_pytorch_model()
    input_len = input_tensor.shape[-1]
    baseline = torch.zeros_like(input_tensor)

    # 1. Compute f(x) and f(baseline) for completeness verification
    with torch.no_grad():
        m_base, t_base = model(baseline)
        m_x, t_x = model(input_tensor)
        l_base = m_base if target_head == "mode" else t_base
        l_x = m_x if target_head == "mode" else t_x
        if target_class is None:
            target_class = l_x.argmax(dim=1).item()
        f_baseline = float(l_base[0, target_class].item())
        f_x = float(l_x[0, target_class].item())

    # 2. Interpolate between baseline and input
    scaled_inputs = [
        baseline + (float(i) / n_steps) * (input_tensor - baseline)
        for i in range(n_steps + 1)
    ]
    scaled_inputs = torch.cat(scaled_inputs, dim=0).requires_grad_(True)

    mode_logits, traffic_logits = model(scaled_inputs)
    logits = mode_logits if target_head == "mode" else traffic_logits

    model.zero_grad()
    score = logits[:, target_class].sum()
    score.backward()

    grads = scaled_inputs.grad
    avg_grads = grads.mean(dim=0, keepdim=True)
    attributions = (input_tensor - baseline) * avg_grads  # (1, 2, input_len)
    attr_np = attributions.squeeze(0).detach().cpu().numpy()

    # Completeness check
    sum_attr = float(attr_np.sum())
    expected_delta = f_x - f_baseline
    completeness_delta = abs(sum_attr - expected_delta)

    channel_importance = [
        float(np.abs(attr_np[0]).sum()),
        float(np.abs(attr_np[1]).sum()),
    ]

    combined = np.abs(attr_np).sum(axis=0)
    top_indices = np.argsort(combined)[::-1][:5].tolist()

    class_names = (
        ["transport", "tunnel"] if target_head == "mode"
        else ["https", "voip", "icmp"]
    )

    return {
        "attributions": attr_np.tolist(),
        "channel_importance": channel_importance,
        "predicted_class": class_names[target_class],
        "top_indices": top_indices,
        "completeness_delta": round(completeness_delta, 4),
        "f_x": round(f_x, 4),
        "f_baseline": round(f_baseline, 4),
    }
