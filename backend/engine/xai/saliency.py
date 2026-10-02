"""
1D Gradient-weighted Class Activation Mapping (Grad-CAM)
and Integrated Gradients for the DataPlaneCNN model.

References:
  - Selvaraju et al., "Grad-CAM" (ICCV 2017), adapted for 1D convolutions
  - Sundararajan et al., "Axiomatic Attribution for Deep Networks" (ICML 2017)
"""

import numpy as np
import torch
import torch.nn.functional as F
from pathlib import Path

from backend.engine.data_plane.cnn_model import DataPlaneCNN

WEIGHTS_DIR = Path(__file__).resolve().parent.parent / "data_plane" / "weights"


def _load_pytorch_model() -> DataPlaneCNN:
    """Load PyTorch model for gradient-based XAI (not ONNX)."""
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

    Args:
        input_tensor: shape (1, 2, 30) — normalized S_L and S_IAT
        target_head: "mode" or "traffic"
        target_class: class index to explain (None = predicted class)

    Returns:
        {
            "heatmap": list[float],   # 30-element saliency per sequence position
            "predicted_class": str,
            "predicted_confidence": float,
            "top_indices": list[int], # Top 5 most influential sequence positions
        }
    """
    model = _load_pytorch_model()

    # Hook into the last conv layer output (trunk[3] = second Conv1d)
    activations = {}
    gradients = {}

    def forward_hook(module, inp, out):
        activations["value"] = out

    def backward_hook(module, grad_in, grad_out):
        gradients["value"] = grad_out[0]

    # Register hooks on the second Conv1d (trunk layer index 3)
    target_layer = model.trunk[3]  # Second nn.Conv1d(64, 64, 3)
    fh = target_layer.register_forward_hook(forward_hook)
    bh = target_layer.register_full_backward_hook(backward_hook)

    # Forward pass
    input_tensor = input_tensor.clone().detach().requires_grad_(True)
    mode_logits, traffic_logits = model(input_tensor)

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
    grads = gradients["value"]             # (1, 64, seq_len)
    acts = activations["value"]            # (1, 64, seq_len)
    weights = grads.mean(dim=2, keepdim=True)  # Global avg pool of gradients
    cam = (weights * acts).sum(dim=1)      # (1, seq_len)
    cam = F.relu(cam)                       # ReLU to keep positive influence
    cam = cam.squeeze(0).detach().numpy()

    # Normalize to [0, 1]
    if cam.max() > 0:
        cam = cam / cam.max()

    # Clean up hooks
    fh.remove()
    bh.remove()

    # Top influential positions
    top_indices = np.argsort(cam)[::-1][:5].tolist()

    return {
        "heatmap": cam.tolist(),
        "predicted_class": class_names[target_class],
        "predicted_confidence": float(probs[0, target_class].item()),
        "top_indices": top_indices,
    }


def integrated_gradients_1d(
    input_tensor: torch.Tensor,
    target_head: str = "mode",
    target_class: int | None = None,
    n_steps: int = 50,
) -> dict:
    """
    Compute Integrated Gradients attribution for the 1D-CNN.

    Uses a zero baseline and interpolates in n_steps.

    Returns:
        {
            "attributions": list[list[float]],  # (2, 30) per-channel attributions
            "channel_importance": list[float],   # [S_L importance, S_IAT importance]
            "predicted_class": str,
            "top_indices": list[int],
        }
    """
    model = _load_pytorch_model()

    baseline = torch.zeros_like(input_tensor)

    # Interpolate between baseline and input
    scaled_inputs = [
        baseline + (float(i) / n_steps) * (input_tensor - baseline)
        for i in range(n_steps + 1)
    ]
    scaled_inputs = torch.cat(scaled_inputs, dim=0)  # (n_steps+1, 2, 30)
    scaled_inputs.requires_grad_(True)

    # Forward pass
    mode_logits, traffic_logits = model(scaled_inputs)
    logits = mode_logits if target_head == "mode" else traffic_logits

    if target_class is None:
        with torch.no_grad():
            m, t = model(input_tensor)
            target_class = (m if target_head == "mode" else t).argmax(dim=1).item()

    # Backward
    scores = logits[:, target_class].sum()
    scores.backward()

    grads = scaled_inputs.grad  # (n_steps+1, 2, 30)

    # Riemann approximation of the integral
    avg_grads = grads.mean(dim=0)  # (2, 30)
    attributions = (input_tensor.squeeze(0) - baseline.squeeze(0)) * avg_grads
    attributions = attributions.detach().numpy()

    # Channel importance
    channel_importance = [
        float(np.abs(attributions[0]).sum()),  # S_L importance
        float(np.abs(attributions[1]).sum()),  # S_IAT importance
    ]

    # Top indices (by combined channel attribution magnitude)
    combined = np.abs(attributions).sum(axis=0)
    top_indices = np.argsort(combined)[::-1][:5].tolist()

    class_names = (
        ["transport", "tunnel"] if target_head == "mode"
        else ["https", "voip", "icmp"]
    )

    return {
        "attributions": attributions.tolist(),
        "channel_importance": channel_importance,
        "predicted_class": class_names[target_class],
        "top_indices": top_indices,
    }
