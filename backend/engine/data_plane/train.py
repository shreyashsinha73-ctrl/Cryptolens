"""
train.py
--------
Stage: engine/data_plane

Trains DataPlaneCNN on the features from feature_extract.py / dataset.py.
Reports per-class precision/recall/F1 + confusion matrix for BOTH heads
(mode and inner-traffic), per the project doc's validation methodology -
not just aggregate accuracy, since that hides poor performance on the
rarer class (ICMP).

Usage:
    python train.py FEATURE_DIR --epochs 30
    python train.py FEATURE_DIR --held-out-config cfg06   # cross-config check

Outputs (written next to this script unless --out-dir given):
    weights/cnn_mode_traffic.onnx   - ONNX export, matches repo layout
    weights/cnn_mode_traffic.pt     - raw PyTorch state_dict (for resuming / debugging)
    metrics.json                    - full confusion matrices + per-class P/R/F1
"""

import argparse
import json
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import classification_report, confusion_matrix

from cnn_model import DataPlaneCNN
from dataset import (
    cross_config_split,
    load_sessions,
    normalize,
    session_level_split,
    to_arrays,
)
from feature_extract import MODE_CLASSES, TRAFFIC_CLASSES


def evaluate(model, X, y_mode, y_traffic, device):
    model.eval()
    with torch.no_grad():
        xb = torch.tensor(X, dtype=torch.float32, device=device)
        mode_logits, traffic_logits = model(xb)
        pred_mode = mode_logits.argmax(dim=1).cpu().numpy()
        pred_traffic = traffic_logits.argmax(dim=1).cpu().numpy()

    mode_report = classification_report(
        y_mode, pred_mode, target_names=MODE_CLASSES, output_dict=True, zero_division=0
    )
    traffic_report = classification_report(
        y_traffic, pred_traffic, target_names=TRAFFIC_CLASSES, output_dict=True, zero_division=0
    )
    mode_cm = confusion_matrix(y_mode, pred_mode, labels=range(len(MODE_CLASSES)))
    traffic_cm = confusion_matrix(y_traffic, pred_traffic, labels=range(len(TRAFFIC_CLASSES)))

    return {
        "mode_report": mode_report,
        "traffic_report": traffic_report,
        "mode_confusion_matrix": mode_cm.tolist(),
        "traffic_confusion_matrix": traffic_cm.tolist(),
    }


def train(args):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")

    sessions = load_sessions(args.feature_dir)

    if args.held_out_config:
        train_s, val_s, test_s = cross_config_split(sessions, args.held_out_config)
        print(f"Cross-config split | train={len(train_s)} test(held-out)={len(test_s)}")
    else:
        train_s, val_s, test_s = session_level_split(sessions)
        print(f"Session-level split | train={len(train_s)} val={len(val_s)} test={len(test_s)}")

    X_train, ym_train, yt_train = to_arrays(train_s)
    X_test, ym_test, yt_test = to_arrays(test_s)
    if val_s:
        X_val, ym_val, yt_val = to_arrays(val_s)
        (X_train, X_val, X_test), (mean, std) = normalize(X_train, X_val, X_test)
    else:
        (X_train, X_test), (mean, std) = normalize(X_train, X_test)
        X_val = ym_val = yt_val = None

    model = DataPlaneCNN().to(device)
    opt = torch.optim.Adam(model.parameters(), lr=args.lr)
    loss_fn = nn.CrossEntropyLoss()

    Xt = torch.tensor(X_train, dtype=torch.float32, device=device)
    ymt = torch.tensor(ym_train, dtype=torch.long, device=device)
    ytt = torch.tensor(yt_train, dtype=torch.long, device=device)

    n = Xt.shape[0]
    batch_size = min(args.batch_size, n)

    for epoch in range(1, args.epochs + 1):
        model.train()
        perm = torch.randperm(n)
        total_loss = 0.0
        for i in range(0, n, batch_size):
            idx = perm[i : i + batch_size]
            xb, ymb, ytb = Xt[idx], ymt[idx], ytt[idx]

            opt.zero_grad()
            mode_logits, traffic_logits = model(xb)
            # Equal-weighted joint loss - both heads matter for the demo.
            loss = loss_fn(mode_logits, ymb) + loss_fn(traffic_logits, ytb)
            loss.backward()
            opt.step()
            total_loss += loss.item() * xb.shape[0]

        avg_loss = total_loss / n
        if epoch % max(1, args.epochs // 10) == 0 or epoch == args.epochs:
            msg = f"epoch {epoch:3d}/{args.epochs}  train_loss={avg_loss:.4f}"
            if X_val is not None:
                val_metrics = evaluate(model, X_val, ym_val, yt_val, device)
                msg += f"  val_mode_acc={val_metrics['mode_report']['accuracy']:.3f}"
                msg += f"  val_traffic_acc={val_metrics['traffic_report']['accuracy']:.3f}"
            print(msg)

    print("\n=== Final test-set evaluation ===")
    test_metrics = evaluate(model, X_test, ym_test, yt_test, device)
    print(f"Mode accuracy:    {test_metrics['mode_report']['accuracy']:.3f}")
    print(f"Traffic accuracy: {test_metrics['traffic_report']['accuracy']:.3f}")
    print("Mode confusion matrix (rows=true, cols=pred):")
    print(np.array(test_metrics["mode_confusion_matrix"]))
    print("Traffic confusion matrix (rows=true, cols=pred):")
    print(np.array(test_metrics["traffic_confusion_matrix"]))

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    torch.save(model.state_dict(), out_dir / "cnn_mode_traffic.pt")

    # metrics.json lives inside out_dir alongside the weights it describes -
    # simpler and less surprising than a "next to the folder" convention,
    # and avoids writing outside out_dir if a caller passes a relative path.
    metrics_path = out_dir / "metrics.json"
    with open(metrics_path, "w") as f:
        json.dump(
            {
                "split": "cross_config" if args.held_out_config else "session_level",
                "held_out_config": args.held_out_config,
                "train_sessions": len(train_s),
                "test_sessions": len(test_s),
                "normalization_mean": mean.squeeze().tolist(),
                "normalization_std": std.squeeze().tolist(),
                **test_metrics,
            },
            f,
            indent=2,
        )
    print(f"\nMetrics written to {metrics_path}")

    export_onnx(model, out_dir / "cnn_mode_traffic.onnx", device)


def export_onnx(model, out_path, device):
    model.eval()
    dummy_input = torch.randn(1, 2, 30, device=device)
    torch.onnx.export(
        model,
        dummy_input,
        str(out_path),
        input_names=["esp_sequence"],
        output_names=["mode_logits", "traffic_logits"],
        dynamic_axes={"esp_sequence": {0: "batch"}},
        opset_version=18,
    )
    print(f"ONNX model exported to {out_path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("feature_dir", help="Directory of .npz files from feature_extract.py")
    ap.add_argument("--epochs", type=int, default=30)
    ap.add_argument("--batch-size", type=int, default=32)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument(
        "--held-out-config",
        default=None,
        help="If set, runs the cross-config generalization check instead of the "
        "standard session-level split (e.g. --held-out-config cfg06).",
    )
    ap.add_argument("--out-dir", default="weights")
    args = ap.parse_args()
    train(args)


if __name__ == "__main__":
    main()
