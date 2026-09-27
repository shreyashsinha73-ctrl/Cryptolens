#!/usr/bin/env python3
"""
Validate inference pipeline accuracy against labeled dataset.

Measures:
1. API-vs-ground-truth accuracy (from filename labels)
2. Heuristic-vs-API agreement (live metric)
3. Confidence score statistics

Generates metrics_report.json with detailed breakdown.
"""

import argparse
import json
import logging
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Auto-switch to .venv python if available and not currently running inside a virtual environment
if sys.prefix == sys.base_prefix:
    venv_python = PROJECT_ROOT / ".venv" / "bin" / "python3"
    if venv_python.exists():
        import os
        os.execv(str(venv_python), [str(venv_python)] + sys.argv)

try:
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env")
except ImportError:
    pass

from backend.engine.data_plane.feature_extract import (
    parse_label_from_filename,
)

from backend.engine.data_plane.traffic_analyzer import analyze_data_plane

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def compute_confusion_matrix(
    predictions: List[Tuple[str, str]], classes: List[str]
) -> Dict[str, Dict[str, int]]:
    """Build confusion matrix from (ground_truth, predicted) tuples."""
    matrix = {c: {c2: 0 for c2 in classes} for c in classes}
    for gt, pred in predictions:
        if gt in matrix and pred in classes:
            matrix[gt][pred] += 1
    return matrix


def compute_f1_macro(confusion_matrix: Dict[str, Dict[str, int]]) -> float:
    """Compute macro F1 score from confusion matrix."""
    class_scores = []
    for class_name, row in confusion_matrix.items():
        tp = row.get(class_name, 0)
        fp = sum(v for k, v in row.items() if k != class_name)
        fn = sum(confusion_matrix[c].get(class_name, 0) for c in confusion_matrix if c != class_name)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        class_scores.append(f1)

    return sum(class_scores) / len(class_scores) if class_scores else 0.0


def validate_dataset(dataset_dir: Path, verbose: bool = False) -> Dict[str, Any]:
    """
    Validate all labeled PCAPs in dataset_dir.

    Returns metrics dict with API-vs-GT accuracy and heuristic-vs-API agreement.
    """
    pcap_files = sorted(dataset_dir.glob("*__*__*__*.pcap"))
    if not pcap_files:
        pcap_files = sorted([f for f in dataset_dir.glob("*.pcap")]) + sorted([f for f in dataset_dir.glob("*.pcapng")])
    if not pcap_files:
        logger.warning(f"No PCAP files found in {dataset_dir}")
        return _empty_metrics()

    logger.info(f"Found {len(pcap_files)} PCAP files for validation")

    # Track results
    mode_predictions: List[Tuple[str, str]] = []  # (ground_truth, predicted)
    traffic_predictions: List[Tuple[str, str]] = []
    agreement_results = {"mode": 0, "traffic": 0, "overall": 0}
    api_call_count = {"success": 0, "failed": 0}
    confidence_stats = {
        "mode": {"scores": [], "count": 0},
        "traffic": {"scores": [], "count": 0},
    }

    for pcap_path in pcap_files:
        try:
            # Parse filename for ground truth
            label = parse_label_from_filename(str(pcap_path))
            gt_mode = label.mode
            gt_traffic = label.traffic_type
            config_id = label.config_id

            if verbose:
                logger.info(f"Validating {pcap_path.name} (GT: {gt_mode}/{gt_traffic})")

            

            # Alternative: Use traffic_analyzer which handles extraction
            data_plane_result = analyze_data_plane(str(pcap_path))
            heuristic_mode = data_plane_result.get("heuristic_mode_prediction")
            api_mode = data_plane_result.get("llm_mode_prediction")
            api_confidence = data_plane_result.get("ai_confidence_score", 0.0)
            agreement_flag = data_plane_result.get("agreement_flag", False)

            if api_mode is None:
                logger.warning(f"  → No ESP packets or API inference failed for {pcap_path.name}")
                api_call_count["failed"] += 1
                continue

            api_call_count["success"] += 1

            # Track API-vs-GT accuracy
            # Normalize modes (API returns lowercase)
            api_mode_norm = api_mode.lower() if api_mode else "unknown"
            gt_mode_norm = gt_mode.lower() if gt_mode else "unknown"
            mode_predictions.append((gt_mode_norm, api_mode_norm))

            # Note: Traffic type from data_plane is categorized (VoIP, Messaging, Web, Video)
            # not the raw https/voip/icmp from API. So we approximate based on heuristic.
            # For full accuracy, would need to modify data_plane_result structure.
            # For now, track agreement flag and confidence.
            traffic_predictions.append((gt_traffic, "unknown"))  # Placeholder

            # Track heuristic-vs-API agreement
            if heuristic_mode and api_mode and heuristic_mode.lower() == api_mode.lower():
                agreement_results["mode"] += 1
            if api_confidence > 0:
                confidence_stats["mode"]["scores"].append(api_confidence)
                confidence_stats["mode"]["count"] += 1

            if verbose:
                logger.info(
                    f"  → API: {api_mode} (conf={api_confidence:.2f}), "
                    f"Heuristic: {heuristic_mode}, Agreement: {agreement_flag}"
                )

        except Exception as e:
            logger.error(f"Error processing {pcap_path.name}: {e}")
            api_call_count["failed"] += 1

    # Compute summary metrics
    mode_accuracy = (
        sum(1 for gt, pred in mode_predictions if gt == pred) / len(mode_predictions)
        if mode_predictions
        else 0.0
    )
    mode_confusion = compute_confusion_matrix(
        mode_predictions, ["tunnel", "transport", "unknown"]
    )
    mode_f1 = compute_f1_macro(mode_confusion)

    traffic_accuracy = (
        sum(1 for gt, pred in traffic_predictions if gt == pred) / len(traffic_predictions)
        if traffic_predictions
        else 0.0
    )
    traffic_confusion = compute_confusion_matrix(
        traffic_predictions, ["https", "voip", "icmp", "unknown"]
    )
    traffic_f1 = compute_f1_macro(traffic_confusion)

    # Agreement rates
    total_with_prediction = sum(agreement_results.values())
    mode_agreement_rate = (
        agreement_results["mode"] / len(mode_predictions)
        if mode_predictions
        else 0.0
    )

    # Confidence stats
    mode_confidence_dist = {
        "mean": (
            sum(confidence_stats["mode"]["scores"]) / len(confidence_stats["mode"]["scores"])
            if confidence_stats["mode"]["scores"]
            else 0.0
        ),
        "min": (
            min(confidence_stats["mode"]["scores"])
            if confidence_stats["mode"]["scores"]
            else 0.0
        ),
        "max": (
            max(confidence_stats["mode"]["scores"])
            if confidence_stats["mode"]["scores"]
            else 0.0
        ),
        "count": confidence_stats["mode"]["count"],
    }

    return {
        "metadata": {
            "total_pcaps": len(pcap_files),
            "api_calls_successful": api_call_count["success"],
            "api_calls_failed": api_call_count["failed"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "api_vs_ground_truth": {
            "mode": {
                "accuracy": round(mode_accuracy, 3),
                "f1_macro": round(mode_f1, 3),
                "confusion_matrix": mode_confusion,
                "total_samples": len(mode_predictions),
            },
            "traffic": {
                "accuracy": round(traffic_accuracy, 3),
                "f1_macro": round(traffic_f1, 3),
                "confusion_matrix": traffic_confusion,
                "total_samples": len(traffic_predictions),
                "note": "Traffic type inference not yet extracted; placeholder values",
            },
        },
        "heuristic_vs_api": {
            "mode_agreement_rate": round(mode_agreement_rate, 3),
            "note": "Measured when both heuristic and API produce non-null predictions",
        },
        "confidence_stats": {
            "mode": mode_confidence_dist,
        },
    }


def _empty_metrics() -> Dict[str, Any]:
    """Return empty metrics template."""
    return {
        "metadata": {
            "total_pcaps": 0,
            "api_calls_successful": 0,
            "api_calls_failed": 0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "api_vs_ground_truth": {
            "mode": {
                "accuracy": 0.0,
                "f1_macro": 0.0,
                "confusion_matrix": {},
                "total_samples": 0,
            },
            "traffic": {
                "accuracy": 0.0,
                "f1_macro": 0.0,
                "confusion_matrix": {},
                "total_samples": 0,
            },
        },
        "heuristic_vs_api": {"mode_agreement_rate": 0.0},
        "confidence_stats": {"mode": {"mean": 0.0, "min": 0.0, "max": 0.0}},
    }


def main():
    parser = argparse.ArgumentParser(
        description="Validate CryptoLens inference pipeline accuracy"
    )
    parser.add_argument(
        "--dataset-dir",
        "--dir",
        type=Path,
        default=Path("captures"),
        help="Path to labeled PCAP directory (default: captures)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("backend/validation_dataset/metrics_report.json"),
        help="Output path for metrics JSON",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose logging",
    )

    args = parser.parse_args()

    logger.info(f"Validating PCAPs in {args.dataset_dir}")
    metrics = validate_dataset(args.dataset_dir, verbose=args.verbose)

    # Save results
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(metrics, f, indent=2)

    logger.info(f"Metrics saved to {args.output}")

    # Print summary
    print("\n" + "=" * 70)
    print("VALIDATION SUMMARY")
    print("=" * 70)
    print(f"Total PCAPs: {metrics['metadata']['total_pcaps']}")
    print(
        f"API Calls: {metrics['metadata']['api_calls_successful']} successful, "
        f"{metrics['metadata']['api_calls_failed']} failed"
    )
    print(
        f"Mode Accuracy (API vs. Ground Truth): "
        f"{metrics['api_vs_ground_truth']['mode']['accuracy']:.1%}"
    )
    print(
        f"Mode Agreement (Heuristic vs. API): "
        f"{metrics['heuristic_vs_api']['mode_agreement_rate']:.1%}"
    )
    if metrics['confidence_stats']['mode']['count'] > 0:
        print(
            f"Avg Confidence (Mode): "
            f"{metrics['confidence_stats']['mode']['mean']:.2f} "
            f"(min={metrics['confidence_stats']['mode']['min']:.2f}, "
            f"max={metrics['confidence_stats']['mode']['max']:.2f})"
        )
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
