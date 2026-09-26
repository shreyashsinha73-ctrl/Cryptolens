"""
Inference pipeline: Unified orchestration of Gemini API-based mode + traffic inference.

Functions:
- infer_mode_and_traffic(): Call Gemini API, return predictions + confidence
- validate_and_merge(): Compare API predictions against heuristic baseline, compute agreement

Separately tracks:
1. API-vs-ground-truth accuracy (validated offline against labeled dataset)
2. Heuristic-vs-API agreement (live metric from production traffic)
"""

import logging
from typing import Optional

from backend.engine.llm_client.client import GeminiClient, GeminiClientConfig
from backend.engine.llm_client.schema import (
    AgreementCheckResult,
    LLMInferenceResponse,
    ModeAndTrafficInferenceRequest,
)

logger = logging.getLogger(__name__)


import os
from backend.engine.llm_client.schema import ModeInferenceResult, TrafficInferenceResult

def infer_mode_and_traffic(
    packet_lengths: list[float],
    inter_arrival_times: list[float],
    packet_count: int,
) -> Optional[LLMInferenceResponse]:
    backend = os.getenv("CLASSIFIER_BACKEND", "cnn").lower().strip()

    if backend == "cnn":
        try:
            from backend.engine.data_plane.classifier import classify_traffic
            res = classify_traffic({
                "lengths": packet_lengths,
                "iats": inter_arrival_times,
                "total_esp_packets": packet_count,
            })
            if not res.get("error"):
                logger.info(f"CNN inference: mode={res['mode']} ({res['mode_confidence']:.2f}), traffic={res['traffic_type']} ({res['traffic_confidence']:.2f})")
                return LLMInferenceResponse(
                    mode=ModeInferenceResult(
                        predicted_mode=res["mode"],
                        confidence=res["mode_confidence"],
                    ),
                    traffic=TrafficInferenceResult(
                        predicted_traffic_type=res["traffic_type"],
                        confidence=res["traffic_confidence"],
                    ),
                    model_version="cnn-1d-dataplane",
                )
        except Exception as e:
            logger.warning(f"CNN inference error, attempting LLM fallback: {e}")

    config = GeminiClientConfig()
    if config.validate():
        client = GeminiClient(config)
        request = ModeAndTrafficInferenceRequest(
            packet_lengths=packet_lengths,
            inter_arrival_times=inter_arrival_times,
            packet_count=packet_count,
        )
        result = client.infer_mode_and_traffic(request)
        if result:
            return result
        logger.warning("Gemini API inference failed")

    if backend != "cnn":
        try:
            from backend.engine.data_plane.classifier import classify_traffic
            res = classify_traffic({
                "lengths": packet_lengths,
                "iats": inter_arrival_times,
                "total_esp_packets": packet_count,
            })
            if not res.get("error"):
                return LLMInferenceResponse(
                    mode=ModeInferenceResult(
                        predicted_mode=res["mode"],
                        confidence=res["mode_confidence"],
                    ),
                    traffic=TrafficInferenceResult(
                        predicted_traffic_type=res["traffic_type"],
                        confidence=res["traffic_confidence"],
                    ),
                    model_version="cnn-1d-dataplane",
                )
        except Exception as e:
            logger.warning(f"Fallback CNN inference failed: {e}")

    return None


def validate_and_merge(
    api_response: LLMInferenceResponse,
    heuristic_mode: Optional[str],
    heuristic_traffic: Optional[str],
) -> AgreementCheckResult:
    """
    Compare API predictions against heuristic baseline.

    Computes two independent metrics:
    1. Heuristic-vs-API agreement (live, for transparency)
    2. (Ground-truth accuracy measured offline via validation dataset)

    Args:
        api_response: Result from Gemini API.
        heuristic_mode: Baseline mode from size-based heuristic ("tunnel"/"transport"/None).
        heuristic_traffic: Baseline traffic from size-based heuristic ("https"/"voip"/"icmp"/None).

    Returns:
        AgreementCheckResult with predictions, agreement flags, and combined confidence.
    """
    api_mode = api_response.mode.predicted_mode
    api_traffic = api_response.traffic.predicted_traffic_type
    api_mode_conf = api_response.mode.confidence
    api_traffic_conf = api_response.traffic.confidence

    # Compute agreement flags (independent of ground truth)
    mode_agree = (heuristic_mode is not None) and (heuristic_mode == api_mode)
    traffic_agree = (heuristic_traffic is not None) and (heuristic_traffic == api_traffic)
    overall_agree = mode_agree and traffic_agree

    # Combined confidence (average of mode + traffic)
    avg_confidence = (api_mode_conf + api_traffic_conf) / 2.0

    logger.info(
        f"Agreement check: mode={'✓' if mode_agree else '✗'} "
        f"traffic={'✓' if traffic_agree else '✗'} "
        f"overall={'✓' if overall_agree else '✗'} "
        f"confidence={avg_confidence:.2f}"
    )

    return AgreementCheckResult(
        api_mode_prediction=api_mode,
        api_traffic_prediction=api_traffic,
        heuristic_mode_prediction=heuristic_mode,
        heuristic_traffic_prediction=heuristic_traffic,
        mode_agreement=mode_agree,
        traffic_agreement=traffic_agree,
        overall_agreement=overall_agree,
        api_avg_confidence=avg_confidence,
    )


def infer_with_fallback(
    packet_lengths: list[float],
    inter_arrival_times: list[float],
    packet_count: int,
    heuristic_mode: Optional[str],
    heuristic_traffic: Optional[str],
) -> Optional[AgreementCheckResult]:
    """
    Full pipeline: Try API inference, fall back to heuristic on failure.

    Args:
        packet_lengths: ESP packet lengths.
        inter_arrival_times: Inter-arrival times.
        packet_count: Total packets.
        heuristic_mode: Fallback mode baseline.
        heuristic_traffic: Fallback traffic baseline.

    Returns:
        AgreementCheckResult if API succeeds, or None if both API and heuristic are unavailable.
    """
    # Try API
    api_response = infer_mode_and_traffic(packet_lengths, inter_arrival_times, packet_count)

    if api_response:
        # API succeeded: compare against heuristic
        return validate_and_merge(api_response, heuristic_mode, heuristic_traffic)
    else:
        # API failed: fall back to heuristic only
        if heuristic_mode or heuristic_traffic:
            logger.warning("API inference failed; using heuristic baseline only")
            return AgreementCheckResult(
                api_mode_prediction="unknown",
                api_traffic_prediction="unknown",
                heuristic_mode_prediction=heuristic_mode,
                heuristic_traffic_prediction=heuristic_traffic,
                mode_agreement=False,
                traffic_agreement=False,
                overall_agreement=False,
                api_avg_confidence=0.0,
            )
        else:
            logger.error("Both API and heuristic inference unavailable")
            return None
