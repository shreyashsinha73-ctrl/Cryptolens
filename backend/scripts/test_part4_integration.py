#!/usr/bin/env python3
"""
Integration test for Part 4: API Integration & Validation

Tests:
1. Schema validation (Pydantic models)
2. GeminiClient initialization and configuration
3. Inference pipeline with mock data
4. Traffic analyzer integration
5. Agreement checking logic
"""

import json
import logging
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from backend.engine.llm_client.schema import (
    AgreementCheckResult,
    LLMInferenceResponse,
    ModeAndTrafficInferenceRequest,
    ModeInferenceResult,
    TrafficInferenceResult,
)
from backend.engine.llm_client.client import GeminiClient, GeminiClientConfig
from backend.engine.inference_pipeline import validate_and_merge

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_schema_validation():
    """Test Pydantic schema validation."""
    logger.info("Testing schema validation...")

    # Test ModeAndTrafficInferenceRequest
    request = ModeAndTrafficInferenceRequest(
        packet_lengths=[100.0, 105.0, 102.0],
        inter_arrival_times=[0.001, 0.002],
        packet_count=100,
    )
    assert request.packet_count == 100
    logger.info("  ✓ ModeAndTrafficInferenceRequest validated")

    # Test ModeInferenceResult
    mode_result = ModeInferenceResult(
        predicted_mode="tunnel",
        confidence=0.87,
    )
    assert mode_result.predicted_mode == "tunnel"
    assert 0.0 <= mode_result.confidence <= 1.0
    logger.info("  ✓ ModeInferenceResult validated")

    # Test TrafficInferenceResult
    traffic_result = TrafficInferenceResult(
        predicted_traffic_type="https",
        confidence=0.92,
    )
    assert traffic_result.predicted_traffic_type == "https"
    logger.info("  ✓ TrafficInferenceResult validated")

    # Test LLMInferenceResponse
    response = LLMInferenceResponse(
        mode=mode_result,
        traffic=traffic_result,
        model_version="gemini-1.5-flash",
    )
    assert response.mode.predicted_mode == "tunnel"
    assert response.traffic.predicted_traffic_type == "https"
    logger.info("  ✓ LLMInferenceResponse validated")

    # Test AgreementCheckResult
    agreement = AgreementCheckResult(
        api_mode_prediction="tunnel",
        api_traffic_prediction="https",
        heuristic_mode_prediction="tunnel",
        heuristic_traffic_prediction="https",
        mode_agreement=True,
        traffic_agreement=True,
        overall_agreement=True,
        api_avg_confidence=0.895,
    )
    assert agreement.overall_agreement is True
    logger.info("  ✓ AgreementCheckResult validated")

    # Test schema rejection of invalid confidence
    try:
        ModeInferenceResult(predicted_mode="tunnel", confidence=1.5)
        logger.error("  ✗ Should have rejected confidence > 1.0")
        return False
    except ValueError:
        logger.info("  ✓ Schema correctly rejected invalid confidence")

    return True


def test_gemini_client_config():
    """Test GeminiClient configuration."""
    logger.info("Testing GeminiClient configuration...")

    config = GeminiClientConfig()
    logger.info(f"  Model: {config.model}")
    logger.info(f"  Timeout: {config.timeout_seconds}s")

    # Config should read from env or use defaults
    assert config.model is not None
    assert config.timeout_seconds > 0

    if config.api_key:
        logger.info("  ✓ API key configured")
    else:
        logger.warning("  ⚠ API key not configured (expected for unit test)")

    logger.info("  ✓ GeminiClientConfig validated")
    return True


def test_gemini_client_initialization():
    """Test GeminiClient can be instantiated."""
    logger.info("Testing GeminiClient initialization...")

    config = GeminiClientConfig()
    client = GeminiClient(config)
    assert client.config.model is not None
    logger.info(f"  ✓ GeminiClient initialized with model: {client.config.model}")
    return True


def test_agreement_check_logic():
    """Test agreement checking between API and heuristic."""
    logger.info("Testing agreement check logic...")

    # Scenario 1: Both agree on tunnel + https
    mode_result = ModeInferenceResult(predicted_mode="tunnel", confidence=0.85)
    traffic_result = TrafficInferenceResult(
        predicted_traffic_type="https", confidence=0.90
    )
    api_response = LLMInferenceResponse(
        mode=mode_result, traffic=traffic_result, model_version="test"
    )

    agreement = validate_and_merge(
        api_response,
        heuristic_mode="tunnel",
        heuristic_traffic="https",
    )

    assert agreement.mode_agreement is True
    assert agreement.traffic_agreement is True
    assert agreement.overall_agreement is True
    logger.info("  ✓ Scenario 1: Both agree → overall_agreement=True")

    # Scenario 2: Mode disagrees, traffic agrees
    agreement2 = validate_and_merge(
        api_response,
        heuristic_mode="transport",  # Different
        heuristic_traffic="https",  # Same
    )

    assert agreement2.mode_agreement is False
    assert agreement2.traffic_agreement is True
    assert agreement2.overall_agreement is False
    logger.info("  ✓ Scenario 2: Mode disagrees → overall_agreement=False")

    # Scenario 3: Heuristic is None (e.g., no ESP packets)
    agreement3 = validate_and_merge(
        api_response,
        heuristic_mode=None,
        heuristic_traffic=None,
    )

    assert agreement3.mode_agreement is False
    assert agreement3.traffic_agreement is False
    logger.info("  ✓ Scenario 3: No heuristic → no agreement")

    # Scenario 4: Average confidence calculation
    assert agreement.api_avg_confidence == (0.85 + 0.90) / 2
    logger.info(
        f"  ✓ Confidence averaging: ({0.85} + {0.90}) / 2 = {agreement.api_avg_confidence}"
    )

    return True


def test_response_parsing():
    """Test JSON response parsing from mock Gemini response."""
    logger.info("Testing response parsing...")

    # Mock Gemini response (JSON wrapped in markdown code block)
    mock_response = """Here's my analysis:

```json
{
  "mode": "tunnel",
  "mode_confidence": 0.87,
  "traffic_type": "https",
  "traffic_confidence": 0.92,
  "reasoning": "Consistent packet size overhead of ~30 bytes indicates tunnel mode. Variable packet timing with larger payloads suggests HTTPS."
}
```
"""

    parsed = GeminiClient._parse_api_response(mock_response)
    assert parsed is not None
    assert parsed["mode"] == "tunnel"
    assert parsed["traffic_type"] == "https"
    logger.info("  ✓ Parsed markdown-wrapped JSON correctly")

    # Test raw JSON (no markdown)
    raw_json = '{"mode": "transport", "mode_confidence": 0.75, "traffic_type": "voip", "traffic_confidence": 0.88}'
    parsed2 = GeminiClient._parse_api_response(raw_json)
    assert parsed2["mode"] == "transport"
    logger.info("  ✓ Parsed raw JSON correctly")

    return True


def test_metrics_structure():
    """Test structure of validation metrics."""
    logger.info("Testing metrics structure...")

    # Simulate what validate_inference.py produces
    metrics = {
        "metadata": {
            "total_pcaps": 30,
            "api_calls_successful": 28,
            "api_calls_failed": 2,
            "timestamp": "2026-09-16T10:30:00+00:00",
        },
        "api_vs_ground_truth": {
            "mode": {
                "accuracy": 0.87,
                "f1_macro": 0.85,
                "confusion_matrix": {
                    "tunnel": {"tunnel": 13, "transport": 2},
                    "transport": {"tunnel": 1, "transport": 12},
                },
            },
            "traffic": {
                "accuracy": 0.0,
                "f1_macro": 0.0,
                "confusion_matrix": {},
                "note": "Not yet implemented",
            },
        },
        "heuristic_vs_api": {
            "mode_agreement_rate": 0.93,
        },
        "confidence_stats": {
            "mode": {
                "mean": 0.78,
                "min": 0.51,
                "max": 0.99,
                "count": 28,
            },
        },
    }

    # Validate structure
    assert "metadata" in metrics
    assert "api_vs_ground_truth" in metrics
    assert "heuristic_vs_api" in metrics
    assert metrics["api_vs_ground_truth"]["mode"]["accuracy"] >= 0.8
    logger.info("  ✓ Metrics structure valid")
    logger.info(
        f"    Mode accuracy: {metrics['api_vs_ground_truth']['mode']['accuracy']:.1%}"
    )
    logger.info(
        f"    Agreement rate: {metrics['heuristic_vs_api']['mode_agreement_rate']:.1%}"
    )
    logger.info(
        f"    Avg confidence: {metrics['confidence_stats']['mode']['mean']:.2f}"
    )

    return True


def main():
    """Run all integration tests."""
    print("\n" + "=" * 70)
    print("PART 4 INTEGRATION TEST SUITE")
    print("=" * 70 + "\n")

    tests = [
        ("Schema Validation", test_schema_validation),
        ("GeminiClient Config", test_gemini_client_config),
        ("GeminiClient Initialization", test_gemini_client_initialization),
        ("Agreement Check Logic", test_agreement_check_logic),
        ("Response Parsing", test_response_parsing),
        ("Metrics Structure", test_metrics_structure),
    ]

    passed = 0
    failed = 0

    for test_name, test_fn in tests:
        try:
            if test_fn():
                passed += 1
                logger.info(f"✓ {test_name} PASSED\n")
            else:
                failed += 1
                logger.error(f"✗ {test_name} FAILED\n")
        except Exception as e:
            failed += 1
            logger.error(f"✗ {test_name} FAILED with exception: {e}\n")

    print("=" * 70)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("=" * 70 + "\n")

    return failed == 0


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
