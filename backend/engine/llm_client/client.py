"""
GeminiClient: Async HTTP interface to Google Gemini API for IPsec inference.

Single API call format returns both mode and traffic type predictions.
Handles request formatting, response parsing, validation, and error handling.
"""

import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from typing import Optional

from .schema import (
    LLMInferenceResponse,
    ModeAndTrafficInferenceRequest,
    ModeInferenceResult,
    TrafficInferenceResult,
)

logger = logging.getLogger(__name__)


class GeminiClientConfig:
    """Configuration for Gemini API client."""

    def __init__(self):
        self.enable_cloud_llm = os.getenv("ENABLE_CLOUD_LLM", "false").lower() in ("true", "1", "yes")
        raw_key = os.getenv("GEMINI_API_KEY") or os.getenv("AI_API_KEY") or ""
        self.api_key = raw_key.strip().strip("'\"").strip()
        raw_model = os.getenv("GEMINI_MODEL") or "gemini-2.5-flash"
        self.model = raw_model.strip().strip("'\"").strip()
        self.timeout_seconds = float(os.getenv("GEMINI_TIMEOUT_SECONDS", "30.0"))
        self.api_url_template = (
            "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        )

    def validate(self) -> bool:
        """Check that Cloud LLM is permitted and API key is configured."""
        if not self.enable_cloud_llm:
            logger.info("Cloud LLM disabled by policy (ENABLE_CLOUD_LLM=false)")
            return False
        if not self.api_key:
            logger.error("GEMINI_API_KEY not set. LLM inference disabled.")
            return False
        return True


class GeminiClient:
    """Client for Gemini API-based mode + traffic inference."""

    # Joint prompt template using computed statistics for better classification
    JOINT_PROMPT_TEMPLATE = """You are an expert IPsec network traffic analyst. Classify the following ESP (Encapsulating Security Payload) encrypted traffic based on its statistical metadata.

Classify:
1. Operating mode: "tunnel" or "transport"
2. Application traffic type: "https", "voip", or "icmp"

ESP Packet Size Statistics (bytes):
- Total packets: {packet_count}
- Mean: {mean_size:.1f}
- Median: {median_size:.1f}
- Std Dev: {stdev_size:.1f}
- Min: {min_size}
- Max: {max_size}
- 10th percentile: {p10}
- 25th percentile: {p25}
- 75th percentile: {p75}

Size Distribution:
- Small packets (<250 bytes): {small_pct:.1f}%
- Medium packets (250-600 bytes): {medium_pct:.1f}%
- Large packets (600-1100 bytes): {large_pct:.1f}%
- Very large packets (>1100 bytes): {xlarge_pct:.1f}%

Inter-Arrival Time Statistics (seconds):
- Mean IAT: {mean_iat:.6f}
- Min IAT: {min_iat:.6f}
- Max IAT: {max_iat:.6f}

Classification Rules:
MODE DETECTION — Tunnel mode encapsulates the entire inner packet inside a new IP header, adding ~20-40 bytes of overhead to EVERY packet:
- Tunnel mode: minimum packet size is typically ≥120 bytes, median ≥155 bytes, 10th percentile ≥118 bytes
- Transport mode: minimum packet size is typically ≤115 bytes, median ≤148 bytes, 10th percentile ≤110 bytes
- The key discriminator is the FLOOR (minimum/lower percentile) of packet sizes, not the average

TRAFFIC TYPE DETECTION:
- HTTPS: bimodal distribution with BOTH small ACK packets AND large data packets (>600 bytes present), large packet fraction ≥15%
- VoIP: predominantly small uniform packets (<250 bytes), very few or no large packets, regular timing
- ICMP: all packets very small (<200 bytes), low max size

Respond ONLY with valid JSON (no markdown, no code blocks):
{{
  "mode": "<tunnel|transport>",
  "mode_confidence": <0.0-1.0>,
  "traffic_type": "<https|voip|icmp>",
  "traffic_confidence": <0.0-1.0>,
  "reasoning": "<brief explanation citing specific statistics>"
}}
"""

    def __init__(self, config: Optional[GeminiClientConfig] = None):
        self.config = config or GeminiClientConfig()

    def infer_mode_and_traffic(
        self, request: ModeAndTrafficInferenceRequest
    ) -> Optional[LLMInferenceResponse]:
        """
        Make single Gemini API call returning both mode and traffic predictions.

        Args:
            request: Packet features (lengths, inter-arrivals, count)

        Returns:
            LLMInferenceResponse with mode + traffic predictions + confidences,
            or None if API call fails.
        """
        if not self.config.validate():
            return None

        # Compute statistical features from raw packet data
        lengths = request.packet_lengths[:100]  # Up to 100 packets
        iats = request.inter_arrival_times[:100]
        
        if not lengths:
            return None
        
        sorted_lengths = sorted(lengths)
        n = len(sorted_lengths)
        mean_size = sum(lengths) / n
        median_size = sorted_lengths[n // 2]
        min_size = sorted_lengths[0]
        max_size = sorted_lengths[-1]
        p10 = sorted_lengths[max(0, n // 10)]
        p25 = sorted_lengths[max(0, n // 4)]
        p75 = sorted_lengths[max(0, 3 * n // 4)]
        
        # Standard deviation
        variance = sum((x - mean_size) ** 2 for x in lengths) / max(n - 1, 1)
        stdev_size = variance ** 0.5
        
        # Size distribution percentages
        small_count = sum(1 for s in lengths if s < 250)
        medium_count = sum(1 for s in lengths if 250 <= s < 600)
        large_count = sum(1 for s in lengths if 600 <= s < 1100)
        xlarge_count = sum(1 for s in lengths if s >= 1100)
        
        # IAT stats
        mean_iat = sum(iats) / len(iats) if iats else 0.0
        min_iat = min(iats) if iats else 0.0
        max_iat = max(iats) if iats else 0.0

        # Format prompt with computed statistics
        prompt_text = self.JOINT_PROMPT_TEMPLATE.format(
            packet_count=request.packet_count,
            mean_size=mean_size,
            median_size=median_size,
            stdev_size=stdev_size,
            min_size=min_size,
            max_size=max_size,
            p10=p10,
            p25=p25,
            p75=p75,
            small_pct=(small_count / n) * 100,
            medium_pct=(medium_count / n) * 100,
            large_pct=(large_count / n) * 100,
            xlarge_pct=(xlarge_count / n) * 100,
            mean_iat=mean_iat,
            min_iat=min_iat,
            max_iat=max_iat,
        )

        # Make API call
        raw_response = self._call_gemini_api(prompt_text)
        if not raw_response:
            logger.warning("Gemini API call failed or timed out")
            return None

        # Parse and validate response
        parsed = self._parse_api_response(raw_response)
        if not parsed:
            logger.warning("Failed to parse Gemini response as JSON")
            return None

        # Build typed response
        try:
            mode_result = ModeInferenceResult(
                predicted_mode=parsed.get("mode", "unknown"),
                confidence=float(parsed.get("mode_confidence", 0.0)),
            )
            traffic_result = TrafficInferenceResult(
                predicted_traffic_type=parsed.get("traffic_type", "unknown"),
                confidence=float(parsed.get("traffic_confidence", 0.0)),
            )
            response = LLMInferenceResponse(
                mode=mode_result,
                traffic=traffic_result,
                model_version=self.config.model,
                raw_response=raw_response[:500],  # Truncate for storage
            )
            logger.info(
                f"Inference: mode={response.mode.predicted_mode} "
                f"({response.mode.confidence:.2f}), "
                f"traffic={response.traffic.predicted_traffic_type} "
                f"({response.traffic.confidence:.2f})"
            )
            return response
        except (ValueError, KeyError, TypeError) as e:
            logger.error(f"Failed to construct LLMInferenceResponse: {e}")
            return None

    # Verified-available fallback models (cheapest/fastest first)
    _FALLBACK_MODELS = [
        "gemini-3.5-flash-lite",
        "gemini-2.5-flash-lite",
        "gemini-2.5-flash",
        "gemini-3.8-flash",
    ]

    def _call_gemini_api(self, prompt: str) -> Optional[str]:
        """Call Gemini API with model fallback and exponential backoff retry."""
        if not self.config.enable_cloud_llm:
            logger.info("Cloud LLM disabled by policy (ENABLE_CLOUD_LLM=false)")
            return None
        api_key = self.config.api_key.strip().strip("'\"").strip()

        # Build ordered model list: configured model first, then fallbacks
        models_to_try = [self.config.model]
        for fb in self._FALLBACK_MODELS:
            if fb not in models_to_try:
                models_to_try.append(fb)

        request_body = json.dumps({
            "contents": [
                {
                    "parts": [
                        {
                            "text": prompt
                        }
                    ]
                }
            ]
        }).encode("utf-8")

        max_retries = 3
        base_delay = 2.0  # seconds

        for model in models_to_try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"

            for attempt in range(max_retries + 1):
                try:
                    req = urllib.request.Request(
                        url,
                        data=request_body,
                        headers={
                            "Content-Type": "application/json",
                            "x-goog-api-key": api_key,
                        },
                        method="POST",
                    )

                    with urllib.request.urlopen(
                        req,
                        timeout=max(self.config.timeout_seconds, 30.0)
                    ) as response:
                        body = response.read().decode("utf-8")
                        if model != self.config.model or attempt > 0:
                            logger.info(
                                f"Gemini API succeeded with model '{model}' "
                                f"(attempt {attempt + 1})"
                            )
                        return self._extract_response_text(body)

                except urllib.error.HTTPError as e:
                    err_msg = ""
                    try:
                        err_msg = e.read().decode("utf-8", errors="replace")
                    except Exception:
                        pass

                    # 404: model doesn't exist → skip to next model
                    if e.code == 404:
                        logger.warning(
                            f"Model '{model}' not found (404), trying next fallback..."
                        )
                        break  # break retry loop, try next model

                    # 503/429: transient overload → retry with backoff
                    if e.code in (503, 429) and attempt < max_retries:
                        delay = base_delay * (2 ** attempt)
                        logger.warning(
                            f"Gemini API {e.code} for model '{model}' "
                            f"(attempt {attempt + 1}/{max_retries + 1}). "
                            f"Retrying in {delay:.1f}s..."
                        )
                        time.sleep(delay)
                        continue

                    # 503/429 exhausted retries → try next model
                    if e.code in (503, 429):
                        logger.warning(
                            f"Model '{model}' overloaded after {max_retries + 1} "
                            f"attempts, trying next fallback..."
                        )
                        break

                    # Other HTTP error → give up entirely
                    logger.error(
                        f"Gemini API HTTP error {e.code} for model '{model}': "
                        f"{e.reason} | Response: {err_msg[:500]}"
                    )
                    return None

                except urllib.error.URLError as e:
                    if attempt < max_retries:
                        delay = base_delay * (2 ** attempt)
                        logger.warning(
                            f"Connection error (attempt {attempt + 1}/"
                            f"{max_retries + 1}): {e.reason}. "
                            f"Retrying in {delay:.1f}s..."
                        )
                        time.sleep(delay)
                        continue
                    logger.error(f"Gemini API connection error: {e.reason}")
                    return None

                except Exception as e:
                    logger.error(f"Unexpected error calling Gemini API: {e}")
                    return None

        logger.error("All Gemini models exhausted. API inference unavailable.")
        return None

    @staticmethod
    def _extract_response_text(api_response: str) -> Optional[str]:
        """Extract text content from Gemini API JSON response."""
        try:
            data = json.loads(api_response)
            candidates = data.get("candidates", [])
            if not candidates:
                logger.warning("No candidates in Gemini response")
                return None
            content = candidates[0].get("content", {})
            parts = content.get("parts", [])
            if not parts:
                logger.warning("No parts in Gemini response")
                return None
            return parts[0].get("text", "")
        except json.JSONDecodeError:
            logger.error("Failed to parse Gemini API response as JSON")
            return None

    @staticmethod
    def _parse_api_response(response_text: str) -> Optional[dict]:
        """
        Extract JSON from API response text.

        Handles Markdown code blocks (```json ... ```) if present.
        """
        response_text = response_text.strip()

        # Try to extract JSON from Markdown code block
        match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", response_text)
        if match:
            response_text = match.group(1).strip()

        try:
            return json.loads(response_text)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON: {e}\nResponse: {response_text[:200]}")
            return None
