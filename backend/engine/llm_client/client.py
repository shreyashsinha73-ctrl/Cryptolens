"""
GeminiClient: Async HTTP interface to Google Gemini API for IPsec inference.

Single API call format returns both mode and traffic type predictions.
Handles request formatting, response parsing, validation, and error handling.
"""

import json
import logging
import os
import re
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
        self.api_key = os.getenv("GEMINI_API_KEY") or os.getenv("AI_API_KEY")
        self.model = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
        self.timeout_seconds = float(os.getenv("GEMINI_TIMEOUT_SECONDS", "10.0"))
        self.api_url_template = (
            "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        )

    def validate(self) -> bool:
        """Check that API key is configured."""
        if not self.api_key:
            logger.error("GEMINI_API_KEY not set. LLM inference disabled.")
            return False
        return True


class GeminiClient:
    """Client for Gemini API-based mode + traffic inference."""

    # Joint prompt template (one prompt returns both mode and traffic)
    JOINT_PROMPT_TEMPLATE = """You are an IPsec network traffic analyst. Analyze the following ESP packet metadata to classify:
1. Operating mode (tunnel vs transport)
2. Application traffic type (https, voip, or icmp)

Packet metadata:
- Packet lengths (S_L): {packet_lengths}
- Inter-arrival times in seconds (S_IAT): {inter_arrival_times}
- Total packets in flow: {packet_count}

Analysis guidelines:
- Tunnel mode typically adds consistent overhead (~20-40 bytes) compared to transport mode
- HTTPS traffic shows variable packet sizes with longer inter-packet times
- VoIP traffic shows smaller, more regular packet sizes with consistent timing
- ICMP shows very small packets with variable timing

Respond ONLY with valid JSON (no markdown, no code blocks):
{{
  "mode": "<tunnel|transport|unknown>",
  "mode_confidence": <0.0-1.0>,
  "traffic_type": "<https|voip|icmp|unknown>",
  "traffic_confidence": <0.0-1.0>,
  "reasoning": "<brief explanation>"
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

        # Format prompt with packet data
        prompt_text = self.JOINT_PROMPT_TEMPLATE.format(
            packet_lengths=json.dumps(request.packet_lengths[:30]),  # First 30 packets
            inter_arrival_times=json.dumps(request.inter_arrival_times[:30]),
            packet_count=request.packet_count,
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

    def _call_gemini_api(self, prompt: str) -> Optional[str]:
        """
        Make HTTP POST to Gemini API.

        Args:
            prompt: The full prompt text to send.

        Returns:
            Raw text response from API, or None on failure.
        """
        url = self.config.api_url_template.format(model=self.config.model)
        params = f"?key={self.config.api_key}"
        full_url = url + params

        request_body = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode(
            "utf-8"
        )

        try:
            req = urllib.request.Request(
                full_url,
                data=request_body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as response:
                body = response.read().decode("utf-8")
                return self._extract_response_text(body)
        except urllib.error.HTTPError as e:
            logger.error(f"Gemini API HTTP error {e.code}: {e.reason}")
            return None
        except urllib.error.URLError as e:
            logger.error(f"Gemini API connection error: {e.reason}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error calling Gemini API: {e}")
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
