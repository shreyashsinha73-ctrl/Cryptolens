"""
classifier.py
-------------
Temporary MVP traffic-and-mode classifier for the CryptoLens data plane.

NOTE: This LLM-based classifier is a temporary MVP stand-in.
The intended production path is the 1D-CNN (DataPlaneCNN) exported by
`train.py` to `weights/cnn_mode_traffic.onnx`.

This module abstracts classification behind a single `classify_traffic`
interface. Swapping from the LLM stand-in to the trained CNN in production
is controlled by the `CLASSIFIER_BACKEND` environment variable ("llm" vs "cnn").
"""

import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Union

# Allowed label values per project specification
VALID_MODES = {"tunnel", "transport", "unknown"}
VALID_TRAFFIC_TYPES = {"https", "voip", "icmp", "unknown"}

# Supported backends
BACKEND_LLM = "llm"
BACKEND_CNN = "cnn"

def _load_env_fallback():
    current = Path(__file__).resolve()
    for parent in [current.parent, current.parent.parent, current.parent.parent.parent, Path(".")]:
        env_file = parent / ".env"
        if env_file.is_file():
            try:
                with env_file.open("r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            k, v = k.strip(), v.strip().strip("'\"")
                            if k and k not in os.environ:
                                os.environ[k] = v
            except Exception:
                pass
            break

_load_env_fallback()

DEFAULT_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
DEFAULT_TIMEOUT_SECONDS = float(os.getenv("GEMINI_TIMEOUT_SECONDS", "10.0"))


def _clean_json_text(text: str) -> str:
    """Strips Markdown code block fences (```json ... ```) if present."""
    text = text.strip()
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    if match:
        return match.group(1).strip()
    return text


def _extract_sequences(esp_features: Dict[str, Any]) -> tuple[list, list, int]:
    """Extracts lengths, inter-arrival times, and packet count from esp_features."""
    s_l = esp_features.get("S_L") or esp_features.get("lengths", [])
    s_iat = esp_features.get("S_IAT") or esp_features.get("iats", [])

    # Handle numpy arrays if present without requiring numpy as a hard dependency here
    if hasattr(s_l, "tolist"):
        s_l = s_l.tolist()
    if hasattr(s_iat, "tolist"):
        s_iat = s_iat.tolist()

    packet_count = (
        esp_features.get("n_real_packets")
        or esp_features.get("total_esp_packets")
        or len(s_l)
    )

    # If packet_count is known and sequences are longer (e.g. zero-padded to SEQ_LEN=30),
    # truncate padding for cleaner prompt token usage
    if isinstance(packet_count, int) and packet_count > 0:
        s_l = s_l[:packet_count]
        s_iat = s_iat[:packet_count]

    return s_l, s_iat, int(packet_count)


def _classify_via_cnn(esp_features: Dict[str, Any]) -> Dict[str, Any]:
    """
    CNN inference backend stub.

    Intended production path:
    Load `weights/cnn_mode_traffic.onnx` (exported by `train.py`) via onnxruntime,
    pass normalized `(1, 2, 30)` tensor, and return argmax predictions.
    """
    raise NotImplementedError(
        "CNN backend is not yet wired for live inference. "
        "Production path: load 'weights/cnn_mode_traffic.onnx' exported by train.py."
    )


def _classify_via_llm_request(esp_features: Dict[str, Any]) -> Dict[str, Any]:
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("AI_API_KEY")
    if not api_key:
        raise ValueError(
            "GEMINI_API_KEY environment variable is not set. "
            "Please configure GEMINI_API_KEY in your environment or .env."
        )

    s_l, s_iat, packet_count = _extract_sequences(esp_features)

    # Formulate domain-grounded classification prompt
    prompt = f"""You are an IPsec data-plane traffic analysis engine.
You are given numerical metadata extracted from encrypted IPsec ESP (protocol 50) packets:
- ESP Packet Lengths (bytes on-the-wire IP length): {s_l}
- Inter-Arrival Times (seconds between consecutive packets): {s_iat}
- Total Packet Count: {packet_count}

Structural domain rules:
1. IPsec Operating Mode:
   - "tunnel": Encapsulates inner IP header + payload; packets are typically ~20-40 bytes larger than transport mode.
   - "transport": Only payload is encrypted, no outer IP encapsulation offset.
   - "unknown": If uncertain or insufficient data.
2. Inner Traffic Type:
   - "https": Bursty, variable larger packet lengths (~500-1500 bytes).
   - "voip": Small, near-constant packet lengths (~150-300 bytes) with regular, low-jitter intervals (~20ms).
   - "icmp": Small packets (<100 bytes) with sparse, irregular intervals (~0.5-1.0s).
   - "unknown": If uncertain or does not match profiles.

Classify this session and return STRICT JSON ONLY (no markdown formatting, no explanations) with this exact schema:
{{
  "mode": "tunnel" | "transport" | "unknown",
  "mode_confidence": <float between 0.0 and 1.0>,
  "traffic_type": "https" | "voip" | "icmp" | "unknown",
  "traffic_confidence": <float between 0.0 and 1.0>
}}"""

    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{DEFAULT_MODEL}:generateContent?key={api_key}"
    )

    request_payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "responseMimeType": "application/json",
        },
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(request_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT_SECONDS) as response:
        response_body = response.read().decode("utf-8")

    parsed_response = json.loads(response_body)
    raw_text = parsed_response["candidates"][0]["content"]["parts"][0]["text"]
    cleaned_text = _clean_json_text(raw_text)
    data = json.loads(cleaned_text)

    mode = str(data.get("mode", "unknown")).lower().strip()
    if mode not in VALID_MODES:
        mode = "unknown"

    traffic_type = str(data.get("traffic_type", "unknown")).lower().strip()
    if traffic_type not in VALID_TRAFFIC_TYPES:
        traffic_type = "unknown"

    try:
        mode_conf = max(0.0, min(1.0, float(data.get("mode_confidence", 0.0))))
    except (TypeError, ValueError):
        mode_conf = 0.0

    try:
        traffic_conf = max(0.0, min(1.0, float(data.get("traffic_confidence", 0.0))))
    except (TypeError, ValueError):
        traffic_conf = 0.0

    return {
        "mode": mode,
        "mode_confidence": mode_conf,
        "traffic_type": traffic_type,
        "traffic_confidence": traffic_conf,
        "backend": BACKEND_LLM,
    }


def _classify_via_llm(esp_features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calls the Gemini Flash API to classify IPsec operating mode and inner traffic type.
    Catches all network and parsing errors, returning a guaranteed safe dictionary shape.
    """
    try:
        return _classify_via_llm_request(esp_features)
    except urllib.error.HTTPError as e:
        error_msg = f"Gemini API HTTP error {e.code}: {e.reason}"
        return {
            "mode": "unknown",
            "mode_confidence": 0.0,
            "traffic_type": "unknown",
            "traffic_confidence": 0.0,
            "backend": BACKEND_LLM,
            "error": error_msg,
        }
    except urllib.error.URLError as e:
        error_msg = f"Network connection error: {e.reason}"
        return {
            "mode": "unknown",
            "mode_confidence": 0.0,
            "traffic_type": "unknown",
            "traffic_confidence": 0.0,
            "backend": BACKEND_LLM,
            "error": error_msg,
        }
    except TimeoutError:
        return {
            "mode": "unknown",
            "mode_confidence": 0.0,
            "traffic_type": "unknown",
            "traffic_confidence": 0.0,
            "backend": BACKEND_LLM,
            "error": "Gemini API request timed out",
        }
    except json.JSONDecodeError as e:
        return {
            "mode": "unknown",
            "mode_confidence": 0.0,
            "traffic_type": "unknown",
            "traffic_confidence": 0.0,
            "backend": BACKEND_LLM,
            "error": f"Malformed JSON from LLM: {e}",
        }
    except Exception as e:
        return {
            "mode": "unknown",
            "mode_confidence": 0.0,
            "traffic_type": "unknown",
            "traffic_confidence": 0.0,
            "backend": BACKEND_LLM,
            "error": str(e),
        }


def classify_traffic(esp_features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Public entry point for data-plane classification.

    Dispatches to either the LLM stand-in or the CNN backend depending on the
    CLASSIFIER_BACKEND configuration (default: "llm").

    Returns a standardized dictionary:
    {
        "mode": str ("tunnel"|"transport"|"unknown"),
        "mode_confidence": float (0.0 - 1.0),
        "traffic_type": str ("https"|"voip"|"icmp"|"unknown"),
        "traffic_confidence": float (0.0 - 1.0),
        "backend": str ("llm"|"cnn"),
        "error": str (optional, present on failure)
    }
    """
    backend = os.getenv("CLASSIFIER_BACKEND", BACKEND_LLM).lower().strip()

    if backend == BACKEND_CNN:
        try:
            res = _classify_via_cnn(esp_features)
            res["backend"] = BACKEND_CNN
            return res
        except NotImplementedError as e:
            raise e
        except Exception as e:
            return {
                "mode": "unknown",
                "mode_confidence": 0.0,
                "traffic_type": "unknown",
                "traffic_confidence": 0.0,
                "backend": BACKEND_CNN,
                "error": str(e),
            }

    # Default: LLM backend
    return _classify_via_llm(esp_features)
