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

# Default and fallback models verified available on Google AI Studio
DEFAULT_MODEL = os.getenv("GEMINI_MODEL", "gemini-flash-lite-latest")
FALLBACK_MODELS = [
    "gemini-flash-lite-latest",
    "gemini-3.5-flash-lite",
    "gemini-3.5-flash",
    "gemini-flash-latest",
]
DEFAULT_TIMEOUT_SECONDS = float(os.getenv("GEMINI_TIMEOUT_SECONDS", "10.0"))


def _clean_json_text(text: str) -> str:
    """Strips Markdown code block fences (```json ... ```) if present."""
    text = text.strip()
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    if match:
        return match.group(1).strip()
    return text


def _extract_sequences(esp_features: Dict[str, Any]) -> tuple[list, list, int]:
    """Extracts the observed sequence and the total ESP packet count.

    ``S_L``/``S_IAT`` are fixed-width model inputs and may therefore contain
    zero padding.  ``n_real_packets`` says how many entries in those arrays
    are observations, while ``total_esp_packets`` is the number of ESP frames
    in the capture.  They are deliberately kept separate: treating a
    5-packet capture padded to 30 elements as 30 packets was corrupting the
    metadata sent to the classifier.
    """
    s_l = esp_features.get("S_L") or esp_features.get("lengths", [])
    s_iat = esp_features.get("S_IAT") or esp_features.get("iats", [])

    # Handle numpy arrays if present without requiring numpy as a hard dependency here
    if hasattr(s_l, "tolist"):
        s_l = s_l.tolist()
    if hasattr(s_iat, "tolist"):
        s_iat = s_iat.tolist()

    sequence_packet_count = esp_features.get("n_real_packets")
    total_packet_count = esp_features.get("total_esp_packets")

    if not isinstance(sequence_packet_count, int) or sequence_packet_count < 0:
        sequence_packet_count = len(s_l)
    if not isinstance(total_packet_count, int) or total_packet_count < 0:
        total_packet_count = sequence_packet_count

    # If packet_count is known and sequences are longer (e.g. zero-padded to SEQ_LEN=30),
    # truncate padding for cleaner prompt token usage
    if sequence_packet_count > 0:
        s_l = s_l[:sequence_packet_count]
        s_iat = s_iat[:sequence_packet_count]

    return s_l, s_iat, int(total_packet_count)


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
   - "transport": Host-to-host direct session (no outer IP encapsulation). Typically observed with dedicated endpoint streams, VoIP / small uniform packets (< 350 bytes).
   - "tunnel": Gateway-to-gateway network encapsulation (adds outer IP + ESP overhead). Standard for encapsulated corporate/web sessions, mixed workloads, and larger variable-length packets (average length >= 500 bytes).
   - "unknown": If uncertain or contradictory data.
2. Inner Traffic Type:
   - "voip": Small, constant packet lengths (< 300 bytes) with rapid, periodic stream intervals (< 100ms cadence, continuous flow).
   - "https": Bursty, variable larger packet lengths (~500-1500 bytes).
   - "icmp": Small isolated packets (< 100 bytes) with slow, sparse, irregular intervals (>= 0.5s between requests).
   - "unknown": If uncertain or does not match profiles.

Classify this session and return STRICT JSON ONLY (no markdown formatting, no explanations) with this exact schema:
{{
  "mode": "tunnel" | "transport" | "unknown",
  "mode_confidence": <float between 0.0 and 1.0>,
  "traffic_type": "https" | "voip" | "icmp" | "unknown",
  "traffic_confidence": <float between 0.0 and 1.0>
}}"""

    request_payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "responseMimeType": "application/json",
        },
    }

    models_to_try = [DEFAULT_MODEL]
    for m in FALLBACK_MODELS:
        if m not in models_to_try:
            models_to_try.append(m)

    response_body = None
    last_error = None

    for model in models_to_try:
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{model}:generateContent?key={api_key}"
        )
        req = urllib.request.Request(
            url,
            data=json.dumps(request_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT_SECONDS) as response:
                response_body = response.read().decode("utf-8")
                break
        except urllib.error.HTTPError as e:
            last_error = e
            continue

    if response_body is None:
        if last_error:
            raise last_error
        raise RuntimeError("No available Gemini models responded successfully.")

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
        # Include the provider's response body: "Not Found" alone does not
        # identify whether a model name, endpoint, or API version is wrong.
        try:
            provider_detail = e.read().decode("utf-8", errors="replace")
        except Exception:
            provider_detail = ""
        error_msg = f"Gemini API HTTP error {e.code}: {provider_detail or e.reason}"
    except urllib.error.URLError as e:
        error_msg = f"Network connection error: {e.reason}"
    except TimeoutError:
        error_msg = "Gemini API request timed out"
    except json.JSONDecodeError as e:
        error_msg = f"Malformed JSON from LLM: {e}"
    except Exception as e:
        error_msg = str(e)

    return {
        "mode": "unknown",
        "mode_confidence": 0.0,
        "traffic_type": "unknown",
        "traffic_confidence": 0.0,
        "backend": BACKEND_LLM,
        "error": error_msg,
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
