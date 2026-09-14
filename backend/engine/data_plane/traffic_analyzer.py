"""
traffic_analyzer.py
--------------------
Real (non-stub) data-plane analysis. Replaces the previous hardcoded mock
return values with actual ESP-packet extraction + classification, wired to
match backend/schemas/analysis.py's DataPlaneData model.

Design notes (read before changing anything):

- heuristic_mode_prediction: a deliberately simple, explainable heuristic
  (average ESP packet length vs. a threshold), NOT the trained CNN. This
  is a placeholder for classifier.py's CNN backend once that's wired to
  the ONNX export - swap the body of _heuristic_mode_prediction() then,
  don't change this file's structure.
- llm_mode_prediction / detected_traffic: calls classifier.py's LLM path
  directly (_classify_via_llm), since DataPlaneData wants BOTH a heuristic
  prediction and an LLM prediction every time - this is not the same as
  classify_traffic()'s CNN-or-LLM dispatch, which picks one or the other.
- detected_traffic returns ONE dominant traffic type at 100%, not a
  percentage composition across multiple types. Our testbed only ever
  generates one traffic type per capture, so a multi-type breakdown here
  would be fabricated data. This is a known, documented scope limitation
  vs. what the schema's field name implies - flag it in the model card.
- ai_confidence_score and agreement_flag are intentionally NOT computed
  here (per the original stub's comment) - ScoringEngine derives those
  from heuristic_mode_prediction vs. llm_mode_prediction agreement.

ASSUMPTION TO VERIFY: this imports `_classify_via_llm` from classifier.py
by that exact name. If your classifier.py names it differently, update
the import below - don't guess and leave it silently broken.
"""

from backend.engine.data_plane.feature_extract import (
    extract_esp_lengths_and_times,
    build_sequences,
    SEQ_LEN,
)
from backend.engine.data_plane.classifier import _classify_via_llm

# Tunnel mode adds an outer IP/ESP header, making average ESP packet length
# somewhat larger than Transport mode for equivalent inner traffic. This
# threshold is a rough midpoint derived from our testbed's synthetic
# profiles - it has NOT been calibrated against real captures yet. Treat
# this heuristic as a placeholder, not a validated detector, until the
# trained CNN (see engine/data_plane/train.py) replaces it.
HEURISTIC_TUNNEL_LEN_THRESHOLD_BYTES = 500

# Traffic-type labels the LLM/CNN pipeline was trained/prompted to use vs.
# the display labels the schema/dashboard expects. Extend this if the
# classifier's label set grows (e.g. once video/email/messaging traffic
# generators exist in the testbed).
_TRAFFIC_LABEL_DISPLAY = {
    "https": "HTTPS",
    "voip": "VoIP",
    "icmp": "ICMP",
    "unknown": "Unknown",
}


def _heuristic_mode_prediction(avg_packet_len: float) -> str:
    if avg_packet_len <= 0:
        return "Unknown"
    return "Tunnel" if avg_packet_len >= HEURISTIC_TUNNEL_LEN_THRESHOLD_BYTES else "Transport"


def _display_mode(raw_mode: str) -> str:
    if not raw_mode or raw_mode == "unknown":
        return "Unknown"
    return raw_mode.capitalize()  # "tunnel" -> "Tunnel", "transport" -> "Transport"


def _display_traffic_type(raw_type: str) -> str:
    return _TRAFFIC_LABEL_DISPLAY.get(raw_type, raw_type.capitalize() if raw_type else "Unknown")


def analyze_data_plane(pcap_path: str) -> dict:
    """
    Real data-plane analysis: extracts ESP packet lengths/timings from the
    given pcap, runs a simple length-based heuristic for mode, and calls
    the LLM classifier for a second, independent mode + traffic-type guess.

    Returns a dict matching DataPlaneData's expected fields:
        detected_traffic, heuristic_mode_prediction, llm_mode_prediction
    (ai_confidence_score / agreement_flag are left for ScoringEngine.)
    """
    lengths, timestamps = extract_esp_lengths_and_times(pcap_path)

    if not lengths:
        # No ESP packets found at all (e.g. IKE-only capture, or a capture
        # that doesn't contain this session's traffic). Don't fabricate a
        # confident answer - report the honest "we found nothing" state.
        return {
            "detected_traffic": [],
            "heuristic_mode_prediction": "Unknown",
            "llm_mode_prediction": "Unknown",
        }

    avg_len = sum(lengths) / len(lengths)
    heuristic_mode = _heuristic_mode_prediction(avg_len)

    s_l, s_iat, mask, n_real = build_sequences(lengths, timestamps, SEQ_LEN)
    esp_features = {
        "S_L": s_l.tolist(),
        "S_IAT": s_iat.tolist(),
        # Do not use a generic ``packet_count`` key here.  The classifier
        # needs both values to distinguish real observations from SEQ_LEN
        # padding, and to report the complete capture size accurately.
        "n_real_packets": n_real,
        "total_esp_packets": len(lengths),
    }

    llm_result = _classify_via_llm(esp_features)
    # llm_result is guaranteed by classifier.py's contract to always return
    # this shape, even on API failure (mode="unknown", with an "error" key)
    # - so no try/except needed here, just read the fields.

    llm_mode = _display_mode(llm_result.get("mode", "unknown"))
    traffic_type_label = _display_traffic_type(llm_result.get("traffic_type", "unknown"))

    detected_traffic = [
        {
            "traffic_type": traffic_type_label,
            "percentage": 100.0,
            "packet_count": len(lengths),
            "avg_packet_size_bytes": avg_len,
        }
    ]

    agreement_flag = bool(
        heuristic_mode != "Unknown"
        and llm_mode != "Unknown"
        and heuristic_mode == llm_mode
    )

    return {
        "detected_traffic": detected_traffic,
        "heuristic_mode_prediction": heuristic_mode,
        "llm_mode_prediction": llm_mode,
        "ai_confidence_score": llm_result.get("mode_confidence", 0.0),
        "agreement_flag": agreement_flag,
    }
