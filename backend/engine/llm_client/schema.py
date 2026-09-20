"""
Pydantic schemas for LLM-based inference.

Defines request/response shapes for Gemini API calls to classify:
- Operating mode (tunnel vs transport)
- Application traffic type (https, voip, icmp)

Single API call returns both predictions + confidence scores.
"""

from pydantic import BaseModel, Field
from typing import Literal, Optional


class ModeAndTrafficInferenceRequest(BaseModel):
    """Input features for joint mode + traffic inference via Gemini API.
    
    One request returns both mode and traffic type predictions to save API calls.
    """
    packet_lengths: list[float] = Field(
        ...,
        description="Sequence of ESP packet lengths (S_L) in bytes. First 30 packets.",
        min_items=1,
    )
    inter_arrival_times: list[float] = Field(
        ...,
        description="Sequence of inter-arrival times (S_IAT) in seconds.",
        min_items=1,
    )
    packet_count: int = Field(
        ...,
        description="Total number of packets in the ESP flow.",
        ge=1,
    )


class ModeInferenceResult(BaseModel):
    """Mode prediction (tunnel vs transport) from API."""
    predicted_mode: Literal["tunnel", "transport", "unknown"] = Field(
        ...,
        description="Predicted IPsec operating mode.",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score for mode prediction [0, 1].",
    )


class TrafficInferenceResult(BaseModel):
    """Traffic type prediction (https, voip, icmp) from API."""
    predicted_traffic_type: Literal["https", "voip", "icmp", "unknown"] = Field(
        ...,
        description="Predicted application traffic type.",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score for traffic type prediction [0, 1].",
    )


class LLMInferenceResponse(BaseModel):
    """Combined response from one Gemini API call returning both mode and traffic.
    
    This single response replaces two separate API calls for efficiency.
    """
    mode: ModeInferenceResult = Field(
        ...,
        description="Operating mode prediction.",
    )
    traffic: TrafficInferenceResult = Field(
        ...,
        description="Traffic type prediction.",
    )
    model_version: str = Field(
        default="gemini-3.1-flash-lite",
        description="Model used for inference.",
    )
    raw_response: Optional[str] = Field(
        default=None,
        description="Raw text response from API (for debugging).",
    )


class AgreementCheckResult(BaseModel):
    """Result of comparing API predictions against heuristic baseline.
    
    Tracks two separate metrics:
    1. API vs. ground truth accuracy (validated offline)
    2. Heuristic vs. API agreement (live metric)
    """
    api_mode_prediction: Literal["tunnel", "transport", "unknown"]
    api_traffic_prediction: Literal["https", "voip", "icmp", "unknown"]
    heuristic_mode_prediction: Optional[Literal["tunnel", "transport", "unknown"]] = None
    heuristic_traffic_prediction: Optional[Literal["https", "voip", "icmp", "unknown"]] = None
    mode_agreement: bool = Field(
        default=False,
        description="True if API mode matches heuristic mode.",
    )
    traffic_agreement: bool = Field(
        default=False,
        description="True if API traffic type matches heuristic traffic type.",
    )
    overall_agreement: bool = Field(
        default=False,
        description="True if both mode and traffic_type agree.",
    )
    api_avg_confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Average confidence across mode and traffic predictions.",
    )
