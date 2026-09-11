from typing import List, Optional
from pydantic import BaseModel, Field


# ============================================================
# 1. UPLOAD API SCHEMAS
# ============================================================

class ErrorResponse(BaseModel):
    error_code: str = Field(
        ...,
        examples=["INVALID_FILE_FORMAT"]
    )
    message: str = Field(
        ...,
        examples=["Only .pcap and .pcapng files are supported."]
    )


class UploadResponse(BaseModel):
    job_id: str = Field(
        ...,
        examples=["job_9f8b2c1a"]
    )
    status: str = Field(
        ...,
        examples=["processing"]
    )
    filename: str
    uploaded_at: str


# ============================================================
# 2. ANALYZER OUTPUT / JSON A
#    Produced by Parts 2-4
# ============================================================

class ControlPlaneData(BaseModel):
    """
    Information obtained from the IPsec/IKE control plane.

    These values should come from the analyzer.
    No security-related defaults are used here.
    """

    ike_version: str
    operating_mode: str

    encryption_algorithm: str
    integrity_algorithm: Optional[str] = None

    dh_group: int = Field(..., ge=0)

    pfs_enabled: bool
    key_lifetime_seconds: int = Field(..., gt=0)
    replay_protection_enabled: bool


class TrafficItem(BaseModel):
    """
    Traffic classification/inference produced by
    the data-plane / AI pipeline.
    """

    traffic_type: str

    percentage: float = Field(
        ...,
        ge=0.0,
        le=100.0
    )

    packet_count: int = Field(
        ...,
        ge=0
    )

    avg_packet_size_bytes: float = Field(
        ...,
        gt=0
    )


class DataPlaneData(BaseModel):
    """
    Information inferred from encrypted ESP traffic.
    """

    detected_traffic: List[TrafficItem]

    heuristic_mode_prediction: str
    llm_mode_prediction: str

    ai_confidence_score: float = Field(
        ...,
        ge=0.0,
        le=1.0
    )

    agreement_flag: bool


class AnalysisInput(BaseModel):
    """
    JSON A.

    This is the contract between the analyzer
    (Parts 2-4) and the Part 5 backend.

    IMPORTANT:
    This model contains observations/inferences,
    NOT the final security score.
    """

    control_plane: ControlPlaneData
    data_plane: DataPlaneData


# ============================================================
# 3. PART 5 ASSESSMENT OUTPUT
# ============================================================

class ThreatItem(BaseModel):
    id: str
    severity: str
    category: str
    title: str
    description: str


class SummaryData(BaseModel):
    """
    Result calculated by the Part 5 scoring engine.
    """

    overall_risk_score: int = Field(
        ...,
        ge=0,
        le=100
    )

    risk_level: str

    ai_confidence_score: float = Field(
        ...,
        ge=0.0,
        le=1.0
    )

    agreement_flag: bool


class AnalysisResultResponse(BaseModel):
    """
    Final response returned by the backend.
    """

    job_id: str
    status: str

    summary: Optional[SummaryData] = None

    control_plane: Optional[ControlPlaneData] = None

    data_plane: Optional[DataPlaneData] = None

    threat_matrix: List[ThreatItem] = Field(
        default_factory=list
    )