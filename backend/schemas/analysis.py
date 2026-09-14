from pydantic import BaseModel, Field
from typing import Any, List, Optional


class ErrorResponse(BaseModel):
    error_code: str = Field(..., example="INVALID_FILE_FORMAT")
    message: str = Field(..., example="Only .pcap and .pcapng files are supported.")

class UploadResponse(BaseModel):
    job_id: str = Field(..., example="job_9f8b2c1a")
    status: str = Field(..., example="processing")
    filename: str = Field(..., example="capture.pcap")
    uploaded_at: str

class ControlPlaneData(BaseModel):
    ike_version: Optional[str] = None
    operating_mode: Optional[str] = None
    encryption_algorithm: Optional[str] = None
    integrity_algorithm: Optional[str] = None
    dh_group: Optional[Any] = None
    pfs_enabled: Optional[bool] = None
    key_lifetime_seconds: Optional[int] = None
    replay_protection_enabled: Optional[bool] = None

class TrafficItem(BaseModel):
    traffic_type: str
    percentage: float
    packet_count: int
    avg_packet_size_bytes: float = Field(..., ge=0)


class DataPlaneData(BaseModel):
    detected_traffic: List[TrafficItem] = Field(default_factory=list)
    heuristic_mode_prediction: Optional[str] = None
    llm_mode_prediction: Optional[str] = None
    ai_confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    agreement_flag: bool = False

class ScoreCategory(BaseModel):
    score: float = Field(..., ge=0.0)
    max_score: float = Field(..., gt=0.0)


class ScoreBreakdown(BaseModel):
    encryption: ScoreCategory
    integrity: ScoreCategory
    key_exchange: ScoreCategory
    pfs: ScoreCategory
    replay_protection: ScoreCategory
    key_lifetime: ScoreCategory
    ike_version: ScoreCategory
    mode: ScoreCategory

class ComplianceCounts(BaseModel):
    aligned: int = Field(..., ge=0, alias="ALIGNED")
    review: int = Field(..., ge=0,alias="REVIEW")
    fail: int = Field(..., ge=0,alias= "FAIL")
    not_assessed: int = Field(..., ge=0, alias= "NOT_ASSESSED")


class ComplianceControl(BaseModel):
    control: str
    status: str
    observed_value: Optional[Any] = None
    description: str
    reason: Optional[str] = None
    standard: str
    mapping_version: str


class StandardComplianceResult(BaseModel):
    standard: str
    title: str
    authority: str
    reference: str
    assessment_type: str
    mapping_version: str
    overall_status: str
    counts: ComplianceCounts
    controls: List[ComplianceControl]


class ComplianceResult(BaseModel):
    mapping_version: str
    standards: dict[str, StandardComplianceResult]

class ThreatItem(BaseModel):
    finding_id: str
    severity: str
    category: str = "General"
    title: str
    description: str
    observed_value: Optional[Any] = None
    source: Optional[str] = None

class SummaryData(BaseModel):
    overall_security_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=100.0
    )
    risk_level: str
    ai_confidence_score: float = Field(..., ge=0.0, le=1.0)
    agreement_flag: bool
    processed_packets: int = Field(..., ge=0)





class AnalysisResultResponse(BaseModel):
    job_id: str
    status: str

    summary: Optional[SummaryData] = None

    control_plane: Optional[ControlPlaneData] = None

    data_plane: Optional[DataPlaneData] = None

    score_breakdown: Optional[ScoreBreakdown] = None

    threat_matrix: List[ThreatItem] = Field(default_factory=list)

    compliance: Optional[ComplianceResult] = None

class AnalysisFailureResponse(BaseModel):
    job_id: str
    status: str
    error: ErrorResponse
