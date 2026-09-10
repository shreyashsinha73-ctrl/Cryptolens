from pydantic import BaseModel, Field
from typing import List, Optional

class ErrorResponse(BaseModel):
    error_code: str = Field(..., example="INVALID_FILE_FORMAT")
    message: str = Field(..., example="Only .pcap and .pcapng files are supported.")

class UploadResponse(BaseModel):
    job_id: str = Field(..., example="job_9f8b2c1a")
    status: str = Field(..., example="processing")
    filename: str = Field(..., example="capture.pcap")
    uploaded_at: str

class ControlPlaneData(BaseModel):
    ike_version: str = "IKEv2"
    operating_mode: str = "Tunnel"
    encryption_algorithm: str = "AES-128-CBC"
    integrity_algorithm: str = "HMAC-SHA2-256"
    dh_group: int = 14
    pfs_enabled: bool = False
    key_lifetime_seconds: int = 28800
    replay_protection_enabled: bool = True

class TrafficItem(BaseModel):
    traffic_type: str
    percentage: float
    packet_count: int
    avg_packet_size_bytes: int

class DataPlaneData(BaseModel):
    detected_traffic: List[TrafficItem]
    heuristic_mode_prediction: str = "Tunnel"
    llm_mode_prediction: str = "Tunnel"

class ThreatItem(BaseModel):
    id: str
    severity: str
    category: str
    title: str
    description: str

class SummaryData(BaseModel):
    overall_risk_score: int = Field(..., ge=0, le=100)
    risk_level: str
    ai_confidence_score: float = Field(..., ge=0.0, le=1.0)
    agreement_flag: bool

class AnalysisResultResponse(BaseModel):
    job_id: str
    status: str
    summary: Optional[SummaryData] = None
    control_plane: Optional[ControlPlaneData] = None
    data_plane: Optional[DataPlaneData] = None
    threat_matrix: List[ThreatItem] = []