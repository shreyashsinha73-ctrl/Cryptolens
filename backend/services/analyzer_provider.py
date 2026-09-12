import json
import os
from pathlib import Path

from backend.engine.control_plane.ike_parser import parse_pcap
from backend.engine.data_plane.traffic_analyzer import analyze_data_plane
from backend.schemas.analysis import ControlPlaneData, DataPlaneData


BASE_DIR = Path(__file__).resolve().parent.parent
MOCK_JSON_PATH = BASE_DIR / "mock_data" / "analysis_input.json"


class AnalyzerProvider:
    def __init__(self, mode: str = "mock"):
        self.mode = mode.lower()

        if self.mode not in {"mock", "real"}:
            raise ValueError(
                f"Invalid analyzer mode: {mode}. "
                "Use 'mock' or 'real'."
            )

    def get_analysis(self, pcap_path: str):
        if self.mode == "mock":
            return self._get_mock_analysis()

        return self._get_real_analysis(pcap_path)

    def _get_mock_analysis(self):
        if not MOCK_JSON_PATH.exists():
            raise FileNotFoundError(
                f"Mock analysis file not found: {MOCK_JSON_PATH}"
            )

        with MOCK_JSON_PATH.open("r", encoding="utf-8") as file:
            return json.load(file)

    def _get_real_analysis(self, pcap_path: str):
        control_plane_raw = parse_pcap(pcap_path)
        data_plane_raw = analyze_data_plane(pcap_path)

        return {
            "control_plane": ControlPlaneData(
                **control_plane_raw
            ).model_dump(),
            "data_plane": DataPlaneData(
                **data_plane_raw
            ).model_dump(),
        }


def get_analyzer_provider() -> AnalyzerProvider:
    mode = os.getenv("ANALYZER_MODE", "mock")
    return AnalyzerProvider(mode=mode)