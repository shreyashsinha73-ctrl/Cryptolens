
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

from backend.engine.control_plane.ike_parser import IkeParser
from backend.engine.data_plane.traffic_analyzer import analyze_data_plane
from backend.schemas.analysis import ControlPlaneData


BASE_DIR = Path(__file__).resolve().parent.parent


class AnalyzerProvider:
    def __init__(self, mode: str = "real"):
        self.mode = mode.lower()

        if self.mode not in {"mock", "real"}:
            raise ValueError(
                f"Invalid analyzer mode: {mode}. "
                "Use 'mock' or 'real'."
            )

    @staticmethod
    def _normalize_encryption_algorithm(
        encryption: Optional[str],
    ) -> Optional[str]:
        """
        Normalize Part 2 parser naming to the canonical CryptoLens format.

        Part 2 may return:
            AES-GCM-256
            AES-GCM-128
            AES-CBC-256
            AES-CBC-128

        Part 5 expects:
            AES-256-GCM
            AES-128-GCM
            AES-256-CBC
            AES-128-CBC
        """
        if encryption is None:
            return None

        normalized = str(encryption).strip()

        encryption_map = {
            "AES-GCM-256": "AES-256-GCM",
            "AES-GCM-128": "AES-128-GCM",
            "AES-CBC-256": "AES-256-CBC",
            "AES-CBC-128": "AES-128-CBC",
        }

        return encryption_map.get(normalized, normalized)

    def get_analysis(self, pcap_path: str) -> Dict[str, Any]:
        if self.mode == "mock":
            mock_path = BASE_DIR / "mock_data" / "analysis_input.json"

            if mock_path.exists():
                with mock_path.open("r", encoding="utf-8") as f:
                    return json.load(f)

        return self._get_real_analysis(pcap_path)

    def _get_real_analysis(self, pcap_path: str) -> Dict[str, Any]:
        # Part 2: use the actual parser interface.
        parser = IkeParser(pcap_path)
        parser_result = parser.parse()

        # IkeParser.parse() returns a wrapper object containing
        # "control_plane".
        control_plane_raw = parser_result.get("control_plane")

        if control_plane_raw is None:
            control_plane = None
        else:
            # Normalize Part 2 naming before Part 5 sees the data.
            control_plane_raw = dict(control_plane_raw)

            control_plane_raw["encryption_algorithm"] = (
                self._normalize_encryption_algorithm(
                    control_plane_raw.get("encryption_algorithm")
                )
            )

            # Validate the normalized Part 2 output against our
            # backend schema.
            control_plane = ControlPlaneData(
                **control_plane_raw
            ).model_dump()

        # Part 3 intentionally remains unchanged for now.
        data_plane = analyze_data_plane(pcap_path)

        return {
            "control_plane": control_plane,
            "data_plane": data_plane,
        }


def get_analyzer_provider() -> AnalyzerProvider:
    mode = os.getenv("ANALYZER_MODE", "real")
    return AnalyzerProvider(mode=mode)

