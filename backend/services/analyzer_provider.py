import json
import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
MOCK_JSON_PATH = BASE_DIR / "mock_data" / "analysis_input.json"


class AnalyzerProvider:
    """
    Provides analysis JSON to the backend.

    Modes:
        mock -> reads analysis_input.json
        real -> placeholder for the real Part 1-4 pipeline
    """

    def __init__(self, mode: str = "mock"):
        self.mode = mode.lower()

        if self.mode not in {"mock", "real"}:
            raise ValueError(
                f"Invalid analyzer mode: {mode}. "
                "Use 'mock' or 'real'."
            )

    def get_analysis(self, pcap_path: str) -> dict:
        """
        Analyze the supplied PCAP and return JSON A as a Python dictionary.
        """

        if self.mode == "mock":
            return self._get_mock_analysis()

        return self._get_real_analysis(pcap_path)

    def _get_mock_analysis(self) -> dict:
        """Load the dummy JSON A from disk."""

        if not MOCK_JSON_PATH.exists():
            raise FileNotFoundError(
                f"Mock analysis file not found: {MOCK_JSON_PATH}"
            )

        with open(MOCK_JSON_PATH, "r", encoding="utf-8") as file:
            data = json.load(file)

        return data

    def _get_real_analysis(self, pcap_path: str) -> dict:
        """
        Run the real Part 1-4 pipeline.

        TODO:
        Replace this with the actual integration once
        Parts 1-4 provide their interfaces.
        """

        raise NotImplementedError(
            "Real analyzer integration is not connected yet. "
            "Set ANALYZER_MODE=mock for the POC."
        )


def get_analyzer_provider() -> AnalyzerProvider:
    """
    Create the analyzer provider using the ANALYZER_MODE
    environment variable.

    Example:
        ANALYZER_MODE=mock
        ANALYZER_MODE=real
    """

    mode = os.getenv("ANALYZER_MODE", "mock")

    return AnalyzerProvider(mode=mode)