
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

from backend.engine.control_plane.ike_parser import IkeParser
from backend.engine.data_plane.traffic_analyzer import analyze_data_plane
from backend.schemas.analysis import ControlPlaneData, DataPlaneData



BASE_DIR = Path(__file__).resolve().parent.parent


from backend.schemas.sidecar import IPsecSidecarConfig

FIELD_TO_CATEGORY = {
    "encryption_algorithm": "encryption",
    "integrity_algorithm": "integrity",
    "dh_group": "key_exchange",
    "pfs_enabled": "pfs",
    "replay_protection_enabled": "replay_protection",
    "key_lifetime_seconds": "key_lifetime",
    "ike_version": "ike_version",
    "operating_mode": "mode",
}


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

    def get_analysis(
        self,
        pcap_path: str,
        sidecar_config: Optional[Any] = None,
    ) -> Dict[str, Any]:
        if self.mode == "mock":
            mock_path = BASE_DIR / "mock_data" / "analysis_input.json"

            if mock_path.exists():
                with mock_path.open("r", encoding="utf-8") as f:
                    return json.load(f)

        return self._get_real_analysis(pcap_path, sidecar_config=sidecar_config)

    def _get_real_analysis(
        self,
        pcap_path: str,
        sidecar_config: Optional[Any] = None,
    ) -> Dict[str, Any]:
        # Part 2: use the actual parser interface.
        parser = IkeParser(pcap_path)
        parser_result = parser.parse()

        # IkeParser.parse() returns a wrapper object containing "control_plane".
        control_plane_raw = parser_result.get("control_plane")

        if control_plane_raw is None:
            control_plane_raw = {}
        else:
            control_plane_raw = dict(control_plane_raw)

        # Check for adjacent sidecar configuration if not provided directly
        if sidecar_config is None:
            sidecar_file = Path(pcap_path).with_suffix(".sidecar.json")
            if not sidecar_file.exists():
                sidecar_file = Path(f"{pcap_path}.sidecar.json")
            if sidecar_file.exists():
                try:
                    with open(sidecar_file, "r") as sf:
                        sidecar_config = json.load(sf)
                except Exception:
                    pass

        # Validate and apply operator-supplied sidecar configuration
        sidecar_report = None
        if sidecar_config is not None:
            if isinstance(sidecar_config, dict):
                validated_sidecar = IPsecSidecarConfig(**sidecar_config)
            else:
                validated_sidecar = sidecar_config

            from backend.scoring.sidecar_consistency import check_sidecar_consistency
            sidecar_report = check_sidecar_consistency(pcap_path, control_plane_raw, validated_sidecar)

            if "observability" not in control_plane_raw or not isinstance(control_plane_raw["observability"], dict):
                control_plane_raw["observability"] = {}
            if "evidence_source" not in control_plane_raw or not isinstance(control_plane_raw["evidence_source"], dict):
                control_plane_raw["evidence_source"] = {}

            contradicted_fields = {c.target_field for c in sidecar_report.checks if c.status == "contradicts"}

            for field_name, field_val in validated_sidecar.model_dump(exclude_unset=True).items():
                if field_val is not None:
                    cat = FIELD_TO_CATEGORY.get(field_name, field_name)
                    if field_name in contradicted_fields:
                        control_plane_raw["observability"][cat] = "contradicted"
                        control_plane_raw["evidence_source"][cat] = "contradicted"
                    else:
                        control_plane_raw[field_name] = field_val
                        control_plane_raw["observability"][cat] = "operator_supplied"
                        control_plane_raw["evidence_source"][cat] = "operator_supplied"

        if not control_plane_raw:
            control_plane = None
        else:
            # Normalize Part 2 naming before Part 5 sees the data.
            control_plane_raw["encryption_algorithm"] = (
                self._normalize_encryption_algorithm(
                    control_plane_raw.get("encryption_algorithm")
                )
            )

            # Validate against our backend schema.
            control_plane = ControlPlaneData(
                **control_plane_raw
            ).model_dump()

        # Part 3 intentionally remains unchanged for now.
        data_plane_raw = analyze_data_plane(pcap_path)
        data_plane = DataPlaneData(**data_plane_raw).model_dump()

        result = {
            "control_plane": control_plane,
            "data_plane": data_plane,
        }
        if sidecar_report:
            result["sidecar_consistency"] = sidecar_report.model_dump()
        return result


def get_analyzer_provider() -> AnalyzerProvider:
    mode = os.getenv("ANALYZER_MODE", "real")
    return AnalyzerProvider(mode=mode)

