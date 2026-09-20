from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import yaml


BASE_DIR = Path(__file__).resolve().parent
STANDARDS_FILE = BASE_DIR / "compliance_standards.yaml"


class ComplianceEngine:
    """
    Evaluates observed IPsec parameters against the configured
    standards mapping in compliance_standards.yaml.

    This engine performs standards-alignment assessment only.
    It does not calculate the overall CryptoLens security score.
    """

    def __init__(self, standards_file: Path = STANDARDS_FILE):
        self.standards_file = standards_file

        if not self.standards_file.exists():
            raise FileNotFoundError(
                f"Compliance standards file not found: "
                f"{self.standards_file}"
            )

        with self.standards_file.open("r", encoding="utf-8") as file:
            config = yaml.safe_load(file) or {}

        self.version = config.get("version", "unknown")
        self.standards = config.get("standards", {})

        if not isinstance(self.standards, dict):
            raise ValueError(
                "Invalid compliance_standards.yaml: "
                "'standards' must be a mapping."
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_value(value: Any) -> str:
        """
        Normalize observed values so YAML keys such as:
            true
            14
            IKEv2
        can be compared consistently.
        """
        return str(value)

    @staticmethod
    def _status_counts(results: List[Dict[str, Any]]) -> Dict[str, int]:
        counts = {
            "ALIGNED": 0,
            "REVIEW": 0,
            "FAIL": 0,
            "NOT_ASSESSED": 0,
        }

        for result in results:
            status = result.get("status", "NOT_ASSESSED")

            if status not in counts:
                counts["NOT_ASSESSED"] += 1
            else:
                counts[status] += 1

        return counts

    @staticmethod
    def _overall_status(counts: Dict[str, int]) -> str:
        """
        Derive an overall assessment state.

        FAIL has highest priority.
        Otherwise REVIEW takes priority over ALIGNED.
        If nothing was assessed, return NOT_ASSESSED.
        """
        if counts["FAIL"] > 0:
            return "FAIL"

        if counts["REVIEW"] > 0:
            return "REVIEW"

        if counts["ALIGNED"] > 0:
            return "ALIGNED"

        return "NOT_ASSESSED"

    # ------------------------------------------------------------------
    # Single control evaluation
    # ------------------------------------------------------------------

    def _evaluate_control(
        self,
        standard_name: str,
        control_name: str,
        observed_value: Any,
        control_config: Dict[str, Any],
    ) -> Dict[str, Any]:

        # No evidence available
        if observed_value is None:
            return {
                "control": control_name,
                "status": "NOT_ASSESSED",
                "observed_value": None,
                "description": control_config.get("description", ""),
                "reason": "Required evidence was not observed.",
                "standard": standard_name,
                "mapping_version": self.version,
            }

        values = control_config.get("values", {})

        if not isinstance(values, dict):
            return {
                "control": control_name,
                "status": "NOT_ASSESSED",
                "observed_value": observed_value,
                "description": control_config.get("description", ""),
                "reason": "Invalid standards mapping configuration.",
                "standard": standard_name,
                "mapping_version": self.version,
            }

        normalized_value = self._normalize_value(observed_value)

        rule = None

        for configured_value, configured_rule in values.items():
            if self._normalize_value(configured_value) == normalized_value:
                rule = configured_rule
                break

        # Observed value exists but has no configured mapping
        if rule is None:
            return {
                "control": control_name,
                "status": "NOT_ASSESSED",
                "observed_value": observed_value,
                "description": control_config.get("description", ""),
                "reason": (
                    "The observed value is not present in the "
                    "current standards mapping."
                ),
                "standard": standard_name,
                "mapping_version": self.version,
            }

        status = str(rule.get("status", "NOT_ASSESSED")).upper()

        if status not in {"ALIGNED", "REVIEW", "FAIL"}:
            status = "NOT_ASSESSED"

        return {
            "control": control_name,
            "status": status,
            "observed_value": observed_value,
            "description": control_config.get("description", ""),
            "standard": standard_name,
            "mapping_version": self.version,
        }

    # ------------------------------------------------------------------
    # Standard evaluation
    # ------------------------------------------------------------------

    def _evaluate_standard(
        self,
        standard_name: str,
        standard_config: Dict[str, Any],
        control_plane: Dict[str, Any],
    ) -> Dict[str, Any]:

        controls = standard_config.get("controls", {})

        if not isinstance(controls, dict):
            raise ValueError(
                f"Invalid controls configuration for {standard_name}."
            )

        results: List[Dict[str, Any]] = []

        # Mapping between our AnalysisInput field names and
        # compliance_standards.yaml control names.
        field_map = {
            "encryption": "encryption_algorithm",
            "integrity": "integrity_algorithm",
            "key_exchange": "dh_group",
            "pfs": "pfs_enabled",
            "replay_protection": "replay_protection_enabled",
            "ike_version": "ike_version",
            "operating_mode": "operating_mode",
        }

        # GCM provides authenticated encryption, so the same AEAD
        # interpretation used by ScoringEngine is applied here.
        effective_integrity = control_plane.get("integrity_algorithm")

        encryption = control_plane.get("encryption_algorithm")

        if (
            encryption
            and isinstance(encryption, str)
            and "GCM" in encryption.upper()
        ):
            effective_integrity = "AEAD"

        for control_name, control_config in controls.items():
            if control_name not in field_map:
                results.append(
                    {
                        "control": control_name,
                        "status": "NOT_ASSESSED",
                        "observed_value": None,
                        "description": control_config.get(
                            "description", ""
                        ),
                        "reason": (
                            "This compliance control is not yet "
                            "connected to the AnalysisInput schema."
                        ),
                        "standard": standard_name,
                        "mapping_version": self.version,
                    }
                )
                continue

            field_name = field_map[control_name]

            if control_name == "integrity":
                observed_value = effective_integrity
            else:
                observed_value = control_plane.get(field_name)

            results.append(
                self._evaluate_control(
                    standard_name=standard_name,
                    control_name=control_name,
                    observed_value=observed_value,
                    control_config=control_config,
                )
            )

        counts = self._status_counts(results)

        return {
            "standard": standard_name,
            "title": standard_config.get("title", standard_name),
            "authority": standard_config.get("authority"),
            "reference": standard_config.get("reference"),
            "assessment_type": standard_config.get(
                "assessment_type"
            ),
            "mapping_version": self.version,
            "overall_status": self._overall_status(counts),
            "counts": counts,
            "controls": results,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, analysis_input: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate all configured standards against AnalysisInput.

        Expected input:
        {
            "control_plane": {...},
            "data_plane": {...}
        }
        """

        control_plane = analysis_input.get("control_plane") or {}

        if not isinstance(control_plane, dict):
            raise ValueError(
                "'control_plane' must be an object."
            )

        standard_results = {}

        for standard_name, standard_config in self.standards.items():
            standard_results[standard_name] = self._evaluate_standard(
                standard_name=standard_name,
                standard_config=standard_config,
                control_plane=control_plane,
            )

        return {
            "mapping_version": self.version,
            "standards": standard_results,
        }