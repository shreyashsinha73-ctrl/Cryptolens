import yaml
import os
from pathlib import Path

class ScoringEngine:
    def __init__(self):
        base_dir = Path(__file__).resolve().parent

        with open(base_dir / "weights_config.yaml", "r") as f:
            self.weights = yaml.safe_load(f)

        with open(base_dir / "compliance_map.yaml", "r") as f:
            self.rules = yaml.safe_load(f)

    # Make sure category weights always add up to 100
        total_weight = sum(self.weights.values())

        if total_weight != 100:
            raise ValueError(
                f"Scoring weights must total 100, but got {total_weight}."
            )

        
    def _evaluate_param(self, category: str, value, findings):

         # Evidence was not available
        if value is None:
            findings.append({
                "severity": "INFO",
                "finding_id": f"NOT_OBSERVED_{category.upper()}",
                "title": f"{category.replace('_', ' ').title()} Not Observed",
                "description": (
                    f"No reliable evidence was available to determine "
                    f"the {category.replace('_', ' ')}. "
                    "No security weakness is assumed."
                )
            })
            return 0.0

        rule_set = self.rules.get(category, {})

        rule = None

        for configured_value, configured_rule in rule_set.items():
            if str(configured_value).lower() == str(value).lower():
                rule = configured_rule
                break

        # Evidence exists, but the value is not in the compliance map
        if not rule:
            findings.append({
                "severity": "INFO",
                "finding_id": f"UNKNOWN_{category.upper()}",
                "title": f"Unrecognized {category} parameter",
                "description": (
                    f"The observed parameter '{value}' is not present "
                    "in the current compliance map. No security "
                    "weakness is assumed; manual review is recommended."
                ),
                "category": category.replace("_", " ").title(),
                "observed_value": value,
                "source": "compliance_map.yaml"
            })
            return 0.0
        raw_points = rule.get("awarded_points", 0)

        max_rule_points = max(
            (
                rule_data.get("awarded_points", 0)
                for rule_data in rule_set.values()
                if isinstance(rule_data, dict)
            ),
            default=0
        )

        if max_rule_points <= 0:
            return 0.0

        category_weight = self.weights.get(category, 0)

        awarded = (raw_points / max_rule_points) * category_weight

        finding = rule.get("finding")

        if finding:
            finding_copy = dict(finding)

            finding_copy["category"] = category.replace("_", " ").title()
            finding_copy["observed_value"] = value
            finding_copy["source"] = "compliance_map.yaml"

            findings.append(finding_copy)

        return awarded

    def evaluate_encryption(self, control_plane,findings):
        return self._evaluate_param('encryption', control_plane.get('encryption_algorithm'),findings)

    def evaluate_integrity(self, control_plane,findings):
        encryption = control_plane.get("encryption_algorithm")
        integrity = control_plane.get("integrity_algorithm")

        if encryption and "GCM" in encryption.upper():
            integrity = "AEAD"

        return self._evaluate_param("integrity", integrity,findings)

    

    def evaluate_key_exchange(self, control_plane,findings):
        return self._evaluate_param('key_exchange', control_plane.get('dh_group'),findings)

    def evaluate_pfs(self, control_plane,findings):
        val = str(control_plane.get('pfs_enabled')).lower()
        return self._evaluate_param('pfs', val,findings)

    def evaluate_replay_protection(self, control_plane,findings):
        val = str(control_plane.get('replay_protection_enabled')).lower()
        return self._evaluate_param('replay_protection', val,findings)

    def evaluate_key_lifetime(self, control_plane, findings):
        lifetime = control_plane.get("key_lifetime_seconds")

        max_seconds = self.rules.get("key_lifetime", {}).get("max_seconds")

        if lifetime is None or max_seconds is None:
            findings.append({
                "severity": "INFO",
                "finding_id": "UNKNOWN_KEY_LIFETIME",
                "title": "Key Lifetime Could Not Be Assessed",
                "description": "The key lifetime or assessment threshold is unavailable."
            })
            return 0.0

        val = "valid" if lifetime <= max_seconds else "invalid"

        return self._evaluate_param("key_lifetime", val, findings)

    def evaluate_ike_version(self, control_plane,findings):
        return self._evaluate_param('ike_version', control_plane.get('ike_version'),findings)

    def evaluate_mode(self, control_plane,findings):
        return self._evaluate_param('mode', control_plane.get('operating_mode'),findings)

    def get_risk_level(self, score: float) -> str:
        if score >= 90:
            return "LOW"
        elif score >= 75:
            return "MODERATE"
        elif score >= 50:
            return "HIGH"
        else:
            return "CRITICAL"

    def evaluate(self, analysis_input: dict):
        findings = []
        control_plane = analysis_input.get('control_plane', {})
        data_plane = analysis_input.get('data_plane', {})

        encryption_score = self.evaluate_encryption(control_plane, findings)
        integrity_score = self.evaluate_integrity(control_plane, findings)
        key_exchange_score = self.evaluate_key_exchange(control_plane, findings)
        pfs_score = self.evaluate_pfs(control_plane, findings)
        replay_protection_score = self.evaluate_replay_protection(
            control_plane,
            findings
            )
        key_lifetime_score = self.evaluate_key_lifetime(
            control_plane,
            findings
        )
        ike_version_score = self.evaluate_ike_version(
            control_plane,
            findings
        )
        mode_score = self.evaluate_mode(control_plane, findings)

        score = (
            encryption_score
            + integrity_score
            + key_exchange_score
            + pfs_score
            + replay_protection_score
            + key_lifetime_score
            + ike_version_score
            + mode_score
        )
        score_breakdown = {
            "encryption": {
                "score": encryption_score,
                "max_score": self.weights["encryption"]
            },
            "integrity": {
                "score": integrity_score,
                "max_score": self.weights["integrity"]
            },
            "key_exchange": {
                "score": key_exchange_score,
                "max_score": self.weights["key_exchange"]
            },
            "pfs": {
                "score": pfs_score,
                "max_score": self.weights["pfs"]
            },
            "replay_protection": {
                "score": replay_protection_score,
                "max_score": self.weights["replay_protection"]
            },
            "key_lifetime": {
                "score": key_lifetime_score,
                "max_score": self.weights["key_lifetime"]
            },
            "ike_version": {
                "score": ike_version_score,
                "max_score": self.weights["ike_version"]
            },
            "mode": {
                "score": mode_score,
                "max_score": self.weights["mode"]
            }
        }

        # Final score normalization
        score = round(score, 2)
        score = max(0.0, min(score, 100.0))

        # AI Independence calculations
        # AI results supplied by Part 4
        h_mode = data_plane.get("heuristic_mode_prediction")
        l_mode = data_plane.get("llm_mode_prediction")

# Agreement is calculated independently from the supplied predictions.
        agreement_flag = (
            h_mode is not None
            and l_mode is not None
            and h_mode == l_mode
        )

    
    # Part 4 is the source of this value.
        ai_confidence = data_plane.get("ai_confidence_score", 0.0)

        risk_level = self.get_risk_level(score)

        return {
            "score": score,
            "risk_level": risk_level,
            "findings": findings,
            "score_breakdown": score_breakdown,
            "ai_confidence_score": ai_confidence,
            "agreement_flag": agreement_flag
        }
