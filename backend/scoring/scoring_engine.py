import yaml
import os
from pathlib import Path

class ScoringEngine:
    def __init__(self):
        base_dir = Path(__file__).resolve().parent
        
        with open(base_dir / 'weights_config.yaml', 'r') as f:
            self.weights = yaml.safe_load(f)
            
        with open(base_dir / 'compliance_map.yaml', 'r') as f:
            self.rules = yaml.safe_load(f)
            
        self.findings = []
        
    def _evaluate_param(self, category: str, value: str):
        rule_set = self.rules.get(category, {})
        rule = rule_set.get(str(value))
        
        if not rule:
            # Fallback if the parameter is unknown
            self.findings.append({
                "severity": "HIGH",
                "finding_id": f"UNKNOWN_{category.upper()}",
                "title": f"Unknown {category} parameter",
                "description": f"The parameter '{value}' is not recognized in the compliance map."
            })
            return 0
            
        awarded = rule.get("awarded_points", 0)
        finding = rule.get("finding")
        
        if finding:
            # We append the category for reporting context
            finding_copy = dict(finding)
            finding_copy['category'] = category.replace('_', ' ').title()
            self.findings.append(finding_copy)
            
        return awarded

    def evaluate_encryption(self, control_plane):
        return self._evaluate_param('encryption', control_plane.get('encryption_algorithm'))

    def evaluate_integrity(self, control_plane):
        return self._evaluate_param('integrity', control_plane.get('integrity_algorithm'))

    def evaluate_key_exchange(self, control_plane):
        return self._evaluate_param('key_exchange', control_plane.get('dh_group'))

    def evaluate_pfs(self, control_plane):
        val = str(control_plane.get('pfs_enabled')).lower()
        return self._evaluate_param('pfs', val)

    def evaluate_replay_protection(self, control_plane):
        val = str(control_plane.get('replay_protection_enabled')).lower()
        return self._evaluate_param('replay_protection', val)

    def evaluate_key_lifetime(self, control_plane):
        lifetime = control_plane.get('key_lifetime_seconds', 0)
        val = 'valid' if lifetime <= 86400 else 'invalid'
        return self._evaluate_param('key_lifetime', val)

    def evaluate_ike_version(self, control_plane):
        return self._evaluate_param('ike_version', control_plane.get('ike_version'))

    def evaluate_mode(self, control_plane):
        return self._evaluate_param('mode', control_plane.get('operating_mode'))

    def get_risk_level(self, score: int) -> str:
        if score >= 90:
            return "LOW"
        elif score >= 75:
            return "MODERATE"
        elif score >= 50:
            return "HIGH"
        else:
            return "CRITICAL"

    def evaluate(self, analysis_input: dict):
        self.findings = []
        control_plane = analysis_input.get('control_plane', {})
        data_plane = analysis_input.get('data_plane', {})

        score = 0
        score += self.evaluate_encryption(control_plane)
        score += self.evaluate_integrity(control_plane)
        score += self.evaluate_key_exchange(control_plane)
        score += self.evaluate_pfs(control_plane)
        score += self.evaluate_replay_protection(control_plane)
        score += self.evaluate_key_lifetime(control_plane)
        score += self.evaluate_ike_version(control_plane)
        score += self.evaluate_mode(control_plane)

        # AI Independence calculations
        h_mode = data_plane.get('heuristic_mode_prediction')
        l_mode = data_plane.get('llm_mode_prediction')
        
        if h_mode and l_mode:
            agreement_flag = (h_mode == l_mode)
            ai_confidence = 0.94 if agreement_flag else 0.65
        else:
            agreement_flag = False
            ai_confidence = 0.0

        risk_level = self.get_risk_level(score)

        return {
            "score": score,
            "risk_level": risk_level,
            "findings": self.findings,
            "ai_confidence": ai_confidence,
            "agreement_flag": agreement_flag
        }
