import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import yaml

CATEGORY_TO_FIELD = {
    "encryption": "encryption_algorithm",
    "integrity": "integrity_algorithm",
    "key_exchange": "dh_group",
    "pfs": "pfs_enabled",
    "replay_protection": "replay_protection_enabled",
    "key_lifetime": "key_lifetime_seconds",
    "ike_version": "ike_version",
    "mode": "operating_mode",
}


_RISK_ORDER = ["LOW", "MODERATE", "HIGH", "CRITICAL"]
_SEV_TO_RISK = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MODERATE"}


def compute_risk_level(score_observed_only, coverage_ratio, observed_count, findings):
    """Deterministic risk level: score thresholds, floored by worst observed finding,
    LOW only when coverage_ratio >= 0.8 (else capped at MODERATE). Returns (level, cap_reason)."""
    if observed_count <= 0:
        return "NOT_ASSESSED", ""
    s = score_observed_only
    level = "LOW" if s >= 90 else "MODERATE" if s >= 75 else "HIGH" if s >= 50 else "CRITICAL"
    idx = _RISK_ORDER.index(level)
    for f in findings or []:
        if f.get("observability") in ("observed", "operator_supplied"):
            floor = _SEV_TO_RISK.get(str(f.get("severity", "")).upper())
            if floor:
                idx = max(idx, _RISK_ORDER.index(floor))
    cap_reason = ""
    if _RISK_ORDER[idx] == "LOW" and coverage_ratio < 0.8:
        idx = 1
        cap_reason = f"Capped at MODERATE: only {int(round(coverage_ratio * 100))}% of checks observable (LOW needs >= 80%)."
    return _RISK_ORDER[idx], cap_reason


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

    def _get_observability(self, category: str, control_plane: Optional[dict]) -> str:
        """
        Determine wire observability:
        - 'observed': directly observed on the wire in cleartext
        - 'operator_supplied': explicitly provided by operator sidecar
        - 'inferred': deduced via statistical heuristics or notification payloads
        - 'not_observable': encrypted on wire (e.g. IKEv2 Child SA ESP transforms)
        """
        if isinstance(control_plane, dict):
            field_name = CATEGORY_TO_FIELD.get(category, category)
            # Check explicit observability map
            obs_map = control_plane.get("observability")
            if isinstance(obs_map, dict):
                if category in obs_map:
                    return obs_map[category]
                if field_name in obs_map:
                    return obs_map[field_name]

            # Check evidence_source for operator_supplied
            ev_src = control_plane.get("evidence_source")
            if isinstance(ev_src, dict):
                if ev_src.get(category) == "operator_supplied" or ev_src.get(field_name) == "operator_supplied":
                    return "operator_supplied"

        # Protocol defaults if not explicitly stamped:
        ike_v = str(control_plane.get("ike_version", "")).lower() if isinstance(control_plane, dict) else ""
        if "1" in ike_v or "ikev1" in ike_v:
            # IKEv1 RFC 2409: Phase 1 proposals are cleartext on wire
            if category in ("ike_version", "key_exchange", "encryption", "integrity"):
                return "observed"
            elif category == "replay_protection":
                return "observed"
            elif category == "mode":
                return "inferred"
            else:
                return "not_observable"
        else:
            # IKEv2 RFC 7296: Only IKE_SA_INIT is cleartext on wire
            if category in ("ike_version", "key_exchange"):
                return "observed"
            elif category == "replay_protection":
                return "observed"
            elif category == "mode":
                return "inferred"
            else:
                return "not_observable"

    def _get_evidence_source(self, category: str, value: Any, control_plane: Optional[dict]) -> str:
        field_name = CATEGORY_TO_FIELD.get(category, category)
        if isinstance(control_plane, dict) and "evidence_source" in control_plane:
            src = control_plane["evidence_source"]
            if isinstance(src, dict):
                if category in src:
                    return src[category]
                if field_name in src:
                    return src[field_name]
            elif isinstance(src, str):
                return src

        obs = self._get_observability(category, control_plane)
        if obs == "operator_supplied":
            return "operator_supplied"

        ike_v = str(control_plane.get("ike_version", "")).lower() if isinstance(control_plane, dict) else ""
        if "1" in ike_v or "ikev1" in ike_v:
            if category in ("ike_version", "key_exchange", "encryption", "integrity"):
                return "ike_v1_cleartext"
            elif category == "replay_protection":
                return "esp_header_metadata"
            elif category == "mode":
                return "traffic_statistics"
            else:
                return "inferred"
        else:
            if category in ("ike_version", "key_exchange"):
                return "ike_sa_init"
            elif category == "replay_protection":
                return "esp_header_metadata"
            elif category == "mode":
                return "traffic_statistics"
            else:
                return "testbed_config"

    def _get_provenance(self, obs: str, ev_src: str) -> str:
        if obs == "operator_supplied":
            return "Operator Sidecar"
        elif obs == "observed":
            return f"Wire Observation ({ev_src})"
        elif obs == "inferred":
            return f"Heuristic Inference ({ev_src})"
        else:
            return "Unobservable on Wire"

    def _evaluate_param(self, category: str, value, findings, control_plane: Optional[dict] = None):
        obs = self._get_observability(category, control_plane)
        ev_src = self._get_evidence_source(category, value, control_plane)
        prov = self._get_provenance(obs, ev_src)

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
                ),
                "category": category.replace("_", " ").title(),
                "observed_value": None,
                "source": "compliance_map.yaml",
                "observability": obs,
                "evidence_source": ev_src,
                "provenance": prov,
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
                "source": "compliance_map.yaml",
                "observability": obs,
                "evidence_source": ev_src,
                "provenance": prov,
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
            finding_copy["observability"] = obs
            finding_copy["evidence_source"] = ev_src
            finding_copy["provenance"] = prov
            findings.append(finding_copy)

        return awarded

    def evaluate_encryption(self, control_plane, findings):
        return self._evaluate_param('encryption', control_plane.get('encryption_algorithm'), findings, control_plane)

    def evaluate_integrity(self, control_plane, findings):
        encryption = control_plane.get("encryption_algorithm")
        integrity = control_plane.get("integrity_algorithm")

        if encryption and "GCM" in encryption.upper():
            integrity = "AEAD"

        return self._evaluate_param("integrity", integrity, findings, control_plane)

    def evaluate_key_exchange(self, control_plane, findings):
        return self._evaluate_param('key_exchange', control_plane.get('dh_group'), findings, control_plane)

    def evaluate_pfs(self, control_plane, findings):
        val = control_plane.get('pfs_enabled')
        if val is not None:
            val = str(val).lower()
        return self._evaluate_param('pfs', val, findings, control_plane)

    def evaluate_replay_protection(self, control_plane, findings):
        val = control_plane.get('replay_protection_enabled')
        if val is not None:
            val = str(val).lower()
        awarded = self._evaluate_param('replay_protection', val, findings, control_plane)
        # Grade by observed ESP sequence evidence: duplicate/replayed sequence numbers reduce the award.
        dp = getattr(self, "_current_data_plane", None) or {}
        total = dp.get("esp_packet_count") or 0
        dupes = dp.get("replay_candidate_count") or 0
        if awarded > 0 and total > 0 and dupes > 0:
            awarded *= max(0.0, 1.0 - min(1.0, 2.0 * dupes / total))
        return awarded

    def evaluate_key_lifetime(self, control_plane, findings):
        lifetime = control_plane.get("key_lifetime_seconds")
        max_seconds = self.rules.get("key_lifetime", {}).get("max_seconds")
        obs = self._get_observability("key_lifetime", control_plane)
        ev_src = self._get_evidence_source("key_lifetime", lifetime, control_plane)
        prov = self._get_provenance(obs, ev_src)

        if lifetime is None or max_seconds is None:
            findings.append({
                "severity": "INFO",
                "finding_id": "UNKNOWN_KEY_LIFETIME",
                "title": "Key Lifetime Could Not Be Assessed",
                "description": "The key lifetime or assessment threshold is unavailable.",
                "category": "Key Lifetime",
                "observed_value": lifetime,
                "source": "compliance_map.yaml",
                "observability": obs,
                "evidence_source": ev_src,
                "provenance": prov,
            })
            return 0.0

        # F-03 fix: reject physically impossible lifetimes (< 60 s) as invalid.
        MIN_SANE_SECONDS = 60
        if lifetime < MIN_SANE_SECONDS:
            findings.append({
                "severity": "MEDIUM",
                "finding_id": "INVALID_KEY_LIFETIME",
                "title": f"Implausible SA Lifetime: {lifetime} seconds",
                "description": (
                    f"The configured key lifetime ({lifetime}s) is below the minimum "
                    f"sane threshold of {MIN_SANE_SECONDS}s. This indicates corrupted, "
                    "adversarial, or mis-configured input data. A score of 0 is awarded "
                    "to avoid falsely inflating the security score."
                ),
                "category": "Key Lifetime",
                "observed_value": lifetime,
                "source": "compliance_map.yaml",
                "observability": obs,
                "evidence_source": ev_src,
                "provenance": prov,
            })
            return 0.0

        val = "valid" if lifetime <= max_seconds else "invalid"
        return self._evaluate_param("key_lifetime", val, findings, control_plane)

    def evaluate_ike_version(self, control_plane, findings):
        return self._evaluate_param('ike_version', control_plane.get('ike_version'), findings, control_plane)

    def evaluate_mode(self, control_plane, findings):
        return self._evaluate_param('mode', control_plane.get('operating_mode'), findings, control_plane)

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
        control_plane = analysis_input.get("control_plane") or {}
        data_plane = analysis_input.get("data_plane") or {}
        self._current_data_plane = data_plane

        h_mode = data_plane.get("heuristic_mode_prediction")
        l_mode = data_plane.get("llm_mode_prediction")
        agreement_flag = (
            h_mode is not None
            and l_mode is not None
            and h_mode == l_mode
        )
        ai_confidence = data_plane.get("ai_confidence_score", 0.0)

        categories = [
            "encryption",
            "integrity",
            "key_exchange",
            "pfs",
            "replay_protection",
            "key_lifetime",
            "ike_version",
            "mode",
        ]

        if not control_plane:
            for cat in categories:
                eval_fn = getattr(self, f"evaluate_{cat}")
                eval_fn(control_plane, findings)

            score_breakdown = {}
            for cat in categories:
                score_breakdown[cat] = {
                    "score": 0.0,
                    "max_score": float(self.weights[cat]),
                    "observability": "not_observable",
                    "evidence_source": "inferred",
                }

            return {
                "score": None,
                "risk_level": "NOT_ASSESSED",
                "score_observed_only": None,
                "score_if_unobserved_fail": None,
                "score_if_unobserved_pass": None,
                "score_headline": "N/A",
                "coverage": "0/8",
                "coverage_ratio": 0.0,
                "confidence_label": "LOW",
                "observed_controls_count": 0,
                "operator_supplied_controls_count": 0,
                "unobserved_controls_count": 8,
                "findings": findings,
                "score_breakdown": score_breakdown,
                "ai_confidence_score": ai_confidence,
                "agreement_flag": agreement_flag,
            }

        raw_scores = {
            "encryption": self.evaluate_encryption(control_plane, findings),
            "integrity": self.evaluate_integrity(control_plane, findings),
            "key_exchange": self.evaluate_key_exchange(control_plane, findings),
            "pfs": self.evaluate_pfs(control_plane, findings),
            "replay_protection": self.evaluate_replay_protection(control_plane, findings),
            "key_lifetime": self.evaluate_key_lifetime(control_plane, findings),
            "ike_version": self.evaluate_ike_version(control_plane, findings),
            "mode": self.evaluate_mode(control_plane, findings),
        }

        score_breakdown = {}
        observed_controls_count = 0
        operator_supplied_controls_count = 0
        unobserved_controls_count = 0
        contradicted_controls_count = 0

        sum_verified_awarded = 0.0
        sum_verified_max = 0.0
        sum_unobserved_max = 0.0

        for cat in categories:
            max_w = float(self.weights.get(cat, 0))
            awarded = float(raw_scores.get(cat, 0.0))
            obs = self._get_observability(cat, control_plane)
            val = control_plane.get(CATEGORY_TO_FIELD.get(cat, cat))
            ev_src = self._get_evidence_source(cat, val, control_plane)

            score_breakdown[cat] = {
                "score": awarded,
                "max_score": max_w,
                "observability": obs,
                "evidence_source": ev_src,
            }

            if obs == "contradicted":
                contradicted_controls_count += 1
                unobserved_controls_count += 1
                sum_unobserved_max += max_w
            elif obs == "observed":
                observed_controls_count += 1
                sum_verified_awarded += awarded
                sum_verified_max += max_w
            elif obs == "operator_supplied":
                operator_supplied_controls_count += 1
                sum_verified_awarded += awarded
                sum_verified_max += max_w
            else:
                unobserved_controls_count += 1
                sum_unobserved_max += max_w

        # Merge sidecar consistency findings if provided in analysis input
        sidecar_consistency = analysis_input.get("sidecar_consistency")
        if sidecar_consistency and isinstance(sidecar_consistency, dict):
            extra_findings = sidecar_consistency.get("findings", [])
            for ef in extra_findings:
                if not any(f.get("finding_id") == ef.get("finding_id") for f in findings):
                    findings.append(ef)
            if sidecar_consistency.get("contradictions_count", 0) > 0:
                contradicted_controls_count += sidecar_consistency.get("contradictions_count", 0)

        total_controls = len(categories)
        total_verified = observed_controls_count + operator_supplied_controls_count
        coverage = f"{total_verified}/{total_controls}"
        coverage_ratio = round(total_verified / float(total_controls), 4)

        if total_verified == total_controls:
            confidence_label = "HIGH"
        elif total_verified >= 4:
            confidence_label = "MEDIUM"
        else:
            confidence_label = "LOW"

        score_observed_only = (
            round((sum_verified_awarded / sum_verified_max) * 100.0, 2)
            if sum_verified_max > 0
            else 0.0
        )
        score_if_unobserved_fail = round(sum_verified_awarded, 2)
        score_if_unobserved_pass = round(sum_verified_awarded + sum_unobserved_max, 2)

        score_observed_only = max(0.0, min(100.0, score_observed_only))
        score_if_unobserved_fail = max(0.0, min(100.0, score_if_unobserved_fail))
        score_if_unobserved_pass = max(0.0, min(100.0, score_if_unobserved_pass))

        def _fmt(v: float) -> str:
            return str(int(v)) if v.is_integer() else f"{v:.1f}"

        cov_pct = int(round(coverage_ratio * 100))
        if score_if_unobserved_fail == score_if_unobserved_pass:
            score_headline = f"{_fmt(score_observed_only)}/100, coverage {coverage}"
        else:
            score_headline = f"{_fmt(score_observed_only)}/100 (based on {coverage} observable checks)"

        primary_score = score_observed_only

        risk_level, cap_reason = compute_risk_level(
            score_observed_only, coverage_ratio, total_verified, findings
        )
        base_risk_for_review = risk_level
        missing_cats = [
            k for k, v in score_breakdown.items()
            if v["observability"] in ("not_observable", "inferred", "contradicted")
        ]

        HUMAN_NAMES = {
            "encryption": "Encryption",
            "integrity": "Integrity",
            "key_exchange": "DH Group",
            "pfs": "PFS",
            "replay_protection": "Replay Protection",
            "key_lifetime": "Key Lifetime",
            "ike_version": "IKE Version",
            "mode": "Operating Mode",
        }

        failing_items = []
        for cat in categories:
            info = score_breakdown.get(cat, {})
            if info.get("observability") in ("observed", "operator_supplied") and info.get("score", 0) < info.get("max_score", 1):
                val = control_plane.get(CATEGORY_TO_FIELD.get(cat, cat))
                if cat == "encryption":
                    failing_items.append(f"{val} encryption" if val else "weak encryption")
                elif cat == "pfs":
                    failing_items.append("no PFS" if not val or str(val).lower() in ("false", "0", "none") else "weak PFS")
                elif cat == "key_exchange":
                    failing_items.append(f"DH group {val}" if val else "weak DH group")
                elif cat == "integrity":
                    failing_items.append(f"{val} integrity" if val else "weak integrity")
                elif cat == "replay_protection":
                    failing_items.append("no replay protection")
                else:
                    failing_items.append(f"suboptimal {cat.replace('_', ' ')}")
        if risk_level == "NOT_ASSESSED":
            risk_review = "NOT ASSESSED: no checks could be observed in this capture."
        else:
            failing_desc = (" and ".join(failing_items[:2]) + " observed") if failing_items else "no weaknesses observed"
            unver = total_controls - total_verified
            risk_review = f"{risk_level}: {failing_desc}; {unver} of {total_controls} checks could not be verified."
            if cap_reason:
                risk_review += f" {cap_reason}"

        return {
            "score": primary_score,
            "risk_level": risk_level,
            "base_risk_level": base_risk_for_review,
            "risk_review": risk_review,
            "score_observed_only": score_observed_only,
            "score_if_unobserved_fail": score_if_unobserved_fail,
            "score_if_unobserved_pass": score_if_unobserved_pass,
            "score_headline": score_headline,
            "coverage": coverage,
            "coverage_ratio": coverage_ratio,
            "confidence_label": confidence_label,
            "observed_controls_count": observed_controls_count,
            "operator_supplied_controls_count": operator_supplied_controls_count,
            "unobserved_controls_count": unobserved_controls_count,
            "findings": findings,
            "score_breakdown": score_breakdown,
            "ai_confidence_score": ai_confidence,
            "agreement_flag": agreement_flag,
        }
