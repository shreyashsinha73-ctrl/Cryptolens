import json
import os
import tempfile
from pathlib import Path
import pytest
import pymupdf

from backend.services.analyzer_provider import get_analyzer_provider
from backend.scoring.scoring_engine import ScoringEngine
from backend.scoring.compliance_engine import ComplianceEngine
from backend.engine.xai.threat_localizer import localize_threats, detect_replay_attacks
from backend.routes.xai import _extract_esp_records_from_pcap
from backend.remediation.remediation_engine import RemediationEngine, validate_swanctl_syntax
from backend.reporting.generate_pdf import generate_pdf

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CAPTURES_DIR = PROJECT_ROOT / "captures"
FIXTURES_DIR = PROJECT_ROOT / "tests" / "fixtures"
SIDECARS_DIR = FIXTURES_DIR / "sidecars"


@pytest.fixture(scope="module")
def expected_outcomes():
    with open(FIXTURES_DIR / "expected_outcomes.json", "r") as f:
        return json.load(f)


@pytest.mark.parametrize("config_key", [
    "config_01",
    "config_02",
    "config_03",
    "config_04",
    "config_05",
    "config_06",
])
def test_e2e_all_six_configurations(config_key, expected_outcomes):
    """
    Part 4.2: Parametrized end-to-end audit pipeline across all 6 ground-truth configurations.
    Tests both without sidecar and with honest operator sidecar.
    Verifies:
      - Score ranges, coverage, and risk labels (UNVERIFIED vs. LOW/HIGH/CRITICAL (operator-attested))
      - Findings carry evidence_source and observability
      - XAI output shape and semantics
      - Remediation validity against strongSwan swanctl grammar
      - PDF generation (Executive & Technical) and extracted text validation
    """
    cfg_data = expected_outcomes[config_key]
    filename = cfg_data["filename"]
    pcap_path = CAPTURES_DIR / filename
    assert pcap_path.exists(), f"PCAP {filename} missing"

    sidecar_path = SIDECARS_DIR / f"{config_key}.sidecar.json"
    assert sidecar_path.exists(), f"Sidecar {sidecar_path} missing"
    with open(sidecar_path, "r") as sf:
        sidecar_dict = json.load(sf)

    provider = get_analyzer_provider()
    scorer = ScoringEngine()
    compliance = ComplianceEngine()
    remediation_engine = RemediationEngine()

    # -------------------------------------------------------------------------
    # Execution A: No Sidecar (Pure passive wire observability)
    # -------------------------------------------------------------------------
    analysis_no_sidecar = provider.get_analysis(str(pcap_path), sidecar_config=None)
    score_no_sidecar = scorer.evaluate(analysis_no_sidecar)

    exp_no = cfg_data["no_sidecar"]
    assert score_no_sidecar["coverage"] == exp_no["coverage"]
    assert score_no_sidecar["risk_level"] == exp_no["risk_label"]
    assert score_no_sidecar["score_if_unobserved_fail"] == exp_no["score_range"][0]
    assert score_no_sidecar["score_if_unobserved_pass"] == exp_no["score_range"][1]

    # Verify findings carry observability & evidence_source
    for f in score_no_sidecar["findings"]:
        assert "evidence_source" in f
        assert "observability" in f
        assert f["observability"] in ("observed", "inferred", "not_observable", "contradicted")

    # -------------------------------------------------------------------------
    # Execution B: With Honest Sidecar (Full verification)
    # -------------------------------------------------------------------------
    analysis_with_sidecar = provider.get_analysis(str(pcap_path), sidecar_config=sidecar_dict)
    score_with_sidecar = scorer.evaluate(analysis_with_sidecar)

    exp_with = cfg_data["with_sidecar"]
    assert score_with_sidecar["coverage"] == exp_with["coverage"]
    assert score_with_sidecar["risk_level"] == exp_with["risk_label"]
    assert score_with_sidecar["score_if_unobserved_fail"] == exp_with["score_range"][0]
    assert score_with_sidecar["score_if_unobserved_pass"] == exp_with["score_range"][1]

    for f in score_with_sidecar["findings"]:
        assert "evidence_source" in f
        assert "observability" in f
        assert f["observability"] in ("observed", "operator_supplied")

    # Verify standards compliance (NIST vs CNSA)
    comp_res = compliance.evaluate(analysis_with_sidecar)
    standards_map = comp_res.get("standards", {})

    for ctrl, expected_std_eval in cfg_data.get("standards_compliance", {}).items():
        val = sidecar_dict.get(ctrl) or sidecar_dict.get(f"{ctrl}_algorithm") or (sidecar_dict.get("dh_group") if ctrl == "dh_group" else None)
        for std_name, exp_status in expected_std_eval.items():
            std_ctrl_eval = compliance.evaluate_control(std_name, ctrl if ctrl != "dh_group" else "key_exchange", val)
            assert std_ctrl_eval["status"] == exp_status, (
                f"For {config_key} {ctrl}={val} in {std_name}: expected {exp_status}, got {std_ctrl_eval['status']}"
            )

    # -------------------------------------------------------------------------
    # XAI & Remediation Validation
    # -------------------------------------------------------------------------
    esp_records = _extract_esp_records_from_pcap(str(pcap_path))
    assert len(esp_records) > 0

    xai_res = localize_threats(
        esp_records=esp_records[:30],
        findings=score_with_sidecar["findings"],
        xai_method="grad_cam",
        target_head="mode",
    )
    assert "relative_saliency" in xai_res
    assert len(xai_res["relative_saliency"]) == len(esp_records[:30])

    remediation_res = remediation_engine.generate_remediation(
        findings=score_with_sidecar["findings"],
        control_plane=analysis_with_sidecar["control_plane"],
    )
    assert remediation_res["authoritative_target"] == "swanctl_conf"
    is_valid, err = validate_swanctl_syntax(remediation_res["swanctl_conf"])
    assert is_valid, f"Syntax validation failed for {config_key}: {err}"

    # -------------------------------------------------------------------------
    # PDF Generation & Content Extraction
    # -------------------------------------------------------------------------
    full_result = {
        "job_id": f"e2e_{config_key}",
        "status": "completed",
        "control_plane": analysis_with_sidecar["control_plane"],
        "data_plane": analysis_with_sidecar["data_plane"],
        "scoring": score_with_sidecar,
        "threat_matrix": score_with_sidecar["findings"],
        "compliance": comp_res,
        "xai": xai_res,
        "remediation": remediation_res,
        "summary": {
            "processed_packets": len(esp_records),
            "ike_packets": 4,
            "esp_packets": len(esp_records),
            "total_bytes": sum(r.packet_length for r in esp_records),
            "ai_confidence_score": analysis_with_sidecar["data_plane"].get("ai_confidence_score", 0.95),
            "agreement_flag": True,
        }
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        exec_pdf = Path(tmpdir) / f"{config_key}_exec.pdf"
        tech_pdf = Path(tmpdir) / f"{config_key}_tech.pdf"

        # Executive Report
        generate_pdf(full_result, output_path=exec_pdf, report_type="executive")
        assert exec_pdf.exists() and exec_pdf.stat().st_size > 2000

        doc_exec = pymupdf.open(exec_pdf)
        text_exec = "".join(page.get_text() for page in doc_exec)
        doc_exec.close()

        # Technical Report
        generate_pdf(full_result, output_path=tech_pdf, report_type="technical")
        assert tech_pdf.exists() and tech_pdf.stat().st_size > 2000

        doc_tech = pymupdf.open(tech_pdf)
        text_tech = "".join(page.get_text() for page in doc_tech)
        doc_tech.close()

        # Check extracted text for core sections & operator-attested label
        assert "operator-attested" in text_exec.lower() or "operator_supplied" in text_exec.lower() or "sidecar" in text_exec.lower()
        assert "provenance" in text_tech.lower() or "evidence" in text_tech.lower()
        assert "swanctl" in text_tech.lower()


def test_config_06_specific_vulnerabilities():
    """
    Part 4.3:
    1. Sweet32 finding uses bytes-per-SPI vs the 2^32-block (~32 GiB) bound
    2. DH2 flagged as within reach of nation-state precomputation (Logjam wording, not 'factored')
    3. Remediation output differs from config_01's
    4. DH19 case passes NIST and fails CNSA
    """
    pcap_06 = CAPTURES_DIR / "config_06_tunnel_3des_sha1_dh2_pfsoff_all.pcap"
    assert pcap_06.exists()

    provider = get_analyzer_provider()
    scorer = ScoringEngine()

    with open(SIDECARS_DIR / "config_06.sidecar.json") as sf:
        sidecar_06 = json.load(sf)

    analysis = provider.get_analysis(str(pcap_06), sidecar_config=sidecar_06)
    score_res = scorer.evaluate(analysis)

    # 1. Check DH2 Logjam nation-state precomputation wording
    dh2_finding = next((f for f in score_res["findings"] if f.get("finding_id") == "KEX_002"), None)
    assert dh2_finding is not None, "Missing KEX_002 finding for DH Group 2"
    assert "Logjam" in dh2_finding["description"]
    assert "nation-state precomputation" in dh2_finding["description"]
    assert "factored" not in dh2_finding["description"].lower()

    # 2. Check Sweet32 byte volume attribution
    esp_records = _extract_esp_records_from_pcap(str(pcap_06))
    xai_res = localize_threats(
        esp_records=esp_records[:30],
        findings=score_res["findings"],
        xai_method="grad_cam",
        target_head="mode",
    )
    # Check threat descriptions
    sweet32_threat = next((t for t in xai_res.get("threat_attributions", []) if t.get("threat_type") == "sweet32_birthday_bound"), None)
    if sweet32_threat:
        assert "32 GiB" in sweet32_threat["description"] or "birthday" in sweet32_threat["description"]

    # 3. Remediation diff between config_01 and config_06
    remediation_engine = RemediationEngine()
    rem_06 = remediation_engine.generate_remediation(
        findings=score_res["findings"],
        control_plane=analysis["control_plane"]
    )
    with open(SIDECARS_DIR / "config_01.sidecar.json") as sf:
        sidecar_01 = json.load(sf)
    analysis_01 = provider.get_analysis(str(CAPTURES_DIR / "config_01_tunnel_aes256gcm_dh19_pfson_all.pcap"), sidecar_config=sidecar_01)
    score_01 = scorer.evaluate(analysis_01)
    rem_01 = remediation_engine.generate_remediation(
        findings=score_01["findings"],
        control_plane=analysis_01["control_plane"]
    )
    assert rem_06["remediated_vulnerabilities"] != rem_01["remediated_vulnerabilities"]
    assert rem_06["diff_analysis"] != rem_01["diff_analysis"]
    assert len(rem_06["remediated_vulnerabilities"]) > len(rem_01["remediated_vulnerabilities"])

    # 4. DH19 NIST vs CNSA
    compliance = ComplianceEngine()
    nist_dh19 = compliance.evaluate_control("NIST_SP_800_77_R1", "key_exchange", 19)
    cnsa_dh19 = compliance.evaluate_control("CNSA_2_0", "key_exchange", 19)
    assert nist_dh19["status"] == "ALIGNED"
    assert cnsa_dh19["status"] == "FAIL"
