import os
import tempfile
from pathlib import Path
import pytest

from backend.engine.control_plane.ike_parser import IkeParser
from backend.engine.data_plane.traffic_analyzer import analyze_data_plane
from backend.services.analyzer_provider import get_analyzer_provider
from backend.scoring.scoring_engine import ScoringEngine
from backend.scoring.compliance_engine import ComplianceEngine
from backend.engine.xai.threat_localizer import localize_threats, detect_replay_attacks
from backend.routes.xai import _extract_esp_records_from_pcap
from backend.remediation.remediation_engine import RemediationEngine, validate_swanctl_syntax
from backend.reporting.generate_pdf import generate_pdf


def test_end_to_end_pipeline_pcap_score_xai_remediation_pdf():
    """
    Validate the complete end-to-end flow:
    Upload PCAP -> Score -> XAI -> Remediation -> PDF
    """
    pcap_path = Path("captures/config_01_tunnel_aes256gcm_dh19_pfson_all.pcap")
    assert pcap_path.exists(), f"Ground-truth capture {pcap_path} not found"

    # Step 1: Ingest PCAP & Parse Control-Plane + Data-Plane
    provider = get_analyzer_provider()
    analysis_input = provider.get_analysis(str(pcap_path))

    assert "control_plane" in analysis_input
    assert "data_plane" in analysis_input
    cp = analysis_input["control_plane"]
    assert cp.get("ike_version") in ("IKEv1", "IKEv2")

    # Step 2: Security & Compliance Scoring
    scorer = ScoringEngine()
    score_res = scorer.evaluate(analysis_input)
    assert "score" in score_res
    assert 0 <= score_res["score"] <= 100
    assert "findings" in score_res

    # Check evidence provenance
    for f in score_res["findings"]:
        assert "evidence_source" in f

    compliance = ComplianceEngine()
    comp_res = compliance.evaluate(analysis_input)
    assert "standards" in comp_res

    # Step 3: XAI Threat Localization & Grad-CAM Saliency
    esp_records = _extract_esp_records_from_pcap(str(pcap_path))
    assert len(esp_records) >= 30

    xai_res = localize_threats(
        esp_records=esp_records[:30],
        findings=score_res["findings"],
        xai_method="grad_cam",
        target_head="mode",
    )
    assert "relative_saliency" in xai_res
    assert len(xai_res["relative_saliency"]) == 30
    assert "xai_semantics" in xai_res
    assert "Grad-CAM explains 1D-CNN" in xai_res["xai_semantics"]

    # RFC 4303 anti-replay verification
    replays = detect_replay_attacks(esp_records, window_size=64)
    xai_res["replay_attacks"] = replays

    # Step 4: AI Configuration Remediation
    remediation_engine = RemediationEngine()
    remediation_res = remediation_engine.generate_remediation(
        findings=score_res["findings"],
        control_plane=cp,
    )
    assert remediation_res["authoritative_target"] == "swanctl_conf"
    assert remediation_res["engine_used"] in ("deterministic_template", "gemini", "ollama")
    is_valid, err = validate_swanctl_syntax(remediation_res["swanctl_conf"])
    assert is_valid, f"Remediation generated invalid swanctl syntax: {err}"

    # Step 5: PDF Generation (Executive & Technical)
    full_result = {
        "job_id": "test_e2e_job",
        "status": "completed",
        "control_plane": cp,
        "data_plane": analysis_input["data_plane"],
        "scoring": score_res,
        "threat_matrix": score_res["findings"],
        "compliance": comp_res,
        "xai": xai_res,
        "remediation": remediation_res,
        "summary": {
            "processed_packets": len(esp_records),
            "ike_packets": 4,
            "esp_packets": len(esp_records),
            "total_bytes": sum(r.packet_length for r in esp_records),
            "ai_confidence_score": analysis_input["data_plane"].get("ai_confidence_score", 0.9),
            "agreement_flag": True,
        }
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        exec_pdf = Path(tmpdir) / "test_exec.pdf"
        tech_pdf = Path(tmpdir) / "test_tech.pdf"

        # Generate Executive PDF
        out_exec = generate_pdf(full_result, output_path=exec_pdf, report_type="executive")
        assert Path(out_exec).exists()
        assert Path(out_exec).stat().st_size > 2000
        with open(out_exec, "rb") as f:
            header = f.read(5)
            assert header == b"%PDF-", "Generated file is not a valid PDF"

        # Generate Technical PDF
        out_tech = generate_pdf(full_result, output_path=tech_pdf, report_type="technical")
        assert Path(out_tech).exists()
        assert Path(out_tech).stat().st_size > 2000
        with open(out_tech, "rb") as f:
            header = f.read(5)
            assert header == b"%PDF-", "Generated file is not a valid PDF"
