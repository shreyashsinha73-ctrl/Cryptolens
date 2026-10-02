import pytest
from unittest.mock import patch, MagicMock

from backend.scoring.scoring_engine import ScoringEngine
from backend.scoring.compliance_engine import ComplianceEngine
from backend.engine.control_plane.rules_engine import RulesEngine
from backend.engine.data_plane.traffic_analyzer import analyze_data_plane


VALID_SOURCES = {
    "ike_sa_init",
    "ike_v1_cleartext",
    "esp_header_metadata",
    "traffic_statistics",
    "testbed_config",
    "operator_supplied",
    "inferred",
    "cleartext_on_wire",
}


def test_evidence_source_on_all_scoring_findings():
    """Verify that every finding from ScoringEngine has evidence_source."""
    engine = ScoringEngine()

    analysis_input = {
        "control_plane": {
            "ike_version": "IKEv2",
            "encryption_algorithm": "3DES",
            "integrity_algorithm": "HMAC-MD5",
            "dh_group": 2,
            "pfs_enabled": False,
            "replay_protection_enabled": True,
            "key_lifetime_seconds": 3600,
            "operating_mode": "Tunnel",
        },
        "data_plane": {
            "heuristic_mode_prediction": "tunnel",
            "llm_mode_prediction": "tunnel",
            "ai_confidence_score": 0.95,
        }
    }

    res = engine.evaluate(analysis_input)
    findings = res["findings"]
    assert len(findings) > 0

    for finding in findings:
        assert "evidence_source" in finding, f"Finding {finding.get('finding_id')} lacks evidence_source"
        assert finding["evidence_source"] in VALID_SOURCES, f"Invalid evidence_source {finding['evidence_source']}"

    # Verify that Child SA cipher/PFS under IKEv2 is labeled testbed_config (since it's encrypted on wire)
    enc_findings = [f for f in findings if f.get("category") == "Encryption"]
    if enc_findings:
        assert enc_findings[0]["evidence_source"] == "testbed_config"


def test_evidence_source_on_rules_engine_threats():
    """Verify that RulesEngine outputs evidence_source on all threat_matrix items."""
    engine = RulesEngine(target_standard="nist")
    control_plane = {
        "ike_version": "IKEv1",
        "encryption_algorithm": "3DES-CBC",
        "integrity_algorithm": "HMAC-MD5",
        "dh_group": 2,
        "pfs_enabled": False,
        "replay_protection_enabled": False,
        "key_lifetime_seconds": 30,  # Implausible
    }

    res = engine.evaluate(control_plane)
    threats = res["threat_matrix"]
    assert len(threats) > 0

    for threat in threats:
        assert "evidence_source" in threat, f"Threat {threat['id']} lacks evidence_source"
        assert threat["evidence_source"] in VALID_SOURCES


def test_compliance_profiles_dh19_nist_vs_cnsa():
    """Verify DH 19 (P-256) passes NIST SP 800-77r1 (ALIGNED) but fails CNSA (FAIL)."""
    compliance = ComplianceEngine()

    # NIST evaluation
    nist_res = compliance.evaluate_control("NIST_SP_800_77_R1", "key_exchange", 19)
    assert nist_res["status"] == "ALIGNED", f"NIST key_exchange 19 status was {nist_res['status']}, expected ALIGNED"

    # CNSA evaluation
    cnsa_res = compliance.evaluate_control("CNSA_2_0", "key_exchange", 19)
    assert cnsa_res["status"] == "FAIL", f"CNSA key_exchange 19 status was {cnsa_res['status']}, expected FAIL"

    # DH 20 (P-384) passes both
    nist_dh20 = compliance.evaluate_control("NIST_SP_800_77_R1", "key_exchange", 20)
    cnsa_dh20 = compliance.evaluate_control("CNSA_2_0", "key_exchange", 20)
    assert nist_dh20["status"] == "ALIGNED"
    assert cnsa_dh20["status"] == "ALIGNED"


def test_dpi_field_dissection_and_zero_byte_fix(tmp_path):
    """
    Test field-based dissection and assert that comma-separated frame lengths
    (from packet reassembly) do NOT produce 0-byte frames.
    """
    dummy_pcap = tmp_path / "test.pcap"
    dummy_pcap.write_bytes(b"dummy")

    # Simulate tshark output containing:
    # Line 1: Reassembled packet with comma-separated lengths: "1420,1420"
    # Line 2: Cleartext DNS packet: dns.flags.response=1
    # Line 3: Cleartext ICMP packet: icmp.type=8
    # Line 4: ESP packet: ip.proto=50
    mock_tshark_stdout = (
        "1420,1420\tTCP\t6\t\t\t100.0\t\t\t\t\t\t\n"
        "68\tDNS\t17\t\t\t101.0\t\t\t1\t\t\t\n"
        "84\tICMP\t1\t\t\t102.0\t8\t\t\t\t\t\n"
        "500\tESP\t50\t\t0x12345678\t103.0\t\t\t\t\t\t\n"
    )

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = mock_tshark_stdout
    mock_proc.stderr = ""

    with patch("backend.engine.data_plane.traffic_analyzer.validate_pcap"):
        with patch("subprocess.run", return_value=mock_proc):
            with patch("backend.engine.data_plane.traffic_analyzer.infer_with_fallback", return_value=None):
                res = analyze_data_plane(dummy_pcap)

    detected = res["detected_traffic"]
    assert len(detected) > 0

    # Ensure none of the average packet sizes are 0
    for entry in detected:
        assert entry["avg_packet_size_bytes"] > 0, f"Detected 0-byte frame in {entry}"
        assert "visibility" in entry
        assert "evidence_source" in entry
