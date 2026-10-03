import pytest
from pathlib import Path

from backend.scoring.sidecar_consistency import check_sidecar_consistency
from backend.services.analyzer_provider import AnalyzerProvider
from backend.schemas.sidecar import IPsecSidecarConfig

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CAPTURES_DIR = PROJECT_ROOT / "captures"


def test_honest_sidecars_on_all_six_pcaps():
    """
    Test 3.3: Verify honest sidecars across all 6 baseline captures.
    Checks must return consistent (or inconclusive on short rekey), NEVER contradicts.
    """
    truth = [
        ("config_01_tunnel_aes256gcm_dh19_pfson_all.pcap", {"encryption_algorithm": "AES-256-GCM", "dh_group": 19, "ike_version": "IKEv2", "key_lifetime_seconds": 28800}),
        ("config_02_tunnel_aes128gcm_dh14_pfson_all.pcap", {"encryption_algorithm": "AES-128-GCM", "dh_group": 14, "ike_version": "IKEv2", "key_lifetime_seconds": 28800}),
        ("config_03_tunnel_aes256cbc_sha256_dh14_pfson_all.pcap", {"encryption_algorithm": "AES-256-CBC", "integrity_algorithm": "HMAC-SHA2-256", "dh_group": 14, "ike_version": "IKEv2", "key_lifetime_seconds": 28800}),
        ("config_04_transport_aes128cbc_sha1_dh5_pfsoff_all.pcap", {"encryption_algorithm": "AES-128-CBC", "integrity_algorithm": "HMAC-SHA1-96", "dh_group": 5, "ike_version": "IKEv2", "key_lifetime_seconds": 28800}),
        ("config_05_transport_3des_sha1_dh2_pfsoff_all.pcap", {"encryption_algorithm": "3DES", "integrity_algorithm": "HMAC-SHA1-96", "dh_group": 2, "ike_version": "IKEv2", "key_lifetime_seconds": 28800}),
        ("config_06_tunnel_3des_sha1_dh2_pfsoff_all.pcap", {"encryption_algorithm": "3DES", "integrity_algorithm": "HMAC-SHA1-96", "dh_group": 2, "ike_version": "IKEv2", "key_lifetime_seconds": 28800}),
    ]

    provider = AnalyzerProvider(mode="real")

    for filename, sidecar_dict in truth:
        pcap_path = CAPTURES_DIR / filename
        assert pcap_path.exists(), f"Missing PCAP {filename}"

        analysis = provider.get_analysis(str(pcap_path), sidecar_config=sidecar_dict)
        report = check_sidecar_consistency(
            str(pcap_path),
            analysis.get("control_plane"),
            sidecar_dict,
        )

        assert report.contradictions_count == 0, (
            f"Honest sidecar for {filename} produced contradiction: {report.checks}"
        )
        assert report.overall_status in ("consistent", "inconclusive")


def test_lying_sidecar_on_config_06_triggers_contradicts():
    """
    Test 3.3(1): Lying sidecar asserting AES-256-GCM / DH 20 / IKEv2 on config_06 (3DES / DH 2).
    Must strictly return 'contradicts', record HIGH findings, and flag contradicted fields.
    """
    pcap_path = CAPTURES_DIR / "config_06_tunnel_3des_sha1_dh2_pfsoff_all.pcap"
    assert pcap_path.exists()

    lying_sidecar = {
        "ike_version": "IKEv2",
        "encryption_algorithm": "AES-256-GCM",
        "dh_group": 20,
        "pfs_enabled": True,
        "key_lifetime_seconds": 28800,
    }

    provider = AnalyzerProvider(mode="real")
    analysis = provider.get_analysis(str(pcap_path), sidecar_config=lying_sidecar)

    report = check_sidecar_consistency(
        str(pcap_path),
        analysis.get("control_plane"),
        lying_sidecar,
    )

    assert report.overall_status == "contradicts"
    assert report.contradictions_count >= 1

    contradicted_fields = [c.target_field for c in report.checks if c.status == "contradicts"]
    assert "dh_group" in contradicted_fields, f"Expected dh_group contradiction, got: {contradicted_fields}"

    # Verify that finding is generated with HIGH severity
    assert any(f.get("severity") == "HIGH" for f in report.findings)
    assert any("CONTRADICTED" in f.get("finding_id", "") for f in report.findings)


def test_short_capture_esp_alignment_inconclusive(tmp_path):
    """
    Test 3.3(3): A capture with < 20 ESP packets must return 'inconclusive' for length alignment.
    """
    from scapy.all import wrpcap, Ether, IP, ESP, Raw

    # Craft 5 synthetic ESP packets (< 20)
    pkts = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ESP(spi=0x12345678, seq=i) / Raw(b"A" * 64)
        for i in range(1, 6)
    ]
    pcap_file = tmp_path / "test_short.pcap"
    wrpcap(str(pcap_file), pkts)

    sidecar = {"encryption_algorithm": "AES-256-GCM"}
    report = check_sidecar_consistency(str(pcap_file), {}, sidecar)

    alignment_check = next((c for c in report.checks if c.check_name == "ESP Length Alignment"), None)
    assert alignment_check is not None
    assert alignment_check.status == "inconclusive"
    assert report.contradictions_count == 0
