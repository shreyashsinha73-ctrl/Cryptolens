import pytest
from pathlib import Path
from backend.streaming.live_sniffer import ESPPacketRecord
from backend.engine.xai.threat_localizer import localize_threats, _classify_packet_threat


def test_no_modulo_8_check_in_codebase():
    """Verify that the unscientific len % 8 == 0 check is completely removed."""
    backend_dir = Path(__file__).resolve().parent.parent / "backend"
    for py_file in backend_dir.rglob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        assert "% 8 == 0" not in content, f"Unscientific modulo 8 check found in {py_file}"


def test_sweet32_birthday_bound_attribution():
    """Verify that 3DES threat attribution monitors volume against the 32 GiB birthday bound."""
    record = ESPPacketRecord(
        timestamp=100.0,
        frame_number=1,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        packet_length=1024,
        spi="0x12345678",
        seq_num=1,
    )
    findings = [
        {"title": "Deprecated Cipher 3DES-CBC", "description": "SWEET32 collision risk"}
    ]

    # Test with 50 MB volume
    threat_type, desc = _classify_packet_threat(
        record=record,
        findings=findings,
        saliency=0.2,
        spi_volume_bytes=50 * 1024 * 1024,
    )

    assert threat_type == "sweet32_birthday_bound"
    assert "50.00 MB / 32 GiB" in desc
    assert "birthday collision bound" in desc


def test_saliency_semantics_and_relative_attribution():
    """Verify XAI output semantics, relative saliency, and attribution metadata."""
    records = [
        ESPPacketRecord(
            timestamp=100.0 + i * 0.01,
            frame_number=i + 1,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            packet_length=500 + (i * 10),
            spi="0xabcdef01",
            seq_num=i + 1,
        )
        for i in range(10)
    ]
    findings = []

    res = localize_threats(records, findings, xai_method="grad_cam", target_head="mode")

    assert "relative_saliency" in res
    assert "raw_max_attribution" in res
    assert "predicted_class" in res
    assert "predicted_confidence" in res
    assert "xai_semantics" in res
    assert "Grad-CAM explains 1D-CNN traffic/mode classification" in res["xai_semantics"]
    assert "not cryptographic weaknesses" in res["xai_semantics"]

    for pkt in res["threat_packets"]:
        assert "relative_saliency" in pkt
        assert "saliency_score" in pkt
        if pkt["relative_saliency"] > 0.5:
            assert pkt["threat_type"] == "high_cnn_influence"


@pytest.mark.asyncio
async def test_xai_route_target_head():
    """Test get_threat_localization with target_head parameter."""
    from backend.routes.xai import get_threat_localization
    from backend.services.result_store import ResultStore

    store = ResultStore()
    job_id = "test_xai_job_p1_5"
    store.save(job_id, {
        "data_plane": {
            "esp_records": [
                {
                    "timestamp": 100.0 + i * 0.01,
                    "frame_number": i + 1,
                    "src_ip": "10.0.0.1",
                    "dst_ip": "10.0.0.2",
                    "packet_length": 600,
                    "spi": "0x11223344",
                    "seq_num": i + 1,
                }
                for i in range(8)
            ]
        },
        "findings": [],
    })

    try:
        response_mode = await get_threat_localization(job_id, method="grad_cam", target_head="mode")
        assert "xai" in response_mode
        assert "relative_saliency" in response_mode["xai"]

        response_traffic = await get_threat_localization(job_id, method="grad_cam", target_head="traffic")
        assert "xai" in response_traffic
        assert "relative_saliency" in response_traffic["xai"]
    finally:
        # Cleanup test store file
        store.delete(job_id)
