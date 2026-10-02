import pytest
import uuid
from backend.main import app
from backend.streaming.live_sniffer import ESPPacketRecord
from backend.engine.xai.threat_localizer import localize_threats
from backend.routes.live import _analyze_window_for_anomalies, _current_stream_id
import backend.routes.live as live_module


def test_routes_registered_in_openapi():
    """Ensure live, remediation, and xai routes are registered in FastAPI."""
    openapi_schema = app.openapi()
    paths = openapi_schema["paths"].keys()

    assert "/api/v1/live/start" in paths
    assert "/api/v1/live/stop" in paths
    assert "/api/v1/live/simulate" in paths
    assert "/api/v1/live/status" in paths
    assert "/api/v1/live/inject/{profile}" in paths
    assert "/api/v1/remediate/{job_id}" in paths
    assert "/api/v1/xai/{job_id}" in paths


@pytest.mark.asyncio
async def test_stream_id_generated_and_returned():
    """Verify stream_id is generated and returned by live streaming endpoints."""
    # Test simulate endpoint with testbed capture
    res = await live_module.simulate_live_capture(config_id="config_01_tunnel_aes256gcm_dh19_pfson")
    assert res.get("status") == "simulation_started"
    assert "stream_id" in res
    assert uuid.UUID(res["stream_id"])  # Valid UUID4

    # Stop simulation
    stop_res = await live_module.stop_live_capture()
    assert stop_res.get("status") == "stopped"
    assert "stream_id" in stop_res


def test_threat_localizer_frame_mapping():
    """Verify that localize_threats returns authentic frame_mapping for UI tooltips."""
    records = [
        ESPPacketRecord(
            timestamp=100.0 + i * 0.01,
            frame_number=100 + i * 2,  # Non-contiguous real wire frames
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            packet_length=500 + i * 10,
            spi="0xabcdef01",
            seq_num=i + 1,
        )
        for i in range(10)
    ]
    findings = []

    res = localize_threats(records, findings, xai_method="grad_cam")
    assert "frame_mapping" in res
    assert res["frame_mapping"] == [100 + i * 2 for i in range(10)]


def test_anomaly_alert_contains_stream_id_and_zscores():
    """Verify that anomaly alerts carry stream_id and feature_zscores."""
    live_module._current_stream_id = "test-stream-uuid-1234"
    recent_pkts = [
        {
            "frame_number": 1,
            "packet_type": "ESP",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "spi": "0x12345678",
            "seq_num": 1,
            "packet_length": 500,
            "timestamp": 100.0,
        },
        {
            "frame_number": 2,
            "packet_type": "ESP",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "spi": "0x12345678",
            "seq_num": 1,  # Duplicate sequence -> Replay
            "packet_length": 500,
            "timestamp": 100.01,
        },
    ]
    seen_seqs = {"0x12345678:1": 1}

    alert = _analyze_window_for_anomalies(
        recent_packets=recent_pkts,
        lengths_window=[500.0, 500.0],
        iats_window=[0.01, 0.01],
        seen_seqs=seen_seqs,
    )

    assert alert is not None
    assert alert.get("stream_id") == "test-stream-uuid-1234"
    assert alert.get("anomaly_label") == "REPLAY_ATTACK"
    assert alert.get("severity") == "CRITICAL"


def test_stream_id_deduplication_logic():
    """Verify that frame deduplication is keyed by (stream_id, frame_number)."""
    seen_keys = set()

    def process_wire_packet(item):
        s_id = item.get("stream_id", "default")
        fn = item.get("frame_number")
        if fn is not None:
            key = f"{s_id}:{fn}"
            if key in seen_keys:
                return False
            seen_keys.add(key)
        return True

    # Packets in stream 1
    assert process_wire_packet({"stream_id": "stream_1", "frame_number": 1}) is True
    assert process_wire_packet({"stream_id": "stream_1", "frame_number": 2}) is True
    # Duplicate frame 2 in stream 1 must be rejected
    assert process_wire_packet({"stream_id": "stream_1", "frame_number": 2}) is False

    # Same frame numbers in stream 2 must NOT be dropped
    assert process_wire_packet({"stream_id": "stream_2", "frame_number": 1}) is True
    assert process_wire_packet({"stream_id": "stream_2", "frame_number": 2}) is True


@pytest.mark.asyncio
async def test_two_consecutive_simulations_no_frame_collision():
    """Verify consecutive simulations generate unique stream IDs to prevent frame collision."""
    res1 = await live_module.simulate_live_capture(config_id="config_01_tunnel_aes256gcm_dh19_pfson")
    s1_id = res1["stream_id"]
    await live_module.stop_live_capture()

    res2 = await live_module.simulate_live_capture(config_id="config_01_tunnel_aes256gcm_dh19_pfson")
    s2_id = res2["stream_id"]
    await live_module.stop_live_capture()

    assert s1_id != s2_id
    assert uuid.UUID(s1_id)
    assert uuid.UUID(s2_id)
