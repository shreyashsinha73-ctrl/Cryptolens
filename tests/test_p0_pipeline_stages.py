import struct
import pytest

from backend.streaming.live_sniffer import StreamState, IKEPacketRecord, ESPPacketRecord
from backend.engine.control_plane.ike_parser import parse_ike_bytes
from backend.scoring.scoring_engine import ScoringEngine
from backend.engine.anomaly.detector import AnomalyDetector


def test_ike_queue_bounded_and_drainable():
    """Verify ike_queue is bounded to 1000 items and drains cleanly."""
    state = StreamState()
    assert state.ike_queue.maxlen == 1000

    # Add 1200 packets
    for i in range(1200):
        state.add_ike(IKEPacketRecord(
            timestamp=float(i),
            frame_number=i,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=500,
            dst_port=500,
            raw_bytes=b"dummy",
        ))

    # Should be bounded to 1000
    assert len(state.ike_queue) == 1000
    assert state.total_ike_count == 1200

    # Drain queue
    drained = state.drain_ike_queue()
    assert len(drained) == 1000
    assert len(state.ike_queue) == 0


def test_parse_ike_bytes_and_dynamic_scoring():
    """Verify parsing raw IKEv2 payload and evaluating real security score."""
    # Synthetic minimal IKEv2 header (28 bytes)
    # init_spi (8B), resp_spi (8B), next_payload=33 (SA), version=0x20 (IKEv2), exchange=34, flags=0x08, msg_id=0, total_len=28
    ike_hdr = struct.pack("!8s8sBBBBII", b"\x01" * 8, b"\x02" * 8, 33, 0x20, 34, 0x08, 0, 28)
    cp = parse_ike_bytes(ike_hdr)
    assert cp is not None
    assert cp["ike_version"] == "IKEv2"

    scorer = ScoringEngine()
    analysis_input = {
        "control_plane": cp,
        "data_plane": {
            "heuristic_mode_prediction": "tunnel",
            "llm_mode_prediction": "tunnel",
            "ai_confidence_score": 0.95,
            "detected_traffic": [{"traffic_type": "https", "packet_count": 50}],
        },
    }
    eval_res = scorer.evaluate(analysis_input)
    assert eval_res["score"] is not None
    assert eval_res["score"] > 0
    assert eval_res["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "UNVERIFIED")
