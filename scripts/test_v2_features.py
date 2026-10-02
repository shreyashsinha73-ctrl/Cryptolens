import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import torch
from backend.engine.anomaly.detector import AnomalyDetector
from backend.engine.xai.saliency import grad_cam_1d
from backend.engine.xai.threat_localizer import localize_threats, detect_replay_attacks
from backend.remediation.remediation_engine import RemediationEngine
from backend.streaming.live_sniffer import StreamState, ESPPacketRecord

def test_anomaly_detector():
    d = AnomalyDetector()
    result = d.detect([300, 400, 500, 200, 350] * 6, [0.05, 0.03, 0.04, 0.06, 0.02] * 6)
    print("AnomalyDetector result:", result)

def test_xai():
    tensor = torch.randn(1, 2, 30)
    res = grad_cam_1d(tensor)
    print("Grad-CAM result:", res)
    
def test_threat_localizer():
    records = [
        ESPPacketRecord(0.1, 1, "1.1.1.1", "2.2.2.2", 500, "1234", 1),
        ESPPacketRecord(0.2, 2, "1.1.1.1", "2.2.2.2", 500, "1234", 1) # replay
    ] * 15
    res = localize_threats(records, [])
    replays = detect_replay_attacks(records)
    print("Threat localizer result:", res.get("summary"))
    print("Replay attacks:", len(replays))

def test_remediation():
    engine = RemediationEngine()
    result = engine.generate_remediation(
        findings=[{'severity': 'CRITICAL', 'title': '3DES Deprecated', 'description': 'Sweet32'}],
        control_plane={'encryption_algorithm': '3DES', 'dh_group': 2, 'pfs_enabled': False, 'ike_version': 'IKEv2'}
    )
    print("Remediation engine:", result['engine_used'])

def test_stream_state():
    state = StreamState()
    state.add_esp(ESPPacketRecord(0.1, 1, "1.1.1.1", "2.2.2.2", 500))
    print("StreamState ESP count:", state.total_esp_count)

if __name__ == "__main__":
    test_anomaly_detector()
    test_xai()
    test_threat_localizer()
    test_remediation()
    test_stream_state()
    print("All tests passed.")
