from backend.engine.control_plane.ike_parser import parse_pcap
from backend.engine.data_plane.traffic_analyzer import analyze_data_plane
from backend.schemas.analysis import ControlPlaneData, DataPlaneData

class AnalyzerProvider:
    def analyze(self, pcap_path: str):
        # Phase 3: Control-Plane
        control_plane_raw = parse_pcap(pcap_path)
        
        # Phase 4: Data-Plane
        data_plane_raw = analyze_data_plane(pcap_path)

        return {
            "control_plane": ControlPlaneData(**control_plane_raw).dict(),
            "data_plane": DataPlaneData(**data_plane_raw).dict()
        }
