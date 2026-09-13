def analyze_data_plane(pcap_path: str) -> dict:
    """
    Phase 4: The Data-Plane Analyzer.
    Simulates Deep Packet Inspection (DPI) to return a deterministic traffic breakdown.
    """
    heuristic_mode = "Tunnel"
    llm_mode = "Tunnel"

    # We do NOT return agreement_flag or ai_confidence_score here because 
    # they are not part of the DataPlaneData schema. The ScoringEngine 
    # computes them based on these returned predictions.

    return {
        "detected_traffic": [
            {
                "traffic_type": "VoIP",
                "percentage": 65.0,
                "packet_count": 5000,
                "avg_packet_size_bytes": 200
            },
            {
                "traffic_type": "Video Streaming",
                "percentage": 25.0,
                "packet_count": 1500,
                "avg_packet_size_bytes": 1200
            },
            {
                "traffic_type": "Messaging",
                "percentage": 10.0,
                "packet_count": 500,
                "avg_packet_size_bytes": 150
            }
        ],
        "heuristic_mode_prediction": heuristic_mode,
        "llm_mode_prediction": llm_mode
    }
