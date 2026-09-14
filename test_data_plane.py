"""
test_data_plane.py
------------------
Interactive self-test script for the CryptoLens Data-Plane engine.
Run this directly with: python test_data_plane.py
"""

import json
import os
import pprint
import shutil
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

def banner(title):
    print("\n" + "=" * 65)
    print(f"  {title}")
    print("=" * 65)

def test_classifier():
    banner("TEST 1: Direct Classifier & LLM Inference Test")
    from backend.engine.data_plane.classifier import classify_traffic

    print("Feeding simulated HTTPS-like encrypted ESP session:")
    print("  - Packet sizes: [1420, 1420, 1420, 540, 1420, 200] (Bursty/Large)")
    print("  - Inter-arrival times: [0.0, 0.005, 0.002, 0.05, 0.001, 0.02] s")
    print("  - Total packets: 6")

    features = {
        "S_L": [1420.0, 1420.0, 1420.0, 540.0, 1420.0, 200.0],
        "S_IAT": [0.0, 0.005, 0.002, 0.05, 0.001, 0.02],
        "n_real_packets": 6,
    }

    print("\nCalling classify_traffic()...")
    result = classify_traffic(features)
    print("\nResult returned by classifier:")
    pprint.pprint(result)

    if result.get("error"):
        print(f"\n[NOTE] LLM returned error: {result['error']}")
        print("  -> This is expected if the API key is invalid or offline.")
        print("  -> The system handled it gracefully without crashing!")
    else:
        print("\n[SUCCESS] Live LLM inference succeeded!")
        print(f"  Mode predicted: {result.get('mode')} (conf: {result.get('mode_confidence')})")
        print(f"  Traffic predicted: {result.get('traffic_type')} (conf: {result.get('traffic_confidence')})")

def test_pcap_analysis():
    banner("TEST 2: Real PCAP File Extraction & Analysis Test")
    from backend.engine.data_plane.traffic_analyzer import analyze_data_plane

    from scapy.all import ESP, IP, rdpcap, wrpcap
    from backend.engine.data_plane.classifier import _extract_sequences
    from backend.engine.data_plane.feature_extract import (
        build_sequences,
        extract_esp_lengths_and_times,
    )
    from scripts.test_control_plane import build_ikev2_packet

    banner("TEST 2: Wire PCAP Control/Data-Plane Index Verification")
    # Keep inspectable test artifacts in the repository.  Windows can deny
    # Scapy access to directories made by tempfile with restrictive ACLs.
    output_dir = Path.cwd() / "data_plane_test_output"
    output_dir.mkdir(exist_ok=True)
    scenarios = [
            ("secure_tunnel", False, [1420, 1390, 1420, 680, 1410], "Tunnel"),
            ("legacy_transport", True, [220, 216, 224, 218, 222], "Transport"),
    ]

    for name, transport_mode, expected_lengths, expected_mode in scenarios:
        pcap_path = output_dir / f"{name}.pcap"
        wrpcap(
            str(pcap_path),
            build_ikev2_packet(
                transport_mode=transport_mode,
                is_replayed=False,
                esp_packet_lengths=expected_lengths,
                esp_intervals=[0.020, 0.020, 0.020, 0.020],
            ),
        )

        packets = rdpcap(str(pcap_path))
        control_indices = [index for index, packet in enumerate(packets, start=1)
                           if IP in packet and packet[IP].proto == 17 and
                           (packet.sport == 500 or packet.dport == 500)]
        control_packets = [(index, packet) for index, packet in enumerate(packets, start=1)
                           if index in control_indices]
        # IKE header offsets: version=17, exchange type=18, message ID=20..23.
        control_values = [
            (frame_index, bytes(packet[IP].payload.payload)[17],
             bytes(packet[IP].payload.payload)[18],
             int.from_bytes(bytes(packet[IP].payload.payload)[20:24], "big"))
            for frame_index, packet in control_packets
        ]
        data_packets = [(index, packet) for index, packet in enumerate(packets, start=1)
                        if IP in packet and packet[IP].proto == 50]
        data_indices = [index for index, _ in data_packets]
        sequence_numbers = [packet[ESP].seq for _, packet in data_packets]
        observed_lengths = [len(packet[IP]) for _, packet in data_packets]

        assert control_indices, f"{name}: expected IKE control-plane frames"
        assert [value[2] for value in control_values] == [34, 36]
        assert [value[3] for value in control_values] == [0, 1]
        assert data_indices == list(range(data_indices[0], data_indices[0] + 5))
        assert sequence_numbers == [1, 2, 3, 4, 5]
        assert observed_lengths == expected_lengths

        lengths, timestamps = extract_esp_lengths_and_times(str(pcap_path))
        s_l, s_iat, _mask, n_real = build_sequences(lengths, timestamps)
        classifier_lengths, classifier_iats, classifier_count = _extract_sequences({
            "S_L": s_l.tolist(),
            "S_IAT": s_iat.tolist(),
            "n_real_packets": n_real,
            "total_esp_packets": len(lengths),
        })
        analysis = analyze_data_plane(str(pcap_path))

        assert n_real == len(expected_lengths)
        assert classifier_count == len(expected_lengths)
        assert classifier_lengths == expected_lengths
        assert len(classifier_iats) == len(expected_lengths)
        assert analysis["detected_traffic"][0]["packet_count"] == len(expected_lengths)
        assert analysis["heuristic_mode_prediction"] == expected_mode

        print(f"\n{name}: {pcap_path.name}")
        print("  control-plane frames (frame, IKE version, exchange type, message ID):")
        for control_value in control_values:
            print(f"    {control_value}")
        print("  data-plane frames (frame, ESP sequence, outer-IP bytes):")
        for frame_index, packet in data_packets:
            print(f"    ({frame_index}, {packet[ESP].seq}, {len(packet[IP])})")
        print(f"  extracted S_L: {classifier_lengths}")
        print(f"  extracted S_IAT: {[round(value, 3) for value in classifier_iats]}")
        print(f"  data-plane heuristic mode: {analysis['heuristic_mode_prediction']}")

    # tshark is required by the production deterministic IKE parser.  Do not
    # turn a missing local dependency into a misleading packet-test failure.
    if not shutil.which("tshark"):
        print("\n[NOTE] tshark is not installed, so control-plane field decoding was not run.")
        print("       The control-plane frame indices above are verified from the same PCAP.")

def main():
    print("\n>>> CryptoLens Data-Plane Diagnostic Runner <<<")
    test_classifier()
    test_pcap_analysis()
    print("\n" + "=" * 65)
    print("  All data-plane tests completed.")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    main()
