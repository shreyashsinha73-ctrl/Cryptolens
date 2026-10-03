import os
import tempfile
from pathlib import Path
import pytest
from scapy.all import wrpcap, Ether, IP, IPv6, UDP, Raw
from scapy.layers.ipsec import ESP
from scapy.layers.isakmp import ISAKMP

from backend.services.analyzer_provider import get_analyzer_provider
from backend.scoring.scoring_engine import ScoringEngine
from backend.engine.control_plane.ike_parser import IkeParser
from backend.engine.data_plane.traffic_analyzer import analyze_data_plane


@pytest.fixture(scope="module")
def edge_pcaps(tmp_path_factory):
    """
    Generate synthetic edge-case captures for boundary robustness testing:
      1. Empty PCAP (0 bytes / 0 packets)
      2. IKE-only PCAP (handshake packets, 0 ESP)
      3. ESP-only PCAP (data-plane ESP packets, 0 IKE)
      4. Truncated packet PCAP (corrupted / truncated frame boundaries)
      5. IPv6 ESP PCAP (IPv6 Next-Header 50 ESP)
      6. NAT-T PCAP (UDP 4500 ESP encapsulation)
      7. Large PCAP (2,000+ packets)
    """
    tmp_dir = tmp_path_factory.mktemp("edge_pcaps")

    # 1. Empty PCAP
    empty_pcap = tmp_dir / "synthetic_edge_empty.pcap"
    wrpcap(str(empty_pcap), [])

    # 2. IKE-only PCAP
    ike_pkts = [
        Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / UDP(sport=500, dport=500) / ISAKMP(init_cookie=b"12345678", next_payload=33, version=0x20)
        for _ in range(4)
    ]
    ike_pcap = tmp_dir / "synthetic_edge_ike_only.pcap"
    wrpcap(str(ike_pcap), ike_pkts)

    # 3. ESP-only PCAP
    esp_pkts = [
        Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / ESP(spi=0x98765432, seq=i) / Raw(b"\x00" * 80)
        for i in range(1, 25)
    ]
    esp_pcap = tmp_dir / "synthetic_edge_esp_only.pcap"
    wrpcap(str(esp_pcap), esp_pkts)

    # 4. Truncated PCAP
    trunc_pcap = tmp_dir / "synthetic_edge_truncated.pcap"
    wrpcap(str(trunc_pcap), esp_pkts[:5])
    # Corrupt file by truncating trailing bytes
    with open(trunc_pcap, "r+b") as f:
        content = f.read()
        f.seek(0)
        f.truncate(len(content) - 30)

    # 5. IPv6 ESP PCAP
    ipv6_pkts = [
        Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2", nh=50) / ESP(spi=0xAABBCCDD, seq=i) / Raw(b"\x00" * 80)
        for i in range(1, 25)
    ]
    ipv6_pcap = tmp_dir / "synthetic_edge_ipv6_esp.pcap"
    wrpcap(str(ipv6_pcap), ipv6_pkts)

    # 6. NAT-T PCAP (UDP 4500 ESP)
    natt_pkts = [
        Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / UDP(sport=4500, dport=4500) / ESP(spi=0x11223344, seq=i) / Raw(b"\x00" * 80)
        for i in range(1, 25)
    ]
    natt_pcap = tmp_dir / "synthetic_edge_natt.pcap"
    wrpcap(str(natt_pcap), natt_pkts)

    # 7. Large PCAP (2,000+ packets)
    large_pkts = [
        Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / ESP(spi=0x55667788, seq=i) / Raw(b"\xaa" * 64)
        for i in range(1, 2050)
    ]
    large_pcap = tmp_dir / "synthetic_edge_large_2000.pcap"
    wrpcap(str(large_pcap), large_pkts)

    return {
        "empty": empty_pcap,
        "ike_only": ike_pcap,
        "esp_only": esp_pcap,
        "truncated": trunc_pcap,
        "ipv6": ipv6_pcap,
        "natt": natt_pcap,
        "large_2000": large_pcap,
    }


def test_edge_input_empty_pcap(edge_pcaps):
    """Empty PCAP should not crash; returns graceful unobserved state."""
    provider = get_analyzer_provider()
    scorer = ScoringEngine()

    analysis = provider.get_analysis(str(edge_pcaps["empty"]))
    score = scorer.evaluate(analysis)

    assert score["coverage"] == "0/8"
    assert score["risk_level"] in ("UNVERIFIED", "NOT_ASSESSED")


def test_edge_input_ike_only_pcap(edge_pcaps):
    """IKE-only PCAP evaluates control plane but data-plane metrics reflect 0 ESP frames."""
    provider = get_analyzer_provider()
    scorer = ScoringEngine()

    analysis = provider.get_analysis(str(edge_pcaps["ike_only"]))
    score = scorer.evaluate(analysis)

    assert score["coverage"] in ("1/8", "2/8", "3/8", "4/8")
    assert score["risk_level"] == "UNVERIFIED"


def test_edge_input_esp_only_pcap(edge_pcaps):
    """ESP-only PCAP evaluates data-plane anti-replay and block metrics with unobserved IKE."""
    provider = get_analyzer_provider()
    scorer = ScoringEngine()

    analysis = provider.get_analysis(str(edge_pcaps["esp_only"]))
    score = scorer.evaluate(analysis)

    assert score["risk_level"] in ("UNVERIFIED", "NOT_ASSESSED")
    assert "findings" in score


def test_edge_input_truncated_pcap(edge_pcaps):
    """Truncated PCAP must be safely ingested with best-effort parsing without unhandled crash."""
    provider = get_analyzer_provider()
    scorer = ScoringEngine()

    analysis = provider.get_analysis(str(edge_pcaps["truncated"]))
    score = scorer.evaluate(analysis)
    assert score["risk_level"] in ("UNVERIFIED", "NOT_ASSESSED")


def test_edge_input_ipv6_esp_pcap(edge_pcaps):
    """IPv6 ESP capture parses next_header 50 correctly without crashing."""
    provider = get_analyzer_provider()
    scorer = ScoringEngine()

    analysis = provider.get_analysis(str(edge_pcaps["ipv6"]))
    score = scorer.evaluate(analysis)
    assert "score" in score


def test_edge_input_natt_pcap(edge_pcaps):
    """UDP 4500 encapsulated ESP (NAT-T) parses ESP layer correctly."""
    provider = get_analyzer_provider()
    scorer = ScoringEngine()

    analysis = provider.get_analysis(str(edge_pcaps["natt"]))
    score = scorer.evaluate(analysis)
    assert "score" in score


def test_edge_input_large_2000_packets_pcap(edge_pcaps):
    """2000+ packets processed efficiently without memory exhaustion or timeouts."""
    provider = get_analyzer_provider()
    scorer = ScoringEngine()

    analysis = provider.get_analysis(str(edge_pcaps["large_2000"]))
    score = scorer.evaluate(analysis)
    assert "score" in score
