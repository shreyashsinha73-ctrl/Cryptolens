import pytest
from scapy.all import IP, UDP, Raw
from scapy.layers.inet6 import IPv6
from scapy.layers.ipsec import ESP

from backend.streaming.live_sniffer import LiveSniffer, ESPPacketRecord, IKEPacketRecord


def test_esp_header_extraction_ipv4():
    """Verify that Scapy-dissected ESP over IPv4 extracts correct SPI and sequence number."""
    sniffer = LiveSniffer()
    esp_records = []
    sniffer.on_esp(lambda rec: esp_records.append(rec))

    pkt = IP(src="192.168.1.100", dst="192.168.2.200") / ESP(spi=0xdeadbeef, seq=1337) / Raw(b"testpayload")
    sniffer._packet_handler(pkt)

    assert len(esp_records) == 1
    rec = esp_records[0]
    assert rec.src_ip == "192.168.1.100"
    assert rec.dst_ip == "192.168.2.200"
    assert rec.spi == "0xdeadbeef"
    assert rec.seq_num == 1337


def test_esp_header_extraction_ipv6():
    """Verify that ESP over IPv6 extracts correct SPI and sequence number."""
    sniffer = LiveSniffer()
    esp_records = []
    sniffer.on_esp(lambda rec: esp_records.append(rec))

    pkt = IPv6(src="2001:db8::1", dst="2001:db8::2", nh=50) / ESP(spi=0x12345678, seq=42) / Raw(b"data")
    sniffer._packet_handler(pkt)

    assert len(esp_records) == 1
    rec = esp_records[0]
    assert rec.src_ip == "2001:db8::1"
    assert rec.dst_ip == "2001:db8::2"
    assert rec.spi == "0x12345678"
    assert rec.seq_num == 42


def test_natt_esp_extraction():
    """Verify NAT-T (UDP 4500) ESP packet without Non-ESP Marker extracts SPI and Seq."""
    sniffer = LiveSniffer()
    esp_records = []
    sniffer.on_esp(lambda rec: esp_records.append(rec))

    # In NAT-T ESP, payload starts directly with 4-byte SPI (non-zero) and 4-byte seq
    spi_bytes = (0xaabbccdd).to_bytes(4, "big")
    seq_bytes = (99).to_bytes(4, "big")
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=4500, dport=4500) / Raw(spi_bytes + seq_bytes + b"encrypted")

    sniffer._packet_handler(pkt)

    assert len(esp_records) == 1
    rec = esp_records[0]
    assert rec.spi == "0xaabbccdd"
    assert rec.seq_num == 99


def test_natt_keepalive_ignored():
    """Verify RFC 3948 1-byte 0xFF keepalive is not treated as IKE or ESP."""
    sniffer = LiveSniffer()
    esp_records = []
    ike_records = []
    sniffer.on_esp(lambda rec: esp_records.append(rec))
    sniffer.on_ike(lambda rec: ike_records.append(rec))

    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=4500, dport=4500) / Raw(b"\xff")
    sniffer._packet_handler(pkt)

    assert len(esp_records) == 0
    assert len(ike_records) == 0


def test_natt_ike_with_non_esp_marker():
    """Verify UDP 4500 packet with 4 zero bytes (Non-ESP Marker) is classified as IKE."""
    sniffer = LiveSniffer()
    ike_records = []
    sniffer.on_ike(lambda rec: ike_records.append(rec))

    non_esp_marker = b"\x00\x00\x00\x00"
    ike_payload = b"ike_payload_bytes"
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=4500, dport=4500) / Raw(non_esp_marker + ike_payload)

    sniffer._packet_handler(pkt)

    assert len(ike_records) == 1
    rec = ike_records[0]
    assert rec.src_port == 4500
    assert rec.raw_bytes == ike_payload
