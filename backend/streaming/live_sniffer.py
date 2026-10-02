"""
Real-time ESP/IKE packet sniffer using Scapy AsyncSniffer.
Maintains a rolling buffer of ESP flow metrics for continuous AI inference.
"""

import asyncio
import time
import threading
import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Optional, Callable, Dict, Any, List

from scapy.all import AsyncSniffer, IP, UDP, Raw

logger = logging.getLogger(__name__)

# Protocol constants
ESP_PROTO = 50
IKE_PORTS = {500, 4500}
NON_ESP_MARKER = b"\x00\x00\x00\x00"


@dataclass
class ESPPacketRecord:
    """Single wire packet metadata record (ESP, IKE, ICMP, DNS, TCP, VoIP, etc.)."""
    timestamp: float
    frame_number: int
    src_ip: str
    dst_ip: str
    packet_length: int
    spi: Optional[str] = None
    seq_num: Optional[int] = None
    protocol: str = "ESP"
    packet_type: str = "ESP"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "frame_number": self.frame_number,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "packet_length": self.packet_length,
            "spi": self.spi,
            "seq_num": self.seq_num,
            "protocol": self.protocol,
            "packet_type": self.packet_type,
        }


@dataclass
class IKEPacketRecord:
    """Single IKE packet metadata record."""
    timestamp: float
    frame_number: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    raw_bytes: bytes = b""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "frame_number": self.frame_number,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
        }


@dataclass
class StreamState:
    """Thread-safe container for live stream metrics."""
    esp_buffer: deque = field(default_factory=lambda: deque(maxlen=30))
    esp_lengths: deque = field(default_factory=lambda: deque(maxlen=30))
    esp_iats: deque = field(default_factory=lambda: deque(maxlen=30))
    ike_queue: list = field(default_factory=list)
    total_esp_count: int = 0
    total_ike_count: int = 0
    last_esp_timestamp: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def add_esp(self, record: ESPPacketRecord):
        with self._lock:
            iat = 0.0
            if self.last_esp_timestamp > 0:
                iat = max(0.0, record.timestamp - self.last_esp_timestamp)
            self.last_esp_timestamp = record.timestamp

            self.esp_buffer.append(record)
            self.esp_lengths.append(float(record.packet_length))
            self.esp_iats.append(float(iat))
            self.total_esp_count += 1

    def add_ike(self, record: IKEPacketRecord):
        with self._lock:
            self.ike_queue.append(record)
            self.total_ike_count += 1

    def get_cnn_input(self) -> Optional[dict]:
        """Return current buffer as CNN-compatible input dict."""
        with self._lock:
            if len(self.esp_lengths) < 5:  # Minimum viable sequence
                return None
            return {
                "lengths": list(self.esp_lengths),
                "iats": list(self.esp_iats),
                "total_esp_packets": self.total_esp_count,
            }

    def drain_ike_queue(self) -> list:
        """Pop all pending IKE packets for processing."""
        with self._lock:
            packets = list(self.ike_queue)
            self.ike_queue.clear()
            return packets

    def get_esp_records(self) -> list:
        """Return copy of current ESP buffer for XAI attribution."""
        with self._lock:
            return list(self.esp_buffer)


class LiveSniffer:
    """
    Scapy-based real-time packet sniffer for IPsec traffic.
    Classifies packets into ESP (data-plane) and IKE (control-plane) streams.
    """

    def __init__(self, interface: str = "any", bpf_filter: str = ""):
        self.interface = interface
        self.bpf_filter = bpf_filter or self._default_bpf()
        self.state = StreamState()
        self._sniffer: Optional[AsyncSniffer] = None
        self._frame_counter = 0
        self._on_esp_callback: Optional[Callable] = None
        self._on_ike_callback: Optional[Callable] = None

    @staticmethod
    def _default_bpf() -> str:
        """BPF filter for IPsec traffic: ESP + IKE (UDP 500/4500)."""
        return "(ip proto 50) or (udp port 500) or (udp port 4500)"

    def _packet_handler(self, pkt):
        """Scapy callback — classify each packet as ESP or IKE."""
        self._frame_counter += 1
        ts = float(pkt.time) if hasattr(pkt, "time") else time.time()

        if not pkt.haslayer(IP):
            return

        ip_layer = pkt[IP]

        # Check for ESP (IP protocol 50)
        if ip_layer.proto == ESP_PROTO:
            record = ESPPacketRecord(
                timestamp=ts,
                frame_number=self._frame_counter,
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                packet_length=len(pkt),
            )
            # Try to extract SPI and sequence number from ESP header
            if pkt.haslayer(Raw):
                raw = bytes(pkt[Raw])
                if len(raw) >= 8:
                    record.spi = raw[:4].hex()
                    record.seq_num = int.from_bytes(raw[4:8], "big")
            self.state.add_esp(record)
            if self._on_esp_callback:
                self._on_esp_callback(record)
            return

        # Check for IKE (UDP 500 or 4500)
        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            if udp.sport in IKE_PORTS or udp.dport in IKE_PORTS:
                # NAT-T disambiguation for port 4500
                if udp.sport == 4500 or udp.dport == 4500:
                    if pkt.haslayer(Raw):
                        payload = bytes(pkt[Raw])
                        if len(payload) >= 4 and payload[:4] != NON_ESP_MARKER:
                            # This is NAT-T ESP, not IKE
                            record = ESPPacketRecord(
                                timestamp=ts,
                                frame_number=self._frame_counter,
                                src_ip=ip_layer.src,
                                dst_ip=ip_layer.dst,
                                packet_length=len(pkt),
                            )
                            if len(payload) >= 8:
                                record.spi = payload[:4].hex()
                                record.seq_num = int.from_bytes(payload[4:8], "big")
                            self.state.add_esp(record)
                            if self._on_esp_callback:
                                self._on_esp_callback(record)
                            return

                raw_bytes = bytes(pkt[Raw]) if pkt.haslayer(Raw) else b""
                record = IKEPacketRecord(
                    timestamp=ts,
                    frame_number=self._frame_counter,
                    src_ip=ip_layer.src,
                    dst_ip=ip_layer.dst,
                    src_port=udp.sport,
                    dst_port=udp.dport,
                    raw_bytes=raw_bytes,
                )
                self.state.add_ike(record)
                if self._on_ike_callback:
                    self._on_ike_callback(record)

    def start(self):
        """Start the background sniffer thread."""
        kwargs = {
            "filter": self.bpf_filter,
            "prn": self._packet_handler,
            "store": False,
        }
        if self.interface and self.interface != "any":
            kwargs["iface"] = self.interface

        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.start()
        logger.info(
            f"LiveSniffer started on interface={self.interface}, "
            f"filter='{self.bpf_filter}'"
        )

    def stop(self):
        """Stop the sniffer."""
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception as e:
                logger.warning(f"Error stopping sniffer: {e}")
            self._sniffer = None
            logger.info("LiveSniffer stopped.")

    def on_esp(self, callback: Callable):
        self._on_esp_callback = callback

    def on_ike(self, callback: Callable):
        self._on_ike_callback = callback
