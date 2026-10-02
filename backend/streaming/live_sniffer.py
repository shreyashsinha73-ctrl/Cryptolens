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
from scapy.layers.inet6 import IPv6
from scapy.layers.ipsec import ESP

logger = logging.getLogger(__name__)

# Protocol constants
ESP_PROTO = 50
IKE_PORTS = {500, 4500}
NON_ESP_MARKER = b"\x00\x00\x00\x00"


@dataclass
class ESPPacketRecord:
    """Single ESP packet metadata record."""
    timestamp: float
    frame_number: int
    src_ip: str
    dst_ip: str
    packet_length: int
    spi: Optional[str] = None
    seq_num: Optional[int] = None
    iface: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "frame_number": self.frame_number,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "packet_length": self.packet_length,
            "spi": self.spi,
            "seq_num": self.seq_num,
            "iface": self.iface,
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
    ike_queue: deque = field(default_factory=lambda: deque(maxlen=1000))
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
        """BPF filter for IPsec traffic: ESP + IKE (UDP 500/4500) over IPv4 and IPv6."""
        return "(ip proto 50) or (ip6 proto 50) or (udp port 500) or (udp port 4500)"

    def _packet_handler(self, pkt):
        """Scapy callback — classify each packet as ESP or IKE."""
        self._frame_counter += 1
        ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
        sniffed_iface = getattr(pkt, "sniffed_on", None) or self.interface

        is_ipv4 = pkt.haslayer(IP)
        is_ipv6 = pkt.haslayer(IPv6)
        if not (is_ipv4 or is_ipv6):
            return

        if is_ipv4:
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = ip_layer.proto
        else:
            ip_layer = pkt[IPv6]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = getattr(ip_layer, "nh", None)

        # Check for ESP (IP/IPv6 proto 50 or Scapy ESP layer)
        if proto == ESP_PROTO or pkt.haslayer(ESP):
            record = ESPPacketRecord(
                timestamp=ts,
                frame_number=self._frame_counter,
                src_ip=src_ip,
                dst_ip=dst_ip,
                packet_length=len(pkt),
                iface=str(sniffed_iface) if sniffed_iface else None,
            )
            # Try to extract SPI and sequence number
            if pkt.haslayer(ESP):
                esp = pkt[ESP]
                record.spi = f"0x{esp.spi:08x}" if isinstance(esp.spi, int) else str(esp.spi)
                record.seq_num = int(esp.seq) if esp.seq is not None else None
            elif pkt.haslayer(Raw):
                raw = bytes(pkt[Raw])
                if len(raw) >= 8:
                    spi_val = int.from_bytes(raw[:4], "big")
                    record.spi = f"0x{spi_val:08x}"
                    record.seq_num = int.from_bytes(raw[4:8], "big")

            self.state.add_esp(record)
            if self._on_esp_callback:
                self._on_esp_callback(record)
            return

        # Check for IKE or NAT-T ESP (UDP 500 or 4500)
        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            if udp.sport in IKE_PORTS or udp.dport in IKE_PORTS:
                udp_payload = bytes(udp.payload) if hasattr(udp, "payload") else b""

                # 1-byte 0xFF is RFC 3948 NAT-keepalive, not IKE
                if len(udp_payload) == 1 and udp_payload == b"\xff":
                    logger.debug("NAT-keepalive packet received (RFC 3948 Section 2.3); ignored.")
                    return

                # NAT-T disambiguation on port 4500
                if (udp.sport == 4500 or udp.dport == 4500) and len(udp_payload) >= 4:
                    if udp_payload[:4] != NON_ESP_MARKER:
                        # Non-ESP marker absent: this is NAT-T encapsulated ESP
                        record = ESPPacketRecord(
                            timestamp=ts,
                            frame_number=self._frame_counter,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            packet_length=len(pkt),
                            iface=str(sniffed_iface) if sniffed_iface else None,
                        )
                        if len(udp_payload) >= 8:
                            spi_val = int.from_bytes(udp_payload[:4], "big")
                            record.spi = f"0x{spi_val:08x}"
                            record.seq_num = int.from_bytes(udp_payload[4:8], "big")
                        self.state.add_esp(record)
                        if self._on_esp_callback:
                            self._on_esp_callback(record)
                        return

                raw_bytes = udp_payload[4:] if udp_payload.startswith(NON_ESP_MARKER) else udp_payload
                record = IKEPacketRecord(
                    timestamp=ts,
                    frame_number=self._frame_counter,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
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
