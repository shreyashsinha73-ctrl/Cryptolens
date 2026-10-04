"""
Real-time packet sniffer capturing all wire traffic (ESP, IKE, TCP, UDP, TLS, DNS, ICMP, etc.)
Behaves like standard Wireshark with Scapy and tshark support.
Maintains rolling buffer of ESP flow metrics for continuous AI inference.
"""

import asyncio
import os
import shutil
import subprocess
import time
import threading
import logging
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Callable, Dict, Any, List

from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, Raw
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
    total_packet_count: int = 0
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
            self.total_packet_count += 1

    def add_ike(self, record: IKEPacketRecord):
        with self._lock:
            self.ike_queue.append(record)
            self.total_ike_count += 1
            self.total_packet_count += 1

    def increment_packet_count(self):
        with self._lock:
            self.total_packet_count += 1

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
    Wireshark-compatible real-time packet sniffer.
    Captures all wire frames across all protocols (ESP, IKE, TCP, UDP, TLS, DNS, ICMP, etc.)
    with automatic tshark / Scapy integration.
    """

    def __init__(self, interface: str = "any", bpf_filter: str = "", output_pcap: Optional[Any] = None):
        self.interface = interface
        self.bpf_filter = bpf_filter.strip()  # Empty means capture all packets (Wireshark default)
        self.output_pcap = Path(output_pcap).resolve() if output_pcap else None
        self.state = StreamState()
        self._sniffer: Optional[AsyncSniffer] = None
        self._tshark_proc: Optional[subprocess.Popen] = None
        self._capture_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._frame_counter = 0

        self._on_esp_callback: Optional[Callable] = None
        self._on_ike_callback: Optional[Callable] = None
        self._on_packet_callback: Optional[Callable] = None

    def _packet_handler(self, pkt):
        """Scapy callback — handles all packets (ESP, IKE, TCP, UDP, ICMP, etc.)."""
        self._frame_counter += 1
        ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
        sniffed_iface = getattr(pkt, "sniffed_on", None) or self.interface

        is_ipv4 = pkt.haslayer(IP)
        is_ipv6 = pkt.haslayer(IPv6)
        if not (is_ipv4 or is_ipv6):
            # Non-IP layer (e.g. ARP)
            pkt_len = len(pkt)
            self.state.increment_packet_count()
            if self._on_packet_callback:
                self._on_packet_callback({
                    "type": "packet_event",
                    "frame_number": self._frame_counter,
                    "packet_type": "ARP / Link Layer",
                    "protocol": "ARP",
                    "src_ip": getattr(pkt, "src", "00:00:00:00:00:00"),
                    "dst_ip": getattr(pkt, "dst", "ff:ff:ff:ff:ff:ff"),
                    "src_port": None,
                    "dst_port": None,
                    "packet_length": pkt_len,
                    "spi": "—",
                    "seq_num": None,
                    "timestamp": ts,
                    "details": f"Link-layer frame: Len={pkt_len}B",
                    "severity": "LOW",
                    "iface": str(sniffed_iface) if sniffed_iface else None,
                })
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

        # 1. Check for ESP (IP/IPv6 proto 50 or Scapy ESP layer)
        if proto == ESP_PROTO or pkt.haslayer(ESP):
            record = ESPPacketRecord(
                timestamp=ts,
                frame_number=self._frame_counter,
                src_ip=src_ip,
                dst_ip=dst_ip,
                packet_length=len(pkt),
                iface=str(sniffed_iface) if sniffed_iface else None,
            )
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
            if self._on_packet_callback:
                self._on_packet_callback({
                    "type": "esp_event",
                    "frame_number": self._frame_counter,
                    "packet_type": "ESP (Encrypted)",
                    "protocol": "ESP",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": None,
                    "dst_port": None,
                    "packet_length": len(pkt),
                    "spi": record.spi or "—",
                    "seq_num": record.seq_num,
                    "timestamp": ts,
                    "details": f"Live ESP: SPI={record.spi or '—'}, Seq={record.seq_num or '—'}, Len={len(pkt)}B",
                    "severity": "LOW",
                    "iface": str(sniffed_iface) if sniffed_iface else None,
                })
            return

        # 2. Check for IKE or NAT-T ESP (UDP 500 or 4500)
        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            if udp.sport in IKE_PORTS or udp.dport in IKE_PORTS:
                udp_payload = bytes(udp.payload) if hasattr(udp, "payload") else b""

                if len(udp_payload) == 1 and udp_payload == b"\xff":
                    logger.debug("NAT-keepalive packet received (RFC 3948 Section 2.3); ignored.")
                    return

                if (udp.sport == 4500 or udp.dport == 4500) and len(udp_payload) >= 4:
                    if udp_payload[:4] != NON_ESP_MARKER:
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
                        if self._on_packet_callback:
                            self._on_packet_callback({
                                "type": "esp_event",
                                "frame_number": self._frame_counter,
                                "packet_type": "ESP (NAT-T)",
                                "protocol": "ESP",
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "src_port": udp.sport,
                                "dst_port": udp.dport,
                                "packet_length": len(pkt),
                                "spi": record.spi or "—",
                                "seq_num": record.seq_num,
                                "timestamp": ts,
                                "details": f"NAT-T ESP: SPI={record.spi or '—'}, Seq={record.seq_num or '—'}, Len={len(pkt)}B",
                                "severity": "LOW",
                                "iface": str(sniffed_iface) if sniffed_iface else None,
                            })
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
                if self._on_packet_callback:
                    self._on_packet_callback({
                        "type": "ike_event",
                        "frame_number": self._frame_counter,
                        "packet_type": "IKE Handshake",
                        "protocol": "IKE",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": udp.sport,
                        "dst_port": udp.dport,
                        "packet_length": len(pkt),
                        "spi": "—",
                        "seq_num": None,
                        "timestamp": ts,
                        "details": f"Live IKE Handshake: {src_ip}:{udp.sport} -> {dst_ip}:{udp.dport}",
                        "severity": "LOW",
                        "iface": str(sniffed_iface) if sniffed_iface else None,
                    })
                return

        # 3. All other packets (TCP, UDP, ICMP, DNS, TLS, HTTP, etc. - Wireshark behavior)
        sport = None
        dport = None
        proto_name = "IP"
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            if sport == 443 or dport == 443:
                proto_name = "TLS/HTTPS"
            elif sport == 80 or dport == 80:
                proto_name = "HTTP"
            else:
                proto_name = "TCP"
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            if sport == 53 or dport == 53:
                proto_name = "DNS"
            else:
                proto_name = "UDP"
        elif pkt.haslayer(ICMP):
            proto_name = "ICMP"

        self.state.increment_packet_count()
        if self._on_packet_callback:
            self._on_packet_callback({
                "type": "packet_event",
                "frame_number": self._frame_counter,
                "packet_type": proto_name,
                "protocol": proto_name,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": sport,
                "dst_port": dport,
                "packet_length": len(pkt),
                "spi": "—",
                "seq_num": None,
                "timestamp": ts,
                "details": f"{proto_name}: {src_ip}{f':{sport}' if sport else ''} -> {dst_ip}{f':{dport}' if dport else ''}, Len={len(pkt)}B",
                "severity": "LOW",
                "iface": str(sniffed_iface) if sniffed_iface else None,
            })

    def _run_tshark_capture(self):
        """Live capture loop via tshark for full Wireshark packet coverage."""
        tshark_bin = shutil.which("tshark") or "tshark"
        cmd = [
            tshark_bin,
            "-i", self.interface,
        ]
        if self.output_pcap:
            self.output_pcap.parent.mkdir(parents=True, exist_ok=True)
            cmd.extend(["-w", str(self.output_pcap), "-P"])

        cmd.extend([
            "-l", "-n",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "_ws.col.Protocol",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "ipv6.src",
            "-e", "ipv6.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.srcport",
            "-e", "udp.dstport",
            "-e", "esp.spi",
            "-e", "esp.sequence",
            "-e", "frame.len",
            "-e", "frame.time_epoch",
            "-e", "_ws.col.Info",
        ])
        if self.bpf_filter:
            cmd.extend(["-f", self.bpf_filter])

        try:
            self._tshark_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
            logger.info(f"tshark live capture process started: PID {self._tshark_proc.pid}")

            for line in self._tshark_proc.stdout:
                if self._stop_event.is_set():
                    break
                line = line.rstrip("\r\n")
                if not line:
                    continue

                parts = line.split("\t")
                self._frame_counter += 1

                ws_proto = parts[1] if len(parts) > 1 and parts[1] else "IP"
                src_ip = parts[2] if len(parts) > 2 and parts[2] else (parts[4] if len(parts) > 4 and parts[4] else "0.0.0.0")
                dst_ip = parts[3] if len(parts) > 3 and parts[3] else (parts[5] if len(parts) > 5 and parts[5] else "0.0.0.0")

                tcp_sp = parts[6] if len(parts) > 6 and parts[6].isdigit() else None
                tcp_dp = parts[7] if len(parts) > 7 and parts[7].isdigit() else None
                udp_sp = parts[8] if len(parts) > 8 and parts[8].isdigit() else None
                udp_dp = parts[9] if len(parts) > 9 and parts[9].isdigit() else None

                src_port = int(tcp_sp or udp_sp) if (tcp_sp or udp_sp) else None
                dst_port = int(tcp_dp or udp_dp) if (tcp_dp or udp_dp) else None

                esp_spi = parts[10] if len(parts) > 10 and parts[10] else None
                esp_seq = int(parts[11]) if len(parts) > 11 and parts[11].isdigit() else None
                pkt_len = int(parts[12]) if len(parts) > 12 and parts[12].isdigit() else 64
                ts = float(parts[13]) if len(parts) > 13 and parts[13] else time.time()
                info = parts[14] if len(parts) > 14 and parts[14] else f"{ws_proto} {src_ip}->{dst_ip}"

                # 1. ESP packet
                if ws_proto.upper() == "ESP" or esp_spi:
                    rec = ESPPacketRecord(
                        timestamp=ts,
                        frame_number=self._frame_counter,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        packet_length=pkt_len,
                        spi=esp_spi,
                        seq_num=esp_seq,
                        iface=self.interface,
                    )
                    self.state.add_esp(rec)
                    if self._on_esp_callback:
                        self._on_esp_callback(rec)
                    if self._on_packet_callback:
                        self._on_packet_callback({
                            "type": "esp_event",
                            "frame_number": self._frame_counter,
                            "packet_type": "ESP (Encrypted)",
                            "protocol": "ESP",
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "packet_length": pkt_len,
                            "spi": esp_spi or "—",
                            "seq_num": esp_seq,
                            "timestamp": ts,
                            "details": f"Live ESP: SPI={esp_spi or '—'}, Seq={esp_seq or '—'}, Len={pkt_len}B",
                            "severity": "LOW",
                            "iface": self.interface,
                        })
                    continue

                # 2. IKE packet
                if "IKE" in ws_proto.upper() or src_port in IKE_PORTS or dst_port in IKE_PORTS:
                    rec = IKEPacketRecord(
                        timestamp=ts,
                        frame_number=self._frame_counter,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port or 500,
                        dst_port=dst_port or 500,
                    )
                    self.state.add_ike(rec)
                    if self._on_ike_callback:
                        self._on_ike_callback(rec)
                    if self._on_packet_callback:
                        self._on_packet_callback({
                            "type": "ike_event",
                            "frame_number": self._frame_counter,
                            "packet_type": "IKE Handshake",
                            "protocol": "IKE",
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": src_port or 500,
                            "dst_port": dst_port or 500,
                            "packet_length": pkt_len,
                            "spi": "—",
                            "seq_num": None,
                            "timestamp": ts,
                            "details": f"Live IKE: {src_ip}:{src_port} -> {dst_ip}:{dst_port}",
                            "severity": "LOW",
                            "iface": self.interface,
                        })
                    continue

                # 3. All other packets (TCP, UDP, TLS, DNS, ICMP, etc.)
                self.state.increment_packet_count()
                if self._on_packet_callback:
                    self._on_packet_callback({
                        "type": "packet_event",
                        "frame_number": self._frame_counter,
                        "packet_type": ws_proto,
                        "protocol": ws_proto,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "packet_length": pkt_len,
                        "spi": "—",
                        "seq_num": None,
                        "timestamp": ts,
                        "details": info,
                        "severity": "LOW",
                        "iface": self.interface,
                    })

        except Exception as e:
            logger.warning(f"Error in tshark live capture loop: {e}")

    def start(self):
        """Start packet sniffer using tshark if available, with Scapy fallback."""
        self._stop_event.clear()

        # Prioritize tshark since Wireshark capabilities allow non-root capture of all packets
        if shutil.which("tshark"):
            self._capture_thread = threading.Thread(target=self._run_tshark_capture, daemon=True)
            self._capture_thread.start()
            logger.info(f"LiveSniffer started via tshark on interface={self.interface}")
            return

        # Fallback to Scapy AsyncSniffer
        kwargs = {
            "prn": self._packet_handler,
            "store": False,
        }
        if self.bpf_filter:
            kwargs["filter"] = self.bpf_filter
        if self.interface and self.interface != "any":
            kwargs["iface"] = self.interface

        try:
            self._sniffer = AsyncSniffer(**kwargs)
            self._sniffer.start()
            logger.info(f"LiveSniffer started via Scapy on interface={self.interface}")
        except Exception as e:
            logger.error(f"Failed to start Scapy AsyncSniffer: {e}")

    def stop(self):
        """Stop the sniffer."""
        self._stop_event.set()

        if self._tshark_proc:
            try:
                self._tshark_proc.terminate()
                self._tshark_proc.wait(timeout=1.0)
            except Exception:
                try:
                    self._tshark_proc.kill()
                except Exception:
                    pass
            self._tshark_proc = None

        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception as e:
                logger.warning(f"Error stopping Scapy sniffer: {e}")
            self._sniffer = None

        logger.info("LiveSniffer stopped.")

    def on_esp(self, callback: Callable):
        self._on_esp_callback = callback

    def on_ike(self, callback: Callable):
        self._on_ike_callback = callback

    def on_packet(self, callback: Callable):
        self._on_packet_callback = callback
