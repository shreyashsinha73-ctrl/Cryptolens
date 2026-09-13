"""
PCAP and PCAPNG low-level utilities.
Pure Python standard library implementation for reading, parsing, and writing packet captures.
Designed for high security, zero external dependencies, and robust bounds checking.
"""

import os
import struct
from typing import Dict, Generator, List, Optional, Tuple, Any

PCAP_MAGIC_MICROSECONDS = 0xa1b2c3d4
PCAP_MAGIC_NANOSECONDS  = 0xa1b23c4d
PCAPNG_MAGIC            = 0x0a0d0d0a

# Data Link Types
DLT_NULL       = 0
DLT_EN10MB     = 1    # Standard Ethernet
DLT_RAW        = 101  # Raw IPv4/IPv6
DLT_LINUX_SLL  = 113  # Linux "cooked" capture v1
DLT_LINUX_SLL2 = 276  # Linux "cooked" capture v2


class PcapReader:
    """Safely streams frames from standard PCAP and basic PCAPNG captures."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Capture file not found: {file_path}")
        self.file_size = os.path.getsize(file_path)

    def iter_packets(self) -> Generator[Tuple[float, int, bytes, int], None, None]:
        """
        Yields:
            (timestamp_float, original_wire_len, packet_bytes, link_type)
        """
        with open(self.file_path, "rb") as f:
            header = f.read(24)
            if len(header) < 24:
                return

            magic = struct.unpack("<I", header[:4])[0]
            if magic in (PCAP_MAGIC_MICROSECONDS, PCAP_MAGIC_NANOSECONDS):
                endian = "<"
                nanos = (magic == PCAP_MAGIC_NANOSECONDS)
            else:
                magic_be = struct.unpack(">I", header[:4])[0]
                if magic_be in (PCAP_MAGIC_MICROSECONDS, PCAP_MAGIC_NANOSECONDS):
                    endian = ">"
                    nanos = (magic_be == PCAP_MAGIC_NANOSECONDS)
                elif magic == PCAPNG_MAGIC or magic_be == PCAPNG_MAGIC:
                    f.seek(0)
                    yield from self._iter_pcapng(f)
                    return
                else:
                    raise ValueError(f"Unrecognized capture magic: {hex(magic)}")

            _, _, _, _, snaplen, link_type = struct.unpack(f"{endian}HHIIII", header[4:24])

            while True:
                record_hdr = f.read(16)
                if len(record_hdr) < 16:
                    break

                ts_sec, ts_frac, incl_len, orig_len = struct.unpack(f"{endian}IIII", record_hdr)
                if incl_len > 65535 or incl_len > self.file_size:
                    # Corrupted record length, prevent buffer overread
                    break

                pkt_bytes = f.read(incl_len)
                if len(pkt_bytes) < incl_len:
                    break

                ts = ts_sec + (ts_frac / 1e9 if nanos else ts_frac / 1e6)
                yield (ts, orig_len, pkt_bytes, link_type)

    def _iter_pcapng(self, f) -> Generator[Tuple[float, int, bytes, int], None, None]:
        """Basic block reader for PCAPNG Enhanced Packet Blocks (EPB)."""
        link_type = DLT_EN10MB
        while True:
            hdr = f.read(8)
            if len(hdr) < 8:
                break
            block_type, block_len = struct.unpack("<II", hdr)
            if block_len < 12 or block_len > 10 * 1024 * 1024:
                break

            body = f.read(block_len - 8)
            if len(body) < block_len - 8:
                break

            # Section Header Block (1) or Interface Description Block (1)
            if block_type == 1 and len(body) >= 8:
                link_type = struct.unpack("<H", body[:2])[0]
            # Enhanced Packet Block (6)
            elif block_type == 6 and len(body) >= 20:
                _, ts_high, ts_low, cap_len, orig_len = struct.unpack("<IIIII", body[:20])
                ts_raw = (ts_high << 32) | ts_low
                ts = ts_raw / 1e6  # Default microsecond resolution
                pkt_data = body[20:20 + cap_len]
                yield (ts, orig_len, pkt_data, link_type)


class PcapWriter:
    """Writes standard libpcap files."""

    def __init__(self, file_path: str, link_type: int = DLT_EN10MB, snaplen: int = 65535):
        self.file_path = file_path
        self.link_type = link_type
        self.snaplen = snaplen
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        self.f = open(file_path, "wb")
        # Global header: magic, v2.4, thiszone=0, sigfigs=0, snaplen, link_type
        gh = struct.pack("<IHHiIII", PCAP_MAGIC_MICROSECONDS, 2, 4, 0, 0, self.snaplen, self.link_type)
        self.f.write(gh)

    def write_packet(self, ts: float, pkt_data: bytes, orig_len: Optional[int] = None):
        if orig_len is None:
            orig_len = len(pkt_data)
        incl_len = min(len(pkt_data), self.snaplen)
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1e6)
        hdr = struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)
        self.f.write(hdr)
        self.f.write(pkt_data[:incl_len])

    def close(self):
        if self.f and not self.f.closed:
            self.f.flush()
            self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def parse_packet_layers(pkt_data: bytes, link_type: int) -> Dict[str, Any]:
    """
    Parses Ethernet/SLL, IP, and Layer 4 headers.
    Returns structured metadata including ip_proto, ports, and l4_payload.
    """
    result: Dict[str, Any] = {
        "link_type": link_type,
        "ip_version": None,
        "ip_src": None,
        "ip_dst": None,
        "ip_proto": None,
        "src_port": None,
        "dst_port": None,
        "l4_payload": b"",
        "is_esp": False,
        "is_ike": False,
        "raw_packet_len": len(pkt_data)
    }

    ip_offset = 0
    if link_type == DLT_EN10MB:
        if len(pkt_data) < 14:
            return result
        eth_type = struct.unpack("!H", pkt_data[12:14])[0]
        ip_offset = 14
        # Handle 802.1Q VLAN Tagging
        if eth_type == 0x8100 and len(pkt_data) >= 18:
            eth_type = struct.unpack("!H", pkt_data[16:18])[0]
            ip_offset = 18
        if eth_type == 0x0800:
            version_expected = 4
        elif eth_type == 0x86DD:
            version_expected = 6
        else:
            return result
    elif link_type in (DLT_LINUX_SLL, DLT_LINUX_SLL2):
        if len(pkt_data) < 16:
            return result
        proto = struct.unpack("!H", pkt_data[14:16])[0]
        ip_offset = 16 if link_type == DLT_LINUX_SLL else 20
        if proto == 0x0800:
            version_expected = 4
        elif proto == 0x86DD:
            version_expected = 6
        else:
            return result
    elif link_type == DLT_RAW:
        version_expected = (pkt_data[0] >> 4) if pkt_data else 0
        ip_offset = 0
    else:
        # Fallback heuristic: check first nibble
        if not pkt_data:
            return result
        v = (pkt_data[0] >> 4)
        if v in (4, 6):
            version_expected = v
            ip_offset = 0
        else:
            return result

    if len(pkt_data) < ip_offset + 20:
        return result

    # --- IPv4 Parsing ---
    if version_expected == 4:
        v_ihl = pkt_data[ip_offset]
        ihl = (v_ihl & 0x0F) * 4
        if len(pkt_data) < ip_offset + ihl:
            return result
        protocol = pkt_data[ip_offset + 9]
        src_ip = ".".join(str(b) for b in pkt_data[ip_offset + 12:ip_offset + 16])
        dst_ip = ".".join(str(b) for b in pkt_data[ip_offset + 16:ip_offset + 20])

        result["ip_version"] = 4
        result["ip_src"] = src_ip
        result["ip_dst"] = dst_ip
        result["ip_proto"] = protocol

        l4_offset = ip_offset + ihl
        l4_data = pkt_data[l4_offset:]

        if protocol == 50:  # ESP
            result["is_esp"] = True
            result["l4_payload"] = l4_data
        elif protocol == 17 and len(l4_data) >= 8:  # UDP
            src_p, dst_p, udp_len = struct.unpack("!HHH", l4_data[:6])
            result["src_port"] = src_p
            result["dst_port"] = dst_p
            udp_payload = l4_data[8:udp_len] if len(l4_data) >= udp_len else l4_data[8:]
            result["l4_payload"] = udp_payload

            # Check IKE on 500
            if 500 in (src_p, dst_p):
                result["is_ike"] = True
            # Check NAT-T on 4500
            elif 4500 in (src_p, dst_p):
                # Non-ESP marker check (first 4 bytes are 0x00000000)
                if len(udp_payload) >= 4 and udp_payload[:4] == b"\x00\x00\x00\x00":
                    result["is_ike"] = True
                    result["l4_payload"] = udp_payload[4:]  # Strip non-esp marker for IKE
                else:
                    # Non-zero first 4 bytes is the ESP SPI
                    result["is_esp"] = True

    # --- IPv6 Parsing ---
    elif version_expected == 6:
        if len(pkt_data) < ip_offset + 40:
            return result
        next_hdr = pkt_data[ip_offset + 6]
        result["ip_version"] = 6
        result["ip_proto"] = next_hdr

        l4_offset = ip_offset + 40
        l4_data = pkt_data[l4_offset:]

        if next_hdr == 50:
            result["is_esp"] = True
            result["l4_payload"] = l4_data
        elif next_hdr == 17 and len(l4_data) >= 8:
            src_p, dst_p = struct.unpack("!HH", l4_data[:4])
            result["src_port"] = src_p
            result["dst_port"] = dst_p
            udp_payload = l4_data[8:]
            result["l4_payload"] = udp_payload
            if 500 in (src_p, dst_p):
                result["is_ike"] = True
            elif 4500 in (src_p, dst_p):
                if len(udp_payload) >= 4 and udp_payload[:4] == b"\x00\x00\x00\x00":
                    result["is_ike"] = True
                    result["l4_payload"] = udp_payload[4:]
                else:
                    result["is_esp"] = True

    return result

