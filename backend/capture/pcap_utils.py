"""
pcap_utils.py - Reusable low-level utilities for PCAP/PCAPNG inspection,
safe tshark execution, and packet AST extraction.
"""

import json
import os
import shutil
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
import socket
from typing import Iterator, Tuple

from scapy.utils import RawPcapReader, RawPcapNgReader


PCAP_MAGIC_MICROSECONDS = 0xA1B2C3D4
PCAP_MAGIC_NANOSECONDS = 0xA1B23C4D
PCAP_MAGIC_SWAPPED = 0xD4C3B2A1
PCAP_MAGIC_NANO_SWAPPED = 0x4D3CB2A1
PCAPNG_MAGIC = 0x0A0D0D0A


@dataclass
class PcapMetadata:
    filepath: str
    file_format: str  # "pcap", "pcapng", or "unknown"
    filesize_bytes: int
    packet_count: int
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration_seconds: float = 0.0
    encapsulation: Optional[str] = None
class PcapReader:
    """
    Small compatibility wrapper used by the native IKE parser.

    Yields:
        (timestamp, original_length, raw_packet_bytes, link_type)
    """

    def __init__(self, filepath: str | Path):
        self.filepath = str(filepath)
        self._reader = None
        self._pcapng = False

        file_format = validate_pcap(self.filepath)

        if file_format == "pcapng":
            self._reader = RawPcapNgReader(self.filepath)
            self._pcapng = True
        else:
            self._reader = RawPcapReader(self.filepath)

    def iter_packets(self) -> Iterator[Tuple[float, int, bytes, int]]:
        if self._pcapng:
            # Scapy's PCAPNG reader exposes packet metadata with
            # interface/link-layer information.
            for raw_bytes, meta in self._reader:
                timestamp = float(getattr(meta, "sec", 0)) + (
                    float(getattr(meta, "usec", 0)) / 1_000_000.0
                )
                orig_len = int(
                    getattr(meta, "wirelen", getattr(meta, "caplen", len(raw_bytes)))
                )
                link_type = int(getattr(meta, "linktype", 1))
                yield timestamp, orig_len, raw_bytes, link_type

        else:
            # Classic PCAP.
            link_type = int(getattr(self._reader, "linktype", 1))

            for raw_bytes, meta in self._reader:
                timestamp = float(getattr(meta, "sec", 0)) + (
                    float(getattr(meta, "usec", 0)) / 1_000_000.0
                )
                orig_len = int(
                    getattr(meta, "wirelen", getattr(meta, "caplen", len(raw_bytes)))
                )
                yield timestamp, orig_len, raw_bytes, link_type

    def close(self) -> None:
        if self._reader is not None:
            close_fn = getattr(self._reader, "close", None)
            if callable(close_fn):
                close_fn()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

def parse_packet_layers(
    pkt_bytes: bytes,
    link_type: int
) -> Dict[str, Any]:
    """
    Minimal deterministic packet-layer parser used by the IKE parser.

    Supports:
      - Ethernet
      - RAW IP
      - Linux cooked capture (SLL)
      - Linux cooked v2 (SLL2)
      - IPv4 / IPv6
      - UDP 500 / 4500
      - ESP (IP protocol 50)

    Returns a normalized dictionary consumed by ike_parser.py.
    """

    result = {
        "is_ike": False,
        "is_esp": False,
        "ip_version": None,
        "ip_proto": None,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "l4_payload": b"",
    }

    if not pkt_bytes:
        return result

    data = pkt_bytes
    ether_type = None

    # ---------------------------------------------------------
    # Ethernet
    # DLT_EN10MB = 1
    # ---------------------------------------------------------
    if link_type == 1:
        if len(data) < 14:
            return result

        ether_type = struct.unpack("!H", data[12:14])[0]
        offset = 14

        # VLAN / QinQ
        while ether_type in (0x8100, 0x88A8, 0x9100):
            if len(data) < offset + 4:
                return result

            ether_type = struct.unpack("!H", data[offset + 2:offset + 4])[0]
            offset += 4

        data = data[offset:]

    # ---------------------------------------------------------
    # Linux cooked capture / SLL
    # DLT_LINUX_SLL = 113
    # ---------------------------------------------------------
    elif link_type == 113:
        if len(data) < 16:
            return result

        ether_type = struct.unpack("!H", data[14:16])[0]
        data = data[16:]

    # ---------------------------------------------------------
    # Linux cooked capture v2 / SLL2
    # DLT_LINUX_SLL2 = 276
    # ---------------------------------------------------------
    elif link_type == 276:
        if len(data) < 20:
            return result

        ether_type = struct.unpack("!H", data[0:2])[0]
        data = data[20:]

    # ---------------------------------------------------------
    # Raw IP
    # DLT_RAW = 101
    # ---------------------------------------------------------
    elif link_type == 101:
        if len(data) < 1:
            return result

        first_nibble = (data[0] >> 4) & 0x0F

        if first_nibble == 4:
            ether_type = 0x0800
        elif first_nibble == 6:
            ether_type = 0x86DD

    else:
        # Best-effort fallback: inspect first nibble as raw IP.
        first_nibble = (data[0] >> 4) & 0x0F

        if first_nibble == 4:
            ether_type = 0x0800
        elif first_nibble == 6:
            ether_type = 0x86DD

    # ---------------------------------------------------------
    # IPv4
    # ---------------------------------------------------------
    if ether_type == 0x0800:
        if len(data) < 20:
            return result

        version = (data[0] >> 4) & 0x0F
        ihl = (data[0] & 0x0F) * 4

        if version != 4 or ihl < 20 or len(data) < ihl:
            return result

        total_length = struct.unpack("!H", data[2:4])[0]
        proto = data[9]

        try:
            src_ip = socket.inet_ntoa(data[12:16])
            dst_ip = socket.inet_ntoa(data[16:20])
        except OSError:
            return result

        result["ip_version"] = 4
        result["ip_proto"] = proto
        result["src_ip"] = src_ip
        result["dst_ip"] = dst_ip

        l4 = data[ihl:total_length] if total_length >= ihl else data[ihl:]

    # ---------------------------------------------------------
    # IPv6
    # ---------------------------------------------------------
    elif ether_type == 0x86DD:
        if len(data) < 40:
            return result

        version = (data[0] >> 4) & 0x0F
        if version != 6:
            return result

        next_header = data[6]

        try:
            src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
            dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])
        except OSError:
            return result

        result["ip_version"] = 6
        result["ip_proto"] = next_header
        result["src_ip"] = src_ip
        result["dst_ip"] = dst_ip

        l4 = data[40:]

    else:
        return result

    # ---------------------------------------------------------
    # ESP
    # ---------------------------------------------------------
    if result["ip_proto"] == 50:
        result["is_esp"] = True
        result["l4_payload"] = l4
        return result

    # ---------------------------------------------------------
    # UDP
    # ---------------------------------------------------------
    if result["ip_proto"] == 17:
        if len(l4) < 8:
            return result

        src_port, dst_port, udp_len, _checksum = struct.unpack(
            "!HHHH",
            l4[:8]
        )

        udp_payload = l4[8:]

        result["src_port"] = src_port
        result["dst_port"] = dst_port
        result["l4_payload"] = udp_payload

        # Native IKE:
        #   UDP/500
        #
        # NAT-T:
        #   UDP/4500 + 4-byte non-ESP marker (00 00 00 00)
        is_port_500 = src_port == 500 or dst_port == 500
        is_port_4500 = src_port == 4500 or dst_port == 4500

        if is_port_500:
            result["is_ike"] = True

        elif is_port_4500:
            if len(udp_payload) >= 4 and udp_payload[:4] == b"\x00\x00\x00\x00":
                result["is_ike"] = True
                result["l4_payload"] = udp_payload[4:]
            else:
                # UDP/4500 can also carry encapsulated ESP.
                # Keep it classified as non-IKE unless the
                # non-ESP marker is present.
                result["is_ike"] = False

    return result


def get_tshark_binary() -> str:
    """Dynamically locates the tshark binary on the system.

    Preference order:
    1. explicit environment override (TSHARK_PATH / WIRESHARK_TSHARK_PATH)
    2. shell-discovered tshark executable
    3. Linux/WSL paths
    4. Windows-installed Wireshark paths, including WSL-mounted drives
    """
    override = os.environ.get("TSHARK_PATH") or os.environ.get("WIRESHARK_TSHARK_PATH")
    if override:
        expanded = os.path.expandvars(os.path.expanduser(override))
        if os.path.isfile(expanded):
            return expanded

    for executable_name in ("tshark", "tshark.exe"):
        binary = shutil.which(executable_name)
        if binary:
            return binary

    candidates = [
        "/usr/bin/tshark",
        "/usr/local/bin/tshark",
        "/bin/tshark",
        "/usr/bin/tshark.exe",
        "/usr/local/bin/tshark.exe",
        "/bin/tshark.exe",
        os.path.join(
            os.path.expanduser("~"),
            "Downloads",
            "Wireshark",
            "tshark.exe",
        ),
    ]

    windows_roots = [
        os.environ.get("ProgramFiles"),
        os.environ.get("ProgramFiles(x86)"),
        r"C:\Program Files",
        r"C:\Program Files (x86)",
        "/mnt/c/Program Files",
        "/mnt/c/Program Files (x86)",
        "/c/Program Files",
        "/c/Program Files (x86)",
    ]

    seen: set[str] = set()
    for root in windows_roots:
        if not root:
            continue
        for candidate in (
            os.path.join(root, "Wireshark", "tshark.exe"),
            os.path.join(root, "Wireshark", "tshark"),
            os.path.join(root, "Wireshark", "tshark.exe"),
        ):
            candidate = os.path.normpath(candidate)
            if candidate not in seen:
                seen.add(candidate)
                candidates.append(candidate)

    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate

    raise FileNotFoundError(
        "tshark binary not found on the system. "
        "Please ensure Wireshark/TShark is installed or set TSHARK_PATH/WIRESHARK_TSHARK_PATH."
    )


def get_capinfos_binary() -> Optional[str]:
    """Dynamically locates the capinfos binary on the system if available."""
    binary = shutil.which("capinfos")
    if binary:
        return binary
    for candidate in ["/usr/bin/capinfos", "/usr/local/bin/capinfos"]:
        if os.path.exists(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def validate_pcap(filepath: str | Path) -> str:
    """
    Validates that the file exists, is non-empty, and checks header magic bytes.
    Returns format string: 'pcap', 'pcapng', or raises ValueError.
    """
    p = Path(filepath)
    if not p.exists():
        raise FileNotFoundError(f"Packet capture file not found: {filepath}")
    
    if p.stat().st_size == 0:
        raise ValueError(f"Packet capture file is empty (0 bytes): {filepath}")

    with open(p, "rb") as f:
        magic_bytes = f.read(4)
        if len(magic_bytes) < 4:
            raise ValueError(f"File too small to be a valid PCAP: {filepath}")

        magic = struct.unpack(">I", magic_bytes)[0]
        if magic in (PCAP_MAGIC_MICROSECONDS, PCAP_MAGIC_NANOSECONDS, 
                     PCAP_MAGIC_SWAPPED, PCAP_MAGIC_NANO_SWAPPED):
            return "pcap"
        elif magic == PCAPNG_MAGIC:
            return "pcapng"
        else:
            # Let tshark try validating if custom headers exist
            return "unknown"


def get_pcap_metadata(filepath: str | Path) -> PcapMetadata:
    """
    Extracts dynamic metadata from a packet capture using capinfos or tshark.
    Does not use any hardcoded values or assumptions.
    """
    filepath = str(filepath)
    file_format = validate_pcap(filepath)
    filesize = os.path.getsize(filepath)

    capinfos_bin = get_capinfos_binary()
    if capinfos_bin:
        try:
            cmd = [capinfos_bin, "-c", "-u", "-a", "-e", "-y", "-M", filepath]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
            if res.returncode == 0:
                pkt_count = 0
                duration = 0.0
                start_time = None
                end_time = None
                encap = None

                for line in res.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("Number of packets:"):
                        pkt_count = int(line.split(":")[-1].strip().replace(",", ""))
                    elif line.startswith("Capture duration:"):
                        val_str = line.split(":")[-1].strip().replace("seconds", "").strip()
                        duration = float(val_str)
                    elif line.startswith("First packet time:"):
                        start_time = line.split("First packet time:")[-1].strip()
                    elif line.startswith("Last packet time:"):
                        end_time = line.split("Last packet time:")[-1].strip()
                    elif line.startswith("File encapsulation:"):
                        encap = line.split(":")[-1].strip()

                return PcapMetadata(
                    filepath=filepath,
                    file_format=file_format,
                    filesize_bytes=filesize,
                    packet_count=pkt_count,
                    start_time=start_time,
                    end_time=end_time,
                    duration_seconds=duration,
                    encapsulation=encap
                )
        except Exception:
            pass

    # Fallback to tshark query for packet count and times
    tshark_bin = get_tshark_binary()
    try:
        cmd = [tshark_bin, "-r", filepath, "-T", "fields", "-e", "frame.number", "-e", "frame.time_epoch"]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        lines = [l.strip() for l in res.stdout.splitlines() if l.strip()]
        pkt_count = len(lines)
        duration = 0.0
        start_epoch = None
        end_epoch = None
        if lines:
            first_parts = lines[0].split()
            last_parts = lines[-1].split()
            if len(first_parts) >= 2:
                start_epoch = float(first_parts[1])
            if len(last_parts) >= 2:
                end_epoch = float(last_parts[1])
            if start_epoch is not None and end_epoch is not None:
                duration = max(0.0, end_epoch - start_epoch)

        return PcapMetadata(
            filepath=filepath,
            file_format=file_format,
            filesize_bytes=filesize,
            packet_count=pkt_count,
            start_time=str(start_epoch) if start_epoch else None,
            end_time=str(end_epoch) if end_epoch else None,
            duration_seconds=duration,
            encapsulation=None
        )
    except Exception as e:
        return PcapMetadata(
            filepath=filepath,
            file_format=file_format,
            filesize_bytes=filesize,
            packet_count=0,
            duration_seconds=0.0
        )


def run_tshark_json(
    filepath: str | Path,
    display_filter: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
    timeout: int = 60
) -> List[Dict[str, Any]]:
    """
    Executes tshark with `-T json --no-duplicate-keys` to extract the full JSON Abstract Syntax Tree (AST).
    Returns list of parsed packet objects from the AST.
    """
    tshark_bin = get_tshark_binary()
    cmd = [tshark_bin, "-r", str(filepath), "-T", "json", "--no-duplicate-keys"]
    
    if display_filter:
        cmd.extend(["-Y", display_filter])

    if extra_args:
        cmd.extend(extra_args)

    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout
    )

    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(
            f"tshark failed with exit code {proc.returncode}: {proc.stderr.strip()}"
        )

    output = proc.stdout.strip()
    if not output:
        return []

    try:
        data = json.loads(output)
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            return [data]
        return []
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse tshark JSON AST: {str(e)}\nOutput snippet: {output[:300]}")


def filter_and_save_pcap(
    filepath: str | Path,
    display_filter: str,
    output_path: str | Path,
    timeout: int = 60
) -> int:
    """
    Filters packets from filepath matching display_filter and writes them into output_path.
    Returns the number of matching packets written.
    """
    tshark_bin = get_tshark_binary()
    out_p = Path(output_path)
    out_p.parent.mkdir(parents=True, exist_ok=True)

    cmd = [tshark_bin, "-r", str(filepath), "-Y", display_filter, "-w", str(output_path)]
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout
    )

    if proc.returncode != 0 and not os.path.exists(output_path):
        raise RuntimeError(
            f"tshark filter failed ({proc.returncode}): {proc.stderr.strip()}"
        )

    if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
        meta = get_pcap_metadata(output_path)
        return meta.packet_count
    return 0
# Backward-compatible names used by older Part 2 tests.
PcapReaderCompat = PcapReader


def find_pcap_for_job(job_id: str) -> Optional[Path]:
    """Resolve an uploaded job ID or testbed config ID to its physical PCAP file on disk."""
    if not job_id:
        return None

    root = Path(__file__).resolve().parents[2]
    clean_id = job_id.removeprefix("testbed_")

    # 1. Check uploaded PCAPs
    upload_dir = root / "backend" / "uploads"
    for candidate in (job_id, clean_id):
        for ext in [".pcap", ".pcapng", ".cap"]:
            p = upload_dir / f"{candidate}{ext}"
            if p.exists() and p.stat().st_size > 0:
                return p

    # 2. Check testbed captures direct matches
    cap_dir = root / "captures"
    for candidate in (job_id, clean_id):
        for pattern in [
            f"{candidate}.pcap",
            f"{candidate}_all.pcap",
            f"{candidate}",
            f"{candidate.removesuffix('_all')}_all.pcap",
        ]:
            p = cap_dir / pattern
            if p.exists() and p.stat().st_size > 0:
                return p

    # 3. Check captures/manifest.json
    manifest_path = cap_dir / "manifest.json"
    if manifest_path.exists():
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
                for c in manifest.get("captures", []):
                    cid = c.get("config_id", "")
                    if cid in (job_id, clean_id) or clean_id.startswith(cid) or job_id.startswith(cid):
                        p = root / c.get("pcap_path")
                        if p.exists() and p.stat().st_size > 0:
                            return p
        except Exception:
            pass

    return None

