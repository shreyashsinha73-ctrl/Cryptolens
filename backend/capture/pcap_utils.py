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


def get_tshark_binary() -> str:
    """Dynamically locates the tshark binary on the system."""
    binary = shutil.which("tshark")
    if not binary:
        # Fallback common system locations
        for candidate in ["/usr/bin/tshark", "/usr/local/bin/tshark", "/bin/tshark"]:
            if os.path.exists(candidate) and os.access(candidate, os.X_OK):
                return candidate
        raise FileNotFoundError(
            "tshark binary not found on the system. Please ensure wireshark/tshark is installed."
        )
    return binary


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

