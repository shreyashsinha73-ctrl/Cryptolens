"""
feature_extract.py
-------------------
Stage: engine/data_plane

Turns a single ESP-only capture (already demuxed by capture/demux.py, i.e.
IP proto 50 packets for one session) into the two fixed-length sequences
the CNN consumes:

    S_L    : first SEQ_LEN packet lengths (bytes, on-the-wire IP length)
    S_IAT  : inter-arrival times between consecutive packets (seconds)

Design notes tied to the project doc:
- We take *lengths of the outer IP packet*, not payload length, because the
  Tunnel-vs-Transport size offset (delta S ~= 20-40 bytes) shows up there.
- Fixed SEQ_LEN=30 per the spec ("First 30 packet lengths (S_L)").
- Sessions with fewer than SEQ_LEN packets are zero-padded; we also emit a
  boolean mask so short sessions don't get silently treated as if they had
  real zero-length packets (kept in the .npz for future use, current model
  does not need it but it's cheap to keep and avoids relabeling data later).
- Each session becomes one .npz. A session = one capture file = one tunnel
  run under one config with one traffic type. Filename convention (adjust
  to match whatever run_capture_session.sh actually emits):

      <config_id>__<traffic_type>__<mode>__<run_idx>.pcap
      e.g. cfg03__https__tunnel__002.pcap

  If your naming differs, only `parse_label_from_filename` needs to change.
"""

import argparse
import json
import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path

import numpy as np

try:
    from scapy.all import PcapReader, IP
except ImportError as e:
    raise SystemExit(
        "scapy is required (pip install scapy --break-system-packages). "
        f"Original error: {e}"
    )

SEQ_LEN = 30

# Keep these label sets in one place so dataset.py / cnn_model.py / train.py
# all agree on the integer <-> name mapping.
MODE_CLASSES = ["transport", "tunnel"]
TRAFFIC_CLASSES = ["https", "voip", "icmp"]


@dataclass
class SessionLabel:
    config_id: str
    traffic_type: str
    mode: str
    run_idx: str


def parse_label_from_filename(pcap_path: str) -> SessionLabel:
    """
    Parses '<config_id>__<traffic_type>__<mode>__<run_idx>.pcap'.
    Raises ValueError with a clear message if the filename doesn't match,
    since a silently mislabeled session is worse than a crash here.
    """
    stem = Path(pcap_path).stem
    parts = stem.split("__")
    if len(parts) != 4:
        raise ValueError(
            f"Filename '{stem}' doesn't match "
            "<config_id>__<traffic_type>__<mode>__<run_idx>. "
            "Update parse_label_from_filename() to match your actual "
            "run_capture_session.sh naming convention."
        )
    config_id, traffic_type, mode, run_idx = parts
    traffic_type = traffic_type.lower()
    mode = mode.lower()
    if traffic_type not in TRAFFIC_CLASSES:
        raise ValueError(f"Unknown traffic_type '{traffic_type}' in {stem}")
    if mode not in MODE_CLASSES:
        raise ValueError(f"Unknown mode '{mode}' in {stem}")
    return SessionLabel(config_id, traffic_type, mode, run_idx)


def extract_esp_lengths_and_times(pcap_path: str):
    """
    Reads a pcap and returns (lengths: list[int], timestamps: list[float])
    for packets that carry an ESP payload (IP proto 50), in capture order.
    Streams the file (PcapReader) instead of loading it fully, since capture
    sessions can be large.

    Known limitations (documented, not fixed here - out of MVP scope):
    - IPv4 only. IPv6 ESP (identified via the Next Header field, not proto)
      is not detected. Matches the testbed's current IPv4-only MVP scope.
    - No NAT-Traversal support. ESP encapsulated in UDP (port 4500) for
      NAT-T deployments will not be detected as ESP by this proto==50 check,
      since it arrives as a UDP packet, not proto 50. Fine for a direct,
      non-NATed lab testbed; would need explicit handling for real-world
      NATed deployments.
    """
    lengths, timestamps = [], []
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            if IP in pkt and pkt[IP].proto == 50:  # 50 == ESP
                # len(pkt) would include the link-layer (e.g. Ethernet, ~14 byte)
                # header from however the pcap was captured, which is NOT what
                # we want - the Tunnel/Transport size signature lives in the IP
                # packet itself. len(pkt[IP]) gives the IP header + payload only.
                lengths.append(len(pkt[IP]))
                timestamps.append(float(pkt.time))
    return lengths, timestamps


def build_sequences(lengths, timestamps, seq_len: int = SEQ_LEN):
    """
    Builds fixed-length S_L and S_IAT from raw per-packet lengths/timestamps.

    S_L:   first seq_len lengths, zero-padded if the session is shorter.
    S_IAT: inter-arrival times aligned to S_L. iat[i] = t[i] - t[i-1] for
           i >= 1; iat[0] is set to 0.0 by convention (no "previous" packet).
           This keeps S_L and S_IAT the same length (seq_len), which is what
           the 2-channel CNN input expects.
    mask:  1 where a real packet exists at that position, 0 for padding.
    """
    n = min(len(lengths), seq_len)

    s_l = np.zeros(seq_len, dtype=np.float32)
    s_iat = np.zeros(seq_len, dtype=np.float32)
    mask = np.zeros(seq_len, dtype=np.float32)

    s_l[:n] = lengths[:n]
    mask[:n] = 1.0

    for i in range(1, n):
        s_iat[i] = timestamps[i] - timestamps[i - 1]

    return s_l, s_iat, mask, n


def process_pcap(pcap_path: str, out_dir: str, seq_len: int = SEQ_LEN):
    label = parse_label_from_filename(pcap_path)
    lengths, timestamps = extract_esp_lengths_and_times(pcap_path)

    if len(lengths) == 0:
        raise ValueError(
            f"No ESP (proto 50) packets found in {pcap_path}. "
            "Check that this file was demuxed correctly by capture/demux.py."
        )

    s_l, s_iat, mask, n_real = build_sequences(lengths, timestamps, seq_len)

    session_id = Path(pcap_path).stem
    out_path = Path(out_dir) / f"{session_id}.npz"
    os.makedirs(out_dir, exist_ok=True)

    np.savez(
        out_path,
        S_L=s_l,
        S_IAT=s_iat,
        mask=mask,
        n_real_packets=n_real,
        total_esp_packets=len(lengths),
        session_id=session_id,
        **asdict(label),
    )
    return out_path


def main():
    ap = argparse.ArgumentParser(
        description="Extract S_L/S_IAT features from ESP-only capture sessions."
    )
    ap.add_argument(
        "input_dir",
        help="Directory of demuxed ESP-only .pcap files (one per session).",
    )
    ap.add_argument(
        "output_dir",
        help="Where to write per-session .npz feature files.",
    )
    ap.add_argument("--seq-len", type=int, default=SEQ_LEN)
    args = ap.parse_args()

    pcaps = sorted(Path(args.input_dir).glob("*.pcap"))
    if not pcaps:
        raise SystemExit(f"No .pcap files found in {args.input_dir}")

    ok, failed = 0, []
    for pcap_path in pcaps:
        try:
            out_path = process_pcap(str(pcap_path), args.output_dir, args.seq_len)
            print(f"[ok] {pcap_path.name} -> {out_path.name}")
            ok += 1
        except Exception as e:
            print(f"[FAIL] {pcap_path.name}: {e}")
            failed.append(str(pcap_path))

    summary = {"processed": ok, "failed": failed}
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
