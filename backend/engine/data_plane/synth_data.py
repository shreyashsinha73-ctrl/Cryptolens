"""
synth_data.py
-------------
Stage: engine/data_plane (dev tool, not part of the pipeline itself)

Generates synthetic .npz feature files with the SAME schema feature_extract.py
produces, so you can run dataset.py -> train.py end-to-end *today*, before
Stage 1 (testbed) and Stage 2 (capture/demux) hand you real ESP pcaps.

Signal design (F-02 v2 fix):
------------------------------
The synthetic packet lengths now match the actual frame.len distribution
observed in the 6 strongSwan testbed captures:

  Tunnel mode (n=248):
    min=122, p25=122, p75=270, max=1514, mean=312, std=360
    The captures contain bimodal traffic: small ICMP pings (122B) +
    large iperf/wget data frames (up to 1514B).

  Transport mode (n=249):
    min=102, p25=102, p75=262, max=1510, mean=325, std=395
    Identical bimodal structure but with ~20B smaller floor (no outer IP).

The tunnel/transport discriminator is specifically the lower-percentile floor
(tunnel floor ~122, transport floor ~102, delta ~20B). Jitter on the small
cluster must be << 20B to preserve this signal.  Large data frames carry no
mode signal (both modes hit MTU), so they are modelled with high jitter.

This is NOT a substitute for real traffic. It exists to validate the
feature_extract -> dataset -> cnn_model -> train wiring before real captures
are available. Once real captures flow, retrain with feature_extract.py output.
"""

import argparse
import os
import random

import numpy as np

from feature_extract import MODE_CLASSES, SEQ_LEN, TRAFFIC_CLASSES

# ---------------------------------------------------------------------------
# Realistic frame.len distributions from testbed captures (frame.len includes
# Ethernet header, IP header, ESP header, and payload).
#
# Each profile is a bimodal mixture:
#   - small cluster: control/ICMP/ACK packets
#   - large cluster: data frames (iperf/wget)
# ---------------------------------------------------------------------------

# Tunnel overhead: outer-IP (20B) + ESP header/trailer (~18B avg) = ~38B
# Transport no outer-IP, just ESP header/trailer (~18B avg)
TUNNEL_FLOOR = 122    # min observed tunnel frame (84B ICMP + 38B tunnel overhead)
TRANSPORT_FLOOR = 102 # min observed transport frame (84B ICMP + 18B ESP overhead)
FLOOR_JITTER = 3      # ±3 bytes -- must be < half of (122-102=20) delta

# Data-frame cluster (bimodal high end)
DATA_BASE = 900
DATA_JITTER = 350     # high jitter OK here -- large frames carry no mode signal

# Per-traffic-type IAT (timing used for traffic-type discrimination, not mode)
TRAFFIC_PROFILES = {
    "https": {"iat_mean": 0.010, "iat_jitter": 0.012, "large_prob": 0.55},
    "voip":  {"iat_mean": 0.020, "iat_jitter": 0.002, "large_prob": 0.15},
    "icmp":  {"iat_mean": 0.500, "iat_jitter": 0.350, "large_prob": 0.05},
}


def _packet_length(mode: str, traffic_type: str, rng: random.Random) -> float:
    """Sample one packet length, faithful to the real bimodal distribution."""
    profile = TRAFFIC_PROFILES[traffic_type]
    floor = TUNNEL_FLOOR if mode == "tunnel" else TRANSPORT_FLOOR

    if rng.random() < profile["large_prob"]:
        # Large data frame (goes up to MTU ~1514)
        base = DATA_BASE + rng.gauss(0, DATA_JITTER)
        length = min(1514.0, max(float(floor) + 50, base))
        # Add tunnel overhead to large frames too
        if mode == "tunnel":
            length = min(1514.0, length + rng.gauss(38, 4))
    else:
        # Small control/ICMP packet -- the mode discriminator lives here
        length = floor + rng.gauss(0, FLOOR_JITTER)
        length = max(float(floor), length)

    return length


def make_session(
    config_id: str,
    traffic_type: str,
    mode: str,
    run_idx: int,
    seq_len: int,
    rng: random.Random,
):
    profile = TRAFFIC_PROFILES[traffic_type]

    # Minimum session length 2/3 of seq_len so the model sees enough packets
    # for the floor shift to be statistically visible.
    min_packets = max(seq_len * 2 // 3, 10)
    n_packets = rng.randint(min_packets, seq_len)

    lengths = np.array(
        [_packet_length(mode, traffic_type, rng) for _ in range(n_packets)],
        dtype=np.float32,
    )

    iats = [0.0] + [
        max(0.0005, profile["iat_mean"] + rng.gauss(0, profile["iat_jitter"]))
        for _ in range(n_packets - 1)
    ]
    iats = np.array(iats, dtype=np.float32)

    s_l = np.zeros(seq_len, dtype=np.float32)
    s_iat = np.zeros(seq_len, dtype=np.float32)
    mask = np.zeros(seq_len, dtype=np.float32)
    s_l[:n_packets] = lengths
    s_iat[:n_packets] = iats
    mask[:n_packets] = 1.0

    session_id = f"{config_id}__{traffic_type}__{mode}__{run_idx:03d}"
    return {
        "S_L": s_l,
        "S_IAT": s_iat,
        "mask": mask,
        "n_real_packets": n_packets,
        "total_esp_packets": n_packets,
        "session_id": session_id,
        "config_id": config_id,
        "traffic_type": traffic_type,
        "mode": mode,
        "run_idx": str(run_idx),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("output_dir")
    ap.add_argument(
        "--configs",
        type=int,
        default=6,
        help="Number of synthetic config IDs (cfg01..cfgNN)",
    )
    ap.add_argument("--runs-per-combo", type=int, default=10)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    os.makedirs(args.output_dir, exist_ok=True)

    config_ids = [f"cfg{i:02d}" for i in range(1, args.configs + 1)]
    count = 0
    for config_id in config_ids:
        for mode in MODE_CLASSES:
            for traffic_type in TRAFFIC_CLASSES:
                for run_idx in range(args.runs_per_combo):
                    session = make_session(
                        config_id, traffic_type, mode, run_idx, SEQ_LEN, rng
                    )
                    out_path = os.path.join(
                        args.output_dir, f"{session['session_id']}.npz"
                    )
                    np.savez(out_path, **session)
                    count += 1

    print(f"Wrote {count} synthetic session .npz files to {args.output_dir}")


if __name__ == "__main__":
    main()
