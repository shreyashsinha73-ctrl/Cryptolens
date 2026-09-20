"""
synth_data.py
-------------
Stage: engine/data_plane (dev tool, not part of the pipeline itself)

Generates synthetic .npz feature files with the SAME schema feature_extract.py
produces, so you can run dataset.py -> train.py end-to-end *today*, before
Stage 1 (testbed) and Stage 2 (capture/demux) hand you real ESP pcaps.

The synthetic signal deliberately encodes the two structural facts the
project doc claims are learnable:
- Tunnel mode packets are ~20-40 bytes larger than Transport mode
  (outer IP header + ESP overhead).
- VoIP is small-packet/periodic, HTTPS is larger/bursty-ish, ICMP is
  small/sparse with irregular gaps.

This is NOT a substitute for real traffic - it exists purely to prove the
feature_extract -> dataset -> cnn_model -> train wiring is correct before
you spend testbed time. Delete or ignore once real captures are flowing.
"""

import argparse
import os
import random

import numpy as np

from feature_extract import MODE_CLASSES, SEQ_LEN, TRAFFIC_CLASSES

# Rough per-traffic-type packet size / timing profiles (synthetic, not measured).
TRAFFIC_PROFILES = {
    "https": {"base_len": 1200, "len_jitter": 60, "iat_mean": 0.02, "iat_jitter": 0.015},
    "voip":  {"base_len": 200,  "len_jitter": 15, "iat_mean": 0.02, "iat_jitter": 0.003},
    "icmp":  {"base_len": 84,   "len_jitter": 4,  "iat_mean": 0.5,  "iat_jitter": 0.4},
}
# NOTE on jitter values: the project doc's claimed Tunnel/Transport signature is a
# small, near-constant per-packet size offset (~20-40 bytes) added by the outer
# IP/ESP headers. If per-packet length jitter is comparable to or larger than that
# offset (as a first draft of this generator had it), the offset is buried in noise
# for any session short enough that it doesn't average out - that's a property of
# the data, not the model. Real strongSwan captures should have tighter per-flow
# length distributions than this synthetic jitter models, but if your real accuracy
# on mode detection comes out low, this confound (traffic-type size variance
# swamping the mode offset) is the first thing to check, e.g. via a per-traffic-type
# breakdown of the mode confusion matrix.

TUNNEL_OVERHEAD_BYTES = 30  # midpoint of the doc's ~20-40 byte delta


def make_session(config_id: str, traffic_type: str, mode: str, run_idx: int, seq_len: int, rng: random.Random):
    profile = TRAFFIC_PROFILES[traffic_type]
    n_packets = rng.randint(seq_len // 2, seq_len)  # some sessions shorter than seq_len, on purpose

    lengths = np.array(
        [max(40, profile["base_len"] + rng.gauss(0, profile["len_jitter"])) for _ in range(n_packets)],
        dtype=np.float32,
    )
    if mode == "tunnel":
        lengths += TUNNEL_OVERHEAD_BYTES

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
    ap.add_argument("--configs", type=int, default=6, help="Number of synthetic configs (cfg01..cfgNN)")
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
                    session = make_session(config_id, traffic_type, mode, run_idx, SEQ_LEN, rng)
                    out_path = os.path.join(args.output_dir, f"{session['session_id']}.npz")
                    np.savez(out_path, **session)
                    count += 1

    print(f"Wrote {count} synthetic session .npz files to {args.output_dir}")


if __name__ == "__main__":
    main()
